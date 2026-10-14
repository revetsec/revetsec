/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.revetsec.scim;

import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.Base64;
import java.util.List;
import static java.util.Objects.requireNonNull;

/** Direct, whole-tree evaluation using the facade's original work budget. */
final class ScimFilterEvaluation {
    private final @NonNull ScimResourceType type;
    private final @NonNull ScimStringMatching matching;
    private final @NonNull ScimWork work;
    private final boolean standardGroup;
    private @Nullable ScimError error;

    private ScimFilterEvaluation(@NonNull ScimResourceType type, @NonNull ScimStringMatching matching,
            @NonNull ScimWork work) {
        this.type=type; this.matching=matching; this.work=work;
        standardGroup=type.hasStandardGroupSchema();
    }

    /** Checks size before serialization/reparsing under the receiving provider's limits. */
    static @Nullable String expression(@NonNull ScimFilter filter, @NonNull ScimFilterLimits limits,
            @NonNull ScimWork work) {
        Footprint footprint=new Footprint(limits,work);
        long length=footprint.length(filter,0,1);
        if (length < 0 || !work.spend(length)) return null;
        return filter.toScimString();
    }

    static @NonNull ScimFilterEvaluationResult evaluate(@NonNull ScimResource resource,
            @NonNull ScimFilter bound, @NonNull ScimStringMatching matching, @NonNull ScimWork work) {
        ScimFilterEvaluation engine=new ScimFilterEvaluation(resource.getResourceType(),matching,work);
        boolean matched=engine.predicate(bound,resource.getDocument(),null,null);
        ScimError failure=engine.error;
        return failure == null ? new ScimFilterEvaluationResult.Succeeded(matched)
                : new ScimFilterEvaluationResult.Rejected(failure);
    }

    private boolean spend(long amount) {
        if (error != null) return false;
        if (work.spend(amount)) return true;
        error=ScimError.requestTooLargeInstance(); return false;
    }

    private boolean predicate(@NonNull ScimFilter filter, @NonNull JsonObject container,
            @Nullable ScimAttributeDefinition parent, @Nullable ScimAttributePath prefix) {
        if (!spend(1)) return false;
        if (filter instanceof ScimFilter.And and) {
            boolean result=true;
            for (ScimFilter operand:and.getOperands()) {
                result=predicate(operand,container,parent,prefix) && result;
                if (error != null) return false;
            }
            return result;
        }
        if (filter instanceof ScimFilter.Or or) {
            boolean result=false;
            for (ScimFilter operand:or.getOperands()) {
                result=predicate(operand,container,parent,prefix) || result;
                if (error != null) return false;
            }
            return result;
        }
        if (filter instanceof ScimFilter.Not not) return !predicate(not.getOperand(),container,parent,prefix);
        ScimAttributePath path=filter instanceof ScimFilter.ValuePath valuePath ? valuePath.getAttributePath()
                : filter instanceof ScimFilter.Present present ? present.getAttributePath()
                : ((ScimFilter.Comparison)filter).getAttributePath();
        if (!spend(1L+(parent == null ? type.definitionCount() : parent.definitionCount()))) return false;
        ScimAttributeDefinition top=parent == null
                ? requireNonNull(ScimSchemas.find(type,ScimFilterBinding.path(path.getSchemaId().orElse(null),path.getAttributeName(),null)).orElse(null))
                : requireNonNull(ScimSchemas.attribute(parent.getSubAttributes(),path.getAttributeName()).orElse(null));
        JsonObject scope=container;
        if (parent == null && path.getSchemaId().isPresent()) {
            String id=path.getSchemaId().orElseThrow();
            if (!spend(id.length())) return false;
            JsonValue extension=container.getMembers().get(id);
            if (extension instanceof JsonObject object) scope=object;
            else return test(null,top,filter,path);
        }
        JsonValue value=scope.getMembers().get(top.getName());
        if (filter instanceof ScimFilter.ValuePath valuePath) {
            if (!(value instanceof JsonArray array)) return false;
            boolean result=false;
            for (JsonValue element:array.getElements()) {
                if (!spend(1)) return false;
                if (element instanceof JsonObject object)
                    result=predicate(valuePath.getFilter(),object,top,path) || result;
                if (error != null) return false;
            }
            return result;
        }
        ScimAttributeDefinition leaf=top;
        String sub=path.getSubAttributeName().orElse(null);
        if (sub != null) {
            if (!spend(top.getSubAttributes().size())) return false;
            leaf=requireNonNull(ScimSchemas.attribute(top.getSubAttributes(),sub).orElse(null));
        }
        ScimAttributePath target=path;
        if (prefix != null) {
            if (!spend(1L+prefix.toScimString().length()+path.toScimString().length())) return false;
            // Schema registration forbids nested complex application attributes. A bound
            // ValuePath child therefore has exactly one representable canonical subattribute.
            target=ScimFilterBinding.path(prefix.getSchemaId().orElse(null),prefix.getAttributeName(),path.getAttributeName());
        }
        if (sub != null) {
            if (value instanceof JsonArray array) {
                if (array.getElements().isEmpty()) return test(null,leaf,filter,target);
                boolean result=false;
                for (JsonValue element:array.getElements()) {
                    if (!spend(1)) return false;
                    JsonValue child=element instanceof JsonObject object ? object.getMembers().get(sub) : null;
                    result=test(child,leaf,filter,target) || result;
                    if (error != null) return false;
                }
                return result;
            }
            value=value instanceof JsonObject object ? object.getMembers().get(sub) : null;
        }
        return test(value,leaf,filter,target);
    }

    private boolean test(@Nullable JsonValue value, @NonNull ScimAttributeDefinition definition,
            @NonNull ScimFilter filter, @NonNull ScimAttributePath path) {
        if (!spend(1)) return false;
        if (filter instanceof ScimFilter.Present) return present(value,definition);
        if (filter instanceof ScimFilter.ValuePath) return false;
        ScimFilter.Comparison comparison=(ScimFilter.Comparison)filter;
        ScimComparisonOperator operator=comparison.getOperator();
        ScimFilterValue literal=comparison.getValue();
        if (value instanceof JsonArray array && !array.getElements().isEmpty()) {
            boolean result=false;
            for (JsonValue element:array.getElements()) {
                result=test(element,definition,filter,path) || result;
                if (error != null) return false;
            }
            return result;
        }
        boolean absent=value == null || value instanceof JsonNull
                || definition.isMultiValued() && value instanceof JsonArray array && array.getElements().isEmpty();
        if (literal instanceof ScimFilterValue.NullValue) return operator == ScimComparisonOperator.EQ ? absent : !absent;
        if (absent) return operator == ScimComparisonOperator.NE;
        if (value instanceof JsonString string && literal instanceof ScimFilterValue.StringValue text) {
            String left=string.getValue(), right=text.getValue();
            if (!spend(1L+left.length()+right.length())) return false;
            if (definition.getType() == ScimAttributeType.DATE_TIME) {
                Integer order=ScimTypedComparison.dateComparison(left,right);
                if (order == null) { error=ScimError.invalidFilterInstance(); return false; }
                return verdict(order,operator);
            }
            if (definition.getType() == ScimAttributeType.BINARY)
                return verdict(java.util.Arrays.equals(Base64.getDecoder().decode(left),Base64.getDecoder().decode(right)) ? 0 : 1,operator);
            if (definition.getType() == ScimAttributeType.REFERENCE || groupMemberId(path)) {
                if (operator == ScimComparisonOperator.CO && !spend((long)left.length()*right.length())) return false;
                return switch (operator) {
                    case CO -> left.contains(right); case SW -> left.startsWith(right); case EW -> left.endsWith(right);
                    default -> verdict(left.compareTo(right),operator);
                };
            }
            ScimStringMatchResult result=requireNonNull(matching.match(path,definition,operator,left,right));
            if (result instanceof ScimStringMatchResult.Matched matched) return matched.isMatched();
            error=ScimError.invalidFilterInstance(); return false;
        }
        if (value instanceof JsonNumber number && literal instanceof ScimFilterValue.NumberValue numeric) {
            if (!spend((long)number.getValue().precision()+numeric.getValue().precision())) return false;
            return verdict(number.getValue().compareTo(numeric.getValue()),operator);
        }
        if (value instanceof JsonBoolean bool && literal instanceof ScimFilterValue.BooleanValue booleanValue)
            return verdict(Boolean.compare(bool.getValue(),booleanValue.getValue()),operator);
        error=ScimError.invalidFilterInstance(); return false;
    }

    private boolean present(@Nullable JsonValue value,@NonNull ScimAttributeDefinition definition) {
        if (!spend(1)) return false;
        if (value == null || value instanceof JsonNull) return false;
        if (value instanceof JsonString string) return !string.getValue().isEmpty();
        if (value instanceof JsonArray array) {
            boolean result=false;
            for (JsonValue element:array.getElements()) {
                result=present(element,definition) || result;
                if (error != null) return false;
            }
            return result;
        }
        if (value instanceof JsonObject object) {
            boolean result=false;
            for (ScimAttributeDefinition child:definition.getSubAttributes()) {
                if (!spend(1)) return false;
                if (child.getReturned() != ScimReturned.NEVER)
                    result=present(object.getMembers().get(child.getName()),child) || result;
                if (error != null) return false;
            }
            return result;
        }
        return true;
    }

    private boolean groupMemberId(@NonNull ScimAttributePath path) {
        return standardGroup && path.getSchemaId().isEmpty()
                && path.getAttributeName().equals("members") && path.getSubAttributeName().orElse("").equals("value");
    }

    private static boolean verdict(int comparison,@NonNull ScimComparisonOperator operator) {
        return switch (operator) { case EQ -> comparison == 0; case NE -> comparison != 0;
            case GT -> comparison > 0; case GE -> comparison >= 0; case LT -> comparison < 0; case LE -> comparison <= 0;
            default -> false; };
    }

    /** Exact canonical serialized size, bounded before rendering allocates or reparsing recurses. */
    private static final class Footprint {
        private final @NonNull ScimFilterLimits limits;
        private final @NonNull ScimWork work;
        private int nodes;
        Footprint(@NonNull ScimFilterLimits limits,@NonNull ScimWork work) { this.limits=limits; this.work=work; }
        long length(@NonNull ScimFilter filter,int parentPrecedence,int depth) {
            if (!work.spend(1) || depth > limits.getMaximumDepth() || ++nodes > limits.getMaximumNodes()) return -1;
            int precedence=filter instanceof ScimFilter.Or ? 1 : filter instanceof ScimFilter.And ? 2 : 3;
            long result=precedence < parentPrecedence ? 2 : 0;
            if (filter instanceof ScimFilter.And and) result+=operands(and.getOperands(),5,2,depth);
            else if (filter instanceof ScimFilter.Or or) result+=operands(or.getOperands(),4,1,depth);
            else if (filter instanceof ScimFilter.Not not) { long child=length(not.getOperand(),0,depth+1); if (child < 0) return -1; result+=5+child; }
            else {
                ScimAttributePath path=filter instanceof ScimFilter.ValuePath valuePath ? valuePath.getAttributePath()
                        : filter instanceof ScimFilter.Present present ? present.getAttributePath()
                        : ((ScimFilter.Comparison)filter).getAttributePath();
                long pathLength=path.getAttributeName().length()+path.getSchemaId().map(value -> 1L+value.length()).orElse(0L)
                        +path.getSubAttributeName().map(value -> 1L+value.length()).orElse(0L);
                if (!work.spend(pathLength)) return -1;
                result+=pathLength;
                if (filter instanceof ScimFilter.ValuePath valuePath) { long child=length(valuePath.getFilter(),0,depth+1); if (child < 0) return -1; result+=2+child; }
                else if (filter instanceof ScimFilter.Present) result+=3;
                else {
                    ScimFilterValue value=((ScimFilter.Comparison)filter).getValue();
                    result+=4;
                    if (value instanceof ScimFilterValue.StringValue string) {
                        String text=string.getValue();
                        if (text.length() > limits.getMaximumLiteralCharacters() || !work.spend(text.length())) return -1;
                        result+=2;
                        for (int index=0;index<text.length();index++) {
                            char character=text.charAt(index);
                            result+=character == '"' || character == '\\' || character == '\b' || character == '\f'
                                    || character == '\n' || character == '\r' || character == '\t' ? 2 : character < 0x20 ? 6 : 1;
                        }
                    } else if (value instanceof ScimFilterValue.NumberValue number) {
                        String text=number.expression();
                        if (text.length() > limits.getMaximumNumberCharacters() || !work.spend(text.length())) return -1;
                        result+=text.length();
                    } else if (value instanceof ScimFilterValue.BooleanValue bool) result+=bool.getValue() ? 4 : 5;
                    else result+=4;
                }
            }
            return result < 0 || result > limits.getMaximumExpressionCharacters() ? -1 : result;
        }
        private long operands(@NonNull List<@NonNull ScimFilter> operands,int separator,int precedence,int depth) {
            long result=0;
            for (int index=0;index<operands.size();index++) {
                long child=length(operands.get(index),precedence,depth+1);
                if (child < 0) return -limits.getMaximumExpressionCharacters()-1L;
                result+=child+(index == 0 ? 0 : separator);
                if (result > limits.getMaximumExpressionCharacters()) return -limits.getMaximumExpressionCharacters()-1L;
            }
            return result;
        }
    }
}
