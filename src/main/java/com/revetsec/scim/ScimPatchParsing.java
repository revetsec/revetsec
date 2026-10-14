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

import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded PatchOp grammar, canonical schema binding and partial typed normalization. */
@NotThreadSafe
final class ScimPatchParsing {
    private static final @NonNull String PATCH_SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private final @NonNull ScimResourceType type;
    private final @NonNull ScimCompatibility compatibility;
    private final @NonNull ScimLimits limits;
    private final @NonNull ScimWork work;
    private final @NonNull Object context;
    private final @NonNull Set<@NonNull ScimCompatibilityFeature> used;
    private final @NonNull ScimResourceValidation validation;
    private final @NonNull Set<@NonNull ScimAttributePath> requested=new LinkedHashSet<>();
    private @Nullable ScimError error;
    private ScimPatchParsing(@NonNull ScimResourceType type,@NonNull JsonDocument document,
            @NonNull ScimCompatibility compatibility,@NonNull ScimLimits limits,@NonNull ScimWork work,
            @NonNull Object context,@NonNull Set<@NonNull ScimCompatibilityFeature> used) {
        this.type=type; this.compatibility=compatibility; this.limits=limits; this.work=work;
        this.context=context; this.used=used;
        validation=new ScimResourceValidation(type,document,compatibility,work,false,used);
    }
    static @NonNull ScimPatchParseResult parse(@NonNull ScimResourceType type,@NonNull JsonDocument document,
            @NonNull ScimCompatibility compatibility,@NonNull ScimLimits limits,@NonNull ScimWork work,
            @NonNull Object context,@NonNull Set<@NonNull ScimCompatibilityFeature> used) {
        return new ScimPatchParsing(type,document,compatibility,limits,work,context,used).parse(document.getValue());
    }
    private @NonNull ScimPatchParseResult rejected() {
        return new ScimPatchParseResult.Rejected(work.wasExceeded() ? ScimError.requestTooLargeInstance()
                : error != null ? error : validation.failed() ? validation.error() : ScimError.invalidSyntaxInstance());
    }
    private boolean spend(long amount) {
        if (work.spend(amount)) return true;
        error=ScimError.requestTooLargeInstance(); return false;
    }
    private boolean enabled(@NonNull ScimCompatibilityFeature feature) { return compatibility.getFeatures().contains(feature); }
    private @Nullable Map<@NonNull String,@NonNull JsonValue> folded(@NonNull JsonObject object) {
        Map<String,JsonValue> result=new LinkedHashMap<>();
        for (Map.Entry<String,JsonValue> entry:object.getMembers().entrySet()) {
            if (!spend(1L+entry.getKey().length())) return null;
            if (result.putIfAbsent(AsciiCase.fold(entry.getKey()),entry.getValue()) != null) {
                error=ScimError.invalidSyntaxInstance(); return null;
            }
        }
        return result;
    }
    private @NonNull ScimPatchParseResult parse(@NonNull JsonValue raw) {
        if (!(raw instanceof JsonObject object) || object.getMembers().size()!=2) return rejected();
        Map<String,JsonValue> source=folded(object);
        if (source == null || source.size()!=2 || !source.containsKey("schemas") || !source.containsKey("operations")) return rejected();
        JsonValue schemas=source.get("schemas");
        if (!(schemas instanceof JsonArray declarations) || declarations.getElements().size()!=1
                || !(declarations.getElements().get(0) instanceof JsonString declaration)
                || !declaration.getValue().equals(PATCH_SCHEMA)) return rejected();
        if (!(source.get("operations") instanceof JsonArray array) || array.getElements().isEmpty()) return rejected();
        if (array.getElements().size()>limits.getMaximumPatchOperations()) {
            error=ScimError.requestTooLargeInstance(); return rejected();
        }
        List<ScimPatchOperation> operations=new ArrayList<>();
        for (int index=0;index<array.getElements().size();index++) {
            if (!spend(1) || !(array.getElements().get(index) instanceof JsonObject operation)) return rejected();
            ScimPatchOperation normalized=operation(index,operation);
            if (normalized == null) return rejected();
            operations.add(normalized);
        }
        requested.addAll(validation.supplied());
        return new ScimPatchParseResult.Succeeded(new ScimPatchRequest(type,operations,requested,validation.supplied(),context));
    }
    private @Nullable ScimPatchOperation operation(int index,@NonNull JsonObject object) {
        if (object.getMembers().isEmpty() || object.getMembers().size()>3) return null;
        Map<String,JsonValue> source=folded(object);
        if (source == null) return null;
        for (String key:source.keySet()) if (!key.equals("op") && !key.equals("path") && !key.equals("value")) return null;
        if (!(source.get("op") instanceof JsonString op)) return null;
        String text=op.getValue();
        if (!spend(text.length())) return null;
        String folded=AsciiCase.fold(text);
        if (!text.equals(folded)) {
            if (!enabled(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE)) return null;
            if (!folded.equals("add") && !folded.equals("remove") && !folded.equals("replace")) return null;
            used.add(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE);
        }
        ScimPatchOperationType kind=switch(folded) {
            case "add" -> ScimPatchOperationType.ADD;
            case "remove" -> ScimPatchOperationType.REMOVE;
            case "replace" -> ScimPatchOperationType.REPLACE;
            default -> null;
        };
        if (kind == null) return null;
        JsonValue rawPath=source.get("path"), value=source.get("value");
        if (rawPath == null) {
            if (kind == ScimPatchOperationType.REMOVE) { error=ScimError.noTargetInstance(); return null; }
            if (!(value instanceof JsonObject values) || values.getMembers().isEmpty()) return null;
            JsonObject normalized=resourceObject(values);
            return normalized == null ? null : new ScimPatchOperation(index,kind,null,null,null,normalized);
        }
        if (!(rawPath instanceof JsonString pathString)) { error=ScimError.invalidPathInstance(); return null; }
        Target target=target(pathString.getValue());
        if (target == null) return null;
        requested.add(target.path);
        if (target.suffix != null) requested.add(ScimFilterBinding.path(target.path.getSchemaId().orElse(null),target.path.getAttributeName(),target.suffix));
        if (kind == ScimPatchOperationType.REMOVE) {
            if (value != null) {
                if (!enabled(ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE)
                        || target.filter != null || target.path.getSubAttributeName().isPresent()
                        || !target.path.getAttributeName().equals("members") || target.path.getSchemaId().isPresent()
                        || !standardGroup()) return null;
                JsonValue normalized=validation.patchValue(target.definition,value,target.path.toScimString(),false);
                if (!(normalized instanceof JsonArray members) || !removeIds(members)) { error=ScimError.invalidValueInstance(); return null; }
                used.add(ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE);
                return new ScimPatchOperation(index,kind,target.path,null,null,normalized);
            }
            return new ScimPatchOperation(index,kind,target.path,target.filter,target.suffix,null);
        }
        if (value == null) return null;
        JsonValue incoming=value;
        if (kind == ScimPatchOperationType.ADD && target.filter == null && target.definition.isMultiValued()
                && !(incoming instanceof JsonArray) && !(incoming instanceof JsonNull)) incoming=JsonArray.fromElements(List.of(incoming));
        boolean scalarElement=target.filter != null && target.suffix == null;
        JsonValue normalized=validation.patchValue(target.definition,incoming,target.expression,scalarElement);
        if (normalized == null || validation.failed()) return null;
        return new ScimPatchOperation(index,kind,target.path,target.filter,target.suffix,normalized);
    }
    @SuppressWarnings("ReferenceEquality") // The reviewed standard schema singleton defines this vendor membership shape.
    private boolean standardGroup() { return type.getSchema()==ScimSchema.groupInstance(); }
    private boolean removeIds(@NonNull JsonArray array) {
        if (array.getElements().isEmpty()) return false;
        for (JsonValue element:array.getElements()) {
            if (!spend(1) || !(element instanceof JsonObject member) || !(member.getMembers().get("value") instanceof JsonString)) return false;
            for (Map.Entry<String,JsonValue> entry:member.getMembers().entrySet()) {
                if (!spend(1)) return false;
                if (!entry.getKey().equals("value") && !(entry.getKey().equals("$ref") && entry.getValue() instanceof JsonNull)) return false;
            }
        }
        return true;
    }
    private @Nullable Target target(@NonNull String expression) {
        if (expression.isEmpty() || expression.length()>limits.getFilterLimits().getMaximumExpressionCharacters()) { error=ScimError.invalidPathInstance(); return null; }
        if (!spend(expression.length())) return null;
        int open=-1;
        ScimAttributePathParseResult simple=ScimAttributePath.fromExpressionResult(expression);
        if (!(simple instanceof ScimAttributePathParseResult.Succeeded)) open=openingBracket(expression);
        if (open<0) {
            ScimAttributePath path=canonical(expression);
            if (path==null) return null;
            ScimAttributeDefinition definition=find(path);
            return definition == null ? null : new Target(path,null,null,definition,path.toScimString());
        }
        int close=closingBracket(expression,open);
        if (close<0) { error=ScimError.invalidPathInstance(); return null; }
        String outerExpression=expression.substring(0,open);
        ScimAttributePath outer=canonical(outerExpression);
        if (outer==null) return null;
        ScimAttributeDefinition parent=find(outer);
        if (parent == null || outer.getSubAttributeName().isPresent() || !parent.isMultiValued() || parent.getType()!=ScimAttributeType.COMPLEX
                || parent.getReturned()==ScimReturned.NEVER) { error=ScimError.invalidPathInstance(); return null; }
        String suffixText=expression.substring(close+1);
        String suffix=null;
        ScimAttributeDefinition definition=parent;
        if (!suffixText.isEmpty()) {
            if (!suffixText.startsWith(".") || suffixText.length()==1) { error=ScimError.invalidPathInstance(); return null; }
            ScimAttributePath childPath=canonical(outer.toScimString()+suffixText);
            if (childPath == null || childPath.getSubAttributeName().isEmpty()) return null;
            definition=find(childPath);
            if (definition == null) { error=ScimError.invalidPathInstance(); return null; }
            suffix=childPath.getSubAttributeName().orElse(null);
        }
        String selector=expression.substring(open+1,close);
        ScimFilterParseResult syntax=ScimFilter.fromExpressionResult(selector,limits.getFilterLimits());
        if (!(syntax instanceof ScimFilterParseResult.Succeeded accepted)) { error=ScimError.invalidPathInstance(); return null; }
        ScimFilter bound=bindSelector(accepted.getFilter(),parent,outer);
        if (bound == null) { if (error==null) error=ScimError.invalidPathInstance(); return null; }
        return new Target(outer,bound,suffix,definition,outer.toScimString()+(suffix==null ? "" : "."+suffix));
    }
    private int openingBracket(@NonNull String expression) {
        for (int index=0;index<expression.length();index++) {
            if (expression.charAt(index)=='[') {
                if (!spend(index+1L)) return -1;
                if (ScimAttributePath.fromExpressionResult(expression.substring(0,index)) instanceof ScimAttributePathParseResult.Succeeded) return index;
            }
        }
        return -1;
    }
    private static int closingBracket(@NonNull String expression,int open) {
        boolean quoted=false,escaped=false;
        for (int index=open+1;index<expression.length();index++) {
            char unit=expression.charAt(index);
            if (quoted) {
                if (escaped) escaped=false;
                else if (unit=='\\') escaped=true;
                else if (unit=='"') quoted=false;
            } else if (unit=='"') quoted=true;
            else if (unit==']') return index;
            else if (unit=='[') return -1;
        }
        return -1;
    }
    private @Nullable ScimAttributeDefinition find(@NonNull ScimAttributePath path) {
        if (!spend(4L*type.definitionCount())) return null;
        ScimAttributeDefinition definition=ScimSchemas.find(type,path).orElse(null);
        if (definition == null) error=ScimError.invalidPathInstance();
        return definition;
    }
    private @Nullable ScimAttributePath canonical(@NonNull String expression) {
        if (!spend(1L+4L*type.definitionCount())) return null;
        ScimAttributePathParseResult syntax=ScimAttributePath.fromExpressionResult(expression);
        ScimAttributePath canonical=syntax instanceof ScimAttributePathParseResult.Succeeded accepted
                ? ScimSchemas.canonicalPath(type,accepted.getAttributePath()).orElse(null) : null;
        if (canonical == null) error=ScimError.invalidPathInstance();
        return canonical;
    }
    private @Nullable ScimFilter bindSelector(@NonNull ScimFilter node,@NonNull ScimAttributeDefinition parent,@NonNull ScimAttributePath outer) {
        if (!spend(1L+4L*parent.definitionCount())) return null;
        if (node instanceof ScimFilter.And and) {
            List<ScimFilter> children=new ArrayList<>();
            for (ScimFilter child:and.getOperands()) { ScimFilter bound=bindSelector(child,parent,outer); if (bound==null) return null; children.add(bound); }
            return new ScimFilter.And(children);
        }
        if (node instanceof ScimFilter.Or or) {
            List<ScimFilter> children=new ArrayList<>();
            for (ScimFilter child:or.getOperands()) { ScimFilter bound=bindSelector(child,parent,outer); if (bound==null) return null; children.add(bound); }
            return new ScimFilter.Or(children);
        }
        if (node instanceof ScimFilter.Not not) { ScimFilter child=bindSelector(not.getOperand(),parent,outer); return child==null ? null : new ScimFilter.Not(child); }
        if (node instanceof ScimFilter.ValuePath) return null;
        ScimAttributePath path=node instanceof ScimFilter.Present present ? present.getAttributePath() : ((ScimFilter.Comparison)node).getAttributePath();
        if (path.getSchemaId().isPresent() || path.getSubAttributeName().isPresent()) return null;
        ScimAttributeDefinition definition=ScimSchemas.attribute(parent.getSubAttributes(),path.getAttributeName()).orElse(null);
        if (definition==null || definition.getReturned()==ScimReturned.NEVER || definition.getType()==ScimAttributeType.COMPLEX) return null;
        ScimAttributePath canonical=ScimFilterBinding.path(null,definition.getName(),null);
        requested.add(ScimFilterBinding.path(outer.getSchemaId().orElse(null),outer.getAttributeName(),definition.getName()));
        if (node instanceof ScimFilter.Present) return new ScimFilter.Present(canonical);
        ScimFilter.Comparison comparison=(ScimFilter.Comparison)node;
        if (!operator(definition.getType(),comparison.getOperator())) return null;
        ScimFilterValue literal=literal(definition,comparison.getOperator(),comparison.getValue());
        return literal==null ? null : new ScimFilter.Comparison(canonical,comparison.getOperator(),literal);
    }
    private @Nullable ScimFilterValue literal(@NonNull ScimAttributeDefinition definition,@NonNull ScimComparisonOperator operator,@NonNull ScimFilterValue value) {
        if (value instanceof ScimFilterValue.NullValue) return operator==ScimComparisonOperator.EQ || operator==ScimComparisonOperator.NE ? value : null;
        if (value instanceof ScimFilterValue.StringValue string && !spend(string.getValue().length())) return null;
        if (definition.getType()==ScimAttributeType.BOOLEAN && value instanceof ScimFilterValue.StringValue string
                && enabled(ScimCompatibilityFeature.BOOLEAN_STRINGS) && (string.getValue().equals("true") || string.getValue().equals("false"))) {
            used.add(ScimCompatibilityFeature.BOOLEAN_STRINGS); return new ScimFilterValue.BooleanValue(string.getValue().equals("true"));
        }
        return switch(definition.getType()) {
            case BOOLEAN -> value instanceof ScimFilterValue.BooleanValue ? value : null;
            case INTEGER -> value instanceof ScimFilterValue.NumberValue number && number.getValue().stripTrailingZeros().scale()<=0 ? value : null;
            case DECIMAL -> value instanceof ScimFilterValue.NumberValue ? value : null;
            case STRING -> value instanceof ScimFilterValue.StringValue ? value : null;
            case DATE_TIME -> value instanceof ScimFilterValue.StringValue string && ScimResourceValidation.dateTime(string.getValue()) ? value : null;
            case BINARY -> value instanceof ScimFilterValue.StringValue string && ScimResourceValidation.binary(string.getValue()) ? value : null;
            case REFERENCE -> value instanceof ScimFilterValue.StringValue string && ScimResourceValidation.reference(string.getValue()) ? value : null;
            case COMPLEX -> null;
        };
    }
    private static boolean operator(@NonNull ScimAttributeType type,@NonNull ScimComparisonOperator operator) {
        if (operator==ScimComparisonOperator.EQ || operator==ScimComparisonOperator.NE) return true;
        if (type==ScimAttributeType.BOOLEAN || type==ScimAttributeType.BINARY) return false;
        if (operator==ScimComparisonOperator.CO || operator==ScimComparisonOperator.SW || operator==ScimComparisonOperator.EW)
            return type==ScimAttributeType.STRING || type==ScimAttributeType.REFERENCE;
        return true;
    }
    private @Nullable JsonObject resourceObject(@NonNull JsonObject input) {
        Map<String,JsonValue> fields=folded(input);
        if (fields==null) return null;
        LinkedHashMap<String,JsonValue> normalized=new LinkedHashMap<>();
        Set<ScimAttributePath> suppliedTargets=new LinkedHashSet<>();
        for (Map.Entry<String,JsonValue> entry:input.getMembers().entrySet()) {
            if (!spend(1)) return null;
            ScimSchema extension=extension(entry.getKey());
            if (extension != null) {
                if (!(entry.getValue() instanceof JsonObject object)) { error=ScimError.invalidValueInstance(); return null; }
                for (Map.Entry<String,JsonValue> child:object.getMembers().entrySet()) {
                    if (!noPathField(normalized,suppliedTargets,extension.getId()+":"+child.getKey(),child.getValue(),false)) return null;
                }
                if (object.getMembers().isEmpty()) {
                    normalized.put(extension.getId(),JsonObject.emptyInstance());
                    requested.add(ScimFilterBinding.path(null,"schemas",null));
                }
                continue;
            }
            if (!noPathField(normalized,suppliedTargets,entry.getKey(),entry.getValue(),true)) return null;
        }
        return JsonObject.fromMembers(normalized);
    }
    private @Nullable ScimSchema extension(@NonNull String key) {
        for (ScimSchemaExtension extension:type.getSchemaExtensions()) {
            if (!spend(1L+key.length())) return null;
            if (AsciiCase.fold(extension.getSchema().getId()).equals(AsciiCase.fold(key))) return extension.getSchema();
        }
        return null;
    }
    private boolean noPathField(@NonNull LinkedHashMap<@NonNull String,@NonNull JsonValue> output,
            @NonNull Set<@NonNull ScimAttributePath> targets,@NonNull String expression,@NonNull JsonValue raw,boolean compatibilityKey) {
        if (!(ScimAttributePath.fromExpressionResult(expression) instanceof ScimAttributePathParseResult.Succeeded)) { error=ScimError.invalidPathInstance(); return false; }
        ScimAttributePath path=canonical(expression);
        if (path==null) {
            if (work.wasExceeded() || !enabled(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)) return false;
            error=null;
            if (!scan(raw)) return false;
            used.add(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES); return true;
        }
        if (compatibilityKey && (path.getSubAttributeName().isPresent() || expression.indexOf(':')>=0)) {
            if (!enabled(ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS)) { error=ScimError.invalidPathInstance(); return false; }
            used.add(ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS);
        }
        ScimAttributeDefinition definition=find(path);
        if (definition==null) return false;
        if (path.getSubAttributeName().isPresent()) {
            ScimAttributeDefinition parent=find(ScimFilterBinding.path(path.getSchemaId().orElse(null),path.getAttributeName(),null));
            if (parent==null || parent.isMultiValued()) { error=ScimError.invalidPathInstance(); return false; }
        }
        for (ScimAttributePath existing:targets) {
            if (!spend(1)) return false;
            if (sameParent(existing,path) && (existing.getSubAttributeName().isEmpty() || path.getSubAttributeName().isEmpty() || existing.equals(path))) {
                error=ScimError.invalidSyntaxInstance(); return false;
            }
        }
        targets.add(path); requested.add(path);
        JsonValue value=validation.patchValue(definition,raw,path.toScimString(),false);
        if (value==null || validation.failed()) return false;
        put(output,path,value);
        return true;
    }
    private static boolean sameParent(@NonNull ScimAttributePath left,@NonNull ScimAttributePath right) {
        return left.getSchemaId().equals(right.getSchemaId()) && left.getAttributeName().equals(right.getAttributeName());
    }
    private static void put(@NonNull LinkedHashMap<@NonNull String,@NonNull JsonValue> output,@NonNull ScimAttributePath path,@NonNull JsonValue value) {
        LinkedHashMap<String,JsonValue> container=output;
        String schema=path.getSchemaId().orElse(null);
        if (schema!=null) {
            JsonValue existing=output.get(schema);
            container=new LinkedHashMap<>(existing instanceof JsonObject object ? object.getMembers() : Map.of());
        }
        String sub=path.getSubAttributeName().orElse(null);
        if (sub!=null) {
            JsonValue existing=container.get(path.getAttributeName());
            LinkedHashMap<String,JsonValue> children=new LinkedHashMap<>(existing instanceof JsonObject object ? object.getMembers() : Map.of());
            children.put(sub,value); value=JsonObject.fromMembers(children);
        }
        container.put(path.getAttributeName(),value);
        if (schema!=null) output.put(schema,JsonObject.fromMembers(container));
    }
    private boolean scan(@NonNull JsonValue value) {
        if (!spend(1)) return false;
        if (value instanceof JsonString string) return spend(string.getValue().length());
        if (value instanceof JsonNumber number) return spend(number.getValue().precision());
        if (value instanceof JsonArray array) for (JsonValue child:array.getElements()) if (!scan(child)) return false;
        if (value instanceof JsonObject object) {
            if (folded(object)==null) return false;
            for (JsonValue child:object.getMembers().values()) if (!scan(child)) return false;
        }
        return true;
    }
    private static final class Target {
        final @NonNull ScimAttributePath path;
        final @Nullable ScimFilter filter;
        final @Nullable String suffix;
        final @NonNull ScimAttributeDefinition definition;
        final @NonNull String expression;
        Target(@NonNull ScimAttributePath path,@Nullable ScimFilter filter,@Nullable String suffix,@NonNull ScimAttributeDefinition definition,@NonNull String expression) {
            this.path=path;this.filter=filter;this.suffix=suffix;this.definition=definition;this.expression=expression;
        }
    }
}
