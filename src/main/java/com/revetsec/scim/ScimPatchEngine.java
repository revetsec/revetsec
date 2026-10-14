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
import javax.annotation.concurrent.NotThreadSafe;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Ordered, operation-private transformation. No draft escapes on rejection.
 * The facade admits only parser-created, schema-bound requests with its registration proof;
 * values and relative selector nodes below already have their validated canonical shapes.
 */
@NotThreadSafe
final class ScimPatchEngine {
    private final @NonNull ScimResourceType type;
    private final @NonNull ScimCompatibility compatibility;
    private final @NonNull ScimStringMatching matching;
    private final @NonNull ScimWork work;
    private final @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures;
    private @Nullable ScimError error;

    private ScimPatchEngine(@NonNull ScimResourceType type, @NonNull ScimCompatibility compatibility,
            @NonNull ScimStringMatching matching, @NonNull ScimWork work,
            @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures) {
        this.type=type; this.compatibility=compatibility; this.matching=matching;
        this.work=work; this.usedFeatures=usedFeatures;
    }

    static @NonNull ScimPatchApplicationResult apply(@NonNull ScimResource current,
            @NonNull ScimPatchRequest request, @NonNull ScimCompatibility compatibility,
            @NonNull ScimStringMatching matching, @NonNull ScimWork work, @NonNull Object context,
            @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures) {
        ScimPatchEngine engine=new ScimPatchEngine(current.getResourceType(),compatibility,matching,work,usedFeatures);
        JsonObject draft=current.getDocument();
        for (ScimPatchOperation operation : request.getOperations()) {
            if (!engine.spend(1)) break;
            JsonObject next=engine.operation(draft,operation);
            if (next == null) break;
            draft=next;
        }
        if (engine.error != null) return new ScimPatchApplicationResult.Rejected(engine.error);
        ScimResourceValidation validation=new ScimResourceValidation(engine.type,null,ScimCompatibility.strictInstance(),work,false);
        JsonObject checked=validation.normalize(draft);
        if (checked == null) return new ScimPatchApplicationResult.Rejected(validation.error());
        Set<ScimAttributePath> modified=new LinkedHashSet<>();
        engine.diff(current.getDocument(),checked,modified);
        if (engine.error != null) return new ScimPatchApplicationResult.Rejected(engine.error);
        boolean changed=!modified.isEmpty();
        return new ScimPatchApplicationResult.Succeeded(new ScimPatchResult(changed
                ? ScimResource.parsed(engine.type,checked,context) : current,changed,
                request.getRequestedAttributePaths(),modified,request.getSuppliedAttributePaths(),context));
    }

    private boolean spend(long units) {
        if (error != null) return false;
        if (work.spend(units)) return true;
        error=ScimError.requestTooLargeInstance(); return false;
    }
    private @Nullable JsonObject operation(@NonNull JsonObject root,@NonNull ScimPatchOperation operation) {
        ScimAttributePath path=operation.getAttributePath().orElse(null);
        if (path == null) {
            JsonObject object=(JsonObject)operation.getValue().orElseThrow();
            JsonObject result=root;
            for (Map.Entry<String,JsonValue> member : object.getMembers().entrySet()) {
                if (!spend(1)) return null;
                ScimSchemaExtension extension=extension(member.getKey());
                if (extension != null) {
                    JsonObject children=(JsonObject)member.getValue();
                    for (Map.Entry<String,JsonValue> child : children.getMembers().entrySet()) {
                        if (!spend(1)) return null;
                        ScimAttributePath target=path(extension.getSchema().getId()+":"+child.getKey());
                        if (target == null) return null;
                        result=target(result,target,null,null,operation.getOperationType(),child.getValue());
                        if (result == null) return null;
                    }
                } else {
                    ScimAttributePath target=path(member.getKey());
                    if (target == null) return null;
                    if (target.getAttributeName().equals("id")
                            && compatibility.getFeatures().contains(ScimCompatibilityFeature.PATCH_READ_ONLY_ID_ECHO)
                            && exact(root.getMembers().get("id"),member.getValue())) {
                        usedFeatures.add(ScimCompatibilityFeature.PATCH_READ_ONLY_ID_ECHO); continue;
                    }
                    result=target(result,target,null,null,operation.getOperationType(),member.getValue());
                    if (result == null) return null;
                }
            }
            return result;
        }
        return target(root,path,operation.getValueFilter().orElse(null),operation.getSubAttributeName().orElse(null),
                operation.getOperationType(),operation.getValue().orElse(null));
    }

    private @Nullable JsonObject target(@NonNull JsonObject root,@NonNull ScimAttributePath target,
            @Nullable ScimFilter filter,@Nullable String suffix,@NonNull ScimPatchOperationType kind,
            @Nullable JsonValue incoming) {
        String schema=target.getSchemaId().orElse(null);
        JsonObject scope=root;
        if (schema != null) {
            JsonValue value=root.getMembers().get(schema);
            scope=value instanceof JsonObject object ? object : JsonObject.emptyInstance();
        }
        ScimAttributePath top=path((schema == null ? "" : schema+":")+target.getAttributeName());
        if (top == null || !spend(type.definitionCount())) return null;
        ScimAttributeDefinition definition=ScimSchemas.find(type,top).orElseThrow();
        if (schema == null && definition.getName().equals("schemas")) { error=ScimError.mutabilityInstance(); return null; }
        JsonValue old=scope.getMembers().get(definition.getName());
        String child=suffix == null ? target.getSubAttributeName().orElse(null) : suffix;
        JsonValue next;
        if (filter != null) next=filtered(definition,old,filter,child,kind,incoming,top);
        else if (child != null) next=child(definition,old,child,kind,incoming,top);
        else if (kind == ScimPatchOperationType.REMOVE && incoming != null) {
            if (!(incoming instanceof JsonArray ids) || !groupMembers(top)) { error=ScimError.invalidValueInstance(); return null; }
            next=removeIds(old,ids);
        }
        else next=update(definition,old,incoming,kind,top);
        if (error != null) return null;
        if (definition.isRequired() && !ScimResourceValidation.assigned(next)
                && (kind != ScimPatchOperationType.REMOVE || ScimResourceValidation.assigned(old))) {
            error=ScimError.mutabilityInstance(); return null;
        }
        if (!spend((long)scope.getMembers().size()+1)) return null;
        LinkedHashMap<String,JsonValue> members=new LinkedHashMap<>(scope.getMembers());
        if (next == null) members.remove(definition.getName()); else members.put(definition.getName(),next);
        JsonObject result=JsonObject.fromMembers(members);
        if (schema == null) return result;
        if (!spend((long)root.getMembers().size()+1)) return null;
        LinkedHashMap<String,JsonValue> envelope=new LinkedHashMap<>(root.getMembers());
        if (result.getMembers().isEmpty()) envelope.remove(schema); else envelope.put(schema,result);
        return schemas(envelope);
    }

    private @Nullable JsonObject schemas(@NonNull Map<@NonNull String,@NonNull JsonValue> root) {
        List<JsonValue> ids=new ArrayList<>();
        if (!spend(1L+type.getSchema().getId().length())) return null;
        ids.add(JsonString.fromValue(type.getSchema().getId()));
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            if (!spend(1)) return null;
            String id=extension.getSchema().getId();
            if (root.containsKey(id)) {
                if (!spend(1L+id.length())) return null;
                ids.add(JsonString.fromValue(id));
            }
        }
        root.put("schemas",JsonArray.fromElements(ids));
        return JsonObject.fromMembers(root);
    }
    private @Nullable JsonValue child(@NonNull ScimAttributeDefinition parent,@Nullable JsonValue old,
            @NonNull String name,@NonNull ScimPatchOperationType kind,@Nullable JsonValue incoming,
            @NonNull ScimAttributePath top) {
        if (parent.getMutability() == ScimMutability.READ_ONLY) { error=ScimError.mutabilityInstance(); return null; }
        if (old == null && kind == ScimPatchOperationType.REMOVE) return null;
        if (parent.isMultiValued()) {
            List<JsonValue> result=new ArrayList<>();
            if (old instanceof JsonArray array) for (JsonValue value : array.getElements()) {
                if (!spend(1)) return null;
                JsonObject next=elementChild(parent,(JsonObject)value,name,kind,incoming,top);
                if (next == null) return null;
                result.add(next);
            }
            // Unfiltered subattributes address all existing elements; an absent array has no target.
            if (result.isEmpty() && kind != ScimPatchOperationType.REMOVE) { error=ScimError.noTargetInstance(); return null; }
            JsonArray next=primary(parent,result,suppliedPrimary(incoming,name) ? result.size()-1 : -1);
            return protectParent(parent,old,next);
        }
        JsonObject next=elementChild(parent,old instanceof JsonObject object ? object : JsonObject.emptyInstance(),name,kind,incoming,top);
        return protectParent(parent,old,next);
    }
    private @Nullable JsonObject elementChild(@NonNull ScimAttributeDefinition parent,@NonNull JsonObject old,
            @NonNull String name,@NonNull ScimPatchOperationType kind,@Nullable JsonValue incoming,
            @NonNull ScimAttributePath top) {
        if (!spend(parent.getSubAttributes().size()+old.getMembers().size()+1L)) return null;
        ScimAttributeDefinition definition=ScimSchemas.attribute(parent.getSubAttributes(),name).orElseThrow();
        ScimAttributePath childPath=path(top.toScimString()+"."+name);
        if (childPath == null) return null;
        JsonValue value=update(definition,old.getMembers().get(definition.getName()),incoming,kind,childPath);
        if (error != null) return null;
        LinkedHashMap<String,JsonValue> result=new LinkedHashMap<>(old.getMembers());
        if (value == null) result.remove(definition.getName()); else result.put(definition.getName(),value);
        return JsonObject.fromMembers(result);
    }
    private @Nullable JsonValue protectParent(@NonNull ScimAttributeDefinition parent,@Nullable JsonValue old,@Nullable JsonValue next) {
        if (parent.getMutability() == ScimMutability.IMMUTABLE && ScimResourceValidation.assigned(old) && !exact(old,next))
            if (error == null) error=ScimError.mutabilityInstance();
        return next;
    }

    private @Nullable JsonValue filtered(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue old,
            @NonNull ScimFilter filter,@Nullable String suffix,@NonNull ScimPatchOperationType kind,
            @Nullable JsonValue incoming,@NonNull ScimAttributePath top) {
        if (definition.getMutability() == ScimMutability.READ_ONLY) { error=ScimError.mutabilityInstance(); return null; }
        List<JsonValue> output=new ArrayList<>();
        boolean found=false; int preferred=-1;
        if (old instanceof JsonArray array) for (JsonValue element : array.getElements()) {
            if (!spend(1)) return null;
            JsonObject object=(JsonObject)element;
            boolean selected=predicate(filter,object,definition,top);
            if (error != null) return null;
            if (!selected) { output.add(element); continue; }
            found=true;
            if (suffix == null && (kind == ScimPatchOperationType.REMOVE || incoming instanceof JsonNull)) {
                if (!groupMembers(top) && protectedChildren(definition,object)) { if (error == null) error=ScimError.mutabilityInstance(); return null; }
                continue;
            }
            JsonValue next;
            if (suffix == null) next=merge(definition,object,(JsonObject)java.util.Objects.requireNonNull(incoming),top);
            else next=elementChild(definition,object,suffix,kind,incoming,top);
            if (error != null) return null;
            if (next != null) {
                if (suppliedPrimary(incoming,suffix)) preferred=output.size();
                output.add(next);
            }
        }
        if (!found && kind != ScimPatchOperationType.REMOVE) {
            JsonObject created=upsert(top,filter,suffix,incoming);
            if (created == null) { if (error == null) error=ScimError.noTargetInstance(); return null; }
            output.add(created);
            if (suppliedPrimary(incoming,suffix)) preferred=output.size()-1;
        }
        if (!found && old == null && kind == ScimPatchOperationType.REMOVE) return null;
        return protectParent(definition,old,primary(definition,output,preferred));
    }

    @SuppressWarnings("ReferenceEquality") // Compatibility applies to the trusted standard User schema.
    private @Nullable JsonObject upsert(@NonNull ScimAttributePath top,@NonNull ScimFilter filter,
            @Nullable String suffix,@Nullable JsonValue incoming) {
        if (!compatibility.getFeatures().contains(ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT)
                || type.getSchema() != ScimSchema.userInstance()
                || top.getSchemaId().isPresent() || !top.getAttributeName().equals("emails")
                || !(filter instanceof ScimFilter.Comparison comparison)
                || !comparison.getAttributePath().getAttributeName().equals("type")
                || comparison.getAttributePath().getSubAttributeName().isPresent()
                || comparison.getOperator() != ScimComparisonOperator.EQ
                || !(comparison.getValue() instanceof ScimFilterValue.StringValue label)) return null;
        if (!"value".equals(suffix) || !(incoming instanceof JsonString string) || string.getValue().isEmpty()) return null;
        if (!spend(2L+label.getValue().length())) return null;
        LinkedHashMap<String,JsonValue> result=new LinkedHashMap<>();
        result.put("value",incoming);
        result.put("type",JsonString.fromValue(label.getValue()));
        usedFeatures.add(ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT);
        return JsonObject.fromMembers(result);
    }

    private @Nullable JsonValue update(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue old,
            @Nullable JsonValue incoming,@NonNull ScimPatchOperationType kind,@NonNull ScimAttributePath target) {
        if (!spend(1)) return null;
        if (definition.getMutability() == ScimMutability.READ_ONLY) { error=ScimError.mutabilityInstance(); return null; }
        JsonValue result;
        if (kind == ScimPatchOperationType.REMOVE || incoming instanceof JsonNull) {
            if (old != null && !groupMembers(target) && protectedChildren(definition,old)) { if (error == null) error=ScimError.mutabilityInstance(); return null; }
            result=null;
        } else if (definition.isMultiValued()) result=array(definition,old,(JsonArray)java.util.Objects.requireNonNull(incoming),kind,target);
        else if (definition.getType() == ScimAttributeType.COMPLEX) result=merge(definition,
                old instanceof JsonObject object ? object : JsonObject.emptyInstance(),(JsonObject)java.util.Objects.requireNonNull(incoming),target);
        else result=incoming;
        if (error != null) return null;
        if (definition.isRequired() && !ScimResourceValidation.assigned(result)
                && (kind != ScimPatchOperationType.REMOVE || ScimResourceValidation.assigned(old))) {
            error=ScimError.mutabilityInstance(); return null;
        }
        if (definition.getMutability() == ScimMutability.IMMUTABLE && ScimResourceValidation.assigned(old) && !exact(old,result))
            if (error == null) error=ScimError.mutabilityInstance();
        return result;
    }
    private @Nullable JsonValue merge(@NonNull ScimAttributeDefinition definition,@NonNull JsonObject old,
            @NonNull JsonObject object,@NonNull ScimAttributePath target) {
        if (!spend(old.getMembers().size()+object.getMembers().size()+1L)) return null;
        LinkedHashMap<String,JsonValue> output=new LinkedHashMap<>(old.getMembers());
        for (Map.Entry<String,JsonValue> supplied : object.getMembers().entrySet()) {
            if (!spend(definition.getSubAttributes().size()+1L)) return null;
            ScimAttributeDefinition child=ScimSchemas.attribute(definition.getSubAttributes(),supplied.getKey()).orElseThrow();
            ScimAttributePath childPath=path(target.toScimString()+"."+supplied.getKey());
            if (childPath == null) return null;
            // Group member reference null is unassigned. It cannot clear an assigned immutable reference.
            if (groupMembers(target) && child.getName().equals("$ref") && supplied.getValue() instanceof JsonNull) continue;
            JsonValue value=update(child,old.getMembers().get(child.getName()),supplied.getValue(),ScimPatchOperationType.REPLACE,childPath);
            if (error != null) return null;
            if (value == null) output.remove(child.getName()); else output.put(child.getName(),value);
        }
        JsonObject result=JsonObject.fromMembers(output);
        return protectParent(definition,old,result);
    }

    private @Nullable JsonValue array(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue old,
            @NonNull JsonArray values,@NonNull ScimPatchOperationType kind,@NonNull ScimAttributePath target) {
        if (kind == ScimPatchOperationType.ADD && values.getElements().isEmpty()) return old;
        List<JsonValue> prior=old instanceof JsonArray array ? array.getElements() : List.of();
        if (!spend(prior.size()+1L)) return null;
        List<JsonValue> output=kind == ScimPatchOperationType.ADD ? new ArrayList<>(prior) : new ArrayList<>();
        int preferred=-1;
        for (JsonValue supplied : values.getElements()) {
            if (!spend(1)) return null;
            JsonValue existing=null;
            List<JsonValue> candidates=kind == ScimPatchOperationType.ADD ? output : prior;
            for (int index=0; index<candidates.size(); index++) {
                if (!spend(1)) return null;
                JsonValue candidate=candidates.get(index);
                if (equivalent(definition,candidate,supplied,target,groupMembers(target))) {
                    existing=candidate; break;
                }
                if (error != null) return null;
            }
            if (error != null) return null;
            JsonValue next=supplied;
            if (definition.getType() == ScimAttributeType.COMPLEX) {
                JsonObject basis=existing instanceof JsonObject object ? object : JsonObject.emptyInstance();
                // No positional transfer of protected descendants between unrelated values.
                if (existing == null && kind == ScimPatchOperationType.REPLACE && !groupMembers(target)) for (JsonValue previous : prior) {
                    if (!spend(1)) return null;
                    if (protectedChildren(definition,previous)) { if (error == null) error=ScimError.mutabilityInstance(); return null; }
                }
                next=merge(definition,basis,(JsonObject)supplied,target);
                if (next == null) return null;
            }
            if (kind == ScimPatchOperationType.ADD && existing != null) continue;
            if (suppliedPrimary(supplied,null)) preferred=output.size();
            if (!spend(1)) return null;
            output.add(next);
        }
        // Whole-array replacement may remove Group members; other protected arrays need an unchanged proof.
        if (kind == ScimPatchOperationType.REPLACE && !groupMembers(target)) for (JsonValue previous : prior) {
            if (!spend(1)) return null;
            if (protectedChildren(definition,previous)) {
                boolean retained=false;
                for (JsonValue candidate : output) {
                    if (!spend(1)) return null;
                    if (exact(previous,candidate)) retained=true;
                }
                if (!retained) { if (error == null) error=ScimError.mutabilityInstance(); return null; }
            }
        }
        return primary(definition,output,preferred);
    }
    private @Nullable JsonArray primary(@NonNull ScimAttributeDefinition definition,@NonNull List<@NonNull JsonValue> values,int preferred) {
        if (definition.getType() != ScimAttributeType.COMPLEX) return JsonArray.fromElements(values);
        if (!spend(definition.getSubAttributes().size())) return null;
        ScimAttributeDefinition primary=ScimSchemas.attribute(definition.getSubAttributes(),"primary").orElse(null);
        if (primary == null || primary.getType() != ScimAttributeType.BOOLEAN) return JsonArray.fromElements(values);
        int assigned=-1;
        for (int index=0; index<values.size(); index++) {
            if (!spend(1)) return null;
            JsonObject object=(JsonObject)values.get(index);
            if (object.findBoolean(primary.getName()).orElse(false)) {
                if (assigned >= 0 && preferred < 0) { error=ScimError.invalidValueInstance(); return null; }
                assigned=index;
            }
        }
        if (preferred < 0) return JsonArray.fromElements(values);
        for (int index=0; index<values.size(); index++) {
            if (!spend(1)) return null;
            JsonObject object=(JsonObject)values.get(index);
            if (index != preferred && object.findBoolean(primary.getName()).orElse(false)) {
                if (primary.getMutability() != ScimMutability.READ_WRITE) { error=ScimError.mutabilityInstance(); return null; }
                if (!spend(object.getMembers().size()+1L)) return null;
                LinkedHashMap<String,JsonValue> children=new LinkedHashMap<>(object.getMembers());
                children.put(primary.getName(),JsonBoolean.fromValue(false));
                values.set(index,JsonObject.fromMembers(children));
            }
        }
        return JsonArray.fromElements(values);
    }
    private static boolean suppliedPrimary(@Nullable JsonValue incoming,@Nullable String suffix) {
        return "primary".equals(suffix) && incoming instanceof JsonBoolean value && value.getValue()
                || suffix == null && incoming instanceof JsonObject object && object.findBoolean("primary").orElse(false);
    }
    private @Nullable JsonValue removeIds(@Nullable JsonValue old,@NonNull JsonArray ids) {
        List<JsonValue> output=new ArrayList<>();
        if (old instanceof JsonArray array) for (JsonValue element : array.getElements()) {
            if (!spend(1)) return null;
            JsonValue key=((JsonObject)element).getMembers().get("value");
            boolean remove=false;
            for (JsonValue candidate : ids.getElements()) {
                if (!spend(1)) return null;
                if (exact(key,((JsonObject)candidate).getMembers().get("value"))) remove=true;
            }
            if (!remove) output.add(element);
        }
        return old == null ? null : JsonArray.fromElements(output);
    }

    private boolean protectedChildren(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue value) {
        if (value instanceof JsonArray array) for (JsonValue element : array.getElements()) {
            if (!spend(1) || protectedChildren(definition,element)) return true;
        }
        if (value instanceof JsonObject object) for (ScimAttributeDefinition child : definition.getSubAttributes()) {
            if (!spend(1)) return true;
            JsonValue data=object.getMembers().get(child.getName());
            if (ScimResourceValidation.assigned(data) && child.getMutability() != ScimMutability.READ_WRITE
                    && child.getMutability() != ScimMutability.WRITE_ONLY || protectedChildren(child,data)) return true;
        }
        return false;
    }

    private boolean equivalent(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue left,
            @Nullable JsonValue right,@NonNull ScimAttributePath target,boolean group) {
        if (!spend(1)) return false;
        if (group && left instanceof JsonObject a && right instanceof JsonObject b) {
            JsonValue first=a.getMembers().get("value"), second=b.getMembers().get("value");
            if (ScimResourceValidation.assigned(first) && ScimResourceValidation.assigned(second)) return exact(first,second);
            // No assigned ID is available to identify these elements. Compare their declared data instead.
        }
        if (left == null || right == null || left instanceof JsonNull || right instanceof JsonNull)
            return !ScimResourceValidation.assigned(left) && !ScimResourceValidation.assigned(right);
        if (left instanceof JsonObject a && right instanceof JsonObject b) {
            for (ScimAttributeDefinition child : definition.getSubAttributes()) {
                if (!spend(1)) return false;
                if (child.getMutability() == ScimMutability.READ_ONLY) continue;
                ScimAttributePath childPath=path(target.toScimString()+"."+child.getName());
                if (childPath == null || !equivalent(child,a.getMembers().get(child.getName()),b.getMembers().get(child.getName()),childPath,false)) return false;
            }
            return true;
        }
        if (left instanceof JsonString a && right instanceof JsonString b) {
            if (definition.getType() == ScimAttributeType.STRING) return strategy(target,definition,ScimComparisonOperator.EQ,a.getValue(),b.getValue());
            if (definition.getType() == ScimAttributeType.DATE_TIME) return dateCompare(a.getValue(),b.getValue(),ScimComparisonOperator.EQ);
            if (definition.getType() == ScimAttributeType.BINARY) return binaryEqual(a.getValue(),b.getValue());
        }
        return exact(left,right);
    }

    private boolean predicate(@NonNull ScimFilter filter,@NonNull JsonObject element,
            @NonNull ScimAttributeDefinition parent,@NonNull ScimAttributePath top) {
        if (!spend(1)) return false;
        if (filter instanceof ScimFilter.And and) {
            boolean result=true;
            // Visit all branches: unsupported matching must reject even on a false branch.
            for (ScimFilter operand : and.getOperands()) result=predicate(operand,element,parent,top) && result;
            return result;
        }
        if (filter instanceof ScimFilter.Or or) {
            boolean result=false;
            for (ScimFilter operand : or.getOperands()) result=predicate(operand,element,parent,top) || result;
            return result;
        }
        if (filter instanceof ScimFilter.Not not) return !predicate(not.getOperand(),element,parent,top);
        ScimAttributePath relative=filter instanceof ScimFilter.Present present ? present.getAttributePath()
                : ((ScimFilter.Comparison)filter).getAttributePath();
        if (!spend(parent.getSubAttributes().size())) return false;
        ScimAttributeDefinition definition=ScimSchemas.attribute(parent.getSubAttributes(),relative.getAttributeName()).orElseThrow();
        ScimAttributePath target=path(top.toScimString()+"."+relative.getAttributeName());
        if (target == null) return false;
        JsonValue value=element.getMembers().get(definition.getName());
        if (filter instanceof ScimFilter.Present) return ScimResourceValidation.assigned(value);
        ScimFilter.Comparison comparison=(ScimFilter.Comparison)filter;
        return scalarCompare(target,definition,value,comparison.getValue(),comparison.getOperator(),groupMembers(top) && definition.getName().equals("value"));
    }
    private boolean scalarCompare(@NonNull ScimAttributePath target,@NonNull ScimAttributeDefinition definition,
            @Nullable JsonValue value,@NonNull ScimFilterValue literal,@NonNull ScimComparisonOperator operator,boolean exactId) {
        if (!spend(1)) return false;
        if (literal instanceof ScimFilterValue.NullValue) {
            boolean absent=!ScimResourceValidation.assigned(value);
            return operator == ScimComparisonOperator.EQ ? absent : !absent;
        }
        if (!ScimResourceValidation.assigned(value)) return false;
        if (value instanceof JsonArray array) {
            boolean result=false;
            for (JsonValue element : array.getElements()) result=scalarCompare(target,definition,element,literal,operator,exactId) || result;
            return result;
        }
        if (value instanceof JsonString string && literal instanceof ScimFilterValue.StringValue text) {
            if (definition.getType() == ScimAttributeType.DATE_TIME) return dateCompare(string.getValue(),text.getValue(),operator);
            if (definition.getType() == ScimAttributeType.BINARY) return verdict(binaryEqual(string.getValue(),text.getValue()) ? 0 : 1,operator);
            if (exactId || definition.getType() == ScimAttributeType.REFERENCE) {
                if (!spend((long)string.getValue().length()+text.getValue().length())) return false;
                if (operator == ScimComparisonOperator.CO
                        && !spend((long)string.getValue().length()*text.getValue().length())) return false;
                return switch (operator) {
                    case CO -> string.getValue().contains(text.getValue());
                    case SW -> string.getValue().startsWith(text.getValue());
                    case EW -> string.getValue().endsWith(text.getValue());
                    default -> verdict(string.getValue().compareTo(text.getValue()),operator);
                };
            }
            return strategy(target,definition,operator,string.getValue(),text.getValue());
        }
        if (value instanceof JsonNumber number && literal instanceof ScimFilterValue.NumberValue numeric) {
            if (!spend((long)number.getValue().precision()+numeric.getValue().precision())) return false;
            return verdict(number.getValue().compareTo(numeric.getValue()),operator);
        }
        if (value instanceof JsonBoolean bool && literal instanceof ScimFilterValue.BooleanValue booleanValue)
            return verdict(Boolean.compare(bool.getValue(),booleanValue.getValue()),operator);
        error=ScimError.invalidFilterInstance(); return false;
    }
    private boolean strategy(@NonNull ScimAttributePath target,@NonNull ScimAttributeDefinition definition,
            @NonNull ScimComparisonOperator operator,@NonNull String value,@NonNull String literal) {
        if (!spend(1L+value.length()+literal.length())) return false;
        ScimStringMatchResult result=java.util.Objects.requireNonNull(matching.match(target,definition,operator,value,literal));
        if (result instanceof ScimStringMatchResult.Matched matched) return matched.isMatched();
        error=ScimError.invalidFilterInstance(); return false;
    }
    private static boolean verdict(int comparison,@NonNull ScimComparisonOperator operator) {
        return switch (operator) { case EQ -> comparison == 0; case NE -> comparison != 0;
            case GT -> comparison > 0; case GE -> comparison >= 0; case LT -> comparison < 0; case LE -> comparison <= 0;
            default -> false; };
    }
    private boolean binaryEqual(@NonNull String left,@NonNull String right) {
        if (!spend((long)left.length()+right.length()+1)) return false;
        return java.util.Arrays.equals(Base64.getDecoder().decode(left),Base64.getDecoder().decode(right));
    }
    private boolean dateCompare(@NonNull String left,@NonNull String right,@NonNull ScimComparisonOperator operator) {
        if (!spend(1L+left.length()+right.length())) return false;
        DateValue a=date(left), b=date(right);
        if (a.offset != b.offset) { error=ScimError.invalidFilterInstance(); return false; }
        int comparison=yearCompare(a.year,b.year);
        if (comparison == 0) comparison=Integer.compare(a.month,b.month);
        if (comparison == 0) comparison=Integer.compare(a.day,b.day);
        if (comparison == 0) comparison=Integer.compare(a.seconds,b.seconds);
        if (comparison == 0) {
            int maximum=Math.max(a.fraction.length(),b.fraction.length());
            for (int index=0; index<maximum; index++) {
                char first=index < a.fraction.length() ? a.fraction.charAt(index) : '0';
                char second=index < b.fraction.length() ? b.fraction.charAt(index) : '0';
                comparison=Character.compare(first,second);
                if (comparison != 0) break;
            }
        }
        return verdict(comparison,operator);
    }
    /** Linear calendar normalization avoids constructing unbounded numeric year/fraction values. */
    private static @NonNull DateValue date(@NonNull String value) {
        int start=value.startsWith("-") ? 1 : 0;
        int end=value.indexOf('-',start);
        String year=value.substring(0,end);
        int month=two(value,end+1), day=two(value,end+4);
        int seconds=two(value,end+7)*3600+two(value,end+10)*60+two(value,end+13);
        int fractionStart=end+15, fractionEnd=fractionStart;
        if (fractionStart < value.length() && value.charAt(fractionStart) == '.') {
            fractionEnd=++fractionStart;
            while (fractionEnd < value.length() && value.charAt(fractionEnd) >= '0' && value.charAt(fractionEnd) <= '9') fractionEnd++;
        }
        String fraction=value.substring(fractionStart,fractionEnd);
        boolean offset=fractionEnd < value.length();
        if (offset && value.charAt(fractionEnd) != 'Z') {
            int zone=two(value,fractionEnd+1)*3600+two(value,fractionEnd+4)*60;
            seconds-=value.charAt(fractionEnd) == '-' ? -zone : zone;
        }
        if (seconds < 0) {
            seconds+=86400;
            day--;
            if (day == 0) {
                month--;
                if (month == 0) { year=shiftYear(year,-1); month=12; }
                day=monthDays(year,month);
            }
        } else if (seconds >= 86400) {
            seconds-=86400;
            day++;
            if (day > monthDays(year,month)) {
                day=1; month++;
                if (month == 13) { year=shiftYear(year,1); month=1; }
            }
        }
        return new DateValue(year,month,day,seconds,fraction,offset);
    }
    private static int two(@NonNull String value,int start) { return (value.charAt(start)-'0')*10+value.charAt(start+1)-'0'; }
    private static int monthDays(@NonNull String year,int month) {
        if (month != 2) return month == 4 || month == 6 || month == 9 || month == 11 ? 30 : 31;
        int mod=0;
        for (int index=year.startsWith("-") ? 1 : 0; index<year.length(); index++) mod=(mod*10+year.charAt(index)-'0')%400;
        if (year.startsWith("-")) mod=(401-mod)%400;
        return mod%4 == 0 && (mod%100 != 0 || mod == 0) ? 29 : 28;
    }
    private static int yearCompare(@NonNull String left,@NonNull String right) {
        boolean a=left.startsWith("-"), b=right.startsWith("-");
        if (a != b) return a ? -1 : 1;
        int comparison=Integer.compare(left.length(),right.length());
        if (comparison == 0) comparison=left.compareTo(right);
        return a ? -comparison : comparison;
    }
    private static @NonNull String shiftYear(@NonNull String year,int delta) {
        boolean negative=year.startsWith("-");
        String magnitude=negative ? year.substring(1) : year;
        int direction=negative ? -delta : delta;
        if (direction < 0 && magnitude.equals("0001")) return negative ? "0001" : "-0001";
        StringBuilder digits=new StringBuilder(magnitude);
        for (int index=digits.length()-1; index>=0; index--) {
            int digit=digits.charAt(index)-'0'+direction;
            digits.setCharAt(index,(char)('0'+(digit+10)%10));
            if (digit >= 0 && digit <= 9) break;
            if (index == 0 && direction > 0) digits.insert(0,'1');
        }
        if (digits.length() > 4 && digits.charAt(0) == '0') digits.deleteCharAt(0);
        return negative ? "-"+digits : digits.toString();
    }
    private record DateValue(@NonNull String year,int month,int day,int seconds,@NonNull String fraction,boolean offset) { }

    private boolean exact(@Nullable JsonValue left,@Nullable JsonValue right) {
        if (!spend(1)) return false;
        if (left == null || right == null) return left == null && right == null;
        if (left.getClass() != right.getClass()) return false;
        if (left instanceof JsonObject a) {
            JsonObject b=(JsonObject)right;
            if (a.getMembers().size() != b.getMembers().size()) return false;
            for (Map.Entry<String,JsonValue> member : a.getMembers().entrySet()) {
                if (!spend(member.getKey().length()) || !exact(member.getValue(),b.getMembers().get(member.getKey()))) return false;
            }
            return true;
        }
        if (left instanceof JsonArray a) {
            JsonArray b=(JsonArray)right;
            if (a.getElements().size() != b.getElements().size()) return false;
            for (int index=0; index<a.getElements().size(); index++) if (!exact(a.getElements().get(index),b.getElements().get(index))) return false;
            return true;
        }
        if (left instanceof JsonString a) {
            JsonString b=(JsonString)right;
            return spend((long)a.getValue().length()+b.getValue().length()) && a.getValue().equals(b.getValue());
        }
        if (left instanceof JsonNumber a) {
            JsonNumber b=(JsonNumber)right;
            return spend((long)a.getValue().precision()+b.getValue().precision()) && a.getValue().compareTo(b.getValue()) == 0;
        }
        if (left instanceof JsonBoolean a) return a.getValue().equals(((JsonBoolean)right).getValue());
        return true; // Both are the remaining sealed JSON null type.
    }

    private void diff(@NonNull JsonObject old,@NonNull JsonObject next,@NonNull Set<@NonNull ScimAttributePath> paths) {
        for (ScimAttributeDefinition definition : ScimResources.definitions(type)) {
            if (!spend(1)) return;
            difference(definition,old.getMembers().get(definition.getName()),next.getMembers().get(definition.getName()),definition.getName(),paths);
        }
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            if (!spend(1)) return;
            String id=extension.getSchema().getId();
            JsonValue before=old.getMembers().get(id), after=next.getMembers().get(id);
            JsonObject a=before instanceof JsonObject object ? object : JsonObject.emptyInstance();
            JsonObject b=after instanceof JsonObject object ? object : JsonObject.emptyInstance();
            for (ScimAttributeDefinition definition : extension.getSchema().getAttributes()) {
                if (!spend(1)) return;
                difference(definition,a.getMembers().get(definition.getName()),b.getMembers().get(definition.getName()),id+":"+definition.getName(),paths);
            }
        }
    }
    private void difference(@NonNull ScimAttributeDefinition definition,@Nullable JsonValue before,@Nullable JsonValue after,
            @NonNull String expression,@NonNull Set<@NonNull ScimAttributePath> paths) {
        if (exact(before,after)) return;
        if (error != null) return;
        ScimAttributePath target=path(expression);
        if (target == null || !spend(1)) return;
        paths.add(target);
        if (definition.getType() == ScimAttributeType.COMPLEX) {
            for (ScimAttributeDefinition child : definition.getSubAttributes()) {
                if (!spend(1)) return;
                if (before instanceof JsonObject a && after instanceof JsonObject b) {
                    if (exact(a.getMembers().get(child.getName()),b.getMembers().get(child.getName()))) continue;
                }
                ScimAttributePath nested=path(expression+"."+child.getName());
                if (nested == null || !spend(1)) return;
                paths.add(nested);
            }
        }
    }
    private @Nullable ScimSchemaExtension extension(@NonNull String name) {
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            if (!spend(1L+name.length())) return null;
            if (extension.getSchema().getId().equals(name)) return extension;
        }
        return null;
    }
    private @Nullable ScimAttributePath path(@NonNull String expression) {
        if (!spend(1L+expression.length())) return null;
        // Registration validates every name/URI, and the parser proves each target association.
        return ((ScimAttributePathParseResult.Succeeded)ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
    @SuppressWarnings("ReferenceEquality") // The trusted standard schema singleton defines the membership contract.
    private boolean groupMembers(@NonNull ScimAttributePath target) {
        return type.getSchema() == ScimSchema.groupInstance() && target.getSchemaId().isEmpty()
                && target.getSubAttributeName().isEmpty() && target.getAttributeName().equals("members");
    }
}
