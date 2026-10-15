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

import com.revetsec.internal.json.JsonDocument;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Operation-specific resource candidates; no storage, callbacks or network access. */
final class ScimResources {
    private ScimResources() { }
    static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type, @NonNull JsonDocument document,
            @NonNull ScimCompatibility compatibility, @NonNull ScimLimits limits, @NonNull Object context) {
        ScimWork work = new ScimWork(limits.getMaximumWorkUnits());
        return create(type,document,compatibility,work,context);
    }
    static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type, @NonNull JsonDocument document,
            @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, @NonNull Object context) {
        return create(type,document,compatibility,work,context,new java.util.LinkedHashSet<>());
    }
    static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type, @NonNull JsonDocument document,
            @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, @NonNull Object context,
            @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures) {
        if (!(document.getValue() instanceof JsonObject object)) return new ScimResourceParseResult.Rejected(ScimError.invalidSyntaxInstance());
        ScimResourceValidation validation = new ScimResourceValidation(type,document,compatibility,work,true,usedFeatures);
        JsonObject normalized = validation.normalize(object);
        if (normalized == null) return new ScimResourceParseResult.Rejected(validation.error());
        return new ScimResourceParseResult.Succeeded(ScimResource.parsed(type,normalized,context,
                work.maximum()),validation.supplied(),context);
    }
    static @NonNull ScimResourceParseResult replace(@NonNull ScimResourceType type, @NonNull ScimResource current,
            @NonNull JsonDocument document, @NonNull ScimCompatibility compatibility, @NonNull ScimLimits limits, @NonNull Object context) {
        return replace(type,current,document,compatibility,new ScimWork(limits.getMaximumWorkUnits()),context);
    }
    static @NonNull ScimResourceParseResult replace(@NonNull ScimResourceType type, @NonNull ScimResource current,
            @NonNull JsonDocument document, @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, @NonNull Object context) {
        return replace(type,current,document,compatibility,work,context,new java.util.LinkedHashSet<>());
    }
    static @NonNull ScimResourceParseResult replace(@NonNull ScimResourceType type, @NonNull ScimResource current,
            @NonNull JsonDocument document, @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, @NonNull Object context,
            @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures) {
        if (!(document.getValue() instanceof JsonObject object)) return new ScimResourceParseResult.Rejected(ScimError.invalidSyntaxInstance());
        ScimResourceValidation validation = new ScimResourceValidation(type,document,compatibility,work,true,usedFeatures);
        JsonObject normalized = validation.normalize(object,false);
        if (normalized == null) return new ScimResourceParseResult.Rejected(validation.error());
        Merge merger = new Merge(type,work,validation);
        List<ScimAttributeDefinition> definitions = definitions(type);
        JsonObject merged = merger.object(definitions,current.getDocument(),normalized,false,"");
        if (merged == null) return new ScimResourceParseResult.Rejected(merger.error());
        LinkedHashMap<String,JsonValue> finalMembers = new LinkedHashMap<>(merged.getMembers());
        finalMembers.put("schemas",normalized.getMembers().get("schemas"));
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            String id = extension.getSchema().getId();
            JsonValue old = current.getDocument().getMembers().get(id), incoming = normalized.getMembers().get(id);
            if (old instanceof JsonObject || incoming instanceof JsonObject) {
                JsonObject ext = merger.object(extension.getSchema().getAttributes(),old instanceof JsonObject value ? value : JsonObject.emptyInstance(),
                        incoming instanceof JsonObject value ? value : JsonObject.emptyInstance(),incoming instanceof JsonObject,id+":");
                if (ext == null) return new ScimResourceParseResult.Rejected(merger.error());
                if (incoming != null || !ext.getMembers().isEmpty()) finalMembers.put(id,ext);
                else finalMembers.remove(id);
            }
        }
        JsonValue schemaValue=normalized.getMembers().get("schemas");
        if (!(schemaValue instanceof JsonArray schemaArray)) return new ScimResourceParseResult.Rejected(ScimError.invalidValueInstance());
        List<JsonValue> declared = new ArrayList<>(schemaArray.getElements());
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            if (!work.take(1)) return new ScimResourceParseResult.Rejected(ScimError.requestTooLargeInstance());
            String id=extension.getSchema().getId();
            if (finalMembers.containsKey(id)) {
                boolean already=false;
                for (JsonValue value : declared) {
                    if (!work.take(1)) return new ScimResourceParseResult.Rejected(ScimError.requestTooLargeInstance());
                    if (value instanceof JsonString string && string.getValue().equals(id)) already=true;
                }
                if (!already) declared.add(JsonString.fromValue(id));
            }
        }
        finalMembers.put("schemas",JsonArray.fromElements(declared));
        ScimResourceValidation finalValidation = new ScimResourceValidation(type,null,ScimCompatibility.strictInstance(),work,false);
        JsonObject checked = finalValidation.normalize(JsonObject.fromMembers(finalMembers));
        if (checked == null) return new ScimResourceParseResult.Rejected(finalValidation.error());
        return new ScimResourceParseResult.Succeeded(ScimResource.parsed(type,checked,context,
                work.maximum()),validation.supplied(),context);
    }
    static @Nullable JsonObject project(@NonNull ScimResource resource, @NonNull ScimAttributeSelection selection,
            @NonNull Set<@NonNull ScimAttributePath> suppliedPaths, boolean writeContext, @NonNull ScimWork work) {
        Project project = new Project(selection,suppliedPaths,writeContext,work,resource.getResourceType().getSchema().isDiscovery());
        List<ScimAttributeDefinition> definitions = definitions(resource.getResourceType());
        JsonObject core = project.object(definitions,resource.getDocument(),"",false);
        if (core == null) return null;
        LinkedHashMap<String,JsonValue> members = new LinkedHashMap<>(core.getMembers());
        for (ScimSchemaExtension extension : resource.getResourceType().getSchemaExtensions()) {
            if (!work.take(1)) return null;
            JsonValue value = resource.getDocument().getMembers().get(extension.getSchema().getId());
            if (value instanceof JsonObject object) {
                JsonObject projected = project.object(extension.getSchema().getAttributes(),object,extension.getSchema().getId()+":",false);
                if (projected == null) return null;
                if (!projected.getMembers().isEmpty()) members.put(extension.getSchema().getId(),projected);
            }
        }
        return work.wasExceeded() ? null : JsonObject.fromMembers(members);
    }
    static @NonNull List<@NonNull ScimAttributeDefinition> definitions(@NonNull ScimResourceType type) {
        LinkedHashMap<String,ScimAttributeDefinition> definitions=new LinkedHashMap<>();
        for (ScimAttributeDefinition definition : ScimSchemas.commonAttributes()) definitions.put(com.revetsec.internal.json.AsciiCase.fold(definition.getName()),definition);
        for (ScimAttributeDefinition definition : type.getSchema().getAttributes()) {
            String name=com.revetsec.internal.json.AsciiCase.fold(definition.getName());
            if (type.getSchema().isDiscovery() || !definitions.containsKey(name)) definitions.put(name,definition);
        }
        return List.copyOf(definitions.values());
    }
    static @NonNull String descriptorPath(@NonNull String expression) {
        int start=expression.lastIndexOf(':')+1;
        int first=expression.indexOf('.',start);
        if (first < 0) return expression;
        int second=expression.indexOf('.',first+1);
        return second < 0 ? expression : expression.substring(0,second);
    }
    private static final class Project {
        private final @NonNull ScimAttributeSelection selection;
        private final @NonNull Set<@NonNull ScimAttributePath> supplied;
        private final boolean write;
        private final boolean discovery;
        private final @NonNull ScimWork work;
        Project(@NonNull ScimAttributeSelection selection,@NonNull Set<@NonNull ScimAttributePath> supplied,boolean write,@NonNull ScimWork work,boolean discovery) {
            this.selection=selection; this.supplied=supplied; this.write=write; this.work=work; this.discovery=discovery;
        }
        private @Nullable JsonObject object(@NonNull List<@NonNull ScimAttributeDefinition> definitions,@NonNull JsonObject object,@NonNull String prefix,boolean onlyAlways) {
            LinkedHashMap<String,JsonValue> output=new LinkedHashMap<>();
            for (ScimAttributeDefinition definition : definitions) {
                if (!work.take(1)) return null;
                String name=definition.getName();
                JsonValue raw=object.getMembers().get(name);
                if (raw == null || definition.getReturned() == ScimReturned.NEVER) continue;
                ScimAttributePathParseResult parsed=ScimAttributePath.fromExpressionResult(discovery ? descriptorPath(prefix+name) : prefix+name);
                if (!(parsed instanceof ScimAttributePathParseResult.Succeeded success)) return null;
                ScimAttributePath path=success.getAttributePath();
                boolean always=definition.getReturned() == ScimReturned.ALWAYS;
                boolean explicitlyIncluded=explicit(path);
                if (!work.spend((long)selection.getIncludedAttributes().size()+selection.getExcludedAttributes().size())) return null;
                boolean requested=explicitlyIncluded || write && supplied(path,definition.getType() == ScimAttributeType.COMPLEX);
                boolean eligible=always || !onlyAlways && selection.includes(path) && (definition.getReturned() != ScimReturned.REQUEST || requested);
                if (!eligible && definition.getType() != ScimAttributeType.COMPLEX) continue;
                if (raw instanceof JsonObject complex && definition.getType() == ScimAttributeType.COMPLEX) {
                    JsonObject child=object(definition.getSubAttributes(),complex,prefix+name+".",!eligible);
                    if (child == null) return null;
                    if (always || !child.getMembers().isEmpty()) output.put(name,child);
                } else if (raw instanceof JsonArray array && definition.getType() == ScimAttributeType.COMPLEX) {
                    List<JsonValue> children=new ArrayList<>();
                    boolean anyChildren=false;
                    for (JsonValue value : array.getElements()) {
                        if (!work.take(1)) return null;
                        if (!(value instanceof JsonObject complex)) return null;
                        JsonObject child=object(definition.getSubAttributes(),complex,prefix+name+".",!eligible);
                        if (child == null) return null;
                        anyChildren |= !child.getMembers().isEmpty();
                        children.add(child);
                    }
                    if (eligible || anyChildren) output.put(name,JsonArray.fromElements(children));
                } else {
                    if (!charge(raw)) return null;
                    output.put(name,raw);
                }
            }
            return JsonObject.fromMembers(output);
        }
        private boolean explicit(@NonNull ScimAttributePath path) {
            for (ScimAttributePath included : selection.getIncludedAttributes()) {
                if (!work.take(1)) return false;
                if (included.equals(path) || sameParent(included,path) && included.getSubAttributeName().isEmpty()) return true;
                if (path.getSubAttributeName().isEmpty() && sameParent(included,path)) return true;
            }
            return false;
        }
        private boolean supplied(@NonNull ScimAttributePath path,boolean complex) {
            if (supplied.contains(path)) return true;
            if (complex) for (ScimAttributePath actual : supplied) {
                if (!work.take(1)) return false;
                if (sameParent(actual,path)) return true;
            }
            return false;
        }
        private static boolean sameParent(@NonNull ScimAttributePath left,@NonNull ScimAttributePath right) {
            return left.getSchemaId().equals(right.getSchemaId()) && left.getAttributeName().equals(right.getAttributeName());
        }
        private boolean charge(@NonNull JsonValue raw) {
            if (!work.take(1)) return false;
            if (raw instanceof JsonString string) return work.spend(string.getValue().length());
            if (raw instanceof JsonNumber number) return work.spend(number.getValue().precision());
            if (raw instanceof JsonArray array) for (JsonValue element : array.getElements()) if (!charge(element)) return false;
            return true;
        }
    }
    private static final class Merge {
        private final @NonNull ScimResourceType type;
        private final @NonNull ScimWork work;
        private final @NonNull ScimResourceValidation validation;
        private @Nullable ScimError error;
        Merge(@NonNull ScimResourceType type, @NonNull ScimWork work, @NonNull ScimResourceValidation validation) { this.type=type; this.work = work; this.validation = validation; }
        @NonNull ScimError error() { return error == null ? ScimError.mutabilityInstance() : error; }
        private boolean spend(long amount) { if (work.spend(amount)) return true; error = ScimError.requestTooLargeInstance(); return false; }
        @Nullable JsonObject object(@NonNull List<@NonNull ScimAttributeDefinition> definitions,
                @NonNull JsonObject current, @NonNull JsonObject incoming, boolean suppliedComplex, @NonNull String prefix) {
            LinkedHashMap<String,JsonValue> merged = new LinkedHashMap<>();
            for (ScimAttributeDefinition definition : definitions) {
                if (!spend(1)) return null;
                String name = definition.getName();
                JsonValue old = current.getMembers().get(name), next = incoming.getMembers().get(name);
                if (definition.getMutability() == ScimMutability.READ_ONLY) { if (old != null) merged.put(name,old); continue; }
                if (definition.getMutability() == ScimMutability.IMMUTABLE && ScimResourceValidation.assigned(old)) {
                    if (next == null && suppliedComplex && !validation.explicitlyCleared(incoming,name,prefix)) next = old;
                    if (definition.getType() == ScimAttributeType.COMPLEX && !definition.isMultiValued()
                            && old instanceof JsonObject previous && next instanceof JsonObject suppliedObject) {
                        next = object(definition.getSubAttributes(),previous,suppliedObject,true,prefix+name+".");
                        if (next == null) return null;
                    }
                    if (definition.getType() == ScimAttributeType.COMPLEX && definition.isMultiValued()
                            && old instanceof JsonArray previous && next instanceof JsonArray suppliedArray) {
                        next = immutableArray(definition,previous,suppliedArray,prefix+name+".");
                        if (next == null) return null;
                    }
                    if (!equal(old,next)) { if (error == null) error = ScimError.mutabilityInstance(); return null; }
                    merged.put(name,old); continue;
                }
                if (definition.getType() == ScimAttributeType.COMPLEX) {
                    if (definition.isMultiValued()) {
                        if (name.equals("members") && prefix.isEmpty() && type.hasStandardGroupSchema()
                                && old instanceof JsonArray oldArray && stableMembers(oldArray)) {
                            if (next == null) continue;
                            JsonArray reconciled = members(definition,oldArray,next,prefix+name+".");
                            if (reconciled == null) return null;
                            merged.put(name,reconciled); continue;
                        }
                        if (old instanceof JsonArray array && protectedElements(definition,array)) {
                            if (!equalIgnoringReadOnly(definition,array,next)) { if (error == null) error = ScimError.mutabilityInstance(); return null; }
                            merged.put(name,old); continue;
                        }
                    } else if (old instanceof JsonObject || next instanceof JsonObject) {
                        boolean manager = type.isStandardEnterpriseManagerPath(prefix+name);
                        if (manager && next == null) continue;
                        JsonObject previous = old instanceof JsonObject value ? value : JsonObject.emptyInstance();
                        JsonObject supplied = next instanceof JsonObject value ? value : JsonObject.emptyInstance();
                        if (manager && !java.util.Objects.equals(previous.getMembers().get("value"),
                                supplied.getMembers().get("value"))) {
                            LinkedHashMap<String,JsonValue> retained = new LinkedHashMap<>(previous.getMembers());
                            retained.remove("displayName");
                            previous = JsonObject.fromMembers(retained);
                        }
                        JsonObject object = object(definition.getSubAttributes(),previous,
                                supplied,next instanceof JsonObject,prefix+name+".");
                        if (object == null) return null;
                        if (next != null || !object.getMembers().isEmpty()) merged.put(name,object);
                        continue;
                    }
                }
                if (next != null) merged.put(name,next);
            }
            return JsonObject.fromMembers(merged);
        }
        private @Nullable JsonArray immutableArray(@NonNull ScimAttributeDefinition definition,@NonNull JsonArray current,
                @NonNull JsonArray incoming,@NonNull String prefix) {
            // Positional preservation is confined to an immutable parent: the caller subsequently
            // proves the complete candidate sequence equals current, so changed identities cannot pass.
            if (current.getElements().size() != incoming.getElements().size()) return incoming;
            List<JsonValue> output=new ArrayList<>();
            for (int index=0;index<current.getElements().size();index++) {
                if (!spend(1)) return null;
                if (!(current.getElements().get(index) instanceof JsonObject old) || !(incoming.getElements().get(index) instanceof JsonObject suppliedObject)) return null;
                JsonObject preserved=object(definition.getSubAttributes(),old,suppliedObject,true,prefix);
                if (preserved == null) return null;
                output.add(preserved);
            }
            return JsonArray.fromElements(output);
        }
        private boolean stableMembers(@NonNull JsonArray array) {
            for (JsonValue value : array.getElements()) {
                if (!spend(1)) return false;
                if (!(value instanceof JsonObject object) || object.findString("value").filter(id -> !id.isEmpty()).isEmpty()) return false;
            }
            return true;
        }
        private @Nullable JsonArray members(@NonNull ScimAttributeDefinition definition, @NonNull JsonArray current, @NonNull JsonValue next, @NonNull String prefix) {
            if (!(next instanceof JsonArray incoming)) return null;
            List<JsonValue> output = new ArrayList<>();
            for (JsonValue value : incoming.getElements()) {
                if (!spend(1)) return null;
                if (!(value instanceof JsonObject candidate)) return null;
                JsonObject prior = null;
                String id = candidate.findString("value").orElse(null);
                for (JsonValue old : current.getElements()) {
                    if (!spend(1)) return null;
                    if (old instanceof JsonObject existing && id != null) {
                        String oldId = existing.findString("value").orElseThrow();
                        if (!spend((long)id.length()+oldId.length())) return null;
                        if (id.equals(oldId)) {
                            if (prior != null) { error=ScimError.mutabilityInstance(); return null; }
                            prior=existing;
                        }
                    }
                }
                if (prior == null) output.add(candidate);
                else {
                    JsonObject reconciled = object(definition.getSubAttributes(),prior,candidate,true,prefix);
                    if (reconciled == null) return null;
                    output.add(reconciled);
                }
            }
            return JsonArray.fromElements(output);
        }
        private boolean protectedElements(@NonNull ScimAttributeDefinition definition, @NonNull JsonArray array) {
            for (JsonValue element : array.getElements()) {
                if (!spend(1)) return true;
                if (element instanceof JsonObject object) for (ScimAttributeDefinition child : definition.getSubAttributes()) {
                    if (!spend(1)) return true;
                    if ((child.getMutability() == ScimMutability.READ_ONLY || child.getMutability() == ScimMutability.IMMUTABLE)
                            && ScimResourceValidation.assigned(object.getMembers().get(child.getName()))) return true;
                }
            }
            return false;
        }
        private boolean equalIgnoringReadOnly(@NonNull ScimAttributeDefinition definition, @NonNull JsonArray old, @Nullable JsonValue next) {
            if (!(next instanceof JsonArray array) || old.getElements().size() != array.getElements().size()) return false;
            for (int index=0; index<old.getElements().size(); index++) {
                if (!spend(1)) return false;
                if (!(old.getElements().get(index) instanceof JsonObject a) || !(array.getElements().get(index) instanceof JsonObject b)) return false;
                for (ScimAttributeDefinition child : definition.getSubAttributes()) {
                    if (!spend(1)) return false;
                    if (child.getMutability() != ScimMutability.READ_ONLY && !equal(a.getMembers().get(child.getName()),b.getMembers().get(child.getName()))) return false;
                }
            }
            return true;
        }
        private boolean equal(@Nullable JsonValue left, @Nullable JsonValue right) {
            if (!spend(1)) return false;
            if (left == null || right == null) return left == null && right == null;
            if (left.getClass() != right.getClass()) return false;
            if (left instanceof JsonObject a && right instanceof JsonObject b) {
                if (a.getMembers().size() != b.getMembers().size()) return false;
                for (Map.Entry<String,JsonValue> entry : a.getMembers().entrySet()) if (!equal(entry.getValue(),b.getMembers().get(entry.getKey()))) return false;
                return true;
            }
            if (left instanceof JsonArray a && right instanceof JsonArray b) {
                if (a.getElements().size() != b.getElements().size()) return false;
                for (int index=0; index<a.getElements().size(); index++) if (!equal(a.getElements().get(index),b.getElements().get(index))) return false;
                return true;
            }
            if (left instanceof JsonString a && right instanceof JsonString b) return spend(a.getValue().length() + b.getValue().length()) && a.getValue().equals(b.getValue());
            if (left instanceof JsonNumber a && right instanceof JsonNumber b) return spend(a.getValue().precision()+b.getValue().precision()) && a.getValue().compareTo(b.getValue()) == 0;
            if (left instanceof JsonBoolean a && right instanceof JsonBoolean b) return a.getValue().equals(b.getValue());
            return left instanceof JsonNull;
        }
    }
}
