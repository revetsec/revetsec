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
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Equivalent builtin registrations must retain builtin behavior through public entry points. */
class ScimBuiltinUserEquivalenceTests {
    private static final @NonNull String PATCH_SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static @NonNull ScimAttributeDefinition rebuilt(@NonNull ScimAttributeDefinition original,boolean upperNames) {
        List<ScimAttributeDefinition> children=new ArrayList<>();
        for (ScimAttributeDefinition child:original.getSubAttributes()) children.add(rebuilt(child,upperNames));
        return ScimAttributeDefinition.withName(upperNames ? original.getName().toUpperCase(Locale.ROOT) : original.getName())
                .type(original.getType()).description(original.getDescription().orElse(null)).multiValued(original.isMultiValued())
                .required(original.isRequired()).caseExact(original.isCaseExact()).mutability(original.getMutability())
                .returned(original.getReturned()).uniqueness(original.getUniqueness()).canonicalValues(original.getCanonicalValues())
                .referenceTypes(original.getReferenceTypes()).subAttributes(children).build();
    }
    private static @NonNull ScimSchema rebuilt(@NonNull ScimSchema original,@NonNull String id,boolean upperNames) {
        List<ScimAttributeDefinition> attributes=new ArrayList<>();
        for (ScimAttributeDefinition attribute:original.getAttributes()) attributes.add(rebuilt(attribute,upperNames));
        return ScimSchema.withId(id).name(original.getName()).description(original.getDescription().orElse(null)).attributes(attributes).build();
    }
    private static @NonNull List<@NonNull ScimSchema> variants(@NonNull ScimSchema original) {
        return List.of(original,rebuilt(original,original.getId(),false),
                rebuilt(original,original.getId().toUpperCase(Locale.ROOT),false),
                rebuilt(original,original.getId(),true),rebuilt(original,original.getId().toUpperCase(Locale.ROOT),true));
    }
    private static @NonNull ScimResourceType type(@NonNull ScimSchema user,@NonNull ScimSchema enterprise) {
        return ScimResourceType.withName("DirectoryUser").endpoint("/DirectoryUsers").schema(user)
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(enterprise,false))).build();
    }
    private static @NonNull String extensionId(@NonNull ScimResourceType type) {
        return type.getSchemaExtensions().get(0).getSchema().getId();
    }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type) {
        return provider(type,ScimCompatibility.strictInstance(),null);
    }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type,@NonNull ScimCompatibility compatibility,
            @Nullable ScimObserver observer) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).compatibility(compatibility).observer(observer)
                .stringMatching((path,definition,operator,left,right) -> ScimStringMatchResult.fromMatched(
                        operator == ScimComparisonOperator.NE ? !left.equals(right) : left.equals(right)))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static @NonNull JsonObject document(@NonNull ScimResourceType type,@Nullable JsonObject enterprise) {
        JsonObject.Builder builder=JsonObject.builder().put("schemas",JsonArray.fromElements(enterprise == null
                ? List.of(JsonString.fromValue(type.getSchema().getId()))
                : List.of(JsonString.fromValue(type.getSchema().getId()),JsonString.fromValue(extensionId(type)))))
                .put("userName","Ada").put("displayName","Ada Lovelace").put("active",true)
                .put("emails",JsonArray.fromElements(List.of(JsonObject.builder().put("value","ada@example.invalid").put("type","work").build())));
        if (enterprise != null) builder.put(extensionId(type),enterprise);
        return builder.build();
    }
    private static byte @NonNull [] bytes(@NonNull JsonObject value) { return value.toJson().getBytes(StandardCharsets.UTF_8); }
    private static @NonNull ScimResource created(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,@NonNull JsonObject body) {
        return assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseResourceResult(type,bytes(body))).getResource();
    }
    private static @NonNull ScimPatchParseResult parsePatch(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,
            @NonNull JsonObject operation) {
        return provider.parsePatchRequestResult(type,bytes(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(PATCH_SCHEMA))))
                .put("Operations",JsonArray.fromElements(List.of(operation))).build()));
    }
    private static @NonNull ScimPatchRequest patch(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,
            @NonNull String path,@NonNull JsonValue value) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsePatch(provider,type,
                JsonObject.builder().put("op","replace").put("path",path).put("value",value).build())).getPatchRequest();
    }
    private static @NonNull Set<@NonNull String> paths(@NonNull Set<@NonNull ScimAttributePath> paths) {
        Set<String> result=new LinkedHashSet<>(); for (ScimAttributePath path:paths) result.add(path.toScimString()); return result;
    }
    @Test void equivalentConfiguredSchemasKeepTheirMetadataAndCanonicalBuiltinAttributeSpelling() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            assertEquals(ScimSchema.userInstance(),user); assertEquals(ScimSchema.enterpriseUserInstance(),enterprise);
            ScimResourceType type=type(user,enterprise);
            assertEquals(user,type.getSchema()); assertEquals(user.getId(),type.getSchema().getId());
            assertEquals(user.getName(),type.getSchema().getName()); assertEquals(user.getDescription(),type.getSchema().getDescription());
            assertEquals(ScimSchema.userInstance().getAttributes(),type.getSchema().getAttributes());
            assertEquals(ScimSchema.userInstance().getAttributes().stream().map(ScimAttributeDefinition::getName).toList(),
                    type.getSchema().getAttributes().stream().map(ScimAttributeDefinition::getName).toList());
            ScimSchema registeredEnterprise=type.getSchemaExtensions().get(0).getSchema();
            assertEquals(enterprise,registeredEnterprise); assertEquals(enterprise.getId(),registeredEnterprise.getId());
            assertEquals(enterprise.getName(),registeredEnterprise.getName()); assertEquals(enterprise.getDescription(),registeredEnterprise.getDescription());
            assertEquals(ScimSchema.enterpriseUserInstance().getAttributes().stream().map(ScimAttributeDefinition::getName).toList(),
                    registeredEnterprise.getAttributes().stream().map(ScimAttributeDefinition::getName).toList());
            provider(type);
        }
    }
    @Test void createAndTrustedViewsExposeNormalizedUserAndEnterpriseValuesAcrossEquivalentSpellings() {
        JsonObject extension=JsonObject.builder().put("EMPLOYEENUMBER","employee-1").put("DEPARTMENT","Research")
                .put("ORGANIZATION","Analytical").put("DIVISION","Machines")
                .put("MANAGER",JsonObject.builder().put("VALUE","manager-A").put("$REF","../Users/manager-A").build()).build();
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(user,enterprise); JsonObject body=document(type,extension); ScimServiceProvider provider=provider(type);
            for (ScimResource resource:List.of(created(provider,type,body),ScimResource.withResourceType(type).document(body).build())) {
                ScimUser view=ScimUser.fromResource(resource); assertEquals("Ada",view.getUserName());
                assertEquals("Ada Lovelace",view.getDisplayName().orElseThrow()); assertTrue(view.isActive().orElseThrow());
                assertEquals("ada@example.invalid",view.getEmails().get(0).findString("value").orElseThrow());
                ScimEnterpriseUser enterpriseView=ScimEnterpriseUser.fromResource(resource);
                assertEquals("employee-1",enterpriseView.getEmployeeNumber().orElseThrow());
                assertEquals("Research",enterpriseView.getDepartment().orElseThrow());
                assertEquals("Analytical",enterpriseView.getOrganization().orElseThrow()); assertEquals("Machines",enterpriseView.getDivision().orElseThrow());
                assertEquals("manager-A",enterpriseView.getManager().orElseThrow().findString("value").orElseThrow());
                assertEquals("../Users/manager-A",enterpriseView.getManager().orElseThrow().findString("$ref").orElseThrow());
                ScimAttributePath managerPath=assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                        ScimAttributePath.fromExpressionResult(extensionId(type)+":MANAGER.VALUE")).getAttributePath();
                assertTrue(resource.find(managerPath).isPresent());
            }
        }
    }
    @Test void builtinUserGroupIdentifiersAreCheckedInTrustedDataButCreateAndPutIgnoreReadOnlyInput() {
        for (ScimSchema schema:variants(ScimSchema.userInstance())) {
            ScimResourceType type=type(schema,ScimSchema.enterpriseUserInstance()); ScimServiceProvider provider=provider(type);
            for (String invalid:List.of("","x".repeat(1025),"bulkId:temporary","BULKID","id\nbreak","id\u007fbreak")) {
                JsonObject body=document(type,null); java.util.Map<String,JsonValue> members=new java.util.LinkedHashMap<>(body.getMembers());
                members.put("groups",JsonArray.fromElements(List.of(JsonObject.builder().put("value",invalid).build())));
                JsonObject invalidGroups=JsonObject.fromMembers(members);
                assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(invalidGroups).build(),schema.getId());
                assertTrue(created(provider,type,invalidGroups).getDocument().find("groups").isEmpty());
                members.put("groups",JsonArray.fromElements(List.of(JsonObject.builder().put("value","Group-A").put("display","Stored Group").build())));
                members.put("id",JsonString.fromValue("User-A"));
                ScimResource current=ScimResource.withResourceType(type).document(JsonObject.fromMembers(members)).build();
                ScimResource replaced=assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                        provider.parseReplacementResult(type,current,bytes(invalidGroups))).getResource();
                assertEquals(current.getDocument().find("groups"),replaced.getDocument().find("groups"));
                assertEquals(current.getId(),replaced.getId());
            }
        }
    }
    @Test void enterpriseManagerIdentifiersRejectOnTrustedCreatePutAndPatchForEveryEquivalentRegistration() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(user,enterprise); ScimServiceProvider provider=provider(type);
            ScimResource current=created(provider,type,document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value","manager-A").build()).build()));
            for (String invalid:List.of("","x".repeat(1025),"bulkId:temporary","BULKID","id\nbreak","id\u007fbreak")) {
                JsonObject body=document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value",invalid).build()).build());
                assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(body).build(),enterprise.getId());
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(type,bytes(body))).getError());
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseReplacementResult(type,current,bytes(body))).getError());
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,parsePatch(provider,type,
                        JsonObject.builder().put("op","replace").put("path",extensionId(type)+":MANAGER.VALUE").put("value",invalid).build())).getError());
                assertEquals("manager-A",ScimEnterpriseUser.fromResource(current).getManager().orElseThrow().findString("value").orElseThrow());
            }
        }
    }
    @Test void identifierBoundaryAndOpaqueCaseRemainValidAcrossEquivalentRegistrations() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(user,enterprise); ScimServiceProvider provider=provider(type);
            for (String id:List.of("x".repeat(1024),"Manager-A","manager-a")) {
                JsonObject body=document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value",id).build()).build());
                ScimResource resource=created(provider,type,body);
                assertEquals(id,ScimEnterpriseUser.fromResource(resource).getManager().orElseThrow().findString("value").orElseThrow());
                java.util.Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(body.getMembers());
                fields.put("groups",JsonArray.fromElements(List.of(JsonObject.builder().put("value",id).build())));
                ScimResource trusted=ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build();
                assertEquals(id,assertInstanceOf(JsonObject.class,assertInstanceOf(JsonArray.class,
                        trusted.getDocument().find("groups").orElseThrow()).getElements().get(0)).findString("value").orElseThrow());
            }
            ScimResource current=created(provider,type,document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value","Manager-A").build()).build()));
            ScimPatchResult changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,
                    provider.applyPatchResult(current,patch(provider,type,extensionId(type)+":manager.value",JsonString.fromValue("manager-a")))).getPatchResult();
            assertTrue(changed.isModified());
            assertEquals("manager-a",ScimEnterpriseUser.fromResource(changed.getResource()).getManager().orElseThrow().findString("value").orElseThrow());
            assertEquals("Manager-A",ScimEnterpriseUser.fromResource(current).getManager().orElseThrow().findString("value").orElseThrow());
        }
    }
    @Test void canonicalizedEnterpriseExtensionsRetainTheirRequiredRegistration() {
        for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=ScimResourceType.withName("RequiredUser").endpoint("/RequiredUsers").schema(ScimSchema.userInstance())
                    .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(enterprise,true))).build();
            assertTrue(type.getSchemaExtensions().get(0).isRequired());
            assertEquals(enterprise,type.getSchemaExtensions().get(0).getSchema());
            ScimServiceProvider provider=provider(type,ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build(),null);
            JsonObject missing=document(type,null);
            assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(missing).build());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseResourceResult(type,bytes(missing))).getError());
            ScimResource current=created(provider,type,document(type,JsonObject.builder().put("MANAGER",JsonObject.builder().put("VALUE","manager-A").build()).build()));
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseReplacementResult(type,current,bytes(missing))).getError());
            ScimServiceProvider root=provider;
            ScimPatchRequest removal=assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsePatch(root,type,
                    JsonObject.builder().put("op","remove").put("path",enterprise.getId()).build())).getPatchRequest();
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                    root.applyPatchResult(current,removal)).getError());
            assertEquals("manager-A",ScimEnterpriseUser.fromResource(current).getManager().orElseThrow().findString("value").orElseThrow());
        }
    }
    @Test void putAndPatchClearReadOnlyManagerDisplayNameWhenIdentityChanges() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(user,enterprise); ScimServiceProvider provider=provider(type);
            JsonObject manager=JsonObject.builder().put("VALUE","manager-A").put("DISPLAYNAME","Stored Manager").build();
            JsonObject body=document(type,JsonObject.builder().put("MANAGER",manager).put("DEPARTMENT","Before").build());
            ScimResource current=ScimResource.withResourceType(type).document(body).build(); JsonObject before=current.getDocument();
            JsonObject replacement=document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value","manager-B").put("displayName","Forged").build()).put("department","After").build());
            ScimResourceParseResult.Succeeded replaced=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseReplacementResult(type,current,bytes(replacement)));
            JsonObject putManager=ScimEnterpriseUser.fromResource(replaced.getResource()).getManager().orElseThrow();
            assertEquals("manager-B",putManager.findString("value").orElseThrow()); assertTrue(putManager.findString("displayName").isEmpty());
            assertTrue(paths(replaced.getSuppliedAttributePaths()).contains(extensionId(type)+":manager.value"));
            assertFalse(paths(replaced.getSuppliedAttributePaths()).contains(extensionId(type)+":manager.displayName"));
            ScimPatchRequest request=patch(provider,type,extensionId(type)+":MANAGER.VALUE",JsonString.fromValue("manager-C"));
            assertEquals(Set.of(extensionId(type)+":manager.value"),paths(request.getRequestedAttributePaths()));
            ScimPatchResult changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,request)).getPatchResult();
            assertEquals("manager-C",ScimEnterpriseUser.fromResource(changed.getResource()).getManager().orElseThrow().findString("value").orElseThrow());
            assertTrue(ScimEnterpriseUser.fromResource(changed.getResource()).getManager().orElseThrow().findString("displayName").isEmpty());
            assertEquals(Set.of(extensionId(type)+":manager",extensionId(type)+":manager.value",
                    extensionId(type)+":manager.displayName"),paths(changed.getModifiedAttributePaths()));
            ScimResource sameManager=assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                    provider.parseReplacementResult(type,current,bytes(document(type,JsonObject.builder()
                            .put("manager",JsonObject.builder().put("value","manager-A").build()).build()))))
                    .getResource();
            assertEquals("Stored Manager",ScimEnterpriseUser.fromResource(sameManager).getManager()
                    .orElseThrow().findString("displayName").orElseThrow());
            assertSame(before,current.getDocument());
        }
    }

    @Test void patchCanRemoveManagerAndOptionalExtensionDespiteReadOnlyDisplayName() {
        ScimResourceType type=type(ScimSchema.userInstance(),ScimSchema.enterpriseUserInstance());
        ScimServiceProvider provider=provider(type,ScimCompatibility.builder()
                .features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build(),null);
        ScimResource current=ScimResource.withResourceType(type).document(document(type,
                JsonObject.builder().put("manager",JsonObject.builder().put("value","manager-A")
                        .put("displayName","Stored Manager").build()).build())).build();
        for (String path:List.of(extensionId(type)+":manager",extensionId(type))) {
            ScimPatchRequest removal=assertInstanceOf(ScimPatchParseResult.Succeeded.class,
                    parsePatch(provider,type,JsonObject.builder().put("op","remove").put("path",path).build()))
                    .getPatchRequest();
            ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,
                    provider.applyPatchResult(current,removal)).getPatchResult().getResource();
            assertTrue(changed.getExtension(extensionId(type))
                    .flatMap(extension -> extension.find("manager")).isEmpty());
        }
    }
    @Test void explicitScalarManagerCompatibilityIsEquivalentAndEveryPresetStillRejectsIt() {
        ScimCompatibility scalar=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR)).build();
        for (ScimSchema user:variants(ScimSchema.userInstance())) for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(user,enterprise); JsonObject body=document(type,JsonObject.builder().put("MANAGER","manager-A").build());
            for (ScimCompatibility preset:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.microsoftEntraIdInstance(),ScimCompatibility.oktaInstance())) {
                assertFalse(preset.getFeatures().contains(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR));
                ScimServiceProvider strict=provider(type,preset,null);
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,strict.parseResourceResult(type,bytes(body))).getError());
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,parsePatch(strict,type,
                        JsonObject.builder().put("op","replace").put("path",extensionId(type)+":manager").put("value","manager-A").build())).getError());
            }
            List<ScimCompatibilityFeature> features=new ArrayList<>();
            ScimObserver observer=new ScimObserver() {
                @Override public void didUseCompatibilityFeature(@NonNull ScimCompatibilityFeature feature) { features.add(feature); }
            };
            ScimServiceProvider provider=provider(type,scalar,observer);
            ScimResource created=created(provider,type,body);
            assertEquals("manager-A",ScimEnterpriseUser.fromResource(created).getManager().orElseThrow().findString("value").orElseThrow());
            assertEquals(List.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR),features); features.clear();
            ScimPatchRequest request=patch(provider,type,extensionId(type)+":MANAGER",JsonString.fromValue("manager-B"));
            ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(created,request)).getPatchResult().getResource();
            assertEquals("manager-B",ScimEnterpriseUser.fromResource(changed).getManager().orElseThrow().findString("value").orElseThrow());
            assertEquals(List.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR),features);
            features.clear();
            ScimResource replaced=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseReplacementResult(type,created,bytes(body))).getResource();
            assertEquals("manager-A",ScimEnterpriseUser.fromResource(replaced).getManager().orElseThrow().findString("value").orElseThrow());
            assertEquals(List.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR),features);
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseResourceResult(type,bytes(document(type,JsonObject.builder().put("manager","bulkId:temporary").build())))).getError());
        }
    }
    @SuppressWarnings("ReferenceEquality") // This optional fast path deliberately requires the builtin singleton.
    @Test void reconstructedUserStillUsesTheConservativeOptionalEmailUpsertBoundary() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) {
            ScimResourceType type=type(user,ScimSchema.enterpriseUserInstance()); ScimServiceProvider provider=provider(type,ScimCompatibility.microsoftEntraIdInstance(),null);
            ScimResource current=created(provider,type,JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(user.getId())))).put("userName","Ada").build());
            ScimPatchRequest request=patch(provider,type,"emails[type eq \"work\"].value",JsonString.fromValue("ada@example.invalid"));
            ScimPatchApplicationResult result=provider.applyPatchResult(current,request);
            if (user == ScimSchema.userInstance()) {
                ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,result).getPatchResult().getResource();
                assertEquals("ada@example.invalid",ScimUser.fromResource(changed).getEmails().get(0).findString("value").orElseThrow());
            } else assertSame(ScimError.noTargetInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,result).getError());
        }
    }
    @Test void builtinEmailPrimaryUniquenessAndPatchTransferSurviveReconstructedAttributeNames() {
        for (ScimSchema user:variants(ScimSchema.userInstance())) {
            ScimResourceType type=type(user,ScimSchema.enterpriseUserInstance()); ScimServiceProvider provider=provider(type);
            JsonObject first=JsonObject.builder().put("value","first@example.invalid").put("type","work").put("PRIMARY",true).build();
            JsonObject second=JsonObject.builder().put("value","second@example.invalid").put("type","home").put("PRIMARY",true).build();
            java.util.Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(document(type,null).getMembers());
            fields.put("emails",JsonArray.fromElements(List.of(first,second)));
            JsonObject duplicate=JsonObject.fromMembers(fields);
            assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(duplicate).build());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseResourceResult(type,bytes(duplicate))).getError());
            JsonObject ordinarySecond=JsonObject.builder().put("value","second@example.invalid").put("type","home").put("primary",false).build();
            fields.put("emails",JsonArray.fromElements(List.of(first,ordinarySecond)));
            ScimResource current=ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build();
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseReplacementResult(type,current,bytes(duplicate))).getError());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                    parsePatch(provider,type,JsonObject.builder().put("op","replace").put("path","emails")
                            .put("value",JsonArray.fromElements(List.of(first,second))).build())).getError());
            ScimPatchRequest request=patch(provider,type,"EMAILS[TYPE eq \"home\"].PRIMARY",JsonBoolean.fromValue(true));
            ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,request)).getPatchResult().getResource();
            List<JsonObject> emails=ScimUser.fromResource(changed).getEmails();
            assertEquals(2,emails.size()); assertFalse(emails.get(0).findBoolean("primary").orElse(false));
            assertTrue(emails.get(1).findBoolean("primary").orElseThrow());
            assertTrue(ScimUser.fromResource(current).getEmails().get(0).findBoolean("primary").orElseThrow());
            assertEquals(Set.of("emails","emails.type","emails.primary"),paths(request.getRequestedAttributePaths()));
        }
    }
    @Test void customUppercasePrimaryDefinitionsRetainTheirSpellingAndEnforceUniquenessAndTransfer() {
        for (boolean upperNames:List.of(false,true)) {
            ScimSchema schema=rebuilt(ScimSchema.userInstance(),"urn:example:custom:primary-user",upperNames);
            ScimResourceType type=type(schema,ScimSchema.enterpriseUserInstance()); ScimServiceProvider provider=provider(type);
            assertSame(schema,type.getSchema());
            String emailsName=upperNames ? "EMAILS" : "emails",primaryName=upperNames ? "PRIMARY" : "primary";
            JsonObject first=JsonObject.builder().put("value","first@example.invalid").put("type","work").put("primary",true).build();
            JsonObject second=JsonObject.builder().put("value","second@example.invalid").put("type","home").put("primary",true).build();
            java.util.Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(document(type,null).getMembers());
            fields.put("emails",JsonArray.fromElements(List.of(first,second))); JsonObject duplicate=JsonObject.fromMembers(fields);
            assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(duplicate).build());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseResourceResult(type,bytes(duplicate))).getError());
            JsonObject ordinarySecond=JsonObject.builder().put("value","second@example.invalid").put("type","home").put("primary",false).build();
            fields.put("emails",JsonArray.fromElements(List.of(first,ordinarySecond)));
            ScimResource current=ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build();
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    provider.parseReplacementResult(type,current,bytes(duplicate))).getError());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,parsePatch(provider,type,
                    JsonObject.builder().put("op","replace").put("path","emails").put("value",JsonArray.fromElements(List.of(first,second))).build())).getError());
            JsonObject third=JsonObject.builder().put("value","third@example.invalid").put("type","other").put("primary",true).build();
            List<JsonObject> operations=List.of(JsonObject.builder().put("op","replace").put("path","emails[type eq \"home\"].primary").put("value",true).build(),
                    JsonObject.builder().put("op","replace").put("path","emails[type eq \"home\"]").put("value",second).build(),
                    JsonObject.builder().put("op","add").put("path","emails").put("value",third).build(),
                    JsonObject.builder().put("op","add").put("path","emails").put("value",JsonArray.fromElements(List.of(
                            JsonObject.builder().put("value","fourth@example.invalid").put("primary",false).build(),third))).build());
            for (JsonObject operation:operations) {
                ScimPatchRequest request=assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsePatch(provider,type,operation)).getPatchRequest();
                ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,request)).getPatchResult().getResource();
                JsonArray emails=assertInstanceOf(JsonArray.class,changed.getDocument().find(emailsName).orElseThrow());
                assertFalse(assertInstanceOf(JsonObject.class,emails.getElements().get(0)).findBoolean(primaryName).orElse(false));
                int primaryCount=0;
                for (JsonValue email:emails.getElements()) if (assertInstanceOf(JsonObject.class,email).findBoolean(primaryName).orElse(false)) primaryCount++;
                assertEquals(1,primaryCount); assertTrue(assertInstanceOf(JsonObject.class,emails.getElements().get(emails.getElements().size()-1)).findBoolean(primaryName).orElseThrow());
                assertTrue(assertInstanceOf(JsonObject.class,assertInstanceOf(JsonArray.class,current.getDocument().find(emailsName).orElseThrow())
                        .getElements().get(0)).findBoolean(primaryName).orElseThrow());
            }
        }
        for (boolean primaryString:List.of(false,true)) {
            String child=primaryString ? "PRIMARY" : "PREFERRED";
            ScimSchema custom=ScimSchema.withId("urn:example:custom:non-primary").name("Non-primary")
                    .attributes(List.of(ScimAttributeDefinition.withName("CONTACTS").type(ScimAttributeType.COMPLEX).multiValued(true)
                            .subAttributes(List.of(ScimAttributeDefinition.withName("VALUE").build(),
                                    ScimAttributeDefinition.withName(child).type(primaryString ? ScimAttributeType.STRING : ScimAttributeType.BOOLEAN).build())).build())).build();
            ScimResourceType type=type(custom,ScimSchema.enterpriseUserInstance()); ScimServiceProvider provider=provider(type);
            JsonValue value=primaryString ? JsonString.fromValue("yes") : JsonBoolean.fromValue(true);
            JsonObject first=JsonObject.builder().put("VALUE","first").put(child,value).build();
            JsonObject second=JsonObject.builder().put("VALUE","second").put(child,value).build();
            JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(custom.getId()))))
                    .put("CONTACTS",JsonArray.fromElements(List.of(first,second))).build();
            ScimResource trusted=ScimResource.withResourceType(type).document(body).build();
            ScimResource current=created(provider,type,body); assertEquals(trusted.getDocument(),current.getDocument());
            assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseReplacementResult(type,current,bytes(body)));
            ScimPatchRequest request=patch(provider,type,"contacts[value eq \"second\"]."+child,
                    primaryString ? JsonString.fromValue("changed") : JsonBoolean.fromValue(false));
            ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,request)).getPatchResult().getResource();
            JsonArray contacts=assertInstanceOf(JsonArray.class,changed.getDocument().find("CONTACTS").orElseThrow());
            assertEquals(value,assertInstanceOf(JsonObject.class,contacts.getElements().get(0)).find(child).orElseThrow());
            assertEquals(primaryString ? JsonString.fromValue("changed") : JsonBoolean.fromValue(false),
                    assertInstanceOf(JsonObject.class,contacts.getElements().get(1)).find(child).orElseThrow());
        }
    }
    @Test void equivalentEnterpriseExtensionWorksOnACustomCoreWithoutInventingPrimarySchemaSemantics() {
        ScimSchema custom=ScimSchema.withId("urn:example:custom:empty").name("Custom").build();
        ScimCompatibility scalar=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR)).build();
        for (ScimSchema enterprise:variants(ScimSchema.enterpriseUserInstance())) {
            ScimResourceType type=type(custom,enterprise); ScimServiceProvider provider=provider(type,scalar,null);
            JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(custom.getId()),JsonString.fromValue(enterprise.getId()))))
                    .put(enterprise.getId(),JsonObject.builder().put("MANAGER","manager-A").build()).build();
            ScimResource current=created(provider,type,body);
            assertEquals("manager-A",assertInstanceOf(JsonObject.class,current.getExtension(enterprise.getId()).orElseThrow()
                    .find("manager").orElseThrow()).findString("value").orElseThrow());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,parsePatch(provider,type,
                    JsonObject.builder().put("op","replace").put("path",enterprise.getId()+":manager.value").put("value","bulkId:temporary").build())).getError());
            assertThrows(IllegalArgumentException.class,() -> ScimEnterpriseUser.fromResource(current));
        }
        ScimResourceType misplaced=ScimResourceType.withName("Misplaced").endpoint("/Misplaced")
                .schema(ScimSchema.enterpriseUserInstance()).schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.userInstance(),false))).build();
        ScimServiceProvider provider=provider(misplaced,scalar,null);
        JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(ScimSchema.enterpriseUserInstance().getId()),JsonString.fromValue(ScimSchema.userInstance().getId()))))
                .put("manager",JsonObject.builder().put("value","bulkId:temporary").build())
                .put(ScimSchema.userInstance().getId(),JsonObject.builder().put("userName","Ada")
                        .put("groups",JsonArray.fromElements(List.of(JsonObject.builder().put("value","bulkId:temporary").build()))).build()).build();
        ScimResource trusted=ScimResource.withResourceType(misplaced).document(body).build();
        assertEquals("bulkId:temporary",assertInstanceOf(JsonObject.class,trusted.getDocument().find("manager").orElseThrow()).findString("value").orElseThrow());
        assertThrows(IllegalArgumentException.class,() -> ScimUser.fromResource(trusted));
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                parsePatch(provider,misplaced,JsonObject.builder().put("op","replace").put("path","manager").put("value","manager-A").build())).getError());
    }
    @Test void alteredReservedFacetsRejectRegistrationAndCustomSchemasRetainGenericSpellingAndValues() {
        for (ScimSchema builtin:List.of(ScimSchema.userInstance(),ScimSchema.enterpriseUserInstance())) {
            List<ScimAttributeDefinition> attributes=new ArrayList<>(builtin.getAttributes());
            ScimAttributeDefinition first=attributes.get(0);
            attributes.set(0,ScimAttributeDefinition.withName(first.getName()).type(first.getType())
                    .description(first.getDescription().orElse(null)).multiValued(first.isMultiValued()).required(first.isRequired())
                    .caseExact(!first.isCaseExact()).mutability(first.getMutability()).returned(first.getReturned()).uniqueness(first.getUniqueness())
                    .canonicalValues(first.getCanonicalValues()).referenceTypes(first.getReferenceTypes()).subAttributes(first.getSubAttributes()).build());
            for (ScimSchema changed:List.of(ScimSchema.withId(builtin.getId()).name("Altered").description(builtin.getDescription().orElse(null)).attributes(builtin.getAttributes()).build(),
                    ScimSchema.withId(builtin.getId()).name(builtin.getName()).description("Altered").attributes(builtin.getAttributes()).build(),
                    ScimSchema.withId(builtin.getId()).name(builtin.getName()).description(builtin.getDescription().orElse(null)).attributes(attributes).build())) {
                ScimResourceType type=builtin.equals(ScimSchema.userInstance()) ? type(changed,ScimSchema.enterpriseUserInstance()) : type(ScimSchema.userInstance(),changed);
                assertThrows(IllegalArgumentException.class,() -> provider(type));
            }
        }
        for (boolean upperNames:List.of(false,true)) {
            ScimSchema user=rebuilt(ScimSchema.userInstance(),"urn:example:custom:user",upperNames);
            ScimSchema enterprise=rebuilt(ScimSchema.enterpriseUserInstance(),"urn:example:custom:enterprise",upperNames);
            ScimResourceType type=type(user,enterprise); assertSame(user,type.getSchema()); assertSame(enterprise,type.getSchemaExtensions().get(0).getSchema());
            ScimServiceProvider provider=provider(type);
            JsonObject body=document(type,JsonObject.builder().put("manager",JsonObject.builder().put("value","bulkId:temporary").build()).build());
            ScimResource resource=created(provider,type,body);
            assertEquals("bulkId:temporary",assertInstanceOf(JsonObject.class,resource.getExtension(enterprise.getId()).orElseThrow()
                    .find(upperNames ? "MANAGER" : "manager").orElseThrow()).findString(upperNames ? "VALUE" : "value").orElseThrow());
            java.util.Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(body.getMembers());
            fields.put("groups",JsonArray.fromElements(List.of(JsonObject.builder().put("value","bulkId:temporary").build())));
            assertDoesNotThrow(() -> ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build());
            assertThrows(IllegalArgumentException.class,() -> ScimUser.fromResource(resource));
            assertThrows(IllegalArgumentException.class,() -> ScimEnterpriseUser.fromResource(resource));
            ScimServiceProvider scalar=provider(type,ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR)).build(),null);
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                    scalar.parseResourceResult(type,bytes(document(type,JsonObject.builder().put("manager","manager-A").build())))).getError());
        }
    }
}
