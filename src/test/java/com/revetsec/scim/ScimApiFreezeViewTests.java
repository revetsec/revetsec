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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/** Typed-view construction proves its schema contract before releasing a view. */
class ScimApiFreezeViewTests {
    @Test void userViewRejectsContradictoryReservedSchemaBeforeARequiredGetterCanFail() {
        ScimSchema contradictory = emptyReservedSchema(ScimSchema.userInstance());
        ScimResource resource = resource(type(contradictory), envelope(contradictory));
        assertThrows(IllegalArgumentException.class, () -> ScimUser.fromResource(resource));
        assertThrows(IllegalArgumentException.class, () -> ScimEnterpriseUser.fromResource(resource));
    }

    @Test void groupViewRejectsContradictoryReservedSchemaBeforeARequiredGetterCanFail() {
        ScimSchema contradictory = emptyReservedSchema(ScimSchema.groupInstance());
        ScimResource resource = resource(type(contradictory), envelope(contradictory));
        assertThrows(IllegalArgumentException.class, () -> ScimGroup.fromResource(resource));
    }

    @Test void anAssignedUsernameDoesNotProveContradictoryUserSchemaCharacteristics() {
        ScimSchema builtin = ScimSchema.userInstance();
        ScimSchema contradictory = ScimSchema.withId(builtin.getId()).name("Contradictory")
                .description(builtin.getDescription().orElse(null)).attributes(builtin.getAttributes()).build();
        ScimResource resource = resource(type(contradictory), envelope(contradictory).put("userName", "Ada"));
        assertThrows(IllegalArgumentException.class, () -> ScimUser.fromResource(resource));
    }

    @Test void enterpriseViewRejectsContradictoryExtensionRatherThanHidingAssignedValues() {
        ScimSchema builtin = ScimSchema.enterpriseUserInstance();
        ScimSchema contradictory = ScimSchema.withId(builtin.getId()).name(builtin.getName())
                .attributes(List.of(ScimAttributeDefinition.withName("Department").build())).build();
        ScimResourceType type = userType(ScimSchema.userInstance(), contradictory);
        ScimResource resource = resource(type, userEnvelope(type)
                .put(contradictory.getId(), JsonObject.builder().put("Department", "Engineering").build()));
        assertEquals("Engineering", resource.getExtension(contradictory.getId()).orElseThrow()
                .findString("Department").orElseThrow());
        assertThrows(IllegalArgumentException.class, () -> ScimEnterpriseUser.fromResource(resource));
        assertEquals("Ada", ScimUser.fromResource(resource).getUserName());
    }

    @Test void builtinAndFullyEquivalentFoldedUserAndEnterpriseSchemasKeepTypedValuesAndMetadata() {
        for (ScimSchema user : variants(ScimSchema.userInstance()))
            for (ScimSchema enterprise : variants(ScimSchema.enterpriseUserInstance())) {
                ScimResourceType type = userType(user, enterprise);
                ScimResource resource = resource(type, userEnvelope(type)
                        .put("DISPLAYNAME", "Ada Lovelace").put("ACTIVE", true)
                        .put("EMAILS", JsonArray.fromElements(List.of(JsonObject.builder()
                                .put("VALUE", "ada@example.invalid").build())))
                        .put(enterprise.getId(), JsonObject.builder().put("EMPLOYEENUMBER", "employee-1")
                                .put("DEPARTMENT", "Engineering").put("ORGANIZATION", "Analytical")
                                .put("DIVISION", "Machines").put("MANAGER", JsonObject.builder()
                                        .put("VALUE", "manager-1").put("$REF", "../Users/manager-1").build()).build()));
                ScimUser view = ScimUser.fromResource(resource);
                assertSame(resource, view.getResource());
                assertEquals("Ada", view.getUserName());
                assertEquals("Ada Lovelace", view.getDisplayName().orElseThrow());
                assertTrue(view.isActive().orElseThrow());
                assertEquals("ada@example.invalid", view.getEmails().get(0).findString("value").orElseThrow());
                ScimEnterpriseUser extension = ScimEnterpriseUser.fromResource(resource);
                assertSame(resource, extension.getResource());
                assertEquals("employee-1", extension.getEmployeeNumber().orElseThrow());
                assertEquals("Engineering", extension.getDepartment().orElseThrow());
                assertEquals("Analytical", extension.getOrganization().orElseThrow());
                assertEquals("Machines", extension.getDivision().orElseThrow());
                assertEquals("manager-1", extension.getManager().orElseThrow().findString("value").orElseThrow());
                assertEquals("../Users/manager-1", extension.getManager().orElseThrow().findString("$ref").orElseThrow());
                assertEquals(user.getId(), type.getSchema().getId());
                assertEquals(user.getName(), type.getSchema().getName());
                assertEquals(user.getDescription(), type.getSchema().getDescription());
                ScimSchema registeredEnterprise = type.getSchemaExtensions().get(0).getSchema();
                assertEquals(enterprise.getId(), registeredEnterprise.getId());
                assertEquals(enterprise.getName(), registeredEnterprise.getName());
                assertEquals(enterprise.getDescription(), registeredEnterprise.getDescription());
            }
    }

    @Test void builtinAndFullyEquivalentFoldedGroupSchemasKeepTypedValuesAndMetadata() {
        for (ScimSchema schema : variants(ScimSchema.groupInstance())) {
            ScimResourceType type = type(schema);
            ScimResource resource = resource(type, envelope(schema).put("DISPLAYNAME", "Engineering")
                    .put("MEMBERS", JsonArray.fromElements(List.of(JsonObject.builder().put("VALUE", "user-1").build()))));
            ScimGroup view = ScimGroup.fromResource(resource);
            assertSame(resource, view.getResource());
            assertEquals("Engineering", view.getDisplayName());
            assertEquals("user-1", view.getMembers().get(0).findString("value").orElseThrow());
            assertEquals(schema.getId(), type.getSchema().getId());
            assertEquals(schema.getName(), type.getSchema().getName());
            assertEquals(schema.getDescription(), type.getSchema().getDescription());
        }
    }

    @Test void trulyForeignCoreSchemasDoNotGainTypedViewsByHavingFamiliarData() {
        ScimSchema custom = ScimSchema.withId("urn:example:custom:user").name("Custom")
                .attributes(List.of(ScimAttributeDefinition.withName("userName").required(true).build())).build();
        ScimResource resource = resource(type(custom), envelope(custom).put("userName", "Ada"));
        assertThrows(IllegalArgumentException.class, () -> ScimUser.fromResource(resource));
        assertThrows(IllegalArgumentException.class, () -> ScimGroup.fromResource(resource));
        assertThrows(IllegalArgumentException.class, () -> ScimEnterpriseUser.fromResource(resource));
    }

    @Test void anOptionalUnassignedEnterpriseExtensionCannotProduceATypedExtensionView() {
        ScimResourceType type = ScimResourceType.userInstance();
        ScimResource resource = resource(type, envelope(type.getSchema()).put("userName", "Ada"));
        assertEquals("Ada", ScimUser.fromResource(resource).getUserName());
        assertThrows(IllegalArgumentException.class, () -> ScimEnterpriseUser.fromResource(resource));
    }

    private static @NonNull ScimSchema emptyReservedSchema(@NonNull ScimSchema builtin) {
        return ScimSchema.withId(builtin.getId()).name(builtin.getName()).build();
    }

    private static @NonNull ScimResourceType type(@NonNull ScimSchema schema) {
        return ScimResourceType.withName("DirectoryResource").endpoint("/DirectoryResources").schema(schema).build();
    }

    private static @NonNull ScimResourceType userType(@NonNull ScimSchema user, @NonNull ScimSchema enterprise) {
        return ScimResourceType.withName("DirectoryUser").endpoint("/DirectoryUsers").schema(user)
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(enterprise, false))).build();
    }

    private static JsonObject.@NonNull Builder envelope(@NonNull ScimSchema schema) {
        return JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(schema.getId()))));
    }

    private static JsonObject.@NonNull Builder userEnvelope(@NonNull ScimResourceType type) {
        return JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()),
                        JsonString.fromValue(type.getSchemaExtensions().get(0).getSchema().getId())))).put("USERNAME", "Ada");
    }

    private static @NonNull ScimResource resource(@NonNull ScimResourceType type, JsonObject.@NonNull Builder document) {
        return ScimResource.withResourceType(type).document(document.build()).build();
    }

    private static @NonNull List<@NonNull ScimSchema> variants(@NonNull ScimSchema builtin) {
        List<ScimAttributeDefinition> definitions = new ArrayList<>();
        for (ScimAttributeDefinition definition : builtin.getAttributes()) definitions.add(foldedDefinition(definition));
        ScimSchema folded = ScimSchema.withId(builtin.getId().toUpperCase(Locale.ROOT)).name(builtin.getName())
                .description(builtin.getDescription().orElse(null)).attributes(definitions).build();
        assertEquals(builtin, folded);
        return List.of(builtin, folded);
    }

    private static @NonNull ScimAttributeDefinition foldedDefinition(@NonNull ScimAttributeDefinition builtin) {
        List<ScimAttributeDefinition> children = new ArrayList<>();
        for (ScimAttributeDefinition child : builtin.getSubAttributes()) children.add(foldedDefinition(child));
        return ScimAttributeDefinition.withName(builtin.getName().toUpperCase(Locale.ROOT)).type(builtin.getType())
                .description(builtin.getDescription().orElse(null)).multiValued(builtin.isMultiValued()).required(builtin.isRequired())
                .caseExact(builtin.isCaseExact()).mutability(builtin.getMutability()).returned(builtin.getReturned())
                .uniqueness(builtin.getUniqueness()).canonicalValues(builtin.getCanonicalValues())
                .referenceTypes(builtin.getReferenceTypes()).subAttributes(children).build();
    }
}
