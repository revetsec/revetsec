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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Independent primary-source schema and trusted configuration boundaries. */
class ScimM10SchemaTests {
    @Test void standardResourceAttributesAreComplete() {
        assertNames(ScimSchema.userInstance(), List.of("userName", "name", "displayName", "nickName", "profileUrl",
                "title", "userType", "preferredLanguage", "locale", "timezone", "active", "password", "emails",
                "phoneNumbers", "ims", "photos", "addresses", "groups", "entitlements", "roles", "x509Certificates"));
        assertNames(ScimSchema.groupInstance(), List.of("displayName", "members"));
        assertNames(ScimSchema.enterpriseUserInstance(), List.of("employeeNumber", "costCenter", "organization",
                "division", "department", "manager"));
        assertEquals("urn:ietf:params:scim:schemas:core:2.0:User", ScimSchema.userInstance().getId());
        assertEquals("urn:ietf:params:scim:schemas:core:2.0:Group", ScimSchema.groupInstance().getId());
        assertEquals("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", ScimSchema.enterpriseUserInstance().getId());
        assertSame(ScimSchema.userInstance(), ScimSchema.userInstance());
        assertSame(ScimSchema.groupInstance(), ScimSchema.groupInstance());
        assertSame(ScimSchema.enterpriseUserInstance(), ScimSchema.enterpriseUserInstance());
    }

    @Test void resourceFacetsFollowIndependentNormativeAndVerifiedExpectations() {
        ScimAttributeDefinition userName = definition(ScimSchema.userInstance(), "userName");
        assertEquals(ScimAttributeType.STRING, userName.getType());
        assertTrue(userName.isRequired());
        assertFalse(userName.isCaseExact());
        assertEquals(ScimUniqueness.SERVER, userName.getUniqueness());
        ScimAttributeDefinition password = definition(ScimSchema.userInstance(), "password");
        assertEquals(ScimReturned.NEVER, password.getReturned());
        assertEquals(ScimMutability.WRITE_ONLY, password.getMutability());
        assertTrue(definition(ScimSchema.groupInstance(), "displayName").isRequired()); // Verified 5368.
        assertTrue(sub(ScimSchema.enterpriseUserInstance(), "manager", "value").isCaseExact()); // Verified 8472.
        assertFalse(sub(ScimSchema.enterpriseUserInstance(), "manager", "value").isRequired()); // Held 8359 not adopted.
        assertEquals(Set.of("Group"), sub(ScimSchema.userInstance(), "groups", "$ref").getReferenceTypes()); // Verified 8471.
        assertEquals(ScimMutability.READ_ONLY, definition(ScimSchema.userInstance(), "groups").getMutability());
        assertEquals(ScimMutability.IMMUTABLE, sub(ScimSchema.groupInstance(), "members", "value").getMutability());
        assertEquals(ScimMutability.IMMUTABLE, sub(ScimSchema.groupInstance(), "members", "$ref").getMutability());
        assertEquals(ScimMutability.IMMUTABLE, sub(ScimSchema.groupInstance(), "members", "type").getMutability());
        assertEquals(ScimMutability.READ_ONLY, sub(ScimSchema.groupInstance(), "members", "display").getMutability());
        assertEquals(ScimAttributeType.BOOLEAN, sub(ScimSchema.userInstance(), "addresses", "primary").getType());
        assertEquals(Set.of("work", "home", "other"), sub(ScimSchema.userInstance(), "emails", "type").getCanonicalValues());
        assertEquals(ScimAttributeType.BINARY, sub(ScimSchema.userInstance(), "x509Certificates", "value").getType());
        assertFalse(sub(ScimSchema.userInstance(), "photos", "value").isCaseExact()); // Explicit descriptor retained.
    }

    @Test void discoveryDescriptorsCoverRequiredCapabilitiesAndVerifiedCorrections() {
        assertNames(ScimSchema.serviceProviderConfigInstance(), List.of("documentationUri", "patch", "bulk", "filter",
                "changePassword", "sort", "etag", "authenticationSchemes", "pagination"));
        assertNames(ScimSchema.resourceTypeInstance(), List.of("id", "name", "description", "endpoint", "schema", "schemaExtensions"));
        assertNames(ScimSchema.schemaInstance(), List.of("id", "name", "description", "attributes"));
        for (String capability : List.of("patch", "bulk", "filter", "changePassword", "sort", "etag")) {
            ScimAttributeDefinition definition = definition(ScimSchema.serviceProviderConfigInstance(), capability);
            assertTrue(definition.isRequired());
            assertEquals(ScimMutability.READ_ONLY, definition.getMutability());
            assertTrue(sub(ScimSchema.serviceProviderConfigInstance(), capability, "supported").isRequired());
        }
        assertTrue(sub(ScimSchema.serviceProviderConfigInstance(), "authenticationSchemes", "type").isRequired());
        assertEquals(Set.of("oauth", "oauth2", "oauthbearertoken", "httpbasic", "httpdigest"),
                sub(ScimSchema.serviceProviderConfigInstance(), "authenticationSchemes", "type").getCanonicalValues());
        assertEquals(ScimAttributeType.BOOLEAN, sub(ScimSchema.serviceProviderConfigInstance(), "authenticationSchemes", "primary").getType());
        assertTrue(definition(ScimSchema.resourceTypeInstance(), "schemaExtensions").isMultiValued()); // Verified 7522.
        for (String name : List.of("name", "endpoint")) {
            assertTrue(definition(ScimSchema.resourceTypeInstance(), name).isCaseExact());
            assertEquals(ScimUniqueness.SERVER, definition(ScimSchema.resourceTypeInstance(), name).getUniqueness()); // Verified 8475.
        }
        assertTrue(sub(ScimSchema.schemaInstance(), "attributes", "type").getCanonicalValues().contains("binary")); // Verified 5606.
        ScimAttributeDefinition subAttributes = sub(ScimSchema.schemaInstance(), "attributes", "subAttributes");
        ScimAttributeDefinition type = subAttributes.getSubAttributes().stream().filter(d -> d.getName().equals("type")).findFirst().orElseThrow();
        assertEquals(Set.of("string", "boolean", "decimal", "integer", "dateTime", "reference", "binary"), type.getCanonicalValues()); // Verified 8415.
        assertTrue(subAttributes.getSubAttributes().stream().filter(d -> d.getName().equals("referenceTypes")).findFirst().orElseThrow().isMultiValued()); // Verified 5607.
        for (String name : List.of("defaultPageSize", "maxPageSize", "cursorTimeout"))
            assertEquals(ScimAttributeType.INTEGER, sub(ScimSchema.serviceProviderConfigInstance(), "pagination", name).getType());
    }

    @Test void commonDefinitionsAreFixedAndReachableThroughCoreOnly() {
        ScimResourceType user = ScimResourceType.userInstance();
        ScimAttributeDefinition id = ScimSchemas.find(user, path("id")).orElseThrow();
        assertFalse(id.isRequired()); // A create candidate precedes authoritative ID assignment.
        assertTrue(id.isCaseExact());
        assertEquals(ScimReturned.ALWAYS, id.getReturned());
        assertEquals(ScimMutability.READ_ONLY, id.getMutability());
        assertEquals(ScimUniqueness.SERVER, id.getUniqueness());
        assertTrue(ScimSchemas.find(user, path("externalId")).orElseThrow().isCaseExact());
        assertEquals(ScimAttributeType.DATE_TIME, ScimSchemas.find(user, path("meta.created")).orElseThrow().getType());
        assertEquals(ScimAttributeType.REFERENCE, ScimSchemas.find(user, path("meta.location")).orElseThrow().getType());
        assertEquals(ScimReturned.ALWAYS, ScimSchemas.find(user, path("schemas")).orElseThrow().getReturned());
        String extension = ScimSchema.enterpriseUserInstance().getId();
        assertTrue(ScimSchemas.find(user, path(extension + ":id")).isEmpty());
        assertTrue(ScimSchemas.find(user, path("department")).isEmpty());
        assertTrue(ScimSchemas.find(user, path(extension + ":department")).isPresent());
        assertTrue(ScimSchemas.find(user, path("urn:foreign:x:userName")).isEmpty());
    }

    @Test void lookupIsAsciiInsensitiveAndCanonicalizesOnlyRegisteredComponents() {
        ScimResourceType user = ScimResourceType.userInstance();
        String core = "URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER";
        assertEquals("userName", ScimSchemas.canonicalPath(user, path(core + ":USERNAME")).orElseThrow().toScimString());
        String extension = ScimSchema.enterpriseUserInstance().getId();
        assertEquals(extension + ":manager.value", ScimSchemas.canonicalPath(user,
                path("URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER:MANAGER.VALUE")).orElseThrow().toScimString());
        assertTrue(ScimSchemas.canonicalPath(user, path("name.unknown")).isEmpty());
        assertTrue(ScimSchemas.find(user, path("userName.value")).isEmpty());
        assertEquals(List.of(ScimSchema.userInstance(), ScimSchema.enterpriseUserInstance()), ScimSchemas.allSchemas(user));
        assertEquals(List.of(ScimSchema.groupInstance()), ScimSchemas.allSchemas(ScimResourceType.groupInstance()));
    }

    @SuppressWarnings("NullAway") // Intentionally exercise programmer misuse of a required factory input.
    @Test void absoluteUriIdsSupportHttpsIpv6AndNeverUseNameGuessing() {
        for (String uri : List.of("urn:example:custom", "https://example.com/scim/User", "https://[2001:db8::1]/schema"))
            assertEquals(uri, ScimSchema.withId(uri).name("Example").build().getId());
        for (String uri : List.of("User", "//example.com/a", "http://[broken]/schema", "urn:example:bad%zz", "urn:example:a b"))
            assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId(uri));
        assertThrows(NullPointerException.class, () -> ScimSchema.withId(null));
        assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId("urn:" + "x".repeat(2045)));
        assertDoesNotThrow(() -> ScimSchema.withId("urn:" + "x".repeat(2044)).name("Name").build());
    }

    @Test void definitionDefaultsAndNullResetsAreComplete() {
        ScimAttributeDefinition value = ScimAttributeDefinition.withName("custom")
                .type(ScimAttributeType.BOOLEAN).type(null).description("Description").description(null)
                .multiValued(true).multiValued(null).required(true).required(null).caseExact(true).caseExact(null)
                .mutability(ScimMutability.IMMUTABLE).mutability(null).returned(ScimReturned.REQUEST).returned(null)
                .uniqueness(ScimUniqueness.SERVER).uniqueness(null).canonicalValues(Set.of("suggested")).canonicalValues(null)
                .referenceTypes(Set.of("User")).referenceTypes(null).subAttributes(List.of(ScimAttributeDefinition.withName("child").build()))
                .subAttributes(null).build();
        assertEquals(ScimAttributeType.STRING, value.getType());
        assertFalse(value.isMultiValued()); assertFalse(value.isRequired()); assertFalse(value.isCaseExact());
        assertEquals(ScimMutability.READ_WRITE, value.getMutability()); assertEquals(ScimReturned.DEFAULT, value.getReturned());
        assertEquals(ScimUniqueness.NONE, value.getUniqueness()); assertTrue(value.getDescription().isEmpty());
        assertTrue(value.getCanonicalValues().isEmpty()); assertTrue(value.getReferenceTypes().isEmpty());
        assertTrue(value.getSubAttributes().isEmpty());
    }

    @Test void incompatibleFacetsAndNestedApplicationDefinitionsReject() {
        ScimAttributeDefinition child = ScimAttributeDefinition.withName("value").build();
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").subAttributes(List.of(child)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").referenceTypes(Set.of("User")).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").type(ScimAttributeType.BOOLEAN).caseExact(true).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").type(ScimAttributeType.COMPLEX).uniqueness(ScimUniqueness.SERVER).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").mutability(ScimMutability.WRITE_ONLY).build());
        assertDoesNotThrow(() -> ScimAttributeDefinition.withName("x").mutability(ScimMutability.WRITE_ONLY).returned(ScimReturned.NEVER).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").type(ScimAttributeType.BOOLEAN).canonicalValues(Set.of("true")).build());
        ScimAttributeDefinition nested = ScimAttributeDefinition.withName("outer").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(ScimAttributeDefinition.withName("inner").type(ScimAttributeType.COMPLEX).subAttributes(List.of(child)).build())).build();
        assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId("urn:example:custom").name("Custom").attributes(List.of(nested)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Discovery").endpoint("/Discovery").schema(ScimSchema.schemaInstance()).build());
        assertThrows(IllegalArgumentException.class, () -> ScimSchemaExtension.fromSchema(ScimSchema.schemaInstance(), false));
    }

    @Test void namesDuplicatesAndCommonOverridesRejectWithoutDiagnosticEcho() {
        for (String name : List.of("", "1first", "a.b", "urn:a:b", "a b", "ünicode", "a".repeat(129)))
            assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName(name));
        for (String common : List.of("ID", "externalId", "META", "schemas", "$ref", "$REF"))
            assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId("urn:example:custom").name("Custom")
                    .attributes(List.of(ScimAttributeDefinition.withName(common).build())).build());
        ScimAttributeDefinition first = ScimAttributeDefinition.withName("name").build();
        ScimAttributeDefinition duplicate = ScimAttributeDefinition.withName("NAME").build();
        assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId("urn:example:custom").name("Custom").attributes(List.of(first, duplicate)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("x").type(ScimAttributeType.COMPLEX).subAttributes(List.of(first, duplicate)).build());
        assertDoesNotThrow(() -> ScimAttributeDefinition.withName("x").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(ScimAttributeDefinition.withName("$ref").type(ScimAttributeType.REFERENCE).build())).build());
        assertThrows(IllegalStateException.class, () -> ScimSchema.withId("urn:example:custom").name("Name").name(null).build());
    }

    @Test void collectionSnapshotsReplaceRatherThanAppendAndAreImmutable() {
        Set<@NonNull String> strings = new LinkedHashSet<>(List.of("one"));
        ScimAttributeDefinition.Builder attrBuilder = ScimAttributeDefinition.withName("x").canonicalValues(strings);
        strings.add("two");
        ScimAttributeDefinition first = attrBuilder.build();
        assertEquals(Set.of("one"), first.getCanonicalValues());
        assertThrows(UnsupportedOperationException.class, () -> first.getCanonicalValues().add("three"));
        assertEquals(Set.of("replacement"), attrBuilder.canonicalValues(Set.of("replacement")).build().getCanonicalValues());
        List<@NonNull ScimAttributeDefinition> values = new ArrayList<>(List.of(first));
        ScimSchema.Builder schemaBuilder = ScimSchema.withId("urn:example:custom").name("Custom").attributes(values);
        values.clear();
        ScimSchema schema = schemaBuilder.build();
        assertEquals(1, schema.getAttributes().size());
        assertThrows(UnsupportedOperationException.class, () -> schema.getAttributes().clear());
        assertTrue(schemaBuilder.attributes(null).build().getAttributes().isEmpty());
        List<@NonNull ScimSchemaExtension> extensions = new ArrayList<>(List.of(ScimSchemaExtension.fromSchema(schema, false)));
        ScimResourceType.Builder typeBuilder = ScimResourceType.withName("Type").schema(ScimSchema.userInstance()).endpoint("/Types").schemaExtensions(extensions);
        extensions.clear();
        assertEquals(1, typeBuilder.build().getSchemaExtensions().size());
        assertTrue(typeBuilder.schemaExtensions(null).build().getSchemaExtensions().isEmpty());
    }

    @Test void staticBoundsApplyBeforeCopiesIncludingAggregateDefinitions() {
        ScimAttributeDefinition attr = ScimAttributeDefinition.withName("a").build();
        assertThrows(IllegalArgumentException.class, () -> ScimSchema.withId("urn:example:custom").name("Custom")
                .attributes(java.util.Collections.nCopies(1025, attr)));
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type")
                .schemaExtensions(java.util.Collections.nCopies(17, ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false))));
        List<@NonNull ScimAttributeDefinition> attrs = new ArrayList<>();
        for (int index = 0; index < 1024; index++) attrs.add(ScimAttributeDefinition.withName("a" + index).build());
        ScimSchema schema = ScimSchema.withId("urn:example:custom").name("Custom").attributes(attrs).build();
        assertEquals(1024, schema.getAttributes().size());
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type").endpoint("/Types").schema(schema).build());
        assertDoesNotThrow(() -> ScimAttributeDefinition.withName("a".repeat(128)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("a".repeat(129)));
        assertDoesNotThrow(() -> ScimAttributeDefinition.withName("a").description("x".repeat(1024)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("a").description("x".repeat(1025)));
    }

    @Test void endpointPathsRejectAuthorityQueryFragmentsAndTraversal() {
        for (String endpoint : List.of("https://foreign.example/Users", "//foreign.example/Users", "Users", "/", "/Users/",
                "/Users?query=x", "/Users#fragment", "/Users/../Admins", "/Users/./Admins", "/Users/%2e%2E/Admins",
                "/Users//Admins", "/Users/%2fAdmins", "/Users/%5cAdmins", "/Users\\Admins", "/Users/%zz", "/Users/with space"))
            assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("User").endpoint(endpoint));
        assertEquals("/v2/Users", ScimResourceType.withName("Type").endpoint("/v2/Users").schema(ScimSchema.userInstance()).build().getEndpoint());
        assertThrows(IllegalStateException.class, () -> ScimResourceType.withName("Type").endpoint("/Types").endpoint(null).schema(ScimSchema.userInstance()).build());
        assertThrows(IllegalStateException.class, () -> ScimResourceType.withName("Type").endpoint("/Types").schema(ScimSchema.userInstance()).schema(null).build());
    }

    @Test void semanticEqualityRetainsFacetsAndTrustedAssociations() {
        ScimAttributeDefinition first = ScimAttributeDefinition.withName("Name").build();
        assertEquals(first, ScimAttributeDefinition.withName("NAME").build());
        assertEquals(first.hashCode(), ScimAttributeDefinition.withName("NAME").build().hashCode());
        assertNotEquals(first, ScimAttributeDefinition.withName("name").required(true).build());
        ScimSchema firstSchema = ScimSchema.withId("urn:example:custom").name("Custom").attributes(List.of(first)).build();
        ScimSchema equalSchema = ScimSchema.withId("URN:EXAMPLE:CUSTOM").name("Custom").attributes(List.of(first)).build();
        assertEquals(firstSchema, equalSchema); assertEquals(firstSchema.hashCode(), equalSchema.hashCode());
        ScimResourceType firstType = ScimResourceType.withName("Type").endpoint("/Types").schema(firstSchema).build();
        assertEquals(firstType, ScimResourceType.withName("Type").endpoint("/Types").schema(equalSchema).build());
        assertNotEquals(firstType, ScimResourceType.withName("type").endpoint("/Types").schema(equalSchema).build());
        assertNotEquals(firstType, ScimResourceType.withName("Type").endpoint("/Types").schema(equalSchema).patchResponseNoContent(true).build());
        assertFalse(ScimResourceType.userInstance().isPatchResponseNoContent()); assertTrue(ScimResourceType.groupInstance().isPatchResponseNoContent());
        assertEquals("User", ScimResourceType.userInstance().getId().orElseThrow());
        assertEquals("Group", ScimResourceType.groupInstance().getId().orElseThrow());
    }

    @Test void localeAndDiagnosticsDoNotChangeStructuralComparisonOrExposeNames() {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertEquals("id", ScimSchemas.canonicalPath(ScimResourceType.userInstance(), path("ID")).orElseThrow().toScimString());
            assertTrue(ScimSchemas.find(ScimResourceType.userInstance(), path("urn:foreign:I:id")).isEmpty());
        } finally { Locale.setDefault(previous); }
        for (Object value : List.of(ScimAttributeDefinition.withName("PRIVATE_FIELD").build(),
                ScimSchema.withId("urn:private:SCHEMA").name("PRIVATE_SCHEMA").build(),
                ScimResourceType.withName("PRIVATE_TYPE").endpoint("/PRIVATE_ENDPOINT").schema(ScimSchema.userInstance()).build(),
                ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false)))
            assertFalse(value.toString().contains("PRIVATE"));
    }

    @Test void everySemanticFacetDistinguishesRegistrationTrust() {
        ScimAttributeDefinition base = ScimAttributeDefinition.withName("x").build();
        for (ScimAttributeDefinition other : List.of(
                ScimAttributeDefinition.withName("x").type(ScimAttributeType.BOOLEAN).build(),
                ScimAttributeDefinition.withName("x").description("Changed").build(),
                ScimAttributeDefinition.withName("x").multiValued(true).build(),
                ScimAttributeDefinition.withName("x").required(true).build(),
                ScimAttributeDefinition.withName("x").caseExact(true).build(),
                ScimAttributeDefinition.withName("x").mutability(ScimMutability.IMMUTABLE).build(),
                ScimAttributeDefinition.withName("x").returned(ScimReturned.REQUEST).build(),
                ScimAttributeDefinition.withName("x").uniqueness(ScimUniqueness.SERVER).build(),
                ScimAttributeDefinition.withName("x").canonicalValues(Set.of("one")).build())) assertNotEquals(base, other);
        assertNotEquals(base, null); assertNotEquals(base, "x");
        ScimAttributeDefinition reference = ScimAttributeDefinition.withName("x").type(ScimAttributeType.REFERENCE).build();
        assertNotEquals(reference, ScimAttributeDefinition.withName("x").type(ScimAttributeType.REFERENCE).referenceTypes(Set.of("User")).build());
        ScimSchema schema = ScimSchema.withId("urn:example:one").name("Name").build();
        for (ScimSchema other : List.of(ScimSchema.withId("urn:example:two").name("Name").build(),
                ScimSchema.withId("urn:example:one").name("Other").build(),
                ScimSchema.withId("urn:example:one").name("Name").description("Changed").build(),
                ScimSchema.withId("urn:example:one").name("Name").attributes(List.of(base)).build())) assertNotEquals(schema, other);
        assertNotEquals(schema, null); assertNotEquals(schema, "Name");
        ScimSchemaExtension extension = ScimSchemaExtension.fromSchema(schema, false);
        assertEquals(extension, ScimSchemaExtension.fromSchema(schema, false));
        assertEquals(extension.hashCode(), ScimSchemaExtension.fromSchema(schema, false).hashCode());
        assertNotEquals(extension, ScimSchemaExtension.fromSchema(schema, true));
        assertNotEquals(extension, ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false));
        assertNotEquals(extension, null); assertNotEquals(extension, schema);
        ScimResourceType type = ScimResourceType.withName("Type").endpoint("/Types").schema(schema).build();
        for (ScimResourceType other : List.of(ScimResourceType.withName("Type").id("id").endpoint("/Types").schema(schema).build(),
                ScimResourceType.withName("Type").description("Changed").endpoint("/Types").schema(schema).build(),
                ScimResourceType.withName("Type").endpoint("/Other").schema(schema).build(),
                ScimResourceType.withName("Type").endpoint("/Types").schema(ScimSchema.userInstance()).build(),
                ScimResourceType.withName("Type").endpoint("/Types").schema(schema)
                        .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false))).build())) assertNotEquals(type, other);
        assertEquals(type.hashCode(), ScimResourceType.withName("Type").endpoint("/Types").schema(schema).build().hashCode());
        assertEquals("Type", type.getName()); assertTrue(type.getDescription().isEmpty());
        assertNotEquals(type, null); assertNotEquals(type, "Type");
        assertTrue(ScimResourceType.withName("Type").id("id").id(null).description("Changed").description(null)
                .endpoint("/Types").schema(schema).build().getId().isEmpty());
        assertEquals("Changed", ScimResourceType.withName("Type").description("Changed").endpoint("/Types").schema(schema).build().getDescription().orElseThrow());
    }

    @Test void discoveryRegistrationUsesItsOwnGrammarAndAlwaysRetainsIdentifier() {
        ScimResourceType schema = ScimResourceType.discovery(ScimSchema.schemaInstance(), "Schema", "/Schemas");
        assertEquals(ScimReturned.ALWAYS, ScimSchemas.find(schema, path("id")).orElseThrow().getReturned());
        assertTrue(ScimSchemas.find(schema, path("externalId")).isEmpty());
        assertTrue(ScimSchemas.find(schema, path("meta")).isEmpty());
        assertTrue(ScimSchemas.find(schema, path("schemas")).isPresent());
        ScimResourceType config = ScimResourceType.discovery(ScimSchema.serviceProviderConfigInstance(), "Config", "/ServiceProviderConfig");
        assertTrue(ScimSchemas.find(config, path("meta.created")).isPresent());
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.discovery(ScimSchema.userInstance(), "User", "/Users"));
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("User").endpoint("/Users")
                .schema(ScimSchema.userInstance()).schemaExtensions(List.of(
                        ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false),
                        ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), true))).build());
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("User").endpoint("/Users")
                .schema(ScimSchema.userInstance()).schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.userInstance(), false))).build());
    }

    @Test void configuredIdentifiersAndTextRejectReservedAndMalformedCharacters() {
        for (String value : List.of("bulkId:one", "prefix-BULKID-suffix", "embedded whitespace", "private\u007fidentifier"))
            assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type").id(value));
        for (String value : List.of("name\nnewline", "name\tTab", "name\rCR", "\ud800x"))
            assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName(value));
        assertDoesNotThrow(() -> ScimAttributeDefinition.withName("x").description("line\tpart\r\ncontinued").build());
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type").endpoint("/" + "x".repeat(2048)));
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type").endpoint("/Users%"));
        assertThrows(IllegalArgumentException.class, () -> ScimResourceType.withName("Type").endpoint("/Users%0"));
        assertDoesNotThrow(() -> ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Description")
                .specUri(java.net.URI.create("http://example.com/docs")).build());
        ScimAttributeDefinition deep = ScimAttributeDefinition.withName("leaf").build();
        for (int depth = 1; depth < 64; depth++) deep = ScimAttributeDefinition.withName("n" + depth)
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(deep)).build();
        ScimAttributeDefinition maximum = deep;
        assertThrows(IllegalArgumentException.class, () -> ScimAttributeDefinition.withName("tooDeep")
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(maximum)).build());
    }

    private static void assertNames(@NonNull ScimSchema schema, @NonNull List<@NonNull String> expected) {
        assertEquals(expected, schema.getAttributes().stream().map(ScimAttributeDefinition::getName).toList());
    }
    private static @NonNull ScimAttributeDefinition definition(@NonNull ScimSchema schema, @NonNull String name) {
        return schema.getAttributes().stream().filter(d -> d.getName().equals(name)).findFirst().orElseThrow();
    }
    private static @NonNull ScimAttributeDefinition sub(@NonNull ScimSchema schema, @NonNull String parent, @NonNull String name) {
        return definition(schema, parent).getSubAttributes().stream().filter(d -> d.getName().equals(name)).findFirst().orElseThrow();
    }
    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return ((ScimAttributePathParseResult.Succeeded) ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
}
