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
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/** Independent facade registration, reserved namespace and private provenance review regressions. */
class ScimM10RegistrationReviewTests {
    @Test void effectiveTypeBoundDoesNotBecomeAnUnapprovedWholeProviderBound() {
        ScimSchema first = custom("urn:review:one", 600);
        ScimSchema second = custom("urn:review:two", 600);
        ScimResourceType one = type("One", "/Ones", first);
        ScimResourceType two = type("Two", "/Twos", second);
        assertTrue(one.definitionCount() <= 1024); assertTrue(two.definitionCount() <= 1024);
        assertTrue(one.definitionCount() + two.definitionCount() > 1024);
        ScimServiceProvider provider = provider(List.of(one, two));
        assertEquals(List.of(one, two), provider.getResourceTypes());
    }

    @Test void identicalSchemaUrisCannotCarryConflictingSecurityCharacteristics() {
        ScimSchema first = ScimSchema.withId("urn:review:shared").name("Shared")
                .attributes(List.of(ScimAttributeDefinition.withName("role").build())).build();
        ScimSchema changed = ScimSchema.withId("URN:REVIEW:SHARED").name("Shared")
                .attributes(List.of(ScimAttributeDefinition.withName("role").returned(ScimReturned.NEVER).build())).build();
        assertThrows(IllegalArgumentException.class, () -> provider(List.of(type("One", "/Ones", first), type("Two", "/Twos", changed))));
        ScimSchema equal = ScimSchema.withId("URN:REVIEW:SHARED").name("Shared").attributes(first.getAttributes()).build();
        assertDoesNotThrow(() -> provider(List.of(type("One", "/Ones", first), type("Two", "/Twos", equal))));
    }

    @Test void builtInSchemaIdsCannotLaunderCustomPermissionFacets() {
        ScimSchema changed = ScimSchema.withId(ScimSchema.userInstance().getId()).name("User")
                .attributes(List.of(ScimAttributeDefinition.withName("userName").required(false).build())).build();
        assertThrows(IllegalArgumentException.class, () -> provider(List.of(type("User", "/Users", changed))));
        ScimSchema original = ScimSchema.userInstance();
        ScimSchema copied = ScimSchema.withId(original.getId()).name(original.getName())
                .description(original.getDescription().orElse(null)).attributes(original.getAttributes()).build();
        assertDoesNotThrow(() -> provider(List.of(type("User", "/Users", copied))));
    }

    @Test void mandatoryDiscoveryNamespacesCannotBeReplacedByApplicationTypes() {
        ScimSchema schema = custom("urn:review:custom", 1);
        for (String name : List.of("Schema", "ResourceType", "ServiceProviderConfig"))
            assertThrows(IllegalArgumentException.class, () -> provider(List.of(type(name, "/Applications", schema))));
        for (String endpoint : List.of("/Schemas", "/ResourceTypes", "/ServiceProviderConfig", "/Schemas/child",
                "/ResourceTypes/child", "/ServiceProviderConfig/child"))
            assertThrows(IllegalArgumentException.class, () -> provider(List.of(type("Custom", endpoint, schema))));
        assertDoesNotThrow(() -> provider(List.of(type("schema", "/schemas", schema))));
    }

    @Test void typeAndPolicyAssociationUsesIdentityRatherThanEqualDefinitions() {
        ScimResourceType first = type("Custom", "/Customs", custom("urn:review:custom", 1));
        ScimResourceType equal = type("Custom", "/Customs", custom("urn:review:custom", 1));
        assertEquals(first, equal);
        ScimServiceProvider provider = provider(List.of(first));
        assertThrows(IllegalArgumentException.class, () -> provider.parseQueryResult(equal, ""));
        assertThrows(IllegalArgumentException.class, () -> ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim"))
                .resourceTypes(List.of(first)).filterPolicies(Map.of(equal, ScimFilterPolicy.rejectAllInstance())).build());
    }

    @Test void changedCompatibilityRejectsOldCarrierWhileTrustedBaseCopiesRetainProof() {
        ScimResourceType user = ScimResourceType.userInstance();
        ScimServiceProvider strict = provider(List.of(user));
        ScimQuery query = ((ScimQueryParseResult.Succeeded) strict.parseQueryResult(user, "count=0")).getQuery();
        ScimListPage page = ScimListPage.withQuery(query).totalResults(0L).build();
        ScimServiceProvider copied = strict.copy().baseUri(URI.create("https://copy.example.test/scim")).finish();
        assertInstanceOf(ScimResponseResult.Prepared.class, copied.listResponseResult(page));
        ScimServiceProvider changed = strict.copy().compatibility(ScimCompatibility.oktaInstance()).finish();
        assertInstanceOf(ScimResponseResult.Rejected.class, changed.listResponseResult(page));
        assertInstanceOf(ScimResponseResult.Prepared.class, strict.copy().compatibility(ScimCompatibility.builder().build()).finish().listResponseResult(page));
    }

    private static @NonNull ScimSchema custom(@NonNull String id, int definitions) {
        List<@NonNull ScimAttributeDefinition> attrs = new ArrayList<>();
        for (int index = 0; index < definitions; index++) attrs.add(ScimAttributeDefinition.withName("a" + index).build());
        return ScimSchema.withId(id).name("Custom").attributes(attrs).build();
    }
    private static @NonNull ScimResourceType type(@NonNull String name, @NonNull String endpoint, @NonNull ScimSchema schema) {
        return ScimResourceType.withName(name).endpoint(endpoint).schema(schema).build();
    }
    private static @NonNull ScimServiceProvider provider(@NonNull List<@NonNull ScimResourceType> types) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim")).resourceTypes(types).build();
    }
}
