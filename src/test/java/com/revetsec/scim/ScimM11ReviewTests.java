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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Public-edge regressions for PATCH request parsing and application. */
class ScimM11ReviewTests {
    @Test void reconstructedGroupSchemaCannotConvertASelectedVendorRemovalIntoRemoveAll() {
        ScimSchema standard = ScimSchema.groupInstance();
        ScimSchema reconstructed = ScimSchema.withId(standard.getId()).name(standard.getName())
                .description(standard.getDescription().orElseThrow()).attributes(standard.getAttributes()).build();
        assertEquals(standard, reconstructed);
        ScimResourceType type = ScimResourceType.withName("Group").endpoint("/Groups").schema(reconstructed).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.microsoftEntraIdInstance(), ScimLimits.fromDefaults());
        assertInstanceOf(ScimPatchParseResult.Rejected.class, provider.parsePatchRequestResult(type,
                body("{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"B\"}]}")));
    }

    @Test void alternateRegistrationUsingTheStandardGroupSchemaHasExactFullAndReducedMembershipSemantics() {
        ScimResourceType type = ScimResourceType.withName("DirectoryGroup").endpoint("/DirectoryGroups")
                .schema(ScimSchema.groupInstance()).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.microsoftEntraIdInstance(), ScimLimits.fromDefaults());
        JsonObject a = JsonObject.builder().put("value", "A").put("display", "Private Name").build();
        JsonObject b = JsonObject.builder().put("value", "B").build();
        ScimResource current = resource(type, JsonObject.builder().put("id", "Group-1").put("displayName", "Private Group")
                .put("members", JsonArray.fromElements(List.of(a, b))).build());
        ScimPatchRequest request = parse(provider, type,
                "{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"B\"}]}" + ","
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"a\"},{\"value\":\"A\"}]}");
        ScimMembershipPatch reduced = assertInstanceOf(ScimMembershipPatchResult.Reduced.class,
                provider.reduceMembershipPatchResult(request)).getMembershipPatch();
        assertEquals(ScimMembershipPatch.Kind.REMOVE_IDS, reduced.getSteps().get(0).getKind());
        assertEquals(List.of("B"), reduced.getSteps().get(0).getValues());
        ScimPatchResult applied = applied(provider, current, request);
        assertEquals(JsonArray.fromElements(List.of(a, JsonObject.builder().put("value", "a").build())),
                applied.getResource().getDocument().find("members").orElseThrow());
    }

    @Test void ipv6SchemaUriAndQuotedBracketSelectorBindTheActualSuffix() {
        String schemaId = "https://[2001:db8::1]/schemas/profile?revision=2";
        ScimAttributeDefinition entries = ScimAttributeDefinition.withName("entries").type(ScimAttributeType.COMPLEX)
                .multiValued(true).subAttributes(List.of(
                        ScimAttributeDefinition.withName("key").mutability(ScimMutability.IMMUTABLE).build(),
                        ScimAttributeDefinition.withName("note").build(),
                        ScimAttributeDefinition.withName("secret").mutability(ScimMutability.WRITE_ONLY)
                                .returned(ScimReturned.NEVER).build())).build();
        ScimSchema extension = ScimSchema.withId(schemaId).name("Profile").attributes(List.of(entries)).build();
        ScimResourceType type = ScimResourceType.withName("Custom").endpoint("/Customs")
                .schema(ScimSchema.withId("urn:example:custom").name("Custom").build())
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(extension, false))).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.strictInstance(), ScimLimits.fromDefaults());
        JsonObject originalEntry = JsonObject.builder().put("key", "Private]Key").put("note", "Old")
                .put("secret", "Private Secret").build();
        ScimResource current = resource(type, JsonObject.builder().put("id", "1")
                .put(schemaId, JsonObject.builder().put("entries", JsonArray.fromElements(List.of(originalEntry))).build()).build());
        String path = schemaId + ":entries[key eq \"Private]Key\"].note";
        ScimPatchRequest request = parse(provider, type, JsonObject.builder().put("op", "replace").put("path", path)
                .put("value", "New").build().toJson());
        assertEquals("note", request.getOperations().get(0).getSubAttributeName().orElseThrow());
        ScimPatchResult result = applied(provider, current, request);
        JsonObject changed = assertInstanceOf(JsonObject.class, assertInstanceOf(JsonArray.class,
                result.getResource().getExtension(schemaId).orElseThrow().find("entries").orElseThrow()).getElements().get(0));
        assertEquals("Private]Key", changed.findString("key").orElseThrow());
        assertEquals("New", changed.findString("note").orElseThrow());
        assertEquals("Private Secret", changed.findString("secret").orElseThrow());

        String hidden = schemaId + ":entries[key eq \"Private]Key\" or secret pr].note";
        ScimPatchParseResult.Rejected rejected = assertInstanceOf(ScimPatchParseResult.Rejected.class,
                provider.parsePatchRequestResult(type, body(JsonObject.builder().put("op", "replace")
                        .put("path", hidden).put("value", "Leaked").build().toJson())));
        assertEquals(ScimErrorType.INVALID_PATH, rejected.getError().getErrorType().orElseThrow());
        assertEquals("Old", originalEntry.findString("note").orElseThrow());
        assertFalse(rejected.toString().contains("Private"));
    }

    @Test void timezoneNormalizationCrossesTheNoYearZeroBoundaryAndRetainsFractionPrecision() {
        ScimAttributeDefinition events = ScimAttributeDefinition.withName("events").type(ScimAttributeType.COMPLEX)
                .multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("when")
                        .type(ScimAttributeType.DATE_TIME).build())).build();
        ScimResourceType type = ScimResourceType.withName("Events").endpoint("/Events")
                .schema(ScimSchema.withId("urn:example:events").name("Events").attributes(List.of(events)).build()).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.strictInstance(), ScimLimits.fromDefaults());
        JsonObject negative = JsonObject.builder().put("when", "-0001-12-31T23:00:00-01:00").build();
        JsonObject precise = JsonObject.builder().put("when", "0001-01-01T00:00:00.00000000001Z").build();
        ScimResource current = resource(type, JsonObject.builder().put("id", "1")
                .put("events", JsonArray.fromElements(List.of(negative, precise))).build());
        ScimPatchRequest request = parse(provider, type, JsonObject.builder().put("op", "remove")
                .put("path", "events[when eq \"0001-01-01T00:00:00Z\"]").build().toJson());
        assertEquals(JsonArray.fromElements(List.of(precise)),
                applied(provider, current, request).getResource().getDocument().find("events").orElseThrow());
    }

    @Test void exactReferenceSubstringMatchingChargesItsPotentialComparisonWorkBeforeExecution() {
        ScimAttributeDefinition refs = ScimAttributeDefinition.withName("refs").type(ScimAttributeType.COMPLEX)
                .multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("target")
                        .type(ScimAttributeType.REFERENCE).build())).build();
        ScimResourceType type = ScimResourceType.withName("References").endpoint("/References")
                .schema(ScimSchema.withId("urn:example:references").name("References").attributes(List.of(refs)).build()).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.strictInstance(),
                ScimLimits.builder().maximumWorkUnits(10_000).build());
        ScimResource current = resource(type, JsonObject.builder().put("id", "1")
                .put("refs", JsonArray.fromElements(List.of(JsonObject.builder().put("target", "a".repeat(4096) + "b").build()))).build());
        ScimPatchRequest request = parse(provider, type, JsonObject.builder().put("op", "remove")
                .put("path", "refs[target co \"" + "a".repeat(2047) + "b\"]").build().toJson());
        ScimPatchApplicationResult.Rejected rejected = assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                provider.applyPatchResult(current, request));
        assertSame(ScimError.requestTooLargeInstance(), rejected.getError());
        assertEquals(1, assertInstanceOf(JsonArray.class, current.getDocument().find("refs").orElseThrow()).getElements().size());
    }

    @Test void visiblePredicatesMayTargetWriteOnlySuffixesWhileHiddenPredicatesRemainForbidden() {
        ScimAttributeDefinition rows = ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX)
                .multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("type").build(),
                        ScimAttributeDefinition.withName("secret").mutability(ScimMutability.WRITE_ONLY)
                                .returned(ScimReturned.NEVER).build(), ScimAttributeDefinition.withName("note").build())).build();
        ScimResourceType type = ScimResourceType.withName("PrivateRows").endpoint("/PrivateRows")
                .schema(ScimSchema.withId("urn:example:private-rows").name("PrivateRows").attributes(List.of(rows)).build()).build();
        ScimServiceProvider provider = provider(type, ScimCompatibility.strictInstance(), ScimLimits.fromDefaults());
        ScimResource current = resource(type, JsonObject.builder().put("id", "1")
                .put("rows", JsonArray.fromElements(List.of(JsonObject.builder().put("type", "work")
                        .put("secret", "Stored Private Secret").put("note", "Visible").build()))).build());
        ScimAttributeSelection selection = assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                provider.parseAttributeSelectionResult(type, "")).getAttributeSelection();
        for (String operation : List.of("add", "replace", "remove")) {
            JsonObject.Builder input = JsonObject.builder().put("op", operation).put("path", "rows[type eq \"work\"].secret");
            if (!operation.equals("remove")) input.put("value", "Updated Private Secret");
            ScimPatchRequest request = parse(provider, type, input.build().toJson());
            ScimPatchResult result = applied(provider, current, request);
            JsonObject row = assertInstanceOf(JsonObject.class, assertInstanceOf(JsonArray.class,
                    result.getResource().getDocument().find("rows").orElseThrow()).getElements().get(0));
            assertEquals("Visible", row.findString("note").orElseThrow());
            if (operation.equals("remove")) assertTrue(row.find("secret").isEmpty());
            else assertEquals("Updated Private Secret", row.findString("secret").orElseThrow());
            ScimResponse response = assertInstanceOf(ScimResponseResult.Prepared.class, provider.patchResponseResult(
                    result.getResource(), result.getSuppliedAttributePaths(), selection)).getResponse();
            String output = new String(response.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8);
            assertTrue(output.contains("Visible"));
            assertFalse(output.contains("secret"));
            assertFalse(output.contains("Private Secret"));
        }
        for (String selector : List.of("secret eq \"Stored Private Secret\"", "type eq \"work\" or secret pr")) {
            ScimPatchParseResult.Rejected rejected = assertInstanceOf(ScimPatchParseResult.Rejected.class,
                    provider.parsePatchRequestResult(type, body(JsonObject.builder().put("op", "replace")
                            .put("path", "rows[" + selector + "].note").put("value", "Forbidden").build().toJson())));
            assertEquals(ScimErrorType.INVALID_PATH, rejected.getError().getErrorType().orElseThrow());
        }
    }

    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type,
            @NonNull ScimCompatibility compatibility, @NonNull ScimLimits limits) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
                .compatibility(compatibility).limits(limits)
                .stringMatching((path, definition, operator, value, literal) ->
                        ScimStringMatchResult.fromMatched(value.equalsIgnoreCase(literal))).build();
    }

    private static @NonNull ScimPatchRequest parse(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType type, @NonNull String operations) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,
                provider.parsePatchRequestResult(type, body(operations))).getPatchRequest();
    }

    private static byte @NonNull [] body(@NonNull String operations) {
        return ("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[" + operations + "]}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull ScimPatchResult applied(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource current, @NonNull ScimPatchRequest request) {
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,
                provider.applyPatchResult(current, request)).getPatchResult();
    }

    private static @NonNull ScimResource resource(@NonNull ScimResourceType type, @NonNull JsonObject data) {
        java.util.LinkedHashMap<String, com.revetsec.json.JsonValue> document = new java.util.LinkedHashMap<>(data.getMembers());
        List<com.revetsec.json.JsonValue> schemas = new java.util.ArrayList<>();
        schemas.add(JsonString.fromValue(type.getSchema().getId()));
        for (ScimSchemaExtension extension : type.getSchemaExtensions())
            if (document.containsKey(extension.getSchema().getId())) schemas.add(JsonString.fromValue(extension.getSchema().getId()));
        document.put("schemas", JsonArray.fromElements(schemas));
        return ScimResource.withResourceType(type).document(JsonObject.fromMembers(document)).build();
    }
}
