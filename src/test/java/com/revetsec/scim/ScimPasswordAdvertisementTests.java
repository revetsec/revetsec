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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Conformance of existing password behavior; no runtime failing-before claim. */
final class ScimPasswordAdvertisementTests {
    private static final ScimResourceType USER = ScimResourceType.userInstance();
    private static final String SECRET = "fixture-private-password-739";
    private static final String OLD = "fixture-old-password-551";

    @Test void passwordAdvertisementDefaultsFalseAndNullRestoresIt() {
        var defaults = ScimServiceProviderConfig.builder().build();
        assertFalse(defaults.isChangePasswordSupported()); assertFalse(defaults.isPatchSupported()); assertTrue(defaults.isEtagSupported());
        assertTrue(ScimServiceProviderConfig.builder().changePasswordSupported(true).build().isChangePasswordSupported());
        assertEquals(defaults, ScimServiceProviderConfig.builder().changePasswordSupported(true).changePasswordSupported(null).build());
        assertFalse(ScimServiceProviderConfig.builder().changePasswordSupported(false).build().isChangePasswordSupported());
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> discoveryTruthfullyReportsIndependentPasswordAndPatchFlags() {
        return Stream.of("default", "false", "true").flatMap(state -> Stream.of(false, true).map(patch -> DynamicTest.dynamicTest(state + " patch=" + patch, () -> {
            var provider = provider(state, patch); var json = decoded(prepared(provider.serviceProviderConfigResponseResult("")));
            assertEquals(state.equals("true"), supported(json, "changePassword")); assertEquals(patch, supported(json, "patch"));
            assertFalse(supported(json, "filter")); assertFalse(supported(json, "sort")); assertFalse(supported(json, "bulk")); assertTrue(supported(json, "etag"));
            var result = provider.parsePatchRequestResult(USER, bytes(patchBody()));
            if (patch) assertInstanceOf(ScimPatchParseResult.Succeeded.class, result);
            else assertEquals(403, assertInstanceOf(ScimPatchParseResult.Rejected.class, result).getError().getStatusCode());
        })));
    }

    @Test void standardPasswordSchemaRemainsWriteOnlyNeverReturnedAndOptional() {
        var definition = USER.getSchema().getAttributes().stream().filter(value -> value.getName().equals("password")).findFirst().orElseThrow();
        assertEquals(ScimAttributeType.STRING, definition.getType()); assertEquals(ScimMutability.WRITE_ONLY, definition.getMutability());
        assertEquals(ScimReturned.NEVER, definition.getReturned()); assertFalse(definition.isRequired());
        for (String state : List.of("default", "false", "true")) {
            var provider = provider(state, false);
            var attrs = (JsonArray) decoded(prepared(provider.schemaResponseResult(USER.getSchema().getId(), ""))).find("attributes").orElseThrow();
            var password = attrs.getElements().stream().map(JsonObject.class::cast).filter(value -> value.find("name").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow().equals("password")).findFirst().orElseThrow();
            assertEquals(JsonString.fromValue("writeOnly"), password.find("mutability").orElseThrow());
            assertEquals(JsonString.fromValue("never"), password.find("returned").orElseThrow());
        }
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> passwordWritesProduceExplicitTransientCandidatesRegardlessOfAdvertisement() {
        return Stream.of("default", "false", "true").flatMap(state -> Stream.of("create", "put", "patch").map(operation -> DynamicTest.dynamicTest(state + " " + operation, () -> {
            var provider = provider(state, true); var current = current(OLD); var before = current.getDocument();
            ScimResource candidate; Set<ScimAttributePath> supplied;
            if (operation.equals("patch")) {
                var request = assertInstanceOf(ScimPatchParseResult.Succeeded.class, provider.parsePatchRequestResult(USER, bytes(patchBody()))).getPatchRequest();
                var result = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current, request)).getPatchResult();
                candidate = result.getResource(); supplied = result.getSuppliedAttributePaths();
                assertFalse(request.toString().contains(SECRET)); assertFalse(result.toString().contains(SECRET));
            } else {
                var result = assertInstanceOf(ScimResourceParseResult.Succeeded.class, operation.equals("create") ? provider.parseResourceResult(USER, bytes(body())) : provider.parseReplacementResult(USER, current, bytes(body())));
                candidate = result.getResource(); supplied = result.getSuppliedAttributePaths(); assertFalse(result.toString().contains(SECRET));
            }
            assertEquals(JsonString.fromValue(SECRET), candidate.getDocument().find("password").orElseThrow());
            assertTrue(supplied.stream().anyMatch(value -> value.toScimString().equals("password")));
            assertFalse(candidate.toString().contains(SECRET)); assertEquals(before, current.getDocument());
            assertEquals(JsonString.fromValue(OLD), current.getDocument().find("password").orElseThrow());
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> everyRenderingPathOmitsPasswordEvenWhenRequestedAndSupplied() {
        return Stream.of("default", "false", "true").flatMap(state -> Stream.of("get", "create", "put", "patch", "list").flatMap(operation ->
                Stream.of("", "attributes=password", "attributes=userName,password", "excludedAttributes=userName").map(query -> DynamicTest.dynamicTest(state + " " + operation + " " + query, () -> {
            var provider = provider(state, true); var current = current(SECRET); var before = current.getDocument();
            var selection = assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, provider.parseAttributeSelectionResult(USER, query)).getAttributeSelection();
            Set<ScimAttributePath> supplied = Set.of(path("password"), path("userName")); ScimResponseResult result;
            switch (operation) {
                case "get" -> result = provider.resourceResponseResult(current, selection);
                case "create" -> result = provider.createdResponseResult(current, supplied, selection);
                case "put" -> result = provider.replacementResponseResult(current, supplied, selection);
                case "patch" -> result = provider.patchResponseResult(current, supplied, selection);
                default -> {
                    var parsed = assertInstanceOf(ScimQueryParseResult.Succeeded.class, provider.parseQueryResult(USER, query)).getQuery();
                    result = provider.listResponseResult(ScimListPage.withQuery(parsed).resources(List.of(current)).totalResults(1L).build());
                }
            }
            var response = prepared(result); String wire = new String(response.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8);
            assertFalse(wire.contains("\"password\"")); assertFalse(wire.contains(SECRET));
            assertFalse(response.getHeaders().toString().contains(SECRET)); assertFalse(response.toString().contains(SECRET));
            assertEquals(before, current.getDocument()); assertEquals(JsonString.fromValue(SECRET), current.getDocument().find("password").orElseThrow(), "rendering does not erase the application's transient candidate");
        }))));
    }

    private static @NonNull ScimServiceProvider provider(@NonNull String state, boolean patch) {
        var config = ScimServiceProviderConfig.builder().patchSupported(patch);
        if (!state.equals("default")) config = config.changePasswordSupported(state.equals("true"));
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).serviceProviderConfig(config.build()).stringMatching((path, definition, operator, left, right) -> ScimStringMatchResult.fromMatched(left.equals(right))).build();
    }
    private static @NonNull JsonObject body() { return JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId())))).put("userName", "subject").put("password", SECRET).build(); }
    private static @NonNull JsonObject patchBody() { return JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue("urn:ietf:params:scim:api:messages:2.0:PatchOp"))))
            .put("Operations", JsonArray.fromElements(List.of(JsonObject.builder().put("op", "replace").put("path", "password").put("value", SECRET).build()))).build(); }
    private static @NonNull ScimResource current(@NonNull String secret) { return ScimResource.withResourceType(USER).document(JsonObject.builder()
            .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId())))).put("id", "user.1").put("userName", "subject").put("password", secret)
            .put("meta", JsonObject.builder().put("version", "W/\"one\"").build()).build()).build(); }
    private static @NonNull ScimAttributePath path(@NonNull String value) { return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class, ScimAttributePath.fromExpressionResult(value)).getAttributePath(); }
    private static @NonNull ScimResponse prepared(@NonNull ScimResponseResult result) { return assertInstanceOf(ScimResponseResult.Prepared.class, result).getResponse(); }
    private static @NonNull JsonObject decoded(@NonNull ScimResponse response) { return (JsonObject) assertInstanceOf(JsonParseResult.Succeeded.class, JsonCodec.parseResult(response.toHttpBodyWithPersonalData(), JsonLimits.scim(1_000_000, 100_000))).getDocument().getValue(); }
    private static boolean supported(@NonNull JsonObject value, @NonNull String name) { return ((JsonBoolean) ((JsonObject) value.find(name).orElseThrow()).find("supported").orElseThrow()).getValue(); }
    private static byte @NonNull [] bytes(@NonNull JsonObject value) { return value.toJson().getBytes(StandardCharsets.UTF_8); }
}
