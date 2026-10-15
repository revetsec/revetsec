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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bounded M10 public-facade inputs and response-association/privacy properties. Authored wire seeds target query
 * decoding, SearchRequest/resource distinction, read-only input, integer wire syntax and atomic replacement. The
 * model target generates a transient synthetic password at runtime; no password is persisted in seed fixtures.
 */
@ThreadSafe
public final class ScimM10FuzzTests {
    private static final @NonNull String CORE = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String EXTENSION = "urn:example:scim:fuzz:counter";
    private static final @NonNull String PRIVATE_PREFIX = "m10-private-password-";
    private static final @NonNull ScimSchema COUNTERS = ScimSchema.withId(EXTENSION).name("Counters")
            .attributes(List.of(ScimAttributeDefinition.withName("counter").type(ScimAttributeType.INTEGER).build())).build();
    private static final @NonNull ScimResourceType USER = ScimResourceType.withName("User").id("User").endpoint("/Users")
            .schema(ScimSchema.userInstance()).schemaExtensions(List.of(ScimSchemaExtension.fromSchema(COUNTERS, false))).build();
    private static final @NonNull ScimLimits LIMITS = ScimLimits.builder().maximumBodyBytes(16_384).maximumJsonNodes(1_000)
            .maximumRawQueryBytes(4_096).maximumParameterCharacters(512).maximumQueryParameters(16).maximumPageSize(10)
            .maximumResponseBytes(2_048).maximumResponseHeaderBytes(512).maximumWorkUnits(10_000).build();
    private static final @NonNull ScimServiceProvider STRICT = provider(ScimCompatibility.strictInstance());
    private static final @NonNull ScimServiceProvider COMPATIBLE = provider(ScimCompatibility.microsoftEntraIdInstance());
    private static final @NonNull List<@NonNull ScimServiceProvider> PROVIDERS = List.of(STRICT, COMPATIBLE);
    private static final @NonNull ScimResource CURRENT = persisted("existing", "before", false, "");
    private static final @NonNull Set<@NonNull String> DETAILS = Set.of("Invalid filter expression.", "Too many matching resources.",
            "Invalid request syntax.", "Invalid attribute path.", "The operation has no target.", "Invalid attribute value.",
            "The operation violates attribute mutability.", "Invalid SCIM version.", "Invalid pagination cursor.", "The pagination cursor has expired.",
            "Invalid pagination count.", "The operation violates attribute uniqueness.", "The sensitive operation is forbidden.",
            "Authentication is required.", "The operation is forbidden.", "The resource was not found.", "The request precondition was not satisfied.",
            "The request exceeds the size limit.", "Unsupported media type.", "The request method is not allowed.", "The operation is not implemented.",
            "The request could not be processed.", "The response exceeds the size limit.", "The service is unavailable.");

    /** Arbitrary raw query text yields a bounded, normalized approved query or a fixed error. */
    @FuzzTest(maxDuration = "5m")
    public void rawQueriesStayBoundedAndApproved(byte @NonNull [] input) {
        String raw = new String(input, StandardCharsets.UTF_8);
        for (ScimServiceProvider provider : PROVIDERS) {
            ScimQueryParseResult parsed = provider.parseQueryResult(USER, raw);
            if (parsed instanceof ScimQueryParseResult.Rejected rejected) { fixed(rejected.getError()); continue; }
            ScimQuery query = ((ScimQueryParseResult.Succeeded) parsed).getQuery();
            Assertions.assertSame(USER, query.getResourceType());
            Assertions.assertTrue(query.getCount() >= 0 && query.getCount() <= 10);
            query.getStartIndex().ifPresent(index -> Assertions.assertTrue(index >= 1));
            query.getFilter().ifPresent(filter -> {
                allowedFilter(filter, false);
                Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class, provider.parseFilterResult(USER, filter.toScimString()));
            });
            ScimAttributeSelectionResult selection = provider.parseAttributeSelectionResult(USER, raw);
            Assertions.assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, selection);
        }
    }

    /** Raw Search/create/replacement inputs cannot mutate the authoritative current resource on any outcome. */
    @FuzzTest(maxDuration = "5m")
    public void rawBodiesStayBoundedAndAtomic(byte @NonNull [] input) throws JsonParseException {
        JsonObject before = CURRENT.getDocument();
        for (ScimServiceProvider provider : PROVIDERS) {
            ScimQueryParseResult search = provider.parseSearchRequestResult(USER, input);
            if (search instanceof ScimQueryParseResult.Rejected rejected) fixed(rejected.getError());
            else {
                ScimQuery query = ((ScimQueryParseResult.Succeeded) search).getQuery();
                Assertions.assertTrue(query.getCount() >= 0 && query.getCount() <= 10);
                query.getFilter().ifPresent(filter -> allowedFilter(filter, false));
            }
            ScimResourceParseResult create = provider.parseResourceResult(USER, input);
            resourceOutcome(provider, create);
            ScimResourceParseResult replacement = provider.parseReplacementResult(USER, CURRENT, input);
            resourceOutcome(provider, replacement);
            Assertions.assertSame(before, CURRENT.getDocument());
            Assertions.assertEquals("before", CURRENT.getDocument().find("userName").map(com.revetsec.json.JsonString.class::cast).map(com.revetsec.json.JsonString::getValue).orElseThrow());
            if (replacement instanceof ScimResourceParseResult.Succeeded succeeded)
                Assertions.assertEquals("existing", succeeded.getResource().getId().orElseThrow());
        }
    }

    /** Approved response selections stay associated, and transient write-only data is stripped from every output. */
    @FuzzTest(maxDuration = "5m")
    public void resourcesRenderWithoutNeverAttributesOrForeignSelections(@NonNull FuzzedDataProvider data) throws JsonParseException {
        String username = "fixture-" + data.consumeAsciiString(64).replace(PRIVATE_PREFIX, "fixture");
        String password = PRIVATE_PREFIX + data.consumeAsciiString(16);
        ScimResource resource = persisted("fuzz", username, data.consumeBoolean(), password);
        String projection = data.consumeBoolean() ? "attributes=userName,active" : "excludedAttributes=displayName";
        ScimAttributeSelection own = Assertions.assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                STRICT.parseAttributeSelectionResult(USER, projection)).getAttributeSelection();
        ScimAttributeSelection foreign = Assertions.assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                COMPATIBLE.parseAttributeSelectionResult(USER, projection)).getAttributeSelection();
        Assertions.assertInstanceOf(ScimResponseResult.Rejected.class, STRICT.resourceResponseResult(resource, foreign));
        ScimResponseResult output = STRICT.resourceResponseResult(resource, own);
        ScimResponse prepared = Assertions.assertInstanceOf(ScimResponseResult.Prepared.class, output).getResponse();
        bounded(prepared);
        JsonObject body = (JsonObject) JsonCodec.parse(prepared.toHttpBodyWithPersonalData(), JsonLimits.protocolDocument(2_048));
        Assertions.assertFalse(body.getMembers().containsKey("password"));
        Assertions.assertFalse(new String(prepared.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8).contains(PRIVATE_PREFIX));
        Assertions.assertEquals(password, resource.getDocument().find("password").map(com.revetsec.json.JsonString.class::cast).map(com.revetsec.json.JsonString::getValue).orElseThrow());
        Assertions.assertFalse(resource.toString().contains(PRIVATE_PREFIX));
    }

    private static void resourceOutcome(@NonNull ScimServiceProvider provider, @NonNull ScimResourceParseResult parsed) throws JsonParseException {
        if (parsed instanceof ScimResourceParseResult.Rejected rejected) { fixed(rejected.getError()); return; }
        ScimResourceParseResult.Succeeded succeeded = (ScimResourceParseResult.Succeeded) parsed;
        for (ScimAttributePath path : succeeded.getSuppliedAttributePaths()) {
            Assertions.assertNotEquals("id", path.getAttributeName());
            Assertions.assertNotEquals("meta", path.getAttributeName());
        }
        ScimResource candidate = succeeded.getResource();
        Map<String, JsonValue> values = new LinkedHashMap<>(candidate.getDocument().getMembers());
        values.put("id", JsonString.fromValue("fuzz"));
        values.put("meta", JsonObject.builder().put("version", "W/\"fuzz\"")
                .put("location", provider.resourceLocationFor(USER, "fuzz").toASCIIString()).build());
        ScimResource stored = ScimResource.withResourceType(USER).document(JsonObject.fromMembers(values)).build();
        ScimAttributeSelection selection = Assertions.assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                provider.parseAttributeSelectionResult(USER, "")).getAttributeSelection();
        ScimResponseResult result = provider.resourceResponseResult(stored, selection);
        if (result instanceof ScimResponseResult.Rejected rejected) { fixed(rejected.getError()); return; }
        ScimResponse response = ((ScimResponseResult.Prepared) result).getResponse();
        bounded(response);
        JsonObject body = (JsonObject) JsonCodec.parse(response.toHttpBodyWithPersonalData(), JsonLimits.protocolDocument(2_048));
        Assertions.assertFalse(body.getMembers().containsKey("password"));
    }

    private static @NonNull ScimServiceProvider provider(@NonNull ScimCompatibility compatibility) {
        ScimFilterPolicy email = ScimFilterPolicy.builder().allowedComparisons(Map.of("value", Set.of(ScimComparisonOperator.EQ),
                "type", Set.of(ScimComparisonOperator.EQ))).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).build();
        ScimFilterPolicy policy = ScimFilterPolicy.builder().allowedComparisons(Map.of("userName", Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.NE),
                "active", Set.of(ScimComparisonOperator.EQ), EXTENSION + ":counter", Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.GT)))
                .allowedPresence(Set.of("userName")).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND, ScimLogicalOperator.OR, ScimLogicalOperator.NOT))
                .allowedValuePaths(Map.of("emails", email)).build();
        ScimPaginationConfig pagination = ScimPaginationConfig.builder().cursorSupported(true).cursorTimeout(Duration.ofSeconds(1))
                .defaultPageSize(3).maximumPageSize(10).build();
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/")).resourceTypes(List.of(USER))
                .limits(LIMITS).compatibility(compatibility).filterPolicies(Map.of(USER, policy))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).sortSupported(true)
                        .filterMaximumResults(10).pagination(pagination).build()).build();
    }

    private static @NonNull ScimResource persisted(@NonNull String id, @NonNull String username, boolean active, @NonNull String password) {
        JsonObject.Builder body = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(CORE))))
                .put("id", id).put("userName", username).put("active", active)
                .put("meta", JsonObject.builder().put("version", "W/\"fuzz\"").put("location", "https://example.test/scim/Users/" + id).build());
        if (!password.isEmpty()) body.put("password", password);
        return ScimResource.withResourceType(USER).document(body.build()).build();
    }
    private static void fixed(@NonNull ScimError error) {
        Assertions.assertTrue(DETAILS.contains(error.getDetail()));
        Assertions.assertTrue(Set.of(400, 401, 403, 404, 405, 409, 412, 413, 415, 500, 501, 503).contains(error.getStatusCode()));
        error.getExpressionOffset().ifPresent(offset -> Assertions.assertTrue(offset >= 0 && offset <= 8_192));
    }
    private static void bounded(@NonNull ScimResponse response) {
        long headers = 0;
        for (Map.Entry<String, List<String>> entry : response.getHeaders().entrySet()) for (String value : entry.getValue())
            headers += (entry.getKey() + ": " + value + "\r\n").getBytes(StandardCharsets.UTF_8).length;
        Assertions.assertTrue(headers <= 512);
        Assertions.assertTrue(headers + response.toHttpBodyWithPersonalData().length + 128 <= 2_048);
        Assertions.assertEquals(List.of("private, no-store"), response.getHeaders().get("Cache-Control"));
    }
    private static void allowedFilter(@NonNull ScimFilter filter, boolean element) {
        if (filter instanceof ScimFilter.And value) { for (ScimFilter child : value.getOperands()) allowedFilter(child, element); }
        else if (filter instanceof ScimFilter.Or value) { for (ScimFilter child : value.getOperands()) allowedFilter(child, element); }
        else if (filter instanceof ScimFilter.Not value) allowedFilter(value.getOperand(), element);
        else if (filter instanceof ScimFilter.ValuePath value) {
            Assertions.assertFalse(element); Assertions.assertEquals("emails", value.getAttributePath().getAttributeName());
            allowedFilter(value.getFilter(), true);
        } else if (filter instanceof ScimFilter.Present value) {
            Assertions.assertFalse(element); Assertions.assertEquals("userName", value.getAttributePath().getAttributeName());
        } else if (filter instanceof ScimFilter.Comparison value) {
            String name = value.getAttributePath().getAttributeName();
            Assertions.assertTrue((element ? Set.of("value", "type") : Set.of("userName", "active", "counter")).contains(name));
            Assertions.assertNotEquals("password", name);
        }
    }
}
