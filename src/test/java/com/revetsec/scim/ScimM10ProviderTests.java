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

import static org.junit.jupiter.api.Assertions.*;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.JsonObject;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Public facade, association and application page framing behavior. */
class ScimM10ProviderTests {
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull String URN = USER.getSchema().getId();

    private static @NonNull ScimServiceProvider provider() {
        return ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.invalid/scim/v2"))
                .resourceTypes(List.of(USER, ScimResourceType.groupInstance()))
                .build();
    }

    private static @NonNull JsonObject object(@NonNull String text) {
        return (JsonObject)
                ((JsonParseResult.Succeeded)
                                JsonCodec.parseResult(bytes(text), JsonLimits.scim(100000, 1000)))
                        .getDocument()
                        .getValue();
    }

    private static byte @NonNull [] bytes(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull ScimResource user(@NonNull String id) {
        return ScimResource.withResourceType(USER)
                .document(
                        object(
                                "{\"schemas\":[\""
                                        + URN
                                        + "\"],\"id\":\""
                                        + id
                                        + "\",\"userName\":\"ada\",\"password\":\"test-fixture-secret\",\"meta\":{\"version\":\"W/\\\"v1\\\"\"}}"))
                .build();
    }

    private static @NonNull ScimAttributeSelection selection(
            @NonNull ScimServiceProvider p, @NonNull String raw) {
        return assertInstanceOf(
                        ScimAttributeSelectionResult.Succeeded.class,
                        p.parseAttributeSelectionResult(USER, raw))
                .getAttributeSelection();
    }

    private static @NonNull ScimQuery query(@NonNull ScimServiceProvider p, @NonNull String raw) {
        return assertInstanceOf(ScimQueryParseResult.Succeeded.class, p.parseQueryResult(USER, raw))
                .getQuery();
    }

    private static @NonNull ScimResponse response(@NonNull ScimResponseResult result) {
        return assertInstanceOf(ScimResponseResult.Prepared.class, result).getResponse();
    }

    private static @NonNull String text(@NonNull ScimResponse response) {
        return new String(response.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8);
    }

    @Test
    void defaultSnapshotAndNullableReplacementDefaults() {
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid"))
                        .resourceTypes(null)
                        .resourceTypes(List.of(USER))
                        .serviceProviderConfig(null)
                        .filterPolicies(null)
                        .compatibility(null)
                        .stringMatching(null)
                        .limits(null)
                        .observer(null)
                        .build();
        assertEquals(URI.create("https://example.invalid/"), p.getBaseUri());
        assertEquals(List.of(USER), p.getResourceTypes());
        assertFalse(p.getServiceProviderConfig().isFilterSupported());
        assertFalse(p.getServiceProviderConfig().isPatchSupported());
        assertSame(ScimCompatibility.strictInstance(), p.getCompatibility());
        assertTrue(p.getStringMatching().isEmpty());
        assertTrue(p.getFilterPolicies().isEmpty());
        assertNotNull(p.getLimits());
        assertThrows(UnsupportedOperationException.class, () -> p.getResourceTypes().clear());
        assertFalse(p.toString().contains("example"));
        ScimServiceProvider copy = p.copy().baseUri(null).compatibility(null).finish();
        assertEquals(p.getBaseUri(), copy.getBaseUri());
        assertEquals(
                200,
                response(copy.resourceResponseResult(user("1"), selection(p, ""))).getStatusCode());
    }

    @Test
    void configurationRejectsMissingForeignAmbiguousAndContradictoryRegistration() {
        assertThrows(
                NullPointerException.class,
                () -> ScimServiceProvider.builder().resourceTypes(List.of(USER)).build());
        assertThrows(
                IllegalStateException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .build());
        for (String uri :
                List.of(
                        "ftp://example.invalid/",
                        "https://a:b@example.invalid/",
                        "https://example.invalid/?q",
                        "https://example.invalid/#f",
                        "https://example.invalid/a/../b",
                        "https://example.invalid/a%2fb"))
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            ScimServiceProvider.builder()
                                    .baseUri(URI.create(uri))
                                    .resourceTypes(List.of(USER))
                                    .build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(USER, USER))
                                .build());
        ScimResourceType foreign =
                ScimResourceType.withName("User")
                        .id("User")
                        .endpoint("/Users")
                        .schema(ScimSchema.userInstance())
                        .build();
        assertThrows(
                IllegalArgumentException.class, () -> provider().parseQueryResult(foreign, ""));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(USER))
                                .filterPolicies(
                                        Map.of(foreign, ScimFilterPolicy.rejectAllInstance()))
                                .build());
        assertThrows(
                IllegalStateException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(USER))
                                .serviceProviderConfig(
                                        ScimServiceProviderConfig.builder()
                                                .filterSupported(true)
                                                .build())
                                .build());
        assertThrows(
                IllegalStateException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(USER))
                                .serviceProviderConfig(
                                        ScimServiceProviderConfig.builder()
                                                .patchSupported(true)
                                                .build())
                                .build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(USER))
                                .limits(ScimLimits.builder().maximumPageSize(1).build())
                                .build());
        ScimSchema contradict =
                ScimSchema.withId(URN)
                        .name("Changed")
                        .attributes(List.of(ScimAttributeDefinition.withName("x").build()))
                        .build();
        ScimResourceType bad =
                ScimResourceType.withName("Bad").endpoint("/Bad").schema(contradict).build();
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create("https://example.invalid"))
                                .resourceTypes(List.of(bad))
                                .build());
    }

    @Test
    void approvedFilterIsTheBoundTreeAndSearchMatchesGet() {
        ScimFilterPolicy policy =
                ScimFilterPolicy.builder()
                        .allowedComparisons(Map.of("emails", Set.of(ScimComparisonOperator.EQ)))
                        .build();
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .serviceProviderConfig(
                                ScimServiceProviderConfig.builder()
                                        .filterSupported(true)
                                        .sortSupported(true)
                                        .build())
                        .filterPolicies(Map.of(USER, policy))
                        .build();
        ScimFilter filter =
                assertInstanceOf(
                                ScimFilterParseResult.Succeeded.class,
                                p.parseFilterResult(USER, "EMAILS eq \"x\""))
                        .getFilter();
        assertEquals("emails.value eq \"x\"", filter.toScimString());
        ScimQuery get =
                query(
                        p,
                        "filter=emails+eq+%22x%22&sortBy=USERNAME&sortOrder=descending&count=1&attributes=userName");
        ScimQuery search =
                assertInstanceOf(
                                ScimQueryParseResult.Succeeded.class,
                                p.parseSearchRequestResult(
                                        USER,
                                        List.of("application/scim+json"),
                                        bytes(
                                                "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"filter\":\"emails eq \\\"x\\\"\",\"sortBy\":\"userName\",\"sortOrder\":\"descending\",\"count\":1,\"attributes\":[\"userName\"]}")))
                        .getQuery();
        assertEquals(get.getFilter(), search.getFilter());
        assertEquals(get.getSortBy(), search.getSortBy());
        assertEquals(get.getSortOrder(), search.getSortOrder());
        assertEquals(get.getCount(), search.getCount());
        assertEquals(get.getRequestedCount(), search.getRequestedCount());
        assertEquals(
                get.getAttributeSelection().getIncludedAttributes(),
                search.getAttributeSelection().getIncludedAttributes());
        assertTrue(get.getCursor().isEmpty());
        assertFalse(get.isFirstCursorPage());
        assertInstanceOf(
                ScimFilterParseResult.Rejected.class, p.parseFilterResult(USER, "password pr"));
        assertSame(
                ScimError.forbiddenInstance(),
                assertInstanceOf(
                                ScimFilterParseResult.Rejected.class,
                                provider().parseFilterResult(USER, "userName pr"))
                        .getError());
    }

    @Test
    void createReplaceAndBodyFailuresUseOneDirectOperation() {
        ScimServiceProvider p = provider();
        String body = "{\"schemas\":[\"" + URN + "\"],\"userName\":\"new\"}";
        ScimResourceParseResult.Succeeded parsed =
                assertInstanceOf(
                        ScimResourceParseResult.Succeeded.class,
                        p.parseResourceResult(
                                USER, List.of("application/json;charset=Latin-1"), bytes(body)));
        assertTrue(parsed.getResource().getId().isEmpty());
        assertFalse(parsed.getSuppliedAttributePaths().isEmpty());
        assertInstanceOf(
                ScimResourceParseResult.Succeeded.class, p.parseResourceResult(USER, bytes(body)));
        assertInstanceOf(
                ScimResourceParseResult.Succeeded.class,
                p.parseReplacementResult(
                        USER, user("1"), List.of("application/scim+json"), bytes(body)));
        assertInstanceOf(
                ScimResourceParseResult.Succeeded.class,
                p.parseReplacementResult(USER, user("1"), bytes(body)));
        for (byte[] malformed :
                List.of(
                        new byte[0],
                        new byte[] {(byte) 0xff},
                        bytes("{}x"),
                        bytes("{\"x\":1,\"X\":2}"))) {
            assertInstanceOf(
                    ScimResourceParseResult.Rejected.class, p.parseResourceResult(USER, malformed));
            assertInstanceOf(
                    ScimResourceParseResult.Rejected.class,
                    p.parseReplacementResult(USER, user("1"), malformed));
            assertInstanceOf(
                    ScimQueryParseResult.Rejected.class,
                    p.parseSearchRequestResult(USER, malformed));
        }
        assertInstanceOf(
                ScimResourceParseResult.Rejected.class,
                p.parseResourceResult(USER, List.of("text/plain"), bytes(body)));
        assertInstanceOf(
                ScimResourceParseResult.Rejected.class,
                p.parseReplacementResult(USER, user("1"), List.of("text/plain"), bytes(body)));
        assertInstanceOf(
                ScimQueryParseResult.Rejected.class,
                p.parseSearchRequestResult(USER, List.of("text/plain"), bytes(body)));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        p.parseReplacementResult(
                                USER,
                                ScimResource.withResourceType(ScimResourceType.groupInstance())
                                        .document(
                                                object(
                                                        "{\"schemas\":[\""
                                                                + ScimSchema.groupInstance().getId()
                                                                + "\"],\"displayName\":\"g\"}"))
                                        .build(),
                                bytes(body)));
    }

    @Test
    void resourceOutputStripsSecretsAndCreationLocationEncodesOneSegment() {
        ScimServiceProvider p = provider();
        ScimResource r = user("1/2");
        ScimAttributeSelection s = selection(p, "");
        ScimResponse get = response(p.resourceResponseResult(r, s));
        assertEquals(200, get.getStatusCode());
        assertFalse(text(get).contains("secret"));
        assertFalse(text(get).contains("password"));
        assertEquals(List.of("W/\"v1\""), get.getHeaders().get("ETag"));
        ScimResponse created = response(p.createdResponseResult(r, Set.of(), s));
        assertEquals(201, created.getStatusCode());
        assertEquals(
                List.of("https://example.invalid/scim/v2/Users/1%2F2"),
                created.getHeaders().get("Location"));
        assertTrue(text(created).contains("https://example.invalid/scim/v2/Users/1%2F2"));
        assertEquals(
                URI.create("https://example.invalid/scim/v2/Users/%2E%2E"),
                p.resourceLocationFor(USER, ".."));
        assertEquals(200, response(p.replacementResponseResult(r, Set.of(), s)).getStatusCode());
        ScimResponse no = p.noContentResponse();
        assertEquals(204, no.getStatusCode());
        assertEquals(0, no.toHttpBodyWithPersonalData().length);
        ScimResponse modified = response(p.notModifiedResponseResult(r));
        assertEquals(304, modified.getStatusCode());
        assertEquals(0, modified.toHttpBodyWithPersonalData().length);
        assertEquals(get.getHeaders().get("ETag"), modified.getHeaders().get("ETag"));
        assertEquals(400, p.errorResponse(ScimError.invalidSyntaxInstance()).getStatusCode());
        assertInstanceOf(
                ScimContentTypeResult.Accepted.class,
                p.validateContentTypeResult(List.of("application/scim+json")));
        assertInstanceOf(
                ScimContentTypeResult.Rejected.class, p.validateContentTypeResult(List.of()));
        assertInstanceOf(
                ScimIfMatchResult.Satisfied.class, p.checkIfMatchResult(List.of("\"v1\""), r));
        assertInstanceOf(
                ScimIfMatchResult.Rejected.class, p.checkIfMatchResult(List.of("\"other\""), r));
        assertInstanceOf(
                ScimIfNoneMatchResult.NotModified.class,
                p.checkIfNoneMatchResult(List.of("\"v1\""), r));
        assertInstanceOf(
                ScimIfNoneMatchResult.Proceed.class,
                p.checkIfNoneMatchResult(List.of("\"other\""), r));
    }

    @Test
    void semanticProvenanceBlocksRelaxedInputWhileBaseOnlyCopySharesIt() {
        ScimServiceProvider strict = provider();
        ScimServiceProvider relaxed =
                strict.copy()
                        .compatibility(
                                ScimCompatibility.builder()
                                        .features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS))
                                        .build())
                        .finish();
        ScimResourceParseResult.Succeeded parsed =
                assertInstanceOf(
                        ScimResourceParseResult.Succeeded.class,
                        relaxed.parseResourceResult(
                                USER,
                                bytes(
                                        "{\"schemas\":[\""
                                                + URN
                                                + "\"],\"userName\":\"a\",\"active\":\"true\"}")));
        assertInstanceOf(
                ScimResponseResult.Rejected.class,
                strict.resourceResponseResult(parsed.getResource(), selection(strict, "")));
        ScimAttributeSelection old = selection(strict, "");
        ScimQuery oldQuery = query(strict, "");
        assertInstanceOf(
                ScimResponseResult.Rejected.class, relaxed.resourceResponseResult(user("1"), old));
        assertInstanceOf(
                ScimResponseResult.Rejected.class,
                relaxed.listResponseResult(
                        ScimListPage.withQuery(oldQuery).totalResults(0L).build()));
        ScimServiceProvider moved =
                strict.copy().baseUri(URI.create("https://new.invalid/scim/")).finish();
        assertInstanceOf(
                ScimResponseResult.Prepared.class, moved.resourceResponseResult(user("1"), old));
        assertInstanceOf(
                ScimResourceParseResult.Rejected.class,
                strict.parseReplacementResult(USER, parsed.getResource(), bytes("{}")));
        assertInstanceOf(
                ScimIfMatchResult.Rejected.class,
                strict.checkIfMatchResult(List.of(), parsed.getResource()));
        assertInstanceOf(
                ScimIfNoneMatchResult.Rejected.class,
                strict.checkIfNoneMatchResult(List.of(), parsed.getResource()));
        assertInstanceOf(
                ScimResponseResult.Rejected.class,
                strict.notModifiedResponseResult(parsed.getResource()));
    }

    @Test
    void outputAssociationMissingIdAndBudgetFailuresAreResults() {
        ScimServiceProvider p = provider();
        ScimAttributeSelection s = selection(p, "");
        ScimResource noId =
                ScimResource.withResourceType(USER)
                        .document(object("{\"schemas\":[\"" + URN + "\"],\"userName\":\"a\"}"))
                        .build();
        assertInstanceOf(
                ScimResponseResult.Rejected.class, p.createdResponseResult(noId, Set.of(), s));
        ScimAttributePath bad =
                assertInstanceOf(
                                ScimAttributePathParseResult.Succeeded.class,
                                ScimAttributePath.fromExpressionResult("unknown"))
                        .getAttributePath();
        assertInstanceOf(
                ScimResponseResult.Rejected.class,
                p.replacementResponseResult(user("1"), Set.of(bad), s));
        ScimResource mismatch =
                ScimResource.withResourceType(USER)
                        .document(
                                object(
                                        "{\"schemas\":[\""
                                                + URN
                                                + "\"],\"id\":\"1\",\"userName\":\"a\",\"meta\":{\"location\":\"https://wrong.invalid/1\"}}"))
                        .build();
        assertInstanceOf(
                ScimResponseResult.Rejected.class, p.createdResponseResult(mismatch, Set.of(), s));
        ScimServiceProvider small =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .limits(ScimLimits.builder().maximumResponseBytes(2048).build())
                        .build();
        ScimResource huge =
                ScimResource.withResourceType(USER)
                        .document(
                                object(
                                        "{\"schemas\":[\""
                                                + URN
                                                + "\"],\"id\":\"1\",\"userName\":\""
                                                + "x".repeat(3000)
                                                + "\"}"))
                        .build();
        assertSame(
                ScimError.responseTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                small.resourceResponseResult(huge, selection(small, "")))
                        .getError());
        ScimServiceProvider tinyBody =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .limits(ScimLimits.builder().maximumBodyBytes(16384).build())
                        .build();
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimResourceParseResult.Rejected.class,
                                tinyBody.parseResourceResult(USER, bytes(" ".repeat(16385))))
                        .getError());
    }

    @Test
    void discoveryIsProjectedTruthfulAndNeverAcceptsFilters() {
        ScimServiceProvider p = provider();
        String config = text(response(p.serviceProviderConfigResponseResult("")));
        assertTrue(
                config.contains(
                        "\"bulk\":{\"supported\":false,\"maxOperations\":0,\"maxPayloadSize\":0}"));
        assertTrue(config.contains("pagination"));
        String types = text(response(p.resourceTypesResponseResult("")));
        assertTrue(types.contains("/Users"));
        assertTrue(types.contains("\"itemsPerPage\":2"));
        assertTrue(
                text(response(p.resourceTypeResponseResult("User", "attributes=name")))
                        .contains("\"name\":\"User\""));
        String schemas = text(response(p.schemasResponseResult("")));
        assertTrue(schemas.contains(URN));
        assertTrue(schemas.contains(ScimSchema.enterpriseUserInstance().getId()));
        assertTrue(
                text(response(p.schemaResponseResult(URN, "attributes=name")))
                        .contains("\"name\":\"User\""));
        assertSame(
                ScimError.notFoundInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.schemaResponseResult("unknown", ""))
                        .getError());
        assertSame(
                ScimError.notFoundInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.resourceTypeResponseResult("user", ""))
                        .getError());
        for (ScimResponseResult result :
                List.of(
                        p.serviceProviderConfigResponseResult("filter="),
                        p.resourceTypesResponseResult("FILTER=x"),
                        p.schemaResponseResult(URN, "filter=x")))
            assertSame(
                    ScimError.forbiddenInstance(),
                    assertInstanceOf(ScimResponseResult.Rejected.class, result).getError());
        assertInstanceOf(
                ScimResponseResult.Rejected.class, p.schemasResponseResult("attributes=unknown"));
    }

    @Test
    void listFramingRejectsInconsistentApplicationPagesAndAlwaysEmitsResources() {
        ScimServiceProvider p = provider();
        ScimQuery q = query(p, "count=2&startIndex=1");
        ScimListPage page =
                ScimListPage.withQuery(q).resources(List.of(user("1"))).totalResults(3L).build();
        assertSame(q, page.getQuery());
        assertEquals(1, page.getResources().size());
        assertEquals(3L, page.getTotalResults().orElseThrow());
        assertTrue(page.getNextCursor().isEmpty());
        assertTrue(page.getPreviousCursor().isEmpty());
        assertFalse(page.isMoreResultsAvailable());
        String body = text(response(p.listResponseResult(page)));
        assertTrue(body.contains("\"itemsPerPage\":1"));
        assertTrue(body.contains("\"totalResults\":3"));
        assertTrue(body.contains("\"startIndex\":1"));
        assertFalse(body.contains("password"));
        String empty =
                text(
                        response(
                                p.listResponseResult(
                                        ScimListPage.withQuery(q)
                                                .resources(null)
                                                .totalResults(0L)
                                                .nextCursor(null)
                                                .previousCursor(null)
                                                .moreResultsAvailable(null)
                                                .build())));
        assertTrue(empty.contains("\"Resources\":[]"));
        assertThrows(IllegalArgumentException.class, () -> ScimListPage.withQuery(q).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(q).totalResults(-1L).build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(q)
                                .resources(List.of(user("1"), user("2"), user("3"))));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(q)
                                .resources(List.of(user("1")))
                                .totalResults(0L)
                                .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(q).totalResults(2L).nextCursor("x").build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(q).totalResults(2L).previousCursor("x").build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(q)
                                .totalResults(2L)
                                .moreResultsAvailable(true)
                                .build());
    }

    @Test
    void cursorPageContractPreservesPresenceZeroCountAndActualTraversal() {
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .serviceProviderConfig(
                                ScimServiceProviderConfig.builder()
                                        .pagination(
                                                ScimPaginationConfig.builder()
                                                        .cursorSupported(true)
                                                        .cursorTimeout(Duration.ofMinutes(2))
                                                        .build())
                                        .build())
                        .build();
        ScimQuery first = query(p, "cursor=&count=2");
        assertEquals("", first.getCursor().orElseThrow());
        assertTrue(first.isFirstCursorPage());
        assertTrue(first.getStartIndex().isEmpty());
        ScimListPage page =
                ScimListPage.withQuery(first)
                        .nextCursor("next_1")
                        .moreResultsAvailable(true)
                        .build();
        String body = text(response(p.listResponseResult(page)));
        assertTrue(body.contains("\"nextCursor\":\"next_1\""));
        assertFalse(body.contains("totalResults"));
        assertFalse(body.contains("startIndex"));
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(first).previousCursor("prev").build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(first).nextCursor("next").build());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(first).moreResultsAvailable(true).build());
        ScimQuery later = query(p, "cursor=later&count=2");
        ScimListPage tail = ScimListPage.withQuery(later).previousCursor("prev").build();
        assertTrue(text(response(p.listResponseResult(tail))).contains("previousCursor"));
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(later).previousCursor("").build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(later)
                                .nextCursor("!")
                                .moreResultsAvailable(true)
                                .build());
        ScimQuery countOnly = query(p, "cursor=&count=0");
        assertThrows(
                IllegalArgumentException.class, () -> ScimListPage.withQuery(countOnly).build());
        assertTrue(
                text(response(
                                p.listResponseResult(
                                        ScimListPage.withQuery(countOnly)
                                                .totalResults(12L)
                                                .build())))
                        .contains("\"totalResults\":12"));
    }

    @Test
    void observerLifecycleAndActualRelaxationsContainHookFailures() {
        List<String> events = new ArrayList<>();
        ScimObserver observer =
                new ScimObserver() {
                    @Override
                    public void willProcess(@NonNull Operation operation) {
                        events.add("will:" + operation);
                    }

                    @Override
                    public void didProcess(@NonNull Operation operation, @NonNull Outcome outcome) {
                        events.add("did:" + outcome);
                    }

                    @Override
                    public void didFailToProcess(@NonNull Operation operation) {
                        events.add("fail:" + operation);
                    }

                    @Override
                    public void didUseCompatibilityFeature(
                            @NonNull ScimCompatibilityFeature feature) {
                        events.add("used:" + feature);
                    }
                };
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .observer(observer)
                        .compatibility(
                                ScimCompatibility.builder()
                                        .features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS))
                                        .build())
                        .build();
        assertTrue(events.isEmpty());
        assertNotNull(p.copy().finish());
        assertTrue(events.isEmpty());
        assertInstanceOf(
                ScimResourceParseResult.Succeeded.class,
                p.parseResourceResult(
                        USER,
                        bytes(
                                "{\"schemas\":[\""
                                        + URN
                                        + "\"],\"userName\":\"a\",\"active\":\"true\"}")));
        assertEquals(
                List.of("will:RESOURCE_CREATE", "used:BOOLEAN_STRINGS", "did:SUCCEEDED"), events);
        events.clear();
        assertInstanceOf(
                ScimResourceParseResult.Rejected.class, p.parseResourceResult(USER, new byte[0]));
        assertEquals(List.of("will:RESOURCE_CREATE", "did:REJECTED"), events);
        events.clear();
        List<String> faulty =
                new AbstractList<>() {
                    @Override
                    public @NonNull String get(int index) {
                        throw new IllegalStateException("sentinel-private-data");
                    }

                    @Override
                    public int size() {
                        return 1;
                    }
                };
        assertSame(
                ScimError.internalErrorInstance(),
                assertInstanceOf(
                                ScimContentTypeResult.Rejected.class,
                                p.validateContentTypeResult(faulty))
                        .getError());
        assertEquals(List.of("will:CONTENT_TYPE", "fail:CONTENT_TYPE"), events);
        ScimServiceProvider throwing =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .observer(
                                new ScimObserver() {
                                    @Override
                                    public void willProcess(@NonNull Operation operation) {
                                        throw new IllegalStateException("private");
                                    }

                                    @Override
                                    public void didProcess(
                                            @NonNull Operation operation,
                                            @NonNull Outcome outcome) {
                                        throw new IllegalStateException("private");
                                    }
                                })
                        .build();
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, throwing.parseQueryResult(USER, ""));
    }

    @Test
    void boundedHeaderAndOperationWorkExhaustionReturnsFixedErrors() {
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(USER))
                        .limits(ScimLimits.builder().maximumWorkUnits(10000).build())
                        .build();
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimContentTypeResult.Rejected.class,
                                p.validateContentTypeResult(List.of("x".repeat(6000))))
                        .getError());
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimIfMatchResult.Rejected.class,
                                p.checkIfMatchResult(
                                        java.util.Collections.nCopies(65, ""), user("1")))
                        .getError());
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimIfNoneMatchResult.Rejected.class,
                                p.checkIfNoneMatchResult(List.of("x".repeat(6000)), user("1")))
                        .getError());
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimResourceParseResult.Rejected.class,
                                p.parseResourceResult(USER, bytes(" ".repeat(10001))))
                        .getError());
        ScimResource huge =
                ScimResource.withResourceType(USER)
                        .document(
                                object(
                                        "{\"schemas\":[\""
                                                + URN
                                                + "\"],\"id\":\"1\",\"userName\":\""
                                                + "x".repeat(15000)
                                                + "\"}"))
                        .build();
        assertSame(
                ScimError.responseTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.resourceResponseResult(huge, selection(p, "")))
                        .getError());
        assertSame(
                ScimError.responseTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.listResponseResult(
                                        ScimListPage.withQuery(query(p, "count=1"))
                                                .resources(List.of(huge))
                                                .totalResults(1L)
                                                .build()))
                        .getError());
        Set<ScimAttributePath> paths = new java.util.LinkedHashSet<>();
        for (int index = 0; index < 1025; index++)
            paths.add(
                    assertInstanceOf(
                                    ScimAttributePathParseResult.Succeeded.class,
                                    ScimAttributePath.fromExpressionResult("x" + index))
                            .getAttributePath());
        assertInstanceOf(
                ScimResponseResult.Rejected.class,
                p.replacementResponseResult(user("1"), paths, selection(p, "")));
    }

    @Test
    void boundedConfigurationAndCursorWindowCasesHaveExplicitContracts() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .resourceTypes(java.util.Collections.nCopies(33, USER)));
        Map<ScimResourceType, ScimFilterPolicy> policies = new java.util.LinkedHashMap<>();
        for (int index = 0; index < 33; index++)
            policies.put(
                    ScimResourceType.withName("T" + index)
                            .endpoint("/T" + index)
                            .schema(USER.getSchema())
                            .build(),
                    ScimFilterPolicy.rejectAllInstance());
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimServiceProvider.builder().filterPolicies(policies));
        String maximumBase = "https://x/" + "x".repeat(2038);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimServiceProvider.builder()
                                .baseUri(URI.create(maximumBase))
                                .resourceTypes(List.of(USER))
                                .build());
        ScimServiceProvider p = provider();
        ScimQuery q = query(p, "count=2");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(q)
                                .resources(List.of(user("1"), user("2")))
                                .totalResults(1L)
                                .build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(query(p, "startIndex=10"))
                                .resources(List.of(user("1")))
                                .totalResults(1L)
                                .build());
        ScimResource group =
                ScimResource.withResourceType(ScimResourceType.groupInstance())
                        .document(
                                object(
                                        "{\"schemas\":[\""
                                                + ScimSchema.groupInstance().getId()
                                                + "\"],\"displayName\":\"g\"}"))
                        .build();
        assertThrows(
                IllegalArgumentException.class,
                () -> ScimListPage.withQuery(q).resources(List.of(group)).totalResults(1L).build());
        ScimServiceProvider cursor =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("http://localhost/scim/"))
                        .resourceTypes(List.of(USER))
                        .limits(ScimLimits.builder().maximumCursorCharacters(64).build())
                        .serviceProviderConfig(
                                ScimServiceProviderConfig.builder()
                                        .pagination(
                                                ScimPaginationConfig.builder()
                                                        .cursorSupported(true)
                                                        .cursorTimeout(Duration.ofSeconds(1))
                                                        .build())
                                        .build())
                        .build();
        ScimQuery first = query(cursor, "cursor=");
        String token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ScimListPage.withQuery(first)
                                .nextCursor(token)
                                .moreResultsAvailable(true)
                                .build());
        ScimListPage page =
                ScimListPage.withQuery(first)
                        .nextCursor(token.substring(0, 64))
                        .moreResultsAvailable(true)
                        .build();
        assertFalse(page.toString().contains(token));
        assertTrue(text(response(cursor.listResponseResult(page))).contains("nextCursor"));
    }

    @Test
    void largeConfiguredDiscoveryIsRejectedBeforeDescriptorTreeAllocation() {
        Set<String> suggestions = new java.util.LinkedHashSet<>();
        for (int index = 0; index < 1024; index++) suggestions.add("value-" + index);
        List<ScimAttributeDefinition> definitions = new ArrayList<>();
        for (int index = 0; index < 1000; index++)
            definitions.add(
                    ScimAttributeDefinition.withName("a" + index)
                            .canonicalValues(suggestions)
                            .build());
        ScimSchema schema =
                ScimSchema.withId("https://example.invalid/Large")
                        .name("Large")
                        .attributes(definitions)
                        .build();
        ScimResourceType type =
                ScimResourceType.withName("Large").endpoint("/Large").schema(schema).build();
        ScimServiceProvider p =
                ScimServiceProvider.builder()
                        .baseUri(URI.create("https://example.invalid/"))
                        .resourceTypes(List.of(type))
                        .build();
        // Quota rejection must precede wrapping a million configured suggestions in JSON.
        assertInstanceOf(ScimResponseResult.Prepared.class, p.serviceProviderConfigResponseResult(""));
        com.sun.management.ThreadMXBean allocations = assertInstanceOf(
                com.sun.management.ThreadMXBean.class, java.lang.management.ManagementFactory.getThreadMXBean());
        assertTrue(allocations.isThreadAllocatedMemorySupported());
        assertTrue(allocations.isThreadAllocatedMemoryEnabled());
        long thread = Thread.currentThread().getId();
        long before = allocations.getThreadAllocatedBytes(thread);
        assertSame(
                ScimError.responseTooLargeInstance(),
                assertInstanceOf(ScimResponseResult.Rejected.class, p.schemasResponseResult(""))
                        .getError());
        assertSame(
                ScimError.responseTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.schemaResponseResult(schema.getId(), ""))
                        .getError());
        long allocated = allocations.getThreadAllocatedBytes(thread) - before;
        assertTrue(allocated < 1024 * 1024, "Quota rejection must precede descriptor-tree allocation.");

    }

    @Test
    void discoveryRouteIdentifiersAreBoundedBeforeCanonicalLookupAllocation() {
        ScimServiceProvider p = provider();
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.schemaResponseResult("x".repeat(2049), ""))
                        .getError());
        assertSame(
                ScimError.requestTooLargeInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.resourceTypeResponseResult("x".repeat(129), ""))
                        .getError());
        assertSame(
                ScimError.notFoundInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.schemaResponseResult("x".repeat(2048), ""))
                        .getError());
        assertSame(
                ScimError.notFoundInstance(),
                assertInstanceOf(
                                ScimResponseResult.Rejected.class,
                                p.resourceTypeResponseResult("x".repeat(128), ""))
                        .getError());
    }
}
