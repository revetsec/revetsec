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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Independent request ingress, projection, pagination and SearchRequest matrices. */
class ScimM10QueryTests {
    private static final @NonNull ScimResourceType TYPE = ScimResourceType.userInstance();
    private static final @NonNull Object CONTEXT = new Object();
    private static final @NonNull ScimLimits LIMITS = ScimLimits.fromDefaults();
    private static final @NonNull ScimCompatibility STRICT = ScimCompatibility.strictInstance();
    private static final @NonNull ScimServiceProviderConfig CONFIG = ScimServiceProviderConfig.builder().filterSupported(true).sortSupported(true).build();

    @Test void defaultIndexQueryRetainsNoFabricatedRequestedCount() {
        ScimQuery query = success(query("", CONFIG, LIMITS));
        assertEquals(TYPE, query.getResourceType()); assertTrue(query.getFilter().isEmpty());
        assertFalse(query.getAttributeSelection().isExplicit()); assertTrue(query.getSortBy().isEmpty());
        assertTrue(query.getSortOrder().isEmpty()); assertEquals(ScimPaginationMethod.INDEX, query.getPaginationMethod());
        assertEquals(1L, query.getStartIndex().orElseThrow()); assertEquals(100, query.getCount());
        assertTrue(query.getRequestedCount().isEmpty()); assertTrue(query.getCursor().isEmpty()); assertFalse(query.isFirstCursorPage());
        assertSame(CONTEXT, query.getSemanticContext()); assertSame(CONTEXT, query.getAttributeSelection().getSemanticContext());
    }

    @Test void indexCountClampsAndNegativePagingNormalizesWithoutErasingRequest() {
        ScimQuery query = success(query("startIndex=-5&count=-3", CONFIG, LIMITS));
        assertEquals(1L, query.getStartIndex().orElseThrow()); assertEquals(0, query.getCount()); assertEquals(-3L, query.getRequestedCount().orElseThrow());
        query = success(query("startIndex=0&count=9223372036854775807", CONFIG, LIMITS));
        assertEquals(1L, query.getStartIndex().orElseThrow()); assertEquals(1000, query.getCount());
        assertEquals(Long.MAX_VALUE, query.getRequestedCount().orElseThrow());
        query = success(query("startIndex=9223372036854775807&count=-9223372036854775808", CONFIG, LIMITS));
        assertEquals(Long.MAX_VALUE, query.getStartIndex().orElseThrow()); assertEquals(0, query.getCount());
        assertEquals(Long.MIN_VALUE, query.getRequestedCount().orElseThrow());
        assertEquals(12, success(query("count=0012", CONFIG, LIMITS)).getCount());
    }

    @Test void malformedOrOverflowingIntegerTextNeverWrapsOrThrows() {
        for (String value : List.of("", "-", "+1", " 1", "1 ", "1.0", "1e0", "١", "9223372036854775808", "-9223372036854775809")) {
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query("count=" + value, CONFIG, LIMITS));
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query("startIndex=" + value, CONFIG, LIMITS));
        }
    }

    @Test void recognizedParameterDuplicatesRemainPhysicalAndAsciiInsensitive() {
        for (String raw : List.of("count=1&count=1", "COUNT=1&count=2", "%63ount=1&count=2", "filter=userName+pr&filter=userName+pr",
                "sortBy=userName&SortBy=userName", "attributes=userName&ATTRIBUTES=name", "cursor=&cursor="))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query(raw, CONFIG, LIMITS));
        assertEquals(2, success(query("COUNT=2", CONFIG, LIMITS)).getCount());
        assertEquals(100, success(query("unknown=one&unknown=two", CONFIG, LIMITS)).getCount());
    }

    @Test void plusMeansSpaceAndOnlyPercentEncodedPlusIsLiteralPlus() {
        ScimFilter.Comparison space = (ScimFilter.Comparison) success(query("filter=userName+eq+%22a+b%22", CONFIG, LIMITS)).getFilter().orElseThrow();
        ScimFilter.Comparison plus = (ScimFilter.Comparison) success(query("filter=userName+eq+%22a%2Bb%22", CONFIG, LIMITS)).getFilter().orElseThrow();
        assertEquals("a b", ((ScimFilterValue.StringValue) space.getValue()).getValue());
        assertEquals("a+b", ((ScimFilterValue.StringValue) plus.getValue()).getValue());
        ScimFilter.Comparison unicode = (ScimFilter.Comparison) success(query("filter=userName+eq+%22%C3%A9%F0%9F%98%80%22", CONFIG, LIMITS)).getFilter().orElseThrow();
        assertEquals("é😀", ((ScimFilterValue.StringValue) unicode.getValue()).getValue());
    }

    @Test void malformedEncodingInIgnoredFieldsRejectsTheWholeQuery() {
        for (String value : List.of("%", "%0", "%gg", "%ＦＦ", "%FF", "%C0%AF", "%ED%A0%80", "%F4%90%80%80", "%E2%82", "\ud800"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query("ignored=" + value, CONFIG, LIMITS));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("%FF=ignored", CONFIG, LIMITS));
        assertEquals(100, success(query("ignored=%EF%BB%BF", CONFIG, LIMITS)).getCount());
        assertEquals(100, success(query("ignored=é😀", CONFIG, LIMITS)).getCount());
    }

    @Test void rawByteParameterAndDecodedCharacterCapsIncludeIgnoredFields() {
        ScimLimits bytes = ScimLimits.builder().maximumRawQueryBytes(256).build();
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, query("ignored=" + "x".repeat(248), CONFIG, bytes));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("ignored=" + "x".repeat(249), CONFIG, bytes));
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, query("x=" + "é".repeat(127), CONFIG, bytes));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("x=" + "é".repeat(128), CONFIG, bytes));
        ScimLimits parameters = ScimLimits.builder().maximumQueryParameters(2).build();
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, query("x=a&x=b", CONFIG, parameters));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("x=a&x=b&x=c", CONFIG, parameters));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("&&", CONFIG, parameters));
        ScimLimits characters = ScimLimits.builder().maximumParameterCharacters(256).build();
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, query("x=" + "%F0%9F%98%80".repeat(128), CONFIG, characters));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("x=" + "%F0%9F%98%80".repeat(129), CONFIG, characters));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("x".repeat(257) + "=a", CONFIG, characters));
    }

    @Test void projectionIsRegisteredCanonicalAndMutuallyExclusive() {
        ScimAttributeSelection include = selection("attributes=USERNAME,%20name.GIVENNAME");
        assertTrue(include.isExplicit()); assertEquals(Set.of(path("userName"), path("name.givenName")), include.getIncludedAttributes());
        assertTrue(include.includes(path("name"))); assertTrue(include.includes(path("name.givenName")));
        assertFalse(include.includes(path("name.familyName"))); assertFalse(include.includes(path("emails")));
        ScimAttributeSelection exclude = selection("excludedAttributes=emails");
        assertEquals(Set.of(path("emails")), exclude.getExcludedAttributes());
        assertFalse(exclude.includes(path("emails.value"))); assertTrue(exclude.includes(path("userName")));
        for (String raw : List.of("attributes=userName&excludedAttributes=name", "attributes=", "attributes=,userName", "attributes=userName,",
                "attributes=unknown", "attributes=userName.value", "attributes=department"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query(raw, CONFIG, LIMITS));
        assertEquals(Set.of(path("password")), selection("attributes=password").getIncludedAttributes()); // Rendering still strips never.
        assertThrows(UnsupportedOperationException.class, () -> include.getIncludedAttributes().clear());
    }

    @Test void projectionLimitsCountInputPathsBeforeDeduplication() {
        ScimLimits limits = ScimLimits.builder().maximumProjectionPaths(2).build();
        assertInstanceOf(ScimQueryParseResult.Succeeded.class, query("attributes=userName,USERNAME", CONFIG, limits));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("attributes=userName,USERNAME,userName", CONFIG, limits));
        String extension = ScimSchema.enterpriseUserInstance().getId();
        assertEquals(Set.of(path(extension + ":department")), selection("attributes=" + extension + ":DEPARTMENT").getIncludedAttributes());
    }

    @Test void sortingIsBoundAndCannotExposeNeverValuesOrIgnoredClauses() {
        ScimQuery sorted = success(query("sortBy=USERNAME&sortOrder=DESCENDING", CONFIG, LIMITS));
        assertEquals(path("userName"), sorted.getSortBy().orElseThrow()); assertEquals(ScimSortOrder.DESCENDING, sorted.getSortOrder().orElseThrow());
        assertEquals(ScimSortOrder.ASCENDING, success(query("sortBy=userName", CONFIG, LIMITS)).getSortOrder().orElseThrow());
        for (String raw : List.of("sortOrder=ascending", "sortBy=userName&sortOrder=wrong", "sortBy=unknown", "sortBy=password", "sortBy=name"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query(raw, CONFIG, LIMITS));
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("sortBy=userName", ScimServiceProviderConfig.builder().build(), LIMITS));
    }

    @Test void cursorFramingSeparatesPresenceFirstPageAndRequestedCount() {
        ScimServiceProviderConfig config = cursorConfig(ScimPaginationMethod.INDEX);
        ScimQuery first = success(query("cursor=&count=0", config, LIMITS));
        assertEquals(ScimPaginationMethod.CURSOR, first.getPaginationMethod()); assertTrue(first.isFirstCursorPage());
        assertTrue(first.getStartIndex().isEmpty()); assertEquals("", first.getCursor().orElseThrow());
        assertEquals(0, first.getCount()); assertEquals(0L, first.getRequestedCount().orElseThrow());
        ScimQuery later = success(query("cursor=a-B_c.~9&count=2", config, LIMITS));
        assertFalse(later.isFirstCursorPage()); assertEquals("a-B_c.~9", later.getCursor().orElseThrow()); assertEquals(2, later.getCount());
        ScimQuery implicit = success(query("", cursorConfig(ScimPaginationMethod.CURSOR), LIMITS));
        assertTrue(implicit.isFirstCursorPage()); assertTrue(implicit.getCursor().isEmpty()); assertTrue(implicit.getStartIndex().isEmpty());
        assertEquals(ScimPaginationMethod.INDEX, success(query("startIndex=2", cursorConfig(ScimPaginationMethod.CURSOR), LIMITS)).getPaginationMethod());
        assertEquals(ScimErrorType.INVALID_COUNT, error(query("cursor=&count=1001", config, LIMITS)).getErrorType().orElseThrow());
        for (String raw : List.of("cursor=a&startIndex=1", "cursor=a+b", "cursor=%2F", "cursor=é", "cursor=" + "a".repeat(2049)))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, query(raw, config, LIMITS));
        assertEquals(ScimErrorType.INVALID_CURSOR, error(query("cursor=", CONFIG, LIMITS)).getErrorType().orElseThrow());
    }
    @Test void implicitCursorCountClampsToFilterMaximum() {
        ScimServiceProviderConfig config = ScimServiceProviderConfig.builder()
                .filterSupported(true).filterMaximumResults(50)
                .pagination(ScimPaginationConfig.builder().cursorSupported(true)
                        .defaultMethod(ScimPaginationMethod.CURSOR)
                        .cursorTimeout(Duration.ofMinutes(5)).build()).build();
        ScimQuery implicit = success(query("filter=userName+pr", config, LIMITS));
        assertEquals(50, implicit.getCount());
        assertTrue(implicit.getRequestedCount().isEmpty());
        assertEquals(ScimErrorType.INVALID_COUNT,
                error(query("filter=userName+pr&count=100", config, LIMITS))
                        .getErrorType().orElseThrow());
    }

    @Test void getAndSearchProduceEquivalentApprovedQueryData() {
        ScimQuery get = success(query("filter=userName+eq+%22alice%22&attributes=userName,name.givenName&sortBy=userName&sortOrder=descending&startIndex=5&count=2", CONFIG, LIMITS));
        ScimQuery post = success(search("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"filter\":\"userName eq \\\"alice\\\"\",\"attributes\":[\"userName\",\"name.givenName\"],\"sortBy\":\"userName\",\"sortOrder\":\"descending\",\"startIndex\":5,\"count\":2}", CONFIG));
        assertEquals(get.getResourceType(), post.getResourceType()); assertEquals(get.getFilter(), post.getFilter());
        assertEquals(get.getAttributeSelection().getIncludedAttributes(), post.getAttributeSelection().getIncludedAttributes());
        assertEquals(get.getSortBy(), post.getSortBy()); assertEquals(get.getSortOrder(), post.getSortOrder());
        assertEquals(get.getPaginationMethod(), post.getPaginationMethod()); assertEquals(get.getStartIndex(), post.getStartIndex());
        assertEquals(get.getCount(), post.getCount()); assertEquals(get.getRequestedCount(), post.getRequestedCount());
    }

    @Test void searchRejectsWrongShapesUnknownFieldsAndNonIntegerWireSyntax() {
        String schema = "\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"]";
        for (String json : List.of("[]", "{}", "{\"schemas\":[]}", "{\"schemas\":[\"urn:wrong\"]}", "{" + schema + ",\"unknown\":true}",
                "{" + schema + ",\"count\":\"1\"}", "{" + schema + ",\"count\":1.0}", "{" + schema + ",\"count\":1e0}",
                "{" + schema + ",\"startIndex\":1.0}", "{" + schema + ",\"filter\":true}", "{" + schema + ",\"cursor\":null}",
                "{" + schema + ",\"attributes\":\"userName\"}", "{" + schema + ",\"attributes\":[]}",
                "{" + schema + ",\"attributes\":[1]}", "{" + schema + ",\"attributes\":[\"unknown\"]}"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, search(json, CONFIG));
        assertEquals(0, success(search("{" + schema + ",\"count\":-5}", CONFIG)).getCount());
        assertEquals(0, success(search("{" + schema + ",\"count\":-0}", CONFIG)).getCount());
    }

    @Test void selectionAndDiscoveryDoNotAccidentallyParseCollectionSemantics() {
        assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, ScimQueries.selection(TYPE, "count=wrong&sortBy=unknown",
                LIMITS, CONTEXT, new ScimWork(1000000)));
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class, ScimQueries.discoverySelection(TYPE, "filter=&attributes=userName",
                LIMITS, CONTEXT, new ScimWork(1000000)));
        assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, ScimQueries.discoverySelection(TYPE, "count=wrong&attributes=userName",
                LIMITS, CONTEXT, new ScimWork(1000000)));
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class, ScimQueries.discoverySelection(TYPE, "ignored=%FF",
                LIMITS, CONTEXT, new ScimWork(1000000)));
    }

    @Test void exhaustionAndDiagnosticsNeverProducePartialQueriesOrRequestData() {
        ScimWork work = new ScimWork(1);
        ScimQueryParseResult result = ScimQueries.query(TYPE, "count=2", CONFIG, LIMITS, STRICT, CONTEXT, binding(), new LinkedHashSet<>(), work);
        assertInstanceOf(ScimQueryParseResult.Rejected.class, result); assertTrue(work.wasExceeded());
        result = query("filter=PRIVATE_LITERAL", CONFIG, LIMITS);
        assertFalse(result.toString().contains("PRIVATE_LITERAL")); assertFalse(error(result).getDetail().contains("PRIVATE_LITERAL"));
        assertFalse(success(query("filter=userName+eq+%22PRIVATE_LITERAL%22", CONFIG, LIMITS)).toString().contains("PRIVATE_LITERAL"));
    }

    @Test void searchBodyCountsNamesAndEveryProjectionValueBeforeBinding() {
        String schema = "\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"]";
        for (String body : List.of("{\"schemas\":true}", "{\"schemas\":[1]}",
                "{\"schemas\":[\"" + "x".repeat(8193) + "\"]}",
                "{" + schema + ",\"count\":9223372036854775808}",
                "{" + schema + ",\"count\":-9223372036854775809}",
                "{" + schema + ",\"attributes\":[\"" + "x".repeat(8193) + "\"]}",
                "{" + schema + ",\"filter\":\"" + "x".repeat(8193) + "\"}",
                "{" + schema + ",\"" + "x".repeat(8193) + "\":true}"))
            assertInstanceOf(ScimQueryParseResult.Rejected.class, search(body, CONFIG));
        ScimQuery selected = success(search("{" + schema + ",\"excludedAttributes\":[\"emails\"]}", CONFIG));
        assertEquals(Set.of(path("emails")), selected.getAttributeSelection().getExcludedAttributes());
        ScimLimits small = ScimLimits.builder().maximumProjectionPaths(1).build();
        assertInstanceOf(ScimQueryParseResult.Rejected.class, searchWith("{" + schema
                + ",\"attributes\":[\"userName\",\"userName\"]}", small, new ScimWork(1000000)));
        small = ScimLimits.builder().maximumQueryParameters(1).build();
        assertInstanceOf(ScimQueryParseResult.Rejected.class, searchWith("{" + schema + ",\"count\":1}", small, new ScimWork(1000000)));
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class, ScimQueries.selection(TYPE, "ignored=%FF", LIMITS, CONTEXT, new ScimWork(1000000)));
    }

    @Test void originalBudgetSpansRawAndBodyProjectionFilterAndSortStages() {
        String body = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],"
                + "\"attributes\":[\"userName\"],\"filter\":\"userName eq \\\"alice\\\"\",\"sortBy\":\"userName\",\"count\":1}";
        for (int budget = 0; budget <= 2000; budget += 10) {
            ScimWork work = new ScimWork(budget);
            ScimQueryParseResult result = searchWith(body, LIMITS, work);
            if (work.wasExceeded()) assertInstanceOf(ScimQueryParseResult.Rejected.class, result);
            work = new ScimWork(budget);
            result = ScimQueries.query(TYPE, "attributes=userName&sortBy=userName", CONFIG, LIMITS, STRICT,
                    CONTEXT, binding(), new LinkedHashSet<>(), work);
            if (work.wasExceeded()) assertInstanceOf(ScimQueryParseResult.Rejected.class, result);
        }
    }

    @Test void cursorOnlyRoutesAndWhitespacePathsHavePreciseFraming() {
        ScimServiceProviderConfig onlyCursor = ScimServiceProviderConfig.builder().pagination(ScimPaginationConfig.builder()
                .indexSupported(false).cursorSupported(true).defaultMethod(ScimPaginationMethod.CURSOR)
                .cursorTimeout(Duration.ofMinutes(1)).build()).build();
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("startIndex=1", onlyCursor, LIMITS));
        assertEquals(ScimPaginationMethod.CURSOR, success(query("cursor=&count=-1", onlyCursor, LIMITS)).getPaginationMethod());
        assertEquals(Set.of(path("userName")), selection("attributes=%09%0D%0A%0CuserName%09%0D%0A%0C").getIncludedAttributes());
        assertEquals(ScimSortOrder.ASCENDING, success(query("sortBy=userName&sortOrder=ascending", CONFIG, LIMITS)).getSortOrder().orElseThrow());
        assertInstanceOf(ScimQueryParseResult.Rejected.class, query("sortBy=name..value", CONFIG, LIMITS));
        for (String raw : List.of("x=%0g", "x=%1a", "x=%af", "x=%E2%82%ac", "x=漢", "x=\udc00", "x=\ud800x", "count=" + "9".repeat(100))) {
            ScimQueryParseResult result = query(raw, CONFIG, LIMITS);
            if (raw.equals("x=%1a") || raw.equals("x=%E2%82%ac") || raw.equals("x=漢")) assertInstanceOf(ScimQueryParseResult.Succeeded.class, result);
            else assertInstanceOf(ScimQueryParseResult.Rejected.class, result);
        }
    }

    private static @NonNull ScimQueryParseResult searchWith(@NonNull String json, @NonNull ScimLimits limits, @NonNull ScimWork work) {
        JsonDocument document = ((JsonParseResult.Succeeded) JsonCodec.parseResult(json.getBytes(StandardCharsets.UTF_8),
                JsonLimits.scim(2 * 1024 * 1024, 100000))).getDocument();
        return ScimQueries.search(TYPE, document, CONFIG, limits, STRICT, CONTEXT, binding(), new LinkedHashSet<>(), work);
    }

    private static @NonNull ScimQueryParseResult query(@NonNull String raw, @NonNull ScimServiceProviderConfig config, @NonNull ScimLimits limits) {
        return ScimQueries.query(TYPE, raw, config, limits, STRICT, CONTEXT, binding(), new LinkedHashSet<>(), new ScimWork(1000000));
    }
    private static @NonNull ScimFilterBinding binding() {
        return new ScimFilterBinding(TYPE, ScimFilterLimits.defaultInstance(), STRICT,
                ScimFilterPolicy.builder().allowedComparisons(Map.of("userName", Set.of(ScimComparisonOperator.EQ)))
                        .allowedPresence(Set.of("userName")).build(), true);
    }
    private static @NonNull ScimAttributeSelection selection(@NonNull String raw) {
        return ((ScimAttributeSelectionResult.Succeeded) ScimQueries.selection(TYPE, raw, LIMITS, CONTEXT, new ScimWork(1000000))).getAttributeSelection();
    }
    private static @NonNull ScimQuery success(@NonNull ScimQueryParseResult result) {
        return assertInstanceOf(ScimQueryParseResult.Succeeded.class, result).getQuery();
    }
    private static @NonNull ScimError error(@NonNull ScimQueryParseResult result) {
        return assertInstanceOf(ScimQueryParseResult.Rejected.class, result).getError();
    }
    private static @NonNull ScimQueryParseResult search(@NonNull String json, @NonNull ScimServiceProviderConfig config) {
        JsonDocument document = ((JsonParseResult.Succeeded) JsonCodec.parseResult(json.getBytes(StandardCharsets.UTF_8), JsonLimits.scim(2 * 1024 * 1024, 100000))).getDocument();
        return ScimQueries.search(TYPE, document, config, LIMITS, STRICT, CONTEXT, binding(), new LinkedHashSet<>(), new ScimWork(1000000));
    }
    private static @NonNull ScimServiceProviderConfig cursorConfig(@NonNull ScimPaginationMethod method) {
        return ScimServiceProviderConfig.builder().filterSupported(true).sortSupported(true).pagination(ScimPaginationConfig.builder()
                .cursorSupported(true).cursorTimeout(Duration.ofMinutes(5)).defaultMethod(method).build()).build();
    }
    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return ((ScimAttributePathParseResult.Succeeded) ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
}
