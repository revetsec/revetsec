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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SCIM-A13/A19/A22/A29: original physical headers and bounded query/resource ingress, with an independent
 * GET/SearchRequest framing model. All records and seeds are synthetic. Choice zero exercises ordinary query
 * parsing. Hand-authored header expectations and JDK URL encoding supply the oracle; no production parser
 * calculates an expected result.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class ScimRc3IngressFuzzTests {
    private static final @NonNull String CORE = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String SEARCH = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private static final @NonNull String PRIVATE = "rc3-transient-private-";
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull ScimLimits LIMITS = ScimLimits.builder().maximumBodyBytes(16_384)
            .maximumJsonNodes(1_000).maximumRawQueryBytes(1_024).maximumParameterCharacters(256)
            .maximumQueryParameters(12).maximumPageSize(10).maximumConditionalHeaderBytes(256)
            .maximumConditionalTags(8).maximumResponseBytes(2_048).maximumResponseHeaderBytes(512)
            .maximumWorkUnits(10_000).build();
    private static final @NonNull ScimServiceProvider OWN = provider();
    private static final @NonNull ScimServiceProvider FOREIGN = provider();
    private static final @NonNull ScimResource CURRENT = resource("fixture-before", PRIVATE + "retained");
    private static final @NonNull List<@NonNull List<@NonNull String>> MEDIA = List.of(
            List.of("application/scim+json"), List.of("APPLICATION/JSON; charset=\"UTF-8\""),
            List.of(), List.of("application/scim+json", "application/scim+json"),
            List.of("application/scim+json, application/json"), List.of("application/scim+json\r\nX-Test: fixture"),
            List.of("application/scim+json; boundary=fixture"), List.of("text/plain"));
    private static final @NonNull List<@NonNull List<@NonNull String>> TAGS = List.of(
            List.of(), List.of("*"), List.of("W/\"rc3\""), List.of("\"rc3\""), List.of("\"other\""),
            List.of("\"other\"", "W/\"rc3\""), List.of("*", "\"rc3\""),
            List.of("\"rc3\"\r\nX-Test: fixture"), List.of("W/\"unterminated"),
            List.of("\"other\", W/\"rc3\""));
    private static final @NonNull Set<@NonNull String> FIXED_DETAILS = Set.of(
            "Invalid filter expression.", "Too many matching resources.", "Invalid request syntax.",
            "Invalid attribute path.", "The operation has no target.", "Invalid attribute value.",
            "The operation violates attribute mutability.", "Invalid SCIM version.",
            "Invalid pagination cursor.", "The pagination cursor has expired.", "Invalid pagination count.",
            "The operation violates attribute uniqueness.", "The sensitive operation is forbidden.",
            "Authentication is required.", "The operation is forbidden.", "The resource was not found.",
            "The request precondition was not satisfied.", "The request exceeds the size limit.",
            "Unsupported media type.", "The request method is not allowed.", "The operation is not implemented.",
            "The response exceeds the size limit.", "The service is unavailable.");

    /** Arbitrary ingress remains bounded, while generated legal framing obeys independently authored results. */
    @FuzzTest(maxDuration = "5m")
    public void physicalHeadersQueriesAndBodiesPreserveBoundsPrivacyAndProvenance(byte @NonNull [] input) {
        byte[] payload = input.length == 0 ? input : Arrays.copyOfRange(input, 1, input.length);
        String raw = new String(payload, StandardCharsets.UTF_8);
        JsonObject before = CURRENT.getDocument();
        switch (octet(input, 0) % 4) {
            case 0 -> queryOutcome(OWN.parseQueryResult(USER, raw));
            case 1 -> {
                // NUL separates original physical occurrences; it is never comma-coalesced by this target.
                List<String> fields = Arrays.asList(raw.split("\u0000", -1));
                ScimContentTypeResult media = OWN.validateContentTypeResult(fields);
                if (media instanceof ScimContentTypeResult.Rejected rejected) fixed(rejected.getError());
                if (fields.size() != 1) Assertions.assertInstanceOf(ScimContentTypeResult.Rejected.class, media);
                conditionalOutcome(OWN.checkIfMatchResult(fields, CURRENT), OWN.checkIfNoneMatchResult(fields, CURRENT));
            }
            case 2 -> {
                List<String> fields = MEDIA.get(octet(input, 1) % MEDIA.size());
                queryOutcome(OWN.parseSearchRequestResult(USER, fields, payload));
                resourceOutcome(OWN.parseResourceResult(USER, fields, payload));
                resourceOutcome(OWN.parseReplacementResult(USER, CURRENT, fields, payload));
            }
            default -> {
                queryOutcome(OWN.parseSearchRequestResult(USER, payload));
                resourceOutcome(OWN.parseResourceResult(USER, payload));
                resourceOutcome(OWN.parseReplacementResult(USER, CURRENT, payload));
            }
        }
        model(input);
        Assertions.assertSame(before, CURRENT.getDocument());
        Assertions.assertEquals("fixture-before", CURRENT.getDocument().find("userName").map(com.revetsec.json.JsonString.class::cast).map(com.revetsec.json.JsonString::getValue).orElseThrow());
        Assertions.assertEquals(PRIVATE + "retained", CURRENT.getDocument().find("password").map(com.revetsec.json.JsonString.class::cast).map(com.revetsec.json.JsonString::getValue).orElseThrow());
    }

    private static void model(byte @NonNull [] input) {
        int requested = octet(input, 1) % 21;
        long start = 1L + octet(input, 2);
        String suffix = HexFormat.of().formatHex(Arrays.copyOf(input, Math.min(input.length, 16)));
        String name = "fixture-" + suffix;
        String filter = "userName eq \"" + name + "%2F+\"";
        String query = "startIndex=" + start + "&count=" + requested + "&filter="
                + URLEncoder.encode(filter, StandardCharsets.UTF_8) + "&sortBy=userName&sortOrder=descending&attributes=userName,password";
        // Literal names contain only authored ASCII/hex, so this independent JSON framing needs no escaping beyond quotes.
        String search = "{\"schemas\":[\"" + SEARCH + "\"],\"startIndex\":" + start + ",\"count\":" + requested
                + ",\"filter\":\"userName eq \\\"" + name + "%2F+\\\"\",\"sortBy\":\"userName\","
                + "\"sortOrder\":\"descending\",\"attributes\":[\"userName\",\"password\"]}";
        ScimQuery get = Assertions.assertInstanceOf(ScimQueryParseResult.Succeeded.class,
                OWN.parseQueryResult(USER, query)).getQuery();
        ScimQuery post = Assertions.assertInstanceOf(ScimQueryParseResult.Succeeded.class,
                OWN.parseSearchRequestResult(USER, List.of("application/scim+json"), search.getBytes(StandardCharsets.UTF_8))).getQuery();
        for (ScimQuery approved : List.of(get, post)) {
            Assertions.assertEquals(Math.min(requested, 10), approved.getCount());
            Assertions.assertEquals((long) requested, approved.getRequestedCount().orElseThrow());
            Assertions.assertEquals(start, approved.getStartIndex().orElseThrow());
            Assertions.assertEquals(filter, approved.getFilter().orElseThrow().toScimString());
            Assertions.assertEquals("userName", approved.getSortBy().orElseThrow().getAttributeName());
            Assertions.assertSame(ScimSortOrder.DESCENDING, approved.getSortOrder().orElseThrow());
            Assertions.assertEquals(ScimPaginationMethod.INDEX, approved.getPaginationMethod());
            Assertions.assertTrue(approved.getCursor().isEmpty());
            Assertions.assertEquals(Set.of("userName", "password"), approved.getAttributeSelection().getIncludedAttributes().stream()
                    .map(ScimAttributePath::getAttributeName).collect(Collectors.toSet()));
            ScimListPage empty = ScimListPage.withQuery(approved).totalResults(start + 1).build();
            bounded(Assertions.assertInstanceOf(ScimResponseResult.Prepared.class, OWN.listResponseResult(empty)).getResponse());
            Assertions.assertInstanceOf(ScimResponseResult.Rejected.class, FOREIGN.listResponseResult(empty));
        }
        ScimResource persisted = resource(name, PRIVATE + suffix);
        JsonObject document = persisted.getDocument();
        ScimAttributeSelection own = get.getAttributeSelection();
        ScimAttributeSelection foreign = Assertions.assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                FOREIGN.parseAttributeSelectionResult(USER, "attributes=userName")).getAttributeSelection();
        Assertions.assertInstanceOf(ScimResponseResult.Rejected.class, OWN.resourceResponseResult(persisted, foreign));
        bounded(Assertions.assertInstanceOf(ScimResponseResult.Prepared.class,
                OWN.resourceResponseResult(persisted, own)).getResponse());
        Assertions.assertSame(document, persisted.getDocument());
        Assertions.assertEquals(PRIVATE + suffix, persisted.getDocument().find("password").map(com.revetsec.json.JsonString.class::cast).map(com.revetsec.json.JsonString::getValue).orElseThrow());
        Assertions.assertFalse(persisted.toString().contains(PRIVATE));

        int mediaChoice = octet(input, 3) % MEDIA.size();
        ScimContentTypeResult media = OWN.validateContentTypeResult(MEDIA.get(mediaChoice));
        if (mediaChoice < 2) Assertions.assertInstanceOf(ScimContentTypeResult.Accepted.class, media);
        else Assertions.assertSame(ScimError.unsupportedMediaTypeInstance(),
                Assertions.assertInstanceOf(ScimContentTypeResult.Rejected.class, media).getError());
        int tagChoice = octet(input, 4) % TAGS.size();
        ScimIfMatchResult match = OWN.checkIfMatchResult(TAGS.get(tagChoice), CURRENT);
        ScimIfNoneMatchResult none = OWN.checkIfNoneMatchResult(TAGS.get(tagChoice), CURRENT);
        if (tagChoice >= 6 && tagChoice <= 8) {
            Assertions.assertSame(ScimError.invalidSyntaxInstance(),
                    Assertions.assertInstanceOf(ScimIfMatchResult.Rejected.class, match).getError());
            Assertions.assertSame(ScimError.invalidSyntaxInstance(),
                    Assertions.assertInstanceOf(ScimIfNoneMatchResult.Rejected.class, none).getError());
        } else if (tagChoice == 4) {
            Assertions.assertSame(ScimError.preconditionFailedInstance(),
                    Assertions.assertInstanceOf(ScimIfMatchResult.Rejected.class, match).getError());
            Assertions.assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, none);
        } else {
            Assertions.assertInstanceOf(ScimIfMatchResult.Satisfied.class, match);
            if (tagChoice == 0) Assertions.assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, none);
            else Assertions.assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, none);
        }
        // These pairs are hand-enumerated invalid controls, not expectations copied from another parser.
        Assertions.assertInstanceOf(ScimQueryParseResult.Rejected.class,
                OWN.parseQueryResult(USER, "count=1&COUNT=2"));
        Assertions.assertInstanceOf(ScimQueryParseResult.Rejected.class,
                OWN.parseQueryResult(USER, "filter=password%20eq%20%22fixture%22"));
        Assertions.assertInstanceOf(ScimQueryParseResult.Rejected.class,
                OWN.parseSearchRequestResult(USER, ("{\"schemas\":[\"" + SEARCH + "\"],\"count\":1e0}")
                        .getBytes(StandardCharsets.UTF_8)));
    }

    private static @NonNull ScimServiceProvider provider() {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER)).limits(LIMITS).compatibility(ScimCompatibility.strictInstance())
                .filterPolicies(Map.of(USER, ScimFilterPolicy.builder().allowedComparisons(Map.of("userName",
                        Set.of(ScimComparisonOperator.EQ))).build()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).sortSupported(true)
                        .filterMaximumResults(10).pagination(ScimPaginationConfig.builder().defaultPageSize(3).maximumPageSize(10).build()).build())
                .build();
    }

    private static @NonNull ScimResource resource(@NonNull String name, @NonNull String password) {
        return ScimResource.withResourceType(USER).document(JsonObject.builder()
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(CORE))))
                .put("id", "fixture-id").put("userName", name).put("password", password)
                .put("meta", JsonObject.builder().put("version", "W/\"rc3\"")
                        .put("location", "https://example.test/scim/Users/fixture-id").build()).build()).build();
    }

    private static int octet(byte @NonNull [] input, int index) { return index < input.length ? Byte.toUnsignedInt(input[index]) : 0; }

    private static void queryOutcome(@NonNull ScimQueryParseResult result) {
        if (result instanceof ScimQueryParseResult.Rejected rejected) { fixed(rejected.getError()); return; }
        ScimQuery query = ((ScimQueryParseResult.Succeeded) result).getQuery();
        Assertions.assertSame(USER, query.getResourceType());
        Assertions.assertTrue(query.getCount() >= 0 && query.getCount() <= 10);
        query.getStartIndex().ifPresent(value -> Assertions.assertTrue(value >= 1));
        Assertions.assertFalse(query.toString().contains(PRIVATE));
    }

    private static void resourceOutcome(@NonNull ScimResourceParseResult result) {
        if (result instanceof ScimResourceParseResult.Rejected rejected) { fixed(rejected.getError()); return; }
        ScimResourceParseResult.Succeeded parsed = (ScimResourceParseResult.Succeeded) result;
        for (ScimAttributePath path : parsed.getSuppliedAttributePaths()) {
            Assertions.assertNotEquals("id", path.getAttributeName());
            Assertions.assertNotEquals("meta", path.getAttributeName());
        }
        Assertions.assertFalse(parsed.toString().contains(PRIVATE));
    }

    private static void conditionalOutcome(@NonNull ScimIfMatchResult match, @NonNull ScimIfNoneMatchResult none) {
        if (match instanceof ScimIfMatchResult.Rejected rejected) fixed(rejected.getError());
        if (none instanceof ScimIfNoneMatchResult.Rejected rejected) fixed(rejected.getError());
    }

    private static void fixed(@NonNull ScimError error) {
        Assertions.assertNotSame(ScimError.internalErrorInstance(), error);
        Assertions.assertTrue(Set.of(400, 403, 412, 413, 415, 501).contains(error.getStatusCode()));
        Assertions.assertTrue(FIXED_DETAILS.contains(error.getDetail()));
        Assertions.assertFalse(error.getDetail().contains(PRIVATE));
        Assertions.assertFalse(error.toString().contains(PRIVATE));
        error.getExpressionOffset().ifPresent(offset -> Assertions.assertTrue(offset >= 0 && offset <= 8_192));
    }

    private static void bounded(@NonNull ScimResponse response) {
        int headers = response.getHeaders().entrySet().stream().mapToInt(entry -> entry.getValue().stream()
                .mapToInt(value -> (entry.getKey() + ": " + value + "\r\n").getBytes(StandardCharsets.UTF_8).length).sum()).sum();
        byte[] body = response.toHttpBodyWithPersonalData();
        Assertions.assertTrue(headers <= 512);
        Assertions.assertTrue(body.length + headers + 128 <= 2_048);
        Assertions.assertEquals(List.of("private, no-store"), response.getHeaders().get("Cache-Control"));
        String wire = new String(body, StandardCharsets.UTF_8);
        Assertions.assertFalse(wire.contains("\"password\""));
        Assertions.assertFalse(wire.contains(PRIVATE));
        if (body.length > 0) {
            byte first = body[0]; body[0] ^= 1;
            Assertions.assertEquals(first, response.toHttpBodyWithPersonalData()[0]);
        }
    }

    /** The exact authored corpus is nonempty, synthetic, target-local, and SHA-256 bound. */
    @Test
    void authoredIngressSeedsMatchTheirCompleteManifest() throws Exception {
        Path core = Path.of(System.getProperty("revetsec.core.basedir", "..")).toAbsolutePath().normalize();
        Path resources = core.resolve("fuzz/src/test/resources");
        Path target = resources.resolve("com/revetsec/scim/ScimRc3IngressFuzzTestsInputs/physicalHeadersQueriesAndBodiesPreserveBoundsPrivacyAndProvenance");
        Set<String> expected = new TreeSet<>();
        for (String line : Files.readAllLines(resources.resolve("com/revetsec/scim/rc3-ingress-seeds.sha256"))) {
            Assertions.assertTrue(line.matches("[0-9a-f]{64}  [a-z0-9-]+\\.bin"));
            String name = line.substring(66);
            Assertions.assertTrue(expected.add(name));
            byte[] bytes = Files.readAllBytes(target.resolve(name));
            Assertions.assertTrue(bytes.length > 0 && bytes.length <= 16_386);
            Assertions.assertEquals(line.substring(0, 64), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        }
        try (Stream<Path> paths = Files.list(target)) {
            Assertions.assertEquals(expected, paths.filter(Files::isRegularFile).map(path -> path.getFileName().toString()).collect(Collectors.toSet()));
        }
        Assertions.assertTrue(expected.size() >= 32);
    }
}
