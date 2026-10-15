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
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;

/** Independent bytes, full discovery fields, buffer bounds and response-carrier contracts. */
final class ScimM10ResponseTests {
    private static final @NonNull ScimLimits FLOOR = ScimLimits.builder().maximumResponseBytes(2_048).maximumResponseHeaderBytes(512).build();

    @Test void streamsExactUtf8EscapesNumbersAndRepeatedValuesWithoutChangingTheJsonModel() {
        JsonObject body = JsonObject.builder().put("text", "\"\\\b\f\n\r\t\u0001\u007f\u00e9\u2028\ud83d\ude80")
                .put("number", new BigDecimal("1.50E+30")).put("truth", true).putNull("null")
                .put("array", JsonArray.fromElements(List.of(JsonNumber.fromValue(-1L), JsonObject.emptyInstance()))).build();
        byte[] expected = ("{\"text\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\u007f\u00e9\u2028\ud83d\ude80\","
                + "\"number\":1.50E+30,\"truth\":true,\"null\":null,\"array\":[-1,{}]}").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, ScimJsonOutput.write(body, expected.length, new ScimWork(10_000)));
        assertNull(ScimJsonOutput.write(body, expected.length - 1, new ScimWork(10_000)));
    }

    @Test void canonicalNumberLengthsAreCheckedBeforeEmissionForEveryNotationShape() {
        Map<String, String> expected = Map.of("0", "0", "0.000001", "0.000001", "0.0000001", "1E-7", "0E-10", "0E-10",
                "-1E+30", "-1E+30", "1.50", "1.50", "1000", "1000", "-0.000001", "-0.000001");
        for (Map.Entry<String, String> row : expected.entrySet()) {
            JsonNumber value = JsonNumber.fromValue(new BigDecimal(row.getKey()));
            byte[] bytes = row.getValue().getBytes(StandardCharsets.US_ASCII);
            assertArrayEquals(bytes, ScimJsonOutput.write(value, bytes.length, new ScimWork(10_000)));
            assertNull(ScimJsonOutput.write(value, bytes.length - 1, new ScimWork(10_000)));
        }
    }

    @Test void everyEmittedChunkStopsAtEachInsufficientByteBoundary() {
        List<JsonValue> values = List.of(JsonObject.emptyInstance(), JsonArray.emptyInstance(), JsonNull.defaultInstance(),
                JsonBoolean.trueInstance(), JsonBoolean.falseInstance(), JsonString.fromValue(""), JsonString.fromValue("a"),
                JsonString.fromValue("\""), JsonString.fromValue("\\"), JsonString.fromValue("\u0001"), JsonString.fromValue("\n"),
                JsonString.fromValue("\u00e9"), JsonString.fromValue("\u4e2d"), JsonString.fromValue("\ud83d\ude80"),
                JsonArray.fromElements(List.of(JsonNull.defaultInstance(), JsonBoolean.falseInstance())),
                JsonObject.builder().put("a", true).put("b", false).build());
        List<String> texts = List.of("{}", "[]", "null", "true", "false", "\"\"", "\"a\"", "\"\\\"\"", "\"\\\\\"", "\"\\u0001\"", "\"\\n\"",
                "\"\u00e9\"", "\"\u4e2d\"", "\"\ud83d\ude80\"", "[null,false]", "{\"a\":true,\"b\":false}");
        for (int row = 0; row < values.size(); ++row) {
            byte[] expected = texts.get(row).getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(expected, ScimJsonOutput.write(values.get(row), expected.length, new ScimWork(10_000)));
            for (int limit = 0; limit < expected.length; ++limit)
                assertNull(ScimJsonOutput.write(values.get(row), limit, new ScimWork(10_000)), "row " + row + " limit " + limit);
        }
        assertNull(ScimJsonOutput.write(JsonObject.emptyInstance(), 10, new ScimWork(0)));
    }

    @Test void preparedHeadersHandleUtf8SupplementaryCharactersControlsAndCumulativeBudgets() {
        JsonObject body = JsonObject.emptyInstance();
        for (String value : List.of("\u00e9", "\u4e2d", "\ud83d\ude80", "valid\tvalue", ""))
            assertEquals(List.of(value), prepared(body, Map.of("X", List.of(value))).getHeaders().get("X"));
        for (String value : List.of("bad\udc00", "bad\ud800x", "bad\u007f", "a".repeat(513), "\u00e9".repeat(300)))
            assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body, Map.of("X", List.of(value)), new ScimWork(10_000)));
        for (Map<String, List<String>> headers : List.<Map<String, List<String>>>of(Map.of("", List.of("x")), Map.of("bad name", List.of("x")),
                Map.of("a".repeat(513), List.of("x")), Map.of("X", List.of()), Map.of("X", java.util.Collections.nCopies(513, ""))))
            assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body, headers, new ScimWork(10_000)));
        ScimLimits headerRoom = ScimLimits.builder().maximumResponseBytes(2_048).build();
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(headerRoom, 200, body,
                Map.of("X", List.of("a".repeat(2_048))), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Prepared.class, ScimResponses.prepare(FLOOR, 200, null, Map.of(), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 204, body, Map.of(), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 99, body, Map.of(), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 600, body, Map.of(), new ScimWork(10_000)));
        int headerBytes = "Cache-Control: private, no-store\r\nContent-Type: application/scim+json\r\n".length();
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body, Map.of(), new ScimWork(headerBytes + 127)));
    }

    @Test void outputBudgetIncludesHeaderOccurrencesUtf8BytesAndTheFramingAllowance() {
        String prefix = "{\"value\":\"";
        String suffix = "\"}";
        int headers = "Cache-Control: private, no-store\r\nContent-Type: application/scim+json\r\n".length();
        int bodyBytes = 2_048 - 128 - headers;
        String value = "a".repeat(bodyBytes - prefix.length() - suffix.length());
        JsonObject body = JsonObject.builder().put("value", value).build();
        ScimResponse exact = prepared(body, Map.of());
        assertEquals(bodyBytes, exact.toHttpBodyWithPersonalData().length);
        assertSame(ScimError.responseTooLargeInstance(), rejected(JsonObject.builder().put("value", value + "a").build(), Map.of()));
        assertSame(ScimError.responseTooLargeInstance(), rejected(body, Map.of("X", List.of("\u00e9"))));
    }

    @Test void headerLimitCountsEveryOccurrenceAndEncodedByteAndRejectsInjection() {
        JsonObject body = JsonObject.emptyInstance();
        int defaults = "Cache-Control: private, no-store\r\nContent-Type: application/scim+json\r\n".length();
        int remaining = 512 - defaults - "X: \r\n".length();
        assertEquals(200, prepared(body, Map.of("X", List.of("a".repeat(remaining)))).getStatusCode());
        assertSame(ScimError.responseTooLargeInstance(), rejected(body, Map.of("X", List.of("a".repeat(remaining + 1)))));
        assertSame(ScimError.responseTooLargeInstance(), rejected(body, Map.of("X", List.of("a".repeat(remaining), ""))));
        for (String value : List.of("bad\r\nX: injected", "bad\u0000", "bad\ud800"))
            assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body,
                    Map.of("X", List.of(value)), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body,
                Map.of("content-type", List.of("text/plain")), new ScimWork(10_000)));
    }

    @Test void enormousExpandedSharedTreesAndExhaustedWorkRejectBeforeUnboundedEmission() {
        JsonValue value = JsonString.fromValue("payload");
        for (int index = 0; index < 40; ++index) value = JsonArray.fromElements(List.of(value, value));
        JsonObject body = JsonObject.builder().put("tree", value).build();
        assertSame(ScimError.responseTooLargeInstance(), rejected(body, Map.of()));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, JsonObject.emptyInstance(), Map.of(), new ScimWork(10)));
    }

    @Test void preparedBodiesAndNestedHeaderListsAreDefensivelyImmutableAndDiagnosticsRedacted() {
        LinkedHashMap<String, List<String>> headers = new LinkedHashMap<>();
        List<String> values = new ArrayList<>(List.of("header-secret")); headers.put("X", values);
        byte[] body = "personal-secret".getBytes(StandardCharsets.UTF_8);
        ScimResponse response = new ScimResponse(200, headers, body);
        headers.clear(); values.clear(); body[0] = 0;
        assertEquals("header-secret", requireNonNull(response.getHeaders().get("X")).get(0));
        byte[] emitted = response.toHttpBodyWithPersonalData(); emitted[0] = 0;
        assertEquals("personal-secret", new String(response.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8));
        assertThrows(UnsupportedOperationException.class, () -> response.getHeaders().clear());
        assertThrows(UnsupportedOperationException.class, () -> requireNonNull(response.getHeaders().get("X")).clear());
        assertFalse(response.toString().contains("secret"));
    }

    @Test void allFixedErrorsAndNoContentFitMinimumBudgetsAndErrorStatusRemainsAString() throws JsonParseException {
        for (ScimError error : List.of(ScimError.invalidFilterInstance(), ScimError.tooManyInstance(), ScimError.invalidSyntaxInstance(),
                ScimError.invalidPathInstance(), ScimError.noTargetInstance(), ScimError.invalidValueInstance(), ScimError.mutabilityInstance(),
                ScimError.invalidVersionInstance(), ScimError.invalidCursorInstance(), ScimError.expiredCursorInstance(), ScimError.invalidCountInstance(),
                ScimError.uniquenessInstance(), ScimError.sensitiveInstance(), ScimError.unauthenticatedInstance(), ScimError.forbiddenInstance(),
                ScimError.notFoundInstance(), ScimError.preconditionFailedInstance(), ScimError.requestTooLargeInstance(), ScimError.unsupportedMediaTypeInstance(),
                ScimError.methodNotAllowedInstance(), ScimError.notImplementedInstance(), ScimError.internalErrorInstance(), ScimError.responseTooLargeInstance(),
                ScimError.unavailableInstance(), ScimError.invalidFilterAt(123))) {
            ScimResponse response = ScimResponses.error(error);
            JsonObject body = (JsonObject) JsonCodec.parse(response.toHttpBodyWithPersonalData(), JsonLimits.protocolDocument(2_048));
            assertEquals(JsonString.fromValue(error.getStatusCode().toString()), requireNonNull(body.getMembers().get("status")));
            assertEquals(error.getDetail(), body.find("detail").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
            assertFalse(body.getMembers().containsKey("expressionOffset"));
            assertEquals(error.getStatusCode(), response.getStatusCode());
            assertTrue(response.toHttpBodyWithPersonalData().length + encodedHeaders(response) + 128 <= 2_048);
            assertTrue(encodedHeaders(response) <= 512);
        }
        ScimResponse noContent = ScimResponses.noContent();
        assertEquals(204, noContent.getStatusCode()); assertEquals(0, noContent.toHttpBodyWithPersonalData().length);
        assertEquals(List.of("private, no-store"), noContent.getHeaders().get("Cache-Control"));
        assertInstanceOf(ScimResponseResult.Prepared.class, ScimResponses.prepare(FLOOR, 304, null,
                Map.of("ETag", List.of("W/\"v\"")), new ScimWork(10_000)));
        assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 304, JsonObject.emptyInstance(), Map.of(), new ScimWork(10_000)));
    }

    @Test void discoveryAdvertisesCompleteDisabledCapabilitiesAndExactPaginationWireNames() {
        JsonObject body = ScimDiscovery.configuration(ScimServiceProviderConfig.builder().build());
        assertEquals(JsonArray.fromElements(List.of(JsonString.fromValue("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"))), requireNonNull(body.getMembers().get("schemas")));
        JsonObject bulk = (JsonObject) requireNonNull(body.getMembers().get("bulk"));
        assertEquals(JsonObject.builder().put("supported", false).put("maxOperations", 0L).put("maxPayloadSize", 0L).build(), bulk);
        for (String feature : List.of("patch", "filter", "sort", "changePassword"))
            assertEquals(false, ((JsonObject) requireNonNull(body.getMembers().get(feature))).find("supported").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElseThrow());
        assertEquals(true, ((JsonObject) requireNonNull(body.getMembers().get("etag"))).find("supported").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElseThrow());
        assertEquals(1_000L, ((JsonObject) requireNonNull(body.getMembers().get("filter"))).find("maxResults").filter(JsonNumber.class::isInstance).map(JsonNumber.class::cast).flatMap(JsonNumber::getLongValueExact).orElseThrow());
        assertEquals(JsonArray.emptyInstance(), requireNonNull(body.getMembers().get("authenticationSchemes")));
        assertEquals(JsonObject.builder().put("cursor", false).put("index", true).put("defaultPaginationMethod", "index")
                .put("defaultPageSize", 100L).put("maxPageSize", 1_000L).build(), requireNonNull(body.getMembers().get("pagination")));
    }

    @Test void discoveryEmitsCursorMinimumValidityAndAuthenticationDetailsWithoutInventingBulkSupport() {
        ScimPaginationConfig pagination = ScimPaginationConfig.builder().cursorSupported(true).defaultMethod(ScimPaginationMethod.CURSOR)
                .cursorTimeout(Duration.ofHours(1)).defaultPageSize(100).maximumPageSize(250).build();
        ScimAuthenticationScheme scheme = ScimAuthenticationScheme.withType("oauthbearertoken").name("Bearer").description("Fixture")
                .primary(true).specUri(URI.create("https://example.com/spec")).documentationUri(URI.create("https://example.com/help")).build();
        JsonObject body = ScimDiscovery.configuration(ScimServiceProviderConfig.builder().pagination(pagination).authenticationSchemes(List.of(scheme)).build());
        JsonObject paging = (JsonObject) requireNonNull(body.getMembers().get("pagination"));
        assertEquals("cursor", paging.find("defaultPaginationMethod").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals(3_600L, paging.find("cursorTimeout").filter(JsonNumber.class::isInstance).map(JsonNumber.class::cast).flatMap(JsonNumber::getLongValueExact).orElseThrow());
        assertEquals(250L, paging.find("maxPageSize").filter(JsonNumber.class::isInstance).map(JsonNumber.class::cast).flatMap(JsonNumber::getLongValueExact).orElseThrow());
        JsonObject auth = (JsonObject) ((JsonArray) requireNonNull(body.getMembers().get("authenticationSchemes"))).getElements().get(0);
        assertEquals(JsonObject.builder().put("type", "oauthbearertoken").put("name", "Bearer").put("description", "Fixture").put("primary", true)
                .put("specUri", "https://example.com/spec").put("documentationUri", "https://example.com/help").build(), auth);
    }

    @Test void schemaAndResourceTypeDescriptorsPreserveAttributeFacetsAndExtensionRequiredFlags() {
        JsonObject userType = ScimDiscovery.resourceType(ScimResourceType.userInstance());
        assertEquals("User", userType.find("name").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("/Users", userType.find("endpoint").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("urn:ietf:params:scim:schemas:core:2.0:User", userType.find("schema").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        JsonObject extension = (JsonObject) ((JsonArray) requireNonNull(userType.getMembers().get("schemaExtensions"))).getElements().get(0);
        assertEquals("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", extension.find("schema").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals(false, extension.find("required").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElseThrow());
        JsonObject schema = ScimDiscovery.schema(ScimSchema.userInstance());
        JsonArray attrs = (JsonArray) requireNonNull(schema.getMembers().get("attributes"));
        JsonObject password = attrs.getElements().stream().map(v -> (JsonObject) v).filter(v -> v.find("name").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow().equals("password")).findFirst().orElseThrow();
        assertEquals("writeOnly", password.find("mutability").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("never", password.find("returned").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("string", password.find("type").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        JsonObject name = attrs.getElements().stream().map(v -> (JsonObject) v).filter(v -> v.find("name").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow().equals("name")).findFirst().orElseThrow();
        assertInstanceOf(JsonArray.class, requireNonNull(name.getMembers().get("subAttributes")));
    }

    @Test void customDiscoveryDescriptorsExerciseAllTypesAndDeclaredFacets() {
        List<ScimAttributeDefinition> attributes = List.of(
                ScimAttributeDefinition.withName("once").description("Fixture field").mutability(ScimMutability.IMMUTABLE)
                        .returned(ScimReturned.REQUEST).uniqueness(ScimUniqueness.GLOBAL).canonicalValues(Set.of("work", "home")).build(),
                ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),
                ScimAttributeDefinition.withName("ratio").type(ScimAttributeType.DECIMAL).build(),
                ScimAttributeDefinition.withName("counter").type(ScimAttributeType.INTEGER).build(),
                ScimAttributeDefinition.withName("instant").type(ScimAttributeType.DATE_TIME).build(),
                ScimAttributeDefinition.withName("bytes").type(ScimAttributeType.BINARY).build(),
                ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).referenceTypes(Set.of("uri")).build(),
                ScimAttributeDefinition.withName("box").type(ScimAttributeType.COMPLEX).subAttributes(List.of()).build(),
                ScimAttributeDefinition.withName("always").returned(ScimReturned.ALWAYS).build());
        ScimSchema definition = ScimSchema.withId("urn:example:wire").name("Wire").description("Fixture schema").attributes(attributes).build();
        JsonArray values = (JsonArray) requireNonNull(ScimDiscovery.schema(definition).getMembers().get("attributes"));
        List<String> types = List.of("string", "boolean", "decimal", "integer", "dateTime", "binary", "reference", "complex", "string");
        for (int index = 0; index < types.size(); ++index)
            assertEquals(types.get(index), ((JsonObject) values.getElements().get(index)).find("type").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        JsonObject once = (JsonObject) values.getElements().get(0);
        assertEquals("immutable", once.find("mutability").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("request", once.find("returned").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("global", once.find("uniqueness").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("Fixture field", once.find("description").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals(2, ((JsonArray) requireNonNull(once.getMembers().get("canonicalValues"))).getElements().size());
        ScimResourceType type = ScimResourceType.withName("Wire").schema(definition).endpoint("/Wire").description("Fixture type").build();
        assertEquals("Fixture type", ScimDiscovery.resourceType(type).find("description").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertEquals("https://example.com/help", ScimDiscovery.configuration(ScimServiceProviderConfig.builder()
                .documentationUri(URI.create("https://example.com/help")).build()).find("documentationUri").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
    }

    private static void assertComplexUniquenessAbsent(@NonNull JsonArray attributes) {
        for (JsonValue value : attributes.getElements()) {
            JsonObject attribute = assertInstanceOf(JsonObject.class, value);
            if (attribute.find("type").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow().equals("complex")) {
                assertFalse(attribute.getMembers().containsKey("uniqueness"), "Verified RFC 7643 erratum 6004");
                assertComplexUniquenessAbsent(assertInstanceOf(JsonArray.class, attribute.getMembers().get("subAttributes")));
            }
        }
    }

    private static @NonNull ScimResponse prepared(@NonNull JsonObject body, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) {
        return assertInstanceOf(ScimResponseResult.Prepared.class, ScimResponses.prepare(FLOOR, 200, body, headers, new ScimWork(10_000))).getResponse();
    }
    private static @NonNull ScimError rejected(@NonNull JsonObject body, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) {
        return assertInstanceOf(ScimResponseResult.Rejected.class, ScimResponses.prepare(FLOOR, 200, body, headers, new ScimWork(10_000))).getError();
    }
    private static int encodedHeaders(@NonNull ScimResponse response) {
        int count = 0;
        for (Map.Entry<String, List<String>> entry : response.getHeaders().entrySet()) for (String value : entry.getValue())
            count += (entry.getKey() + ": " + value + "\r\n").getBytes(StandardCharsets.UTF_8).length;
        return count;
    }
}
