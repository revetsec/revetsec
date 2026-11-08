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

import com.revetsec.json.*;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Identical entry/final public fixture; encoding oracle adapts JDK form encoding. */
final class ScimLocationEncodingTests {
    private static final ScimResourceType USER = ScimResourceType.userInstance();
    private static final ScimResourceType GROUP = ScimResourceType.groupInstance();
    private static final String BASE = "https://example.invalid/scim/v2/";
    private static final List<String> IDS = List.of("a.b", ".leading", "trailing.", "a..b", "...", ".x.",
            "../admin?owner=1#fragment", "./child", "x/../y", "x\\..\\y", "%2e", "%2E%2e", "%2e%2fadmin", "%252e%252e", "a%2Fb",
            "a+b", "a b", "ü.😀", "e\u0301.é", "Az09-._~", "x:y;z@q", "a?b#c");

    @TestFactory @NonNull Stream<@NonNull DynamicTest> opaqueIdsUseCanonicalUnreservedEncodingInOneRawSegment() {
        return Stream.of(USER, GROUP).flatMap(type -> Stream.of(BASE, "https://[::1]:9443/v1.0/").flatMap(base -> IDS.stream().map(id ->
                DynamicTest.dynamicTest(type.getName() + " " + base + " " + id, () -> {
            var provider = provider(type, base); URI location = assertDoesNotThrow(() -> provider.resourceLocationFor(type, id));
            String prefix = provider.getBaseUri().toASCIIString() + type.getEndpoint().substring(1) + "/";
            assertEquals(prefix + encoded(id), location.toASCIIString());
            assertEquals(URI.create(base).getRawAuthority(), location.getRawAuthority());
            assertNull(location.getRawQuery()); assertNull(location.getRawFragment()); assertNull(location.getRawUserInfo());
            String rawPrefix = URI.create(prefix).getRawPath();
            assertEquals(rawPrefix + encoded(id), location.getRawPath());
            assertFalse(location.getRawPath().substring(rawPrefix.length()).contains("/"));
            assertEquals(URI.create(prefix).getPath() + id, location.getPath(), "one URI decode must recover the exact opaque ID");
            assertEquals(location, location.normalize(), "URI dot-segment normalization must not change a resource location");
        }))));
    }

    @Test void everyOtherPrintableAsciiCharacterKeepsItsPreviousOneSegmentEncoding() {
        for (int value = 0x20; value <= 0x7e; value++) {
            if (value == '.') continue;
            String id = "left" + (char) value + "right";
            var uri = assertDoesNotThrow(() -> provider(USER, BASE).resourceLocationFor(USER, id));
            assertEquals(BASE + "Users/" + encoded(id), uri.toASCIIString());
            assertEquals("/scim/v2/Users/" + id, uri.getPath()); assertNull(uri.getRawQuery()); assertNull(uri.getRawFragment());
        }
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidAndTraversalOnlyIdentifiersStillReject() {
        return Stream.of(USER, GROUP).flatMap(type -> Stream.of("", ".", "..", "BULKID", "prefixBulkIdSuffix", "a\u0000b", "a\r\nb", "a\u007fb", "a\uD800", "a\uDC00", "x".repeat(1025))
                .map(id -> DynamicTest.dynamicTest(type.getName() + " invalid ID length=" + id.length(), () -> {
            var provider = provider(type, BASE);
            assertThrows(IllegalArgumentException.class, () -> provider.resourceLocationFor(type, id));
            assertThrows(IllegalArgumentException.class, () -> resource(type, id, null));
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> createHeadersAndBodyUseTheSameAuthoritativeCanonicalLocation() {
        return Stream.of(USER, GROUP).flatMap(type -> Stream.of("a.b", "../x", "%2e%2e", "a/b.c", "é.😀").map(id -> DynamicTest.dynamicTest(type.getName() + " create " + id, () -> {
            var provider = provider(type, BASE); var current = resource(type, id, null); var before = current.getDocument();
            var response = prepared(provider, current);
            String expected = BASE + type.getEndpoint().substring(1) + "/" + encoded(id);
            assertEquals(201, response.getStatusCode()); assertEquals(List.of(expected), response.getHeaders().get("Location"));
            String body = new String(response.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8);
            assertTrue(body.contains("\"location\":\"" + expected + "\"")); assertEquals(before, current.getDocument());
            assertFalse(current.getLocation().isPresent()); assertEquals(List.of("W/\"one\""), response.getHeaders().get("ETag"));
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> canonicalStoredMetaLocationAgreesForDottedIds() {
        return Stream.of(USER, GROUP).map(type -> DynamicTest.dynamicTest(type.getName() + " canonical metadata", () -> {
            String expected = BASE + type.getEndpoint().substring(1) + "/a.b";
            var provider = provider(type, BASE); var current = resource(type, "a.b", expected);
            assertEquals(List.of(expected), prepared(provider, current).getHeaders().get("Location"));
            assertEquals(URI.create(expected), current.getLocation().orElseThrow());
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> previousEscapedDotMetadataRequiresExplicitRegeneration() {
        return Stream.of(USER, GROUP).map(type -> DynamicTest.dynamicTest(type.getName() + " legacy metadata", () -> {
            String previous = BASE + type.getEndpoint().substring(1) + "/a%2Eb";
            var provider = provider(type, BASE); var current = resource(type, "a.b", previous); var before = current.getDocument();
            var rejected = assertInstanceOf(ScimResponseResult.Rejected.class, provider.createdResponseResult(current, Set.of(), selection(provider, type)));
            assertEquals(ScimErrorType.INVALID_VALUE, rejected.getError().getErrorType().orElseThrow()); assertEquals(before, current.getDocument());
            var get = assertInstanceOf(ScimResponseResult.Prepared.class, provider.resourceResponseResult(current, selection(provider, type))).getResponse();
            assertTrue(new String(get.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8).contains(previous));
            String canonical = provider.resourceLocationFor(type, "a.b").toASCIIString();
            var regenerated = resource(type, "a.b", canonical);
            assertEquals(List.of(canonical), prepared(provider, regenerated).getHeaders().get("Location"));
        }));
    }

    @Test void unrelatedMetadataCannotChooseTheLocationAndUriEscapeCaseComparisonIsUnchanged() {
        var provider = provider(USER, BASE);
        for (String location : List.of("https://attacker.invalid/Users/a.b", BASE + "Groups/a.b", BASE + "Users/other", BASE + "Users/a.b?x=1", BASE + "Users/a.b#x")) {
            var current = resource(USER, "a.b", location);
            assertInstanceOf(ScimResponseResult.Rejected.class, provider.createdResponseResult(current, Set.of(), selection(provider, USER)));
        }
        var lowerEscape = resource(USER, "a/b", BASE + "Users/a%2fb");
        assertEquals(List.of(BASE + "Users/a%2Fb"), prepared(provider, lowerEscape).getHeaders().get("Location"));
    }

    @Test void identifierLimitAndUtf8EncodingStayBounded() {
        var provider = provider(USER, BASE);
        for (String id : List.of(".".repeat(1024), "." + "あ".repeat(1023), "A." + "😀".repeat(511))) {
            assertEquals(1024, id.length());
            URI location = assertDoesNotThrow(() -> provider.resourceLocationFor(USER, id));
            assertEquals(BASE + "Users/" + encoded(id), location.toASCIIString());
            assertEquals(location, location.normalize()); assertEquals("/scim/v2/Users/" + id, location.getPath());
        }
        assertThrows(IllegalArgumentException.class, () -> provider.resourceLocationFor(USER, ".".repeat(1025)));
    }

    @Test @SuppressWarnings("NullAway") void registrationBaseAndEndpointRemainAuthoritative() {
        var type = ScimResourceType.withName("Person").endpoint("/tenant.v2/People").schema(ScimSchema.userInstance()).build();
        var provider = provider(type, "https://example.invalid/v1.0/scim/");
        assertEquals("https://example.invalid/v1.0/scim/tenant.v2/People/a.b", provider.resourceLocationFor(type, "a.b").toASCIIString());
        assertThrows(IllegalArgumentException.class, () -> provider.resourceLocationFor(USER, "a.b"));
        assertThrows(NullPointerException.class, () -> provider(USER, BASE).resourceLocationFor(USER, null));
    }

    private static @NonNull String encoded(@NonNull String id) { return URLEncoder.encode(id, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~"); }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type, @NonNull String base) { return ScimServiceProvider.builder().baseUri(URI.create(base)).resourceTypes(List.of(type)).build(); }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type, @NonNull String id, @Nullable String location) {
        var document = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId())))).put("id", id);
        document.put(type.hasStandardGroupSchema() ? "displayName" : "userName", "subject");
        var meta = JsonObject.builder().put("version", "W/\"one\""); if (location != null) meta.put("location", location);
        return ScimResource.withResourceType(type).document(document.put("meta", meta.build()).build()).build();
    }
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider provider, @NonNull ScimResourceType type) { return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, provider.parseAttributeSelectionResult(type, "")).getAttributeSelection(); }
    private static @NonNull ScimResponse prepared(@NonNull ScimServiceProvider provider, @NonNull ScimResource resource) { return assertInstanceOf(ScimResponseResult.Prepared.class, provider.createdResponseResult(resource, Set.of(), selection(provider, resource.getResourceType()))).getResponse(); }
}
