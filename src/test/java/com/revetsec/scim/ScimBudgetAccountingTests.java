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

import com.revetsec.json.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Entry-supported fixture for byte/work compatibility and retained semantic fences. */
final class ScimBudgetAccountingTests {
    private static final ScimResourceType USER = ScimResourceType.userInstance();
    private static final int MIB = 1024 * 1024;

    @TestFactory Stream<DynamicTest> writerChargesCumulativeWireBlocksAndEveryNode() {
        List<JsonValue> values = new ArrayList<>(List.of(JsonNull.defaultInstance(), JsonNumber.fromValue(0L), JsonBoolean.trueInstance(),
                JsonObject.emptyInstance(), JsonArray.emptyInstance(), JsonString.fromValue("é中😀\u0001\n\"\\"),
                JsonObject.builder().put("a", "x".repeat(63)).put("array", JsonArray.fromElements(List.of(JsonBoolean.falseInstance(), JsonNumber.fromValue(123L)))).build()));
        for (int length : List.of(0, 1, 13, 14, 15, 16, 17, 29, 30, 31, 32, 33, 63, 64, 65, 255, 256)) values.add(JsonString.fromValue("x".repeat(length)));
        return values.stream().map(value -> DynamicTest.dynamicTest("writer nodes=" + nodes(value) + " chars=" + value.toJson().length(), () -> {
            byte[] expected = value.toJson().getBytes(StandardCharsets.UTF_8); long minimum = nodes(value) + (expected.length + 15L) / 16;
            assertNull(ScimJsonOutput.write(value, expected.length, new ScimWork(minimum - 1)), "work quota must include all nodes and global byte blocks");
            assertArrayEquals(expected, ScimJsonOutput.write(value, expected.length, new ScimWork(minimum)));
            assertNull(ScimJsonOutput.write(value, expected.length - 1, new ScimWork(100_000)), "byte cap remains exact");
        }));
    }

    @Test void scalarProjectionDoesNotSpendContentLengthAgain() {
        var limits = ScimLimits.builder().maximumWorkUnits(10_000).build(); var provider = provider(limits);
        var current = user("one", "x".repeat(128 * 1024)); var before = current.getDocument();
        var response = prepared(provider.resourceResponseResult(current, selection(provider)));
        assertTrue(response.toHttpBodyWithPersonalData().length > 128 * 1024); assertEquals(before, current.getDocument());
        assertTrue(response.toHttpBodyWithPersonalData().length < 160_000);
    }

    @Test void responseSharesOneBudgetAcrossPage() {
        var provider = provider(ScimLimits.builder().maximumWorkUnits(10_000).build()); List<ScimResource> resources = users(500, "");
        assertInstanceOf(ScimResponseResult.Prepared.class, provider.resourceResponseResult(resources.get(0), selection(provider)));
        var rejected = assertInstanceOf(ScimResponseResult.Rejected.class, provider.listResponseResult(page(provider, resources)));
        assertEquals(500, rejected.getError().getStatusCode());
        assertEquals("u0", resources.get(0).getId().orElseThrow());
    }

    @TestFactory Stream<DynamicTest> declaredResponseCapsAreReachableForLinearPages() {
        return Stream.of(new Profile(8 * MIB, "ascii", "x"), new Profile(8 * MIB, "cjk", "中"),
                new Profile(8 * MIB, "escaped", "\u0001"), new Profile(32 * MIB, "ascii", "x"))
                .map(profile -> DynamicTest.dynamicTest("response cap=" + profile.cap() + " " + profile.name(), () -> {
            var limits = ScimLimits.builder().maximumResponseBytes(profile.cap()).build(); var provider = provider(limits);
            var skeleton = prepared(provider.listResponseResult(page(provider, users(1000, ""))));
            long headers = headerBytes(skeleton); int payload = Math.toIntExact(profile.cap() - headers - 128 - skeleton.toHttpBodyWithPersonalData().length);
            List<ScimResource> resources = filledUsers(1000, payload, profile.unit());
            var response = prepared(provider.listResponseResult(page(provider, resources))); byte[] body = response.toHttpBodyWithPersonalData();
            assertEquals(profile.cap(), body.length + headerBytes(response) + 128); assertEquals((byte) '{', body[0]); assertEquals((byte) '}', body[body.length - 1]);
            assertEquals(200, response.getStatusCode()); assertEquals(1000, resources.size());
            var oneLess = provider(ScimLimits.builder().maximumResponseBytes(profile.cap() - 1).build());
            var rejected = assertInstanceOf(ScimResponseResult.Rejected.class, oneLess.listResponseResult(page(oneLess, resources))); assertEquals(500, rejected.getError().getStatusCode());
            String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            var receipt = JsonObject.builder().put("configuredResponseBytes", (long) profile.cap()).put("configuredWorkUnits", (long) limits.getMaximumWorkUnits())
                    .put("bodyBytes", (long) body.length).put("headerBytes", headerBytes(response)).put("framingBytes", 128L).put("resources", 1000L).put("sha256", sha).build();
            Files.writeString(Path.of("target/budget-response-" + profile.cap() + "-" + profile.name() + ".json"), receipt.toJson());
        }));
    }

    @TestFactory Stream<DynamicTest> compatibleInputProfilesReachTheirDeclaredByteCaps() {
        return Stream.of(new InputProfile(MIB, 4_000_000, "ascii", "x"), new InputProfile(6 * MIB, 10_000_000, "ascii", "x"),
                new InputProfile(10 * MIB, 10_000_000, "cjk", "中"))
                .map(profile -> DynamicTest.dynamicTest("input bytes=" + profile.cap() + " " + profile.name(), () -> {
            var limits = ScimLimits.builder().maximumBodyBytes(profile.cap()).maximumWorkUnits(profile.work()).build(); var provider = provider(limits);
            byte[] body = input(profile.cap(), profile.unit()); assertEquals(profile.cap(), body.length);
            var result = assertInstanceOf(ScimResourceParseResult.Succeeded.class, provider.parseResourceResult(USER, body));
            assertTrue(result.getResource().getDocument().find("roles").isPresent());
            assertEquals(413, assertInstanceOf(ScimResourceParseResult.Rejected.class, provider.parseResourceResult(USER, Arrays.copyOf(body, body.length + 1))).getError().getStatusCode());
            Files.writeString(Path.of("target/budget-input-" + profile.cap() + "-" + profile.name() + ".json"), JsonObject.builder().put("bodyBytes", (long) body.length)
                    .put("configuredWorkUnits", (long) profile.work()).put("wireWorkFloor", (body.length + 15L) / 16).build().toJson());
        }));
    }

    @Test void inputWireByteFloorIsExplicit() {
        var provider = provider(ScimLimits.builder().maximumWorkUnits(10_000).build());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class, provider.parseResourceResult(USER, padded(100_000)));
        assertEquals(413, assertInstanceOf(ScimResourceParseResult.Rejected.class, provider.parseResourceResult(USER, padded(160_001))).getError().getStatusCode());
        var floor = provider(ScimLimits.builder().maximumBodyBytes(16 * 1024).maximumWorkUnits(10_000).build());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class, floor.parseResourceResult(USER, padded(16 * 1024)));
        assertEquals(413, assertInstanceOf(ScimResourceParseResult.Rejected.class, floor.parseResourceResult(USER, padded(16 * 1024 + 1))).getError().getStatusCode());
    }

    @Test void byteAndStructuralRefusalsRemainIndependent() {
        var limits = ScimLimits.builder().maximumBodyBytes(64 * 1024).maximumJsonNodes(1000).build(); var provider = provider(limits);
        var body = JsonObject.builder().put("schemas", schemas()).put("userName", "u").put("roles", JsonArray.fromElements(java.util.Collections.nCopies(600, JsonObject.builder().put("value", "x").build()))).build().toJson().getBytes(StandardCharsets.UTF_8);
        assertTrue(body.length < limits.getMaximumBodyBytes());
        assertEquals(413, assertInstanceOf(ScimResourceParseResult.Rejected.class, provider.parseResourceResult(USER, body)).getError().getStatusCode());
        var resource = user("one", "\u0001".repeat(400)); var small = provider(ScimLimits.builder().maximumResponseBytes(2048).build());
        assertEquals(500, assertInstanceOf(ScimResponseResult.Rejected.class, small.resourceResponseResult(resource, selection(small))).getError().getStatusCode());
    }

    private record Profile(int cap, String name, String unit) { }
    private record InputProfile(int cap, int work, String name, String unit) { }
    private static long nodes(JsonValue value) {
        if (value instanceof JsonObject object) return 1 + object.getMembers().values().stream().mapToLong(ScimBudgetAccountingTests::nodes).sum();
        if (value instanceof JsonArray array) return 1 + array.getElements().stream().mapToLong(ScimBudgetAccountingTests::nodes).sum();
        return 1;
    }
    private static List<ScimResource> filledUsers(int count, int bytes, String unit) {
        List<ScimResource> result = new ArrayList<>(); int unitBytes = JsonString.fromValue(unit).toJson().getBytes(StandardCharsets.UTF_8).length - 2;
        for (int i = 0; i < count; i++) { int share = bytes / (count - i); String text = unit.repeat(share / unitBytes) + "x".repeat(share % unitBytes); result.add(user("u" + i, text)); bytes -= share; }
        assertEquals(0, bytes); return result;
    }
    private static List<ScimResource> users(int count, String text) { List<ScimResource> result = new ArrayList<>(); for (int i = 0; i < count; i++) result.add(user("u" + i, text)); return result; }
    private static ScimResource user(String id, String text) { return ScimResource.withResourceType(USER).document(JsonObject.builder().put("schemas", schemas()).put("id", id).put("userName", "u").put("displayName", text).build()).build(); }
    private static JsonArray schemas() { return JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))); }
    private static ScimServiceProvider provider(ScimLimits limits) { return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(USER)).limits(limits).build(); }
    private static ScimAttributeSelection selection(ScimServiceProvider provider) { return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class, provider.parseAttributeSelectionResult(USER, "")).getAttributeSelection(); }
    private static ScimListPage page(ScimServiceProvider provider, List<ScimResource> resources) { var query = assertInstanceOf(ScimQueryParseResult.Succeeded.class, provider.parseQueryResult(USER, "count=" + resources.size())).getQuery(); return ScimListPage.withQuery(query).resources(resources).totalResults((long) resources.size()).build(); }
    private static ScimResponse prepared(ScimResponseResult result) { return assertInstanceOf(ScimResponseResult.Prepared.class, result).getResponse(); }
    private static long headerBytes(ScimResponse response) { long sum = 0; for (var entry : response.getHeaders().entrySet()) for (String value : entry.getValue()) sum += entry.getKey().getBytes(StandardCharsets.UTF_8).length + value.getBytes(StandardCharsets.UTF_8).length + 4L; return sum; }
    private static byte[] padded(int size) { byte[] base = JsonObject.builder().put("schemas", schemas()).put("userName", "u").build().toJson().getBytes(StandardCharsets.UTF_8); byte[] result = Arrays.copyOf(base, size); Arrays.fill(result, base.length, size, (byte) ' '); return result; }
    private static byte[] input(int size, String unit) {
        String prefix = "{\"schemas\":[\"" + USER.getSchema().getId() + "\"],\"userName\":\"u\",\"roles\":[";
        byte[] start = prefix.getBytes(StandardCharsets.UTF_8), element = JsonObject.builder().put("value", unit.repeat(4096)).build().toJson().getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream(size); output.writeBytes(start); boolean first = true;
        while ((long) output.size() + element.length + (first ? 0 : 1) + 2 <= size) { if (!first) output.write(','); output.writeBytes(element); first = false; }
        output.write(']'); output.write('}'); while (output.size() < size) output.write(' '); return output.toByteArray();
    }
}
