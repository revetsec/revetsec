/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 */
package com.revetsec.differential;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** RFC 8259 §§4/6/7/8: exact typed trees, strict duplicate detection and explicit parser differences. */
final class JsonComparatorTests {
    private static final JsonLimits LIMITS = JsonLimits.protocolDocument(256 * 1024);
    private static final JsonFactory JACKSON = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxNumberLength(1024)
                    .maxStringLength(1024 * 1024).build()).build();
    private static final Path CORPUS = Path.of("../src/test/resources/vectors/jsontestsuite/test_parsing");
    private static final Path DISPOSITIONS = Path.of("src/test/resources/rc1/json-corpus-verdicts.tsv");
    private static final List<String> CONTROLS = List.of("null", "true", "false", "0", "-0", "1.0", "1e0",
            "9007199254740993", "0.123456789012345678901234567890", "1e309", "1e-1000", "\"plain\"",
            "\"\\uD834\\uDD1E\"", "\"𝄞\"", "\"é\"", "{\"a\":1,\"A\":2}", "[null,true,1,\"x\",{}]",
            "{\"ordered\":[1,2,3],\"nested\":{\"value\":-2.50},\"string\":\"\\u0000\"}");

    @TestFactory Stream<DynamicTest> typedControlsAgreeWithoutLosingNumericPrecisionOrUnicode() {
        return CONTROLS.stream().map(text -> DynamicTest.dynamicTest("typed-control-" + CONTROLS.indexOf(text), () -> {
            Object core = core(text.getBytes(StandardCharsets.UTF_8));
            assertEquals(core, jackson(text.getBytes(StandardCharsets.UTF_8)));
            assertNotNull(core);
        }));
    }

    @TestFactory Stream<DynamicTest> duplicateNamesAreComparedAfterUnescapingAtEveryDepth() {
        List<String> invalid = List.of("{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}",
                "{\"outer\":{\"x\":true,\"x\":false}}", "[{\"a\":null,\"a\":null}]",
                "{\"𝄞\":1,\"\\uD834\\uDD1E\":2}");
        return invalid.stream().map(text -> DynamicTest.dynamicTest("duplicate-" + invalid.indexOf(text), () -> {
            assertRejected(text.getBytes(StandardCharsets.UTF_8));
        }));
    }

    @TestFactory Stream<DynamicTest> malformedNumberGrammarIsRejectedByBothParsers() {
        return List.of("+1", "01", "-01", "1.", ".1", "1e", "1e+", "NaN", "Infinity", "--1", "[1 2]",
                "{\"n\":0x1}").stream().map(text -> DynamicTest.dynamicTest("number-" + text, () ->
                assertRejected(text.getBytes(StandardCharsets.UTF_8))));
    }

    @TestFactory Stream<DynamicTest> everyVendoredFixtureAndEveryFramingMutationHasAnExactVerdict() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        List<String> rows = Files.readAllLines(DISPOSITIONS);
        Map<String, String> hashes = new LinkedHashMap<>();
        for (String line : Files.readAllLines(CORPUS.getParent().resolve("MANIFEST.sha256"))) {
            String[] fields = line.split("  ", 2);
            if (fields.length == 2 && fields[1].startsWith("test_parsing/")) {
                hashes.put(fields[1].substring("test_parsing/".length()), fields[0]);
            }
        }
        List<String> names;
        try (var paths = Files.list(CORPUS)) { names = paths.map(path -> path.getFileName().toString()).sorted().toList(); }
        assertEquals(names, rows.stream().filter(row -> !row.startsWith("#")).map(row -> row.split("\t", -1)[0]).toList(),
                "every vendored fixture must have exactly one reviewed disposition");
        assertEquals(names, hashes.keySet().stream().sorted().toList(), "every fixture must have a pinned digest");
        for (String row : rows) {
            if (row.startsWith("#")) continue;
            String[] columns = row.split("\t", -1);
            assertEquals(4, columns.length, "fixture/core/Jackson/disposition");
            String name = columns[0];
            byte[] input = Files.readAllBytes(CORPUS.resolve(name));
            try {
                assertEquals(hashes.get(name), java.util.HexFormat.of().formatHex(
                        java.security.MessageDigest.getInstance("SHA-256").digest(input)), name + " fixture digest");
            } catch (java.security.NoSuchAlgorithmException failure) { throw new AssertionError(failure); }
            tests.add(DynamicTest.dynamicTest(name + ":original", () -> {
                Object core = core(input), external = jackson(input);
                assertEquals(Boolean.parseBoolean(columns[1]), core != null, name + " Revetsec");
                assertEquals(Boolean.parseBoolean(columns[2]), external != null, name + " Jackson");
                if (core != null && external != null) assertEquals(core, external, name + " typed tree");
                if ((core != null) != (external != null)) assertFalse(columns[3].equals("AGREE"), name);
                else assertEquals("AGREE", columns[3], name);
            }));
            for (String mutation : List.of("trailing-nul", "leading-nul", "invalid-utf8-prefix")) {
                tests.add(DynamicTest.dynamicTest(name + ":" + mutation, () -> {
                    byte[] changed;
                    if (mutation.equals("trailing-nul")) changed = Arrays.copyOf(input, input.length + 1);
                    else {
                        changed = new byte[input.length + 1];
                        changed[0] = mutation.equals("leading-nul") ? 0 : (byte) 0xff;
                        System.arraycopy(input, 0, changed, 1, input.length);
                    }
                    assertNull(core(changed), "Revetsec must reject changed framing");
                    if (name.equals("n_structure_null-byte-outside-string.json")
                            && !mutation.equals("invalid-utf8-prefix")) {
                        // Adding a zero byte makes Jackson auto-detect UTF-16 and expose an empty array.
                        // Revetsec accepts UTF-8 only; do not reinterpret that wire carrier for comparison.
                        assertEquals(List.of(), jackson(changed));
                    } else assertNull(jackson(changed), "Jackson must reject changed framing");
                }));
            }
        }
        return tests.stream();
    }

    @Test void escapedUnpairedSurrogatesAreAnExplicitJacksonModelDifference() throws IOException {
        for (String text : List.of("\"\\uD800\"", "\"\\uDC00\"", "[\"\\uD800x\"]")) {
            byte[] input = text.getBytes(StandardCharsets.UTF_8);
            assertNull(core(input));
            assertNotNull(jackson(input));
        }
        // Jackson 2.22.4 rejects unpaired surrogates in member names while still exposing them in values.
        for (String text : List.of("{\"\\uD800\":1}", "{\"\\uDC00\":1}"))
            assertRejected(text.getBytes(StandardCharsets.UTF_8));
        // Revetsec's public JSON model deliberately requires scalar Unicode in both positions.
        assertEquals(new Text("\uD800"), jackson("\"\\uD800\"".getBytes(StandardCharsets.UTF_8)));
    }

    @Test void bomIsAnExplicitTransportProfileDifference() throws IOException {
        byte[] input = "\uFEFF{\"value\":1}".getBytes(StandardCharsets.UTF_8);
        assertNull(core(input));
        assertEquals(jackson("{\"value\":1}".getBytes(StandardCharsets.UTF_8)), jackson(input));
    }

    @Test void typedProjectionDetectsPlantedNumericAndUnicodeLoss() throws IOException {
        assertNotEquals(jackson("9007199254740993".getBytes(StandardCharsets.UTF_8)),
                core("9007199254740992".getBytes(StandardCharsets.UTF_8)));
        assertNotEquals(jackson("\"𝄞\"".getBytes(StandardCharsets.UTF_8)),
                core("\"?\"".getBytes(StandardCharsets.UTF_8)));
        assertNotEquals(jackson("[true]".getBytes(StandardCharsets.UTF_8)),
                core("[\"true\"]".getBytes(StandardCharsets.UTF_8)));
        assertThrows(AssertionError.class, () -> assertEquals(jackson("1.01".getBytes(StandardCharsets.UTF_8)),
                core("1.02".getBytes(StandardCharsets.UTF_8))));
    }

    private static void assertRejected(byte[] input) throws IOException {
        assertNull(core(input), "Revetsec must reject");
        assertNull(jackson(input), "Jackson must reject");
    }
    private static Object core(byte[] input) {
        JsonParseResult parsed = JsonCodec.parseResult(input, LIMITS);
        return parsed instanceof JsonParseResult.Succeeded success ? project(success.getDocument().getValue()) : null;
    }
    private static Object project(JsonValue value) {
        if (value instanceof JsonNull) return Null.VALUE;
        if (value instanceof JsonBoolean bool) return bool.getValue();
        if (value instanceof JsonString text) return new Text(text.getValue());
        if (value instanceof JsonNumber number) return number.getValue().stripTrailingZeros();
        if (value instanceof JsonArray array) return array.getElements().stream().map(JsonComparatorTests::project).toList();
        Map<String, Object> members = new LinkedHashMap<>();
        ((JsonObject) value).getMembers().forEach((name, child) -> members.put(name, project(child)));
        return members;
    }
    private static Object jackson(byte[] input) throws IOException {
        try (JsonParser parser = JACKSON.createParser(input)) {
            JsonToken token = parser.nextToken();
            if (token == null) return null;
            Object value = read(parser, token);
            return parser.nextToken() == null ? value : null;
        } catch (IOException | NumberFormatException failure) { return null; }
    }
    private static Object read(JsonParser parser, JsonToken token) throws IOException {
        return switch (token) {
            case VALUE_NULL -> Null.VALUE;
            case VALUE_TRUE -> true;
            case VALUE_FALSE -> false;
            case VALUE_STRING -> new Text(parser.getText());
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> new BigDecimal(parser.getText()).stripTrailingZeros();
            case START_ARRAY -> {
                List<Object> values = new ArrayList<>();
                JsonToken child;
                while ((child = parser.nextToken()) != JsonToken.END_ARRAY) {
                    if (child == null) throw new IOException("Incomplete independent array");
                    values.add(read(parser, child));
                }
                yield values;
            }
            case START_OBJECT -> {
                Map<String, Object> values = new LinkedHashMap<>();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    if (parser.currentToken() != JsonToken.FIELD_NAME) throw new IOException("Incomplete independent object");
                    String name = parser.currentName();
                    JsonToken child = parser.nextToken();
                    if (child == null) throw new IOException("Incomplete independent value");
                    values.put(name, read(parser, child));
                }
                yield values;
            }
            default -> throw new IOException("Unexpected independent token");
        };
    }
    private enum Null { VALUE }
    private record Text(String value) {}
}
