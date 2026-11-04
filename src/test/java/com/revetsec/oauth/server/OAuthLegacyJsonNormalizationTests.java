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

package com.revetsec.oauth.server;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** CAP-05: legacy JSON spelling/ordering is not a semantic or capacity admission shortcut. */
final class OAuthLegacyJsonNormalizationTests {
    private static final @NonNull String RESOURCE = "/fixtures/oauth/cap-05.properties";
    private static final @NonNull String OLD_MASTER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final @NonNull String NEW_MASTER = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC);
    private static final @NonNull OAuthServerIngressLimits LIMITS =
            new OAuthServerIngressLimits(65536, 65536, 65536, 4096, 4096, 8, 16, 128, 128);
    private static final byte @NonNull [] GOLDEN = loadBytes();
    private static final @NonNull Properties PROPERTIES = loadProperties();

    @Test void corpusPinsNumericSemanticsAndOpposingCapacityWitnesses() throws Exception {
        assertEquals("b7433fd4ffd2cb384127838776466a0ba105c27eb4b8753ee7134e9a47bc5a8d",
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(GOLDEN)));
        assertEquals(68, vectors().size()); assertEquals(62, valid().size());
        assertEquals(6, vectors().stream().filter(v -> !v.valid()).count());
        var forms = vectors().stream().filter(v -> v.value("group").equals("forms")).toList();
        assertEquals(56, forms.size());
        assertEquals(14, forms.stream().map(v -> v.kind() + "/" + v.semantic().find("status").map(x -> x.toJson()).orElse("ROOT")).distinct().count());
        assertTrue(forms.stream().anyMatch(v -> v.oldWire().contains("-0.00")));
        assertTrue(forms.stream().anyMatch(v -> v.oldWire().contains("e-1")));
        assertTrue(forms.stream().filter(v -> v.value("layout").equals("reversed-whitespace"))
                .allMatch(v -> v.oldWire().contains("\n") && v.oldWire().contains("\r") && v.oldWire().contains("\t")));
        for (Vector v : valid()) {
            assertEquals(v.semantic(), parse(v.value("normalizedSourcePayloadHex")));
            if (v.value("group").equals("old-length-twin")) {
                assertEquals(12233, v.oldP()); assertEquals(16384, v.entry().toSealedForm().length());
                assertTrue(v.newP() >= 12169 && v.newP() <= 12171);
            }
            if (v.value("group").equals("short-exponent-growth")) {
                assertTrue(v.entry().toSealedForm().length() <= 16225);
                assertEquals(v.oldP() + 66, v.newP());
                assertTrue(v.oldWire().contains("1e9"));
            }
        }
        for (String group : List.of("old-length-twin", "short-exponent-growth")) {
            var sizes = valid().stream().filter(v -> v.value("group").equals(group)).map(Vector::newP).toList();
            assertEquals(List.of(12169, 12170, 12171), sizes);
        }
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> currentLegacyReaderMatchesFrozenSpellingAndSemanticClassification() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) tests.add(DynamicTest.dynamicTest("CAP-05/old/" + v.name(), () -> {
            StateSealer s = sealer(1); var old = legacy(s);
            var entry = v.entry(); String before = entry.toSealedForm();
            assertEquals(v.oldWire(), raw(entry, s, 1));
            assertEquals(v.oldP(), utf8(raw(entry, s, 1)).length);
            assertEquals(wire(v.oldP(), 1), before.length());
            if (v.valid()) {
                var payload = assertDoesNotThrow(() -> readTyped(old, v));
                assertEquals(v.semantic(), payload);
                assertIntegerFacts(v.semantic(), payload);
                assertEquals(v.text("normalizedSourcePayloadHex"), payload.toJson());
                assertEquals(v.retention(), entry.getRetainUntil());
            } else assertThrows(IllegalArgumentException.class, () -> readTyped(old, v));
            assertEquals(before, entry.toSealedForm());
        }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> exactPreparedOutputPreservesValuesAndDecidesFit() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : valid()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-05/prepared/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k); var old = legacy(s); var next = target(s);
                var source = v.entry(); var root = v.root();
                String before = source.toSealedForm(), rootBefore = root.toSealedForm();
                assertEquals(v.semantic(), assertDoesNotThrow(() -> readTyped(old, v)));
                var migration = migration(next);
                var pinned = assertDoesNotThrow(() -> migration.openRoot(root));
                assertEquals(v.rootMinimum(), pinned.minimum());
                assertEquals(property("authority"), pinned.authorityId());
                if (!v.fits()) {
                    assertEquals(12171, v.newP());
                    assertThrows(IllegalArgumentException.class, () -> migration.convert(source, pinned));
                } else {
                    var prepared = assertDoesNotThrow(() -> migration.convert(source, pinned));
                    assertNotEquals(source.getVersion(), prepared.getVersion());
                    assertEquals(source.getKey(), prepared.getKey());
                    assertEquals(source.getRetainUntil(), prepared.getRetainUntil());
                    String actual = raw(prepared, s, 2);
                    assertEquals(v.targetExpected().replace(placeholder(), prepared.getVersion()), actual);
                    assertEquals(v.newP(), utf8(actual).length);
                    assertEquals(wire(v.newP(), k), prepared.toSealedForm().length());
                    var opened = assertDoesNotThrow(() -> next.open(prepared, CLOCK));
                    assertEquals(v.floor(), opened.floor());
                    assertEquals(parse(v.value("targetPayloadHex")), opened.payload());
                    assertIntegerFacts(parse(v.value("targetPayloadHex")), opened.payload());
                    assertEquals(v.text("targetPayloadHex"), opened.payload().toJson());
                    if (v.kind() == OAuthStoreKey.Kind.ISSUER_STATE) {
                        var result = OAuthIssuerRootV2.decode(opened.payload());
                        assertEquals(9007199254740993L, result.epoch());
                        assertEquals(property("authority"), result.authorityId());
                        assertEquals(v.rootMinimum(), result.minimum());
                    } else assertEquals(v.semantic(), opened.payload());
                    if (v.kind() != OAuthStoreKey.Kind.ISSUER_STATE && v.kind() != OAuthStoreKey.Kind.SUBJECT_STATE)
                        assertEquals(source.getRetainUntil(), OAuthAuthorizationRecord.decode(v.kind(), identifier(v.key()), opened.payload(), LIMITS, 1024).retention());
                }
                assertEquals(before, source.toSealedForm()); assertEquals(rootBefore, root.toSealedForm());
                assertEquals(v.semantic(), assertDoesNotThrow(() -> readTyped(old, v)));
                assertEquals(16384, next.maximumRecordBytes());
                assertEquals(16384, SealedStateAccess.get().getMaximumSealedLength(s));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedInvalidNumbersAreNeverCoercedIntoIntegers() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) if (!v.valid()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-05/invalid/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k); var next = target(s); var migration = migration(next);
                var source = v.entry(); String before = source.toSealedForm();
                assertEquals(v.oldWire(), raw(source, s, 1));
                if (v.kind() == OAuthStoreKey.Kind.ISSUER_STATE)
                    assertThrows(IllegalArgumentException.class, () -> migration.openRoot(source));
                else {
                    var pinned = assertDoesNotThrow(() -> migration.openRoot(v.root()));
                    assertThrows(IllegalArgumentException.class, () -> migration.convert(source, pinned));
                }
                assertEquals(before, source.toSealedForm());
            }));
        return tests;
    }

    private static void assertIntegerFacts(@NonNull JsonObject expected, @NonNull JsonObject actual) {
        for (var field : expected.getMembers().entrySet())
            if (field.getValue() instanceof com.revetsec.json.JsonNumber number)
                assertEquals(number.getLongValueExact().orElseThrow(), OAuthStoreFormat.longMember(actual, field.getKey()).orElseThrow());
    }
    private static @NonNull JsonObject readTyped(@NonNull OAuthStoreRecordCodec old, @NonNull Vector v) {
        JsonObject payload = old.open(v.entry(), CLOCK);
        if (v.kind() == OAuthStoreKey.Kind.ISSUER_STATE || v.kind() == OAuthStoreKey.Kind.SUBJECT_STATE)
            OAuthStoreFence.decode(payload, v.kind());
        else OAuthAuthorizationRecord.decode(v.kind(), identifier(v.key()), payload, LIMITS, 1024);
        return payload;
    }
    private record Vector(int index) {
        @NonNull String value(@NonNull String name) { return property("v." + this.index + '.' + name); }
        @NonNull String text(@NonNull String name) { return unhex(value(name)); }
        @NonNull String name() { return value("name"); }
        boolean valid() { return Boolean.parseBoolean(value("valid")); }
        boolean fits() { return Boolean.parseBoolean(value("fits")); }
        OAuthStoreKey.@NonNull Kind kind() { return OAuthStoreKey.Kind.valueOf(value("kind")); }
        @NonNull OAuthStoreKey key() { return OAuthStoreKey.fromStoredForm(value("key")); }
        @NonNull Instant retention() { return Instant.ofEpochSecond(Long.parseLong(value("retain"))); }
        @NonNull Instant floor() { return Instant.ofEpochSecond(Long.parseLong(value("floorSeconds")), Integer.parseInt(value("floorNanos"))); }
        @NonNull Instant rootMinimum() {
            var root = parse(value("rootSemanticHex"));
            return Instant.ofEpochSecond(OAuthStoreFormat.longMember(root, "highWaterSeconds").orElseThrow(),
                    OAuthStoreFormat.longMember(root, "highWaterNanos").orElseThrow());
        }
        int oldP() { return Integer.parseInt(value("oldP")); }
        int newP() { return Integer.parseInt(value("newP")); }
        @NonNull JsonObject semantic() { return parse(value("semanticPayloadHex")); }
        @NonNull String oldWire() { return text("oldWireHex"); }
        @NonNull String targetExpected() { return text("targetExpectedHex"); }
        @NonNull OAuthStoreEntry entry() { return OAuthStoreEntry.fromStoredForm(key(), value("version"), retention(), value("sealed")); }
        @NonNull OAuthStoreEntry root() { return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(property("rootKey")), value("rootVersion"), OAuthStoreFormat.PERMANENT, value("rootSealed")); }
    }
    private static @NonNull List<@NonNull Vector> vectors() {
        List<Vector> result = new ArrayList<>();
        for (int i = 0; i < Integer.parseInt(property("count")); i++) result.add(new Vector(i));
        return result;
    }
    private static @NonNull List<@NonNull Vector> valid() { return vectors().stream().filter(Vector::valid).toList(); }
    private static @NonNull String placeholder() { return property("versionPlaceholder"); }
    private static @NonNull OAuthStoreRecordCodec legacy(@NonNull StateSealer s) { return new OAuthStoreRecordCodec(unhex(property("issuerHex")), s, 16384); }
    private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull StateSealer s) { return new OAuthStoreRecordCodecV2(unhex(property("issuerHex")), s, 16384, LIMITS, 1024); }
    private static @NonNull OAuthStoreMigrationCodec migration(@NonNull OAuthStoreRecordCodecV2 next) {
        return new OAuthStoreMigrationCodec(next, 16384, ClosedMigrationIntent.fromExternalIntent(id(1),
                StoreAdmission.fromIdentifiers(property("authority"), id(3)), Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
    }
    private static @NonNull StateSealer sealer(int k) {
        return StateSealer.withActiveKey(SealingKey.fromBase64("n".repeat(k), NEW_MASTER))
                .verificationKeys(List.of(SealingKey.fromBase64("o", OLD_MASTER))).maximumSealedLength(16384).clock(CLOCK).build();
    }
    private static @NonNull String raw(@NonNull OAuthStoreEntry entry, @NonNull StateSealer s, int schema) throws Exception {
        return SealedStateAccess.get().unseal(s, SealedStateType.AS_RECORD, entry.toSealedForm(),
                "revetsec/as-record/v" + schema + ':' + entry.getKey().getStorageKey(), CLOCK);
    }
    private static @NonNull String identifier(@NonNull OAuthStoreKey key) { return key.getStorageKey().substring(key.getStorageKey().lastIndexOf(':') + 1); }
    private static int wire(int p, int k) { return ((54 + k + p) * 4 + 2) / 3; }
    private static byte @NonNull [] utf8(@NonNull String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull String unhex(@NonNull String s) { return new String(HexFormat.of().parseHex(s), StandardCharsets.UTF_8); }
    private static @NonNull JsonObject parse(@NonNull String hex) { return OAuthStoreRecordCodecV2.parse(unhex(hex), 16384); }
    private static @NonNull String property(@NonNull String name) { return Objects.requireNonNull(PROPERTIES.getProperty(name), name); }
    private static @NonNull String id(int n) { return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array()); }
    private static byte @NonNull [] loadBytes() {
        try (var in = Objects.requireNonNull(OAuthLegacyJsonNormalizationTests.class.getResourceAsStream(RESOURCE))) { return in.readAllBytes(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static @NonNull Properties loadProperties() {
        Properties result = new Properties();
        try (var in = new ByteArrayInputStream(GOLDEN)) { result.load(in); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
        return result;
    }
}
