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
import com.revetsec.internal.crypto.SealerV1;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** CAP-03: authentic old maximum, exact larger target wire, and refusal without lossy fallback. */
final class OAuthLegacyOversizeGoldenTests {
    private static final @NonNull String RESOURCE = "/fixtures/oauth/cap-03.properties";
    private static final @NonNull String OLD_MASTER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final @NonNull String NEW_MASTER = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final @NonNull Instant MINIMUM = Instant.ofEpochSecond(1700000000L, 999999999);
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC);
    private static final @NonNull OAuthServerIngressLimits LIMITS =
            new OAuthServerIngressLimits(65536, 65536, 65536, 1024, 1024, 8, 16, 80, 128);
    private static final byte @NonNull [] GOLDEN = loadBytes();
    private static final @NonNull Properties PROPERTIES = loadProperties();

    @Test void fixedOldMaximumReconstructsThePlannedCounterexample() throws Exception {
        assertEquals("fd379b337eb59bbad6a13b1b740d6ca31992cdf8923e62d8dcab85dfd9e8dc52",
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(GOLDEN)));
        assertEquals(4, vectors().size());
        for (Vector v : vectors()) {
            var record = semantic(v, v.payload());
            assertEquals(80, record.scopes(LIMITS).size());
            assertTrue(record.scopes(LIMITS).stream().allMatch(s -> s.length() == 128 && s.chars().allMatch(c -> c < 128)));
            assertEquals(v.stateLength(), record.text("state").length());
            assertEquals("s".repeat(v.stateLength()), record.text("state"));
            assertEquals(v.retention(), record.retention());
            assertEquals(v.oldP(), utf8(v.oldExpected()).length);
            assertEquals(v.newP(), utf8(v.targetExpected()).length);
            assertEquals(v.oldP() + 49, v.newP());
        }
        Vector maximum = new Vector(2);
        assertEquals(1012, maximum.stateLength());
        assertEquals(12233, maximum.oldP());
        assertEquals(16384, maximum.entry().toSealedForm().length());
        assertEquals(12282, maximum.newP());
        assertEquals(16450, wire(maximum.newP(), 1));
        assertEquals(16534, wire(maximum.newP(), 64));
        assertEquals(12170, new Vector(0).newP());
        assertEquals(900, new Vector(0).stateLength());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> frozenAndCurrentOldCodecsAgreeAtTheOldBoundary() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) tests.add(DynamicTest.dynamicTest("CAP-03/old/" + v.name(), () -> {
            StateSealer s = oldSealer();
            var old = new OAuthStoreRecordCodec(property("issuer"), s, 16384);
            String payloadBefore = v.payload().toJson();
            if (!v.oldAdmitted()) {
                assertEquals(12234, v.oldP());
                assertThrows(IllegalArgumentException.class, () -> old.seal(v.key(), v.retention(), payloadBefore));
                assertNull(PROPERTIES.getProperty("v." + v.index() + ".sealed"));
            } else {
                var frozen = v.entry();
                var opened = assertDoesNotThrow(() -> old.open(frozen, CLOCK));
                assertEquals(v.payload(), opened);
                assertEquals(v.oldExpected().replace(v.placeholder(), frozen.getVersion()), raw(frozen, s, 1));
                assertEquals(wire(v.oldP(), 1), frozen.toSealedForm().length());
                assertEquals(1, Byte.toUnsignedInt(Base64.getUrlDecoder().decode(frozen.toSealedForm())[1]));
                assertEquals(payloadBefore, semantic(v, opened).toPayload());
                var fresh = assertDoesNotThrow(() -> old.seal(v.key(), v.retention(), payloadBefore));
                assertEquals(frozen.toSealedForm().length(), fresh.toSealedForm().length());
                assertEquals(v.oldExpected().replace(v.placeholder(), fresh.getVersion()), raw(fresh, s, 1));
                assertEquals(v.payload(), assertDoesNotThrow(() -> old.open(fresh, CLOCK)));
            }
            assertEquals(payloadBefore, v.payload().toJson());
            assertEquals(16384, SealedStateAccess.get().getMaximumSealedLength(s));
        }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> actualTargetWireCannotBeMadeToFitByShorteningTheKey() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : admitted()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-03/wire/" + v.name() + "/K" + k, () -> {
                StateSealer s = targetSealer(k);
                var next = target(s);
                // Test-only unbounded raw framing proves the physical impossibility independently.
                // It produces no admissible store entry when the configured public carrier is exceeded.
                String rawSealed = rawTargetSeal(v, k);
                assertEquals(wire(v.newP(), k), rawSealed.length());
                assertEquals(k, Byte.toUnsignedInt(Base64.getUrlDecoder().decode(rawSealed)[1]));
                if (v.newP() > 12170) {
                    assertTrue(rawSealed.length() > 16384);
                    assertThrows(IllegalArgumentException.class, () ->
                            OAuthStoreEntry.fromStoredForm(v.key(), v.placeholder(), v.retention(), rawSealed));
                    assertThrows(IllegalArgumentException.class, () ->
                            next.sealVersion(v.key(), v.placeholder(), v.retention(), MINIMUM, v.payload().toJson()));
                } else {
                    var entry = OAuthStoreEntry.fromStoredForm(v.key(), v.placeholder(), v.retention(), rawSealed);
                    assertEquals(v.payload(), next.open(entry, CLOCK).payload());
                    var fresh = assertDoesNotThrow(() ->
                            next.sealVersion(v.key(), v.placeholder(), v.retention(), MINIMUM, v.payload().toJson()));
                    assertEquals(v.targetExpected(), raw(fresh, s, 2));
                    assertEquals(wire(v.newP(), k), fresh.toSealedForm().length());
                }
                assertEquals(16384, next.maximumRecordBytes());
                assertEquals(12170, next.maximumPlaintextBytes());
                assertEquals(16384, SealedStateAccess.get().getMaximumSealedLength(s));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> closedConversionRefusesWithoutTrimmingOrReturningLegacyData() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : admitted()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-03/closed/" + v.name() + "/K" + k, () -> {
                StateSealer s = targetSealer(k);
                var old = new OAuthStoreRecordCodec(property("issuer"), s, 16384);
                var next = target(s);
                var migration = new OAuthStoreMigrationCodec(next, 16384, ClosedMigrationIntent.fromExternalIntent(
                        id(1), StoreAdmission.fromIdentifiers(id(2), id(3)), Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
                var source = v.entry();
                var root = root();
                String sourceBytes = source.toSealedForm(), rootBytes = root.toSealedForm();
                String sourceVersion = source.getVersion(), rootVersion = root.getVersion();
                var sourcePayload = assertDoesNotThrow(() -> old.open(source, CLOCK));
                assertEquals(v.payload(), sourcePayload);
                assertEquals(v.payload().toJson(), semantic(v, sourcePayload).toPayload());
                var pinned = assertDoesNotThrow(() -> migration.openRoot(root));
                assertEquals(MINIMUM, pinned.minimum());
                assertEquals(id(2), pinned.authorityId());
                // A real successful conversion under the same selected target prevents a vacuous refusal oracle.
                var fitting = new Vector(0);
                var control = assertDoesNotThrow(() -> migration.convert(fitting.entry(), pinned));
                assertEquals(fitting.payload(), assertDoesNotThrow(() -> next.open(control, CLOCK)).payload());
                assertEquals(wire(fitting.newP(), k), control.toSealedForm().length());
                if (v.newP() > 12170) {
                    assertThrows(IllegalArgumentException.class, () -> migration.convert(source, pinned));
                } else {
                    var converted = assertDoesNotThrow(() -> migration.convert(source, pinned));
                    assertNotEquals(sourceVersion, converted.getVersion());
                    assertEquals(source.getKey(), converted.getKey());
                    assertEquals(source.getRetainUntil(), converted.getRetainUntil());
                    assertEquals(v.targetExpected().replace(v.placeholder(), converted.getVersion()), raw(converted, s, 2));
                    assertEquals(v.payload(), next.open(converted, CLOCK).payload());
                    assertEquals(MINIMUM, next.open(converted, CLOCK).floor());
                    assertEquals(k, Byte.toUnsignedInt(Base64.getUrlDecoder().decode(converted.toSealedForm())[1]));
                }
                // The codec returns only a prepared replacement. It owns no store or publication capability.
                assertEquals(sourceBytes, source.toSealedForm());
                assertEquals(sourceVersion, source.getVersion());
                assertEquals(rootBytes, root.toSealedForm());
                assertEquals(rootVersion, root.getVersion());
                assertEquals(v.payload(), assertDoesNotThrow(() -> old.open(source, CLOCK)));
                assertEquals(80, semantic(v, v.payload()).scopes(LIMITS).size());
                assertEquals("s".repeat(v.stateLength()), semantic(v, v.payload()).text("state"));
                assertEquals(v.retention(), source.getRetainUntil());
            }));
        return tests;
    }

    private record Vector(int index) {
        @NonNull String value(@NonNull String key) { return property("v." + this.index + '.' + key); }
        @NonNull String name() { return value("name"); }
        int stateLength() { return Integer.parseInt(value("stateLength")); }
        int oldP() { return Integer.parseInt(value("oldP")); }
        int newP() { return Integer.parseInt(value("newP")); }
        boolean oldAdmitted() { return Boolean.parseBoolean(value("oldAdmitted")); }
        @NonNull String placeholder() { return value("versionPlaceholder"); }
        @NonNull OAuthStoreKey key() { return OAuthStoreKey.fromStoredForm(value("key")); }
        @NonNull Instant retention() { return Instant.ofEpochSecond(Long.parseLong(value("retain"))); }
        @NonNull JsonObject payload() { return OAuthStoreRecordCodecV2.parse(unhex(value("payloadHex")), 16384); }
        @NonNull String oldExpected() { return unhex(value("oldExpectedHex")); }
        @NonNull String targetExpected() { return unhex(value("targetExpectedHex")); }
        @NonNull OAuthStoreEntry entry() { return OAuthStoreEntry.fromStoredForm(key(), value("version"), retention(), value("sealed")); }
    }
    private static @NonNull List<@NonNull Vector> vectors() {
        List<Vector> result = new ArrayList<>();
        for (int i = 0; i < Integer.parseInt(property("count")); i++) result.add(new Vector(i));
        return result;
    }
    private static @NonNull List<@NonNull Vector> admitted() { return vectors().stream().filter(Vector::oldAdmitted).toList(); }
    private static @NonNull OAuthAuthorizationRecord semantic(@NonNull Vector v, @NonNull JsonObject payload) {
        return OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION, v.value("id"), payload, LIMITS, 1024);
    }
    private static @NonNull OAuthStoreEntry root() {
        return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(property("rootKey")),
                property("rootVersion"), OAuthStoreFormat.PERMANENT, property("rootSealed"));
    }
    private static @NonNull StateSealer oldSealer() {
        return StateSealer.withActiveKey(SealingKey.fromBase64("o", OLD_MASTER)).maximumSealedLength(16384).clock(CLOCK).build();
    }
    private static @NonNull StateSealer targetSealer(int k) {
        return StateSealer.withActiveKey(SealingKey.fromBase64("n".repeat(k), NEW_MASTER))
                .verificationKeys(List.of(SealingKey.fromBase64("o", OLD_MASTER))).maximumSealedLength(16384).clock(CLOCK).build();
    }
    private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull StateSealer s) {
        return new OAuthStoreRecordCodecV2(property("issuer"), s, 16384, LIMITS, 1024);
    }
    private static @NonNull String rawTargetSeal(@NonNull Vector v, int k) throws Exception {
        String kid = "n".repeat(k), text = v.targetExpected(), context = OAuthStoreRecordCodecV2.context(v.key());
        var key = SealerV1.Key.fromMasterKey(kid, Base64.getDecoder().decode(NEW_MASTER));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(utf8(text + kid));
        String sealed = SealerV1.seal(key, SealedStateType.AS_RECORD, context, v.retention().getEpochSecond(), utf8(text),
                Arrays.copyOfRange(digest, 0, 16), Arrays.copyOfRange(digest, 16, 28));
        assertEquals(text, SealerV1.open(sealed, sealed.length(), Map.of(kid, key), SealedStateType.AS_RECORD, context, Instant.EPOCH));
        return sealed;
    }
    private static @NonNull String raw(@NonNull OAuthStoreEntry entry, @NonNull StateSealer s, int schema) throws Exception {
        return SealedStateAccess.get().unseal(s, SealedStateType.AS_RECORD, entry.toSealedForm(),
                "revetsec/as-record/v" + schema + ':' + entry.getKey().getStorageKey(), CLOCK);
    }
    private static int wire(int p, int k) { return ((54 + k + p) * 4 + 2) / 3; }
    private static byte @NonNull [] utf8(@NonNull String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull String unhex(@NonNull String s) { return new String(HexFormat.of().parseHex(s), StandardCharsets.UTF_8); }
    private static @NonNull String property(@NonNull String name) { return Objects.requireNonNull(PROPERTIES.getProperty(name), name); }
    private static @NonNull String id(int n) { return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array()); }
    private static byte @NonNull [] loadBytes() {
        try (var in = Objects.requireNonNull(OAuthLegacyOversizeGoldenTests.class.getResourceAsStream(RESOURCE))) { return in.readAllBytes(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static @NonNull Properties loadProperties() {
        Properties result = new Properties();
        try (var in = new ByteArrayInputStream(GOLDEN)) { result.load(in); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
        return result;
    }
}
