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
import com.revetsec.internal.http.Deadline;
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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** CAP-04 permanent logical maxima and exact persisted time, independently of timed admission. */
final class OAuthPermanentCapacityGoldenTests {
    private static final @NonNull String RESOURCE = "/fixtures/oauth/cap-04.properties";
    private static final @NonNull String OLD_MASTER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final @NonNull String NEW_MASTER = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final @NonNull Instant NOW = Instant.ofEpochSecond(1700000000L, 123456788);
    private static final @NonNull Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();
    private static final byte @NonNull [] GOLDEN = loadBytes();
    private static final @NonNull Properties PROPERTIES = loadProperties();

    @Test void corpusPinsTheExactPermanentBoundsAndFullWidthIdentities() throws Exception {
        assertEquals("c8b8cc4e1d84c9fd4d407c01f0971707f3369fd46492de6b274cdb511bde0427",
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(GOLDEN)));
        assertEquals(42, vectors().size());
        assertEquals(43, property("authority").length());
        byte[] largestBytes = new byte[32]; java.util.Arrays.fill(largestBytes, (byte) 255);
        assertArrayEquals(largestBytes, Base64.getUrlDecoder().decode(property("authority")));
        assertEquals(1024, subject().length());
        int largestRoot = 0, largestSubject = 0;
        for (Vector v : vectors()) {
            assertEquals(2048, v.issuer().length());
            OAuthServerConfiguration.text(v.issuer(), 2048);
            assertEquals(v.oldP(), utf8(v.oldExpected()).length);
            assertEquals(v.newP(), utf8(v.targetExpected()).length);
            assertEquals(v.rootKind() ? 114 : 115, v.key().getStorageKey().length());
            if (v.rootKind()) largestRoot = Math.max(largestRoot, v.newP());
            else largestSubject = Math.max(largestSubject, v.newP());
            assertTrue(v.newP() <= (v.rootKind() ? 6668 : 6548));
        }
        assertEquals(6668, largestRoot); assertEquals(9048, wire(largestRoot, 64));
        assertEquals(6548, largestSubject); assertEquals(8888, wire(largestSubject, 64));
        assertThrows(IllegalArgumentException.class, () -> new OAuthStoreRecordCodec("漢".repeat(2049), sealer(64), 16384));
        assertThrows(IllegalArgumentException.class, () -> StoreAdmission.fromIdentifiers(property("authority") + "A", id(3)));
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> nativePermanentRecordsReachBoundsWithoutChangingFacts() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-04/native/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k); var next = target(v, s);
                var entry = assertDoesNotThrow(() -> next.sealVersion(v.key(), placeholder(), OAuthStoreFormat.PERMANENT,
                        v.floor(), v.targetPayload().toJson()));
                assertEquals(v.targetExpected(), raw(entry, s, 2));
                assertEquals(v.newP(), utf8(raw(entry, s, 2)).length);
                assertEquals(wire(v.newP(), k), entry.toSealedForm().length());
                assertEquals(OAuthStoreFormat.PERMANENT, entry.getRetainUntil());
                var root = v.rootKind() ? entry : assertDoesNotThrow(() -> next.sealVersion(next.issuerKey(), id(71),
                        OAuthStoreFormat.PERMANENT, v.floor(), v.targetRootPayload().toJson()));
                var opened = assertDoesNotThrow(() -> next.openPermanentFence(entry, admission(), root));
                assertEquals(v.floor(), opened.floor());
                assertEquals(v.targetPayload(), opened.payload());
                typed(v, opened.payload());
                assertThrows(IllegalArgumentException.class, () -> next.openPermanentFence(entry,
                        StoreAdmission.fromIdentifiers(id(8), id(3)), root));
                if (v.rootKind() && v.value("shape").equals("bmp-maximum") && v.value("floorName").equals("widest-negative")) {
                    assertEquals(6668, v.newP()); assertEquals(k == 64 ? 9048 : 8964, entry.toSealedForm().length());
                }
                if (!v.rootKind() && v.value("shape").equals("bmp-maximum") && v.value("floorName").equals("widest-negative")) {
                    assertEquals(6548, v.newP()); assertEquals(k == 64 ? 8888 : 8804, entry.toSealedForm().length());
                }
                assertEquals(12170, next.maximumPlaintextBytes());
                assertEquals(16384, SealedStateAccess.get().getMaximumSealedLength(s));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> frozenPermanentMigrationPreservesExactFloorsAndMaximalEpochs() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-04/closed/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k); var next = target(v, s);
                var old = new OAuthStoreRecordCodec(v.issuer(), s, 16384);
                var source = v.entry(); var root = v.root();
                String before = source.toSealedForm(), rootBefore = root.toSealedForm();
                assertEquals(v.oldPayload(), assertDoesNotThrow(() -> old.open(source, CLOCK)));
                assertEquals(v.oldExpected().replace(placeholder(), source.getVersion()), raw(source, s, 1));
                var migration = new OAuthStoreMigrationCodec(next, 16384, ClosedMigrationIntent.fromExternalIntent(
                        id(1), admission(), Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
                var pinned = assertDoesNotThrow(() -> migration.openRoot(root));
                assertEquals(v.floor(), pinned.minimum()); assertEquals(property("authority"), pinned.authorityId());
                var converted = assertDoesNotThrow(() -> migration.convert(source, pinned));
                assertNotEquals(source.getVersion(), converted.getVersion());
                assertEquals(source.getKey(), converted.getKey());
                assertEquals(source.getRetainUntil(), converted.getRetainUntil());
                assertEquals(v.targetExpected().replace(placeholder(), converted.getVersion()), raw(converted, s, 2));
                assertEquals(wire(v.newP(), k), converted.toSealedForm().length());
                var opened = assertDoesNotThrow(() -> next.open(converted, CLOCK));
                assertEquals(v.floor(), opened.floor()); assertEquals(v.targetPayload(), opened.payload());
                typed(v, opened.payload());
                if (v.rootKind()) assertThrows(IllegalArgumentException.class, () -> OAuthIssuerRootV2.decode(opened.payload()).advance());
                else assertThrows(IllegalArgumentException.class, () -> OAuthStoreFence.decode(opened.payload(), v.kind()).advance(NOW));
                assertEquals(before, source.toSealedForm()); assertEquals(rootBefore, root.toSealedForm());
                assertEquals(v.oldPayload(), assertDoesNotThrow(() -> old.open(source, CLOCK)));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> structuralFitNeverOpensIncompatibleTimedAdmission() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : vectors()) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-04/timed/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k); var next = target(v, s);
                var entry = assertDoesNotThrow(() -> next.sealVersion(v.key(), placeholder(), OAuthStoreFormat.PERMANENT,
                        v.floor(), v.targetPayload().toJson()));
                // A healthy independent root isolates subject-floor rejection from root-floor rejection.
                Instant stableMinimum = NOW.minusNanos(1);
                var root = v.rootKind() ? entry : assertDoesNotThrow(() -> next.sealVersion(next.issuerKey(), id(71),
                        OAuthStoreFormat.PERMANENT, stableMinimum, stableRoot(stableMinimum).toJson()));
                assertEquals(v.floor(), assertDoesNotThrow(() -> next.openPermanentFence(entry, admission(), root)).floor());
                var store = new OAuthAtomicStoreFixture(NOW); store.admission = admission();
                store.rows.put(root.getKey(), root); if (!v.rootKind()) store.rows.put(entry.getKey(), entry);
                var before = Map.copyOf(store.rows);
                var coordinator = new OAuthStoreCoordinator(store, new OAuthStoreRecordCodec(v.issuer(), s, 16384), CLOCK, 1, 1024);
                org.junit.jupiter.api.function.Executable timed = () -> {
                    var session = coordinator.begin(Deadline.fromNow(Duration.ofSeconds(10)));
                    if (!v.rootKind()) assertEquals(Long.MAX_VALUE, session.subject(subject()).epoch());
                    assertEquals(OAuthStoreCommitStatus.COMMITTED, session.barrier());
                };
                if (Boolean.parseBoolean(v.value("timedAllowed"))) {
                    assertDoesNotThrow(timed);
                    assertEquals(1, store.commits);
                    var submitted = Objects.requireNonNull(store.lastTransaction);
                    assertEquals(OAuthStoreTransaction.Purpose.TIMED, submitted.getPurpose());
                    assertTrue(submitted.getMutations().isEmpty());
                    assertEquals(NOW, submitted.getTemporalCondition().orElseThrow().getNotBeforeInclusive());
                    assertEquals(admission().getAuthorityId(), submitted.getExpectedAdmission().getAuthorityId());
                    assertEquals(admission().getRecoveryGeneration(), submitted.getExpectedAdmission().getRecoveryGeneration());
                } else {
                    var failure = assertThrows(OAuthStoreFailure.class, timed);
                    assertEquals(OAuthStoreFailure.Reason.UNAVAILABLE, failure.reason());
                    assertEquals(0, store.commits);
                }
                assertTrue(store.reads >= (v.rootKind() ? 1 : 2));
                assertEquals(before, store.rows);
                assertEquals(v.floor(), assertDoesNotThrow(() -> next.openPermanentFence(entry, admission(), root)).floor());
                assertEquals(OAuthStoreFormat.PERMANENT, entry.getRetainUntil());
            }));
        return tests;
    }

    private static void typed(@NonNull Vector v, @NonNull JsonObject payload) {
        if (v.rootKind()) {
            var decoded = OAuthIssuerRootV2.decode(payload);
            assertEquals(Long.MAX_VALUE, decoded.epoch()); assertEquals(property("authority"), decoded.authorityId());
            assertEquals(property("incarnation"), decoded.incarnation()); assertEquals(v.floor(), decoded.minimum());
        } else {
            var decoded = OAuthStoreFence.decode(payload, v.kind());
            assertEquals(Long.MAX_VALUE, decoded.epoch()); assertEquals(property("subjectIncarnation"), decoded.incarnation());
            assertEquals(1L, OAuthStoreFormat.longMember(payload, "schema").orElseThrow());
        }
    }
    private record Vector(int index) {
        @NonNull String value(@NonNull String key) { return property("v." + this.index + '.' + key); }
        @NonNull String name() { return value("name"); }
        @NonNull String issuer() { return unhex(value("issuerHex")); }
        OAuthStoreKey.@NonNull Kind kind() { return OAuthStoreKey.Kind.valueOf(value("kind")); }
        boolean rootKind() { return kind() == OAuthStoreKey.Kind.ISSUER_STATE; }
        @NonNull OAuthStoreKey key() { return OAuthStoreKey.fromStoredForm(value("key")); }
        int oldP() { return Integer.parseInt(value("oldP")); }
        int newP() { return Integer.parseInt(value("newP")); }
        @NonNull Instant floor() { return Instant.ofEpochSecond(Long.parseLong(value("floorSeconds")), Integer.parseInt(value("floorNanos"))); }
        @NonNull JsonObject oldPayload() { return parseHex(value("oldPayloadHex")); }
        @NonNull JsonObject targetPayload() { return parseHex(value("targetPayloadHex")); }
        @NonNull JsonObject targetRootPayload() { return parseHex(value("targetRootPayloadHex")); }
        @NonNull String oldExpected() { return unhex(value("oldExpectedHex")); }
        @NonNull String targetExpected() { return unhex(value("targetExpectedHex")); }
        @NonNull OAuthStoreEntry entry() { return OAuthStoreEntry.fromStoredForm(key(), value("version"), OAuthStoreFormat.PERMANENT, value("sealed")); }
        @NonNull OAuthStoreEntry root() { return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(value("rootKey")), value("rootVersion"), OAuthStoreFormat.PERMANENT, value("rootSealed")); }
    }
    private static @NonNull List<@NonNull Vector> vectors() {
        List<Vector> result = new ArrayList<>();
        for (int i = 0; i < Integer.parseInt(property("count")); i++) result.add(new Vector(i));
        return result;
    }
    private static @NonNull StoreAdmission admission() { return StoreAdmission.fromIdentifiers(property("authority"), id(3)); }
    private static @NonNull String subject() { return unhex(property("subjectHex")); }
    private static @NonNull String placeholder() { return property("versionPlaceholder"); }
    private static @NonNull JsonObject stableRoot(@NonNull Instant floor) {
        return JsonObject.builder().put("schema", 2L).put("incarnation", property("incarnation")).put("epoch", Long.MAX_VALUE)
                .put("authorityId", property("authority")).put("minimumSeconds", floor.getEpochSecond())
                .put("minimumNanos", (long) floor.getNano()).build();
    }
    private static @NonNull StateSealer sealer(int k) {
        return StateSealer.withActiveKey(SealingKey.fromBase64("n".repeat(k), NEW_MASTER))
                .verificationKeys(List.of(SealingKey.fromBase64("f".repeat(64), OLD_MASTER)))
                .maximumSealedLength(16384).clock(CLOCK).build();
    }
    private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull Vector v, @NonNull StateSealer s) { return new OAuthStoreRecordCodecV2(v.issuer(), s, 16384, LIMITS, 1024); }
    private static @NonNull String raw(@NonNull OAuthStoreEntry entry, @NonNull StateSealer s, int schema) throws Exception {
        return SealedStateAccess.get().unseal(s, SealedStateType.AS_RECORD, entry.toSealedForm(), "revetsec/as-record/v" + schema + ':' + entry.getKey().getStorageKey(), CLOCK);
    }
    private static int wire(int p, int k) { return ((54 + k + p) * 4 + 2) / 3; }
    private static byte @NonNull [] utf8(@NonNull String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull String unhex(@NonNull String s) { return new String(HexFormat.of().parseHex(s), StandardCharsets.UTF_8); }
    private static @NonNull JsonObject parseHex(@NonNull String s) { return OAuthStoreRecordCodecV2.parse(unhex(s), 16384); }
    private static @NonNull String property(@NonNull String name) { return Objects.requireNonNull(PROPERTIES.getProperty(name), name); }
    private static @NonNull String id(int n) { return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array()); }
    private static byte @NonNull [] loadBytes() {
        try (var in = Objects.requireNonNull(OAuthPermanentCapacityGoldenTests.class.getResourceAsStream(RESOURCE))) { return in.readAllBytes(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static @NonNull Properties loadProperties() {
        Properties result = new Properties();
        try (var in = new ByteArrayInputStream(GOLDEN)) { result.load(in); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
        return result;
    }
}
