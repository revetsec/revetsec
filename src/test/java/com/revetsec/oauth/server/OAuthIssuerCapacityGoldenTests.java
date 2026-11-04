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
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
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
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** CAP-02 complete envelopes, independently sized golden JSON, and refusal before store mutation. */
final class OAuthIssuerCapacityGoldenTests {
    private static final @NonNull String RESOURCE = "/fixtures/oauth/cap-02.properties";
    private static final @NonNull String MASTER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final @NonNull Instant NOW = Instant.ofEpochSecond(1700000000L);
    private static final @NonNull Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final @NonNull OAuthServerIngressLimits LIMITS =
            new OAuthServerIngressLimits(65536, 65536, 65536, 4096, 4096, 8, 16, 64, 128);
    private static final byte @NonNull [] GOLDEN = loadBytes();
    private static final @NonNull Properties PROPERTIES = loadProperties();

    @Test void independentCorpusPinsExactCombinedEscapingAndUtf8Boundaries() throws Exception {
        assertEquals("49b4152a89b160b1aa3e9df80bb7b0090b7f22d3c40ad445c2786a07c2313872",
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(GOLDEN)));
        assertEquals(42, vectors().size());
        assertEquals(36, selected("golden").size());
        assertEquals(6, selected("admission").size());
        Set<Integer> boundaries = new LinkedHashSet<>();
        for (Vector v : vectors()) {
            boundaries.add(v.completeBytes());
            assertEquals(v.completeBytes(), utf8(v.outer()).length);
            assertTrue(v.outer().length() < utf8(v.outer()).length);
            for (String text : List.of(v.issuer(), field(v.payload(), v.kind() == OAuthStoreKey.Kind.GRANT ? "subject" : "state"))) {
                assertTrue(text.contains("é") && text.contains("漢") && text.contains("😀"));
                assertTrue(text.contains("\"") && text.contains("\\"));
                assertTrue(JsonString.fromValue(text).toJson().contains("\\\""));
                assertTrue(JsonString.fromValue(text).toJson().contains("\\\\"));
            }
            // These are structural codec fixtures. Public new-request state remains printable ASCII.
            OAuthServerConfiguration.text(v.issuer(), 2048);
            semantic(v, v.payload());
        }
        assertEquals(Set.of(12169, 12170, 12171), boundaries);
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> goldenCompleteUtf8AndActualSealedOutputAgree() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : selected("golden")) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-02/golden/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k);
                var codec = target(v, s);
                assertEquals(v.key(), codec.key(v.kind(), id(7)));
                String before = v.payload().toJson();
                if (v.completeBytes() > 12170) {
                    assertThrows(IllegalArgumentException.class, () ->
                            codec.sealVersion(v.key(), id(70), v.retention(), v.floor(), before));
                } else {
                    var row = codec.sealVersion(v.key(), id(70), v.retention(), v.floor(), before);
                    assertEquals(v.outer(), raw(row, s, 2));
                    assertEquals(wire(v.completeBytes(), k), row.toSealedForm().length());
                    assertEquals(v.payload(), codec.open(row, CLOCK).payload());
                    assertEquals(v.floor(), codec.open(row, CLOCK).floor());
                    if (v.completeBytes() == 12170) assertEquals(k == 64 ? 16384 : 16300, row.toSealedForm().length());
                }
                // Authenticate a complete independently sized over-limit envelope, even where public
                // transport must refuse K64 before codec opening. No production limit is increased.
                String sealed = rawSeal(k, v.key(), v.retention(), v.outer());
                assertEquals(wire(v.completeBytes(), k), sealed.length());
                if (sealed.length() > 16384) {
                    assertThrows(IllegalArgumentException.class, () ->
                            OAuthStoreEntry.fromStoredForm(v.key(), id(70), v.retention(), sealed));
                } else {
                    var row = OAuthStoreEntry.fromStoredForm(v.key(), id(70), v.retention(), sealed);
                    if (v.completeBytes() > 12170) assertThrows(IllegalArgumentException.class, () -> codec.open(row, CLOCK));
                    else assertEquals(v.payload(), codec.open(row, CLOCK).payload());
                }
                assertEquals(before, v.payload().toJson());
                assertEquals(16384, codec.maximumRecordBytes());
                assertEquals(12170, codec.maximumPlaintextBytes());
                assertEquals(16384, SealedStateAccess.get().getMaximumSealedLength(s));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> closedConversionPreservesAllFactsOrReturnsNoReplacement() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : selected("golden")) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-02/closed/" + v.name() + "/K" + k, () -> {
                StateSealer s = sealer(k);
                var old = new OAuthStoreRecordCodec(v.issuer(), s, 16384);
                var codec = target(v, s);
                var source = old.seal(v.key(), v.retention(), v.payload().toJson());
                assertEquals(v.oldOuter().replace(id(70), source.getVersion()), raw(source, s, 1));
                assertEquals(wire(utf8(v.oldOuter()).length, k), source.toSealedForm().length());
                var root = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT,
                        JsonObject.builder().put("schema", 1L).put("incarnation", id(4)).put("epoch", Long.MAX_VALUE)
                                .put("highWaterSeconds", v.floor().getEpochSecond())
                                .put("highWaterNanos", (long) v.floor().getNano()).build().toJson());
                var migration = new OAuthStoreMigrationCodec(codec, 16384, ClosedMigrationIntent.fromExternalIntent(
                        id(1), StoreAdmission.fromIdentifiers(id(2), id(3)), Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
                var pinned = migration.openRoot(root);
                Map<OAuthStoreKey, OAuthStoreEntry> original = Map.of(source.getKey(), source, root.getKey(), root);
                String sourceBytes = source.toSealedForm(), rootBytes = root.toSealedForm();
                if (v.completeBytes() > 12170) {
                    assertThrows(IllegalArgumentException.class, () -> migration.convert(source, pinned));
                } else {
                    var replacement = migration.convert(source, pinned);
                    assertNotEquals(source.getVersion(), replacement.getVersion());
                    assertEquals(source.getKey(), replacement.getKey());
                    assertEquals(source.getRetainUntil(), replacement.getRetainUntil());
                    assertEquals(v.outer().replace(id(70), replacement.getVersion()), raw(replacement, s, 2));
                    assertEquals(wire(v.completeBytes(), k), replacement.toSealedForm().length());
                    assertEquals(v.payload(), codec.open(replacement, CLOCK).payload());
                    assertEquals(v.floor(), codec.open(replacement, CLOCK).floor());
                    semantic(v, codec.open(replacement, CLOCK).payload());
                }
                // The closed codec returns a prepared value; it owns no store and cannot publish it.
                assertSame(source, original.get(v.key()));
                assertSame(root, original.get(root.getKey()));
                assertEquals(sourceBytes, source.toSealedForm());
                assertEquals(rootBytes, root.toSealedForm());
                assertEquals(v.payload(), old.open(source, CLOCK));
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> interactionCapacityIncludesTheCompletedFootprint() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Vector v : selected("admission")) for (int k : List.of(1, 64))
            tests.add(DynamicTest.dynamicTest("CAP-02/admission/" + v.name() + "/K" + k, () -> {
                var s = sealer(k);
                var codec = target(v, s);
                var record = semantic(v, v.payload());
                var pending = codec.sealVersion(v.key(), id(70), v.retention(), v.floor(), record.toPayload());
                assertEquals(v.completeBytes() - 2, utf8(raw(pending, s, 2)).length);
                assertEquals(v.completeBytes(), utf8(v.outer()).length);
                if (v.completeBytes() > 12170) assertThrows(IllegalArgumentException.class, () ->
                        codec.requireInteractionCapacity(v.key(), v.retention(), record));
                else {
                    codec.requireInteractionCapacity(v.key(), v.retention(), record);
                    var completed = codec.sealVersion(v.key(), id(70), v.retention(), v.floor(), record.completed().toPayload());
                    assertEquals(v.outer(), raw(completed, s, 2));
                    assertEquals(wire(v.completeBytes(), k), completed.toSealedForm().length());
                }
                assertEquals("PENDING", record.text("status"));
                assertEquals(v.payload(), codec.open(pending, CLOCK).payload());
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> publicAdmissionRefusesBeforeAnyStoreMutation() {
        List<DynamicTest> tests = new ArrayList<>();
        for (int n = 0; n < 3; n++) for (int k : List.of(1, 64)) {
            int index = n;
            tests.add(DynamicTest.dynamicTest("CAP-02/public/" + (12169 + n) + "/K" + k, () -> {
                String prefix = "service." + index + '.';
                String issuer = unhex(property(prefix + "issuerHex")), client = unhex(property(prefix + "clientHex"));
                String state = unhex(property(prefix + "stateHex")), resource = unhex(property(prefix + "resourceHex"));
                var scopes = new LinkedHashSet<String>();
                for (int i = 0; i < 64; i++) scopes.add(String.format(java.util.Locale.ROOT, "%03d", i) + "s".repeat(125));
                var store = new OAuthAtomicStoreFixture(NOW);
                var s = sealer(k);
                var registration = OAuthServerClientRegistration.withClientId(client).configurationVersion("v1")
                        .redirectUris(List.of(java.net.URI.create("https://client.example/cb")))
                        .allowedScopesByResource(Map.of(resource, scopes)).build();
                var signing = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
                var server = OAuthAuthorizationServer.withIssuer(issuer)
                        .authorizationEndpoint(java.net.URI.create("https://cap-02.issuer.example/authorize"))
                        .tokenEndpoint(java.net.URI.create("https://cap-02.issuer.example/token"))
                        .jwksEndpoint(java.net.URI.create("https://cap-02.issuer.example/jwks"))
                        .clientRepository((id, budget) -> id.equals(client) ? Optional.of(registration) : Optional.empty())
                        .store(store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(
                                OAuthIssuerSigningKey.fromKeyPair("signing", signing.getPrivateKey(), signing.getPublicKey()))
                                .generation("cap-02").publishedAt(NOW.minusSeconds(120)).build()))
                        .stateSealer(s).clock(CLOCK).resources(Map.of(resource, scopes))
                        .grantPolicy((context, budget) -> OAuthAuthorizationDecision.deniedInstance())
                        .maximumStoreRecordBytes(16384).maximumRawQueryLength(65536).maximumClientIdLength(4096)
                        .maximumScopesPerResource(64).acknowledgeUnpatchedRuntime(true).build();
                assertEquals(OAuthStoreCommitStatus.COMMITTED, server.initializeFreshIssuer().getStatus());
                var fields = new LinkedHashMap<String, String>();
                fields.put("client_id", client); fields.put("redirect_uri", "https://client.example/cb");
                fields.put("resource", resource); fields.put("scope", String.join(" ", scopes));
                fields.put("response_type", "code"); fields.put("code_challenge", id(10));
                fields.put("code_challenge_method", "S256"); fields.put("state", state);
                var parts = new ArrayList<String>();
                for (var e : fields.entrySet()) parts.add(FormUrlEncoding.encode(e.getKey()) + '=' + FormUrlEncoding.encode(e.getValue()));
                var before = Map.copyOf(store.rows); int commits = store.commits;
                var result = server.beginAuthorizationResult("GET", String.join("&", parts), new byte[0], Map.of(), id(12));
                int completedBytes = Integer.parseInt(property(prefix + "completeBytes"));
                if (completedBytes > 12170) {
                    assertEquals(commits, store.commits, "Oversize preparation must not submit a transaction");
                    assertEquals(before, store.rows);
                    assertEquals(OAuthServerException.Reason.MALFORMED_REQUEST,
                            assertInstanceOf(OAuthAuthorizationResult.Rejected.class, result).getReason());
                } else {
                    var interaction = assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class, result).getInteraction();
                    var pending = store.rows.values().stream().filter(e -> e.getKey().getKind() == OAuthStoreKey.Kind.INTERACTION)
                            .findFirst().orElseThrow();
                    assertEquals(completedBytes - 10, utf8(raw(pending, s, 2)).length);
                    var done = server.completeAuthorizationResult(interaction.getInteractionValue(), id(12), OAuthAuthorizationDecision.deniedInstance());
                    assertInstanceOf(OAuthAuthorizationResult.Denied.class, done);
                    var completed = Objects.requireNonNull(store.rows.get(pending.getKey()));
                    // Actual floor is NOW/nanos0; allocation reserved an extra 8 nanos digits.
                    assertEquals(completedBytes - 8, utf8(raw(completed, s, 2)).length);
                    assertEquals(wire(completedBytes - 8, k), completed.toSealedForm().length());
                    var opened = new OAuthStoreRecordCodecV2(issuer, s, 16384, LIMITS, 1024).open(completed, CLOCK);
                    assertEquals(state, field(opened.payload(), "state"));
                    assertEquals(client, field(opened.payload(), "clientId"));
                    assertEquals(scopes.size(), OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,
                            OAuthStoreRecordCodecV2.identifier(completed.getKey()), opened.payload(), LIMITS, 1024).scopes(LIMITS).size());
                }
            }));
        }
        return tests;
    }

    private record Vector(int index) {
        @NonNull String value(@NonNull String key) { return property("v." + this.index + '.' + key); }
        @NonNull String name() { return value("name"); }
        @NonNull String group() { return value("group"); }
        @NonNull String issuer() { return unhex(value("issuerHex")); }
        OAuthStoreKey.@NonNull Kind kind() { return OAuthStoreKey.Kind.valueOf(value("kind")); }
        @NonNull OAuthStoreKey key() { return OAuthStoreKey.fromStoredForm(value("key")); }
        @NonNull JsonObject payload() { return OAuthStoreRecordCodecV2.parse(unhex(value("payloadHex")), 16384); }
        @NonNull String outer() { return unhex(value("outerHex")); }
        @NonNull String oldOuter() { return unhex(value("oldOuterHex")); }
        int completeBytes() { return Integer.parseInt(value("completeBytes")); }
        @NonNull Instant floor() { return Instant.ofEpochSecond(Long.parseLong(value("floorSeconds")), Long.parseLong(value("floorNanos"))); }
        @NonNull Instant retention() { return Instant.ofEpochSecond(Long.parseLong(value("retention"))); }
    }
    private static @NonNull List<@NonNull Vector> vectors() {
        List<Vector> result = new ArrayList<>();
        for (int i = 0; i < Integer.parseInt(property("count")); i++) result.add(new Vector(i));
        return result;
    }
    private static @NonNull List<@NonNull Vector> selected(@NonNull String group) {
        return vectors().stream().filter(v -> v.group().equals(group)).toList();
    }
    private static @NonNull OAuthAuthorizationRecord semantic(@NonNull Vector v, @NonNull JsonObject payload) {
        return OAuthAuthorizationRecord.decode(v.kind(), id(7), payload, LIMITS, 1024);
    }
    private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull Vector v, @NonNull StateSealer s) {
        return new OAuthStoreRecordCodecV2(v.issuer(), s, 16384, LIMITS, 1024);
    }
    private static int wire(int plaintextBytes, int k) { return ((54 + k + plaintextBytes) * 4 + 2) / 3; }
    private static byte @NonNull [] utf8(@NonNull String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull String unhex(@NonNull String s) { return new String(HexFormat.of().parseHex(s), StandardCharsets.UTF_8); }
    private static @NonNull String field(@NonNull JsonObject p, @NonNull String name) { return OAuthStoreFormat.stringMember(p, name).orElseThrow(); }
    private static @NonNull String property(@NonNull String key) { return Objects.requireNonNull(PROPERTIES.getProperty(key), key); }
    private static @NonNull String id(int n) { return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array()); }
    private static @NonNull StateSealer sealer(int k) {
        return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(k), MASTER)).maximumSealedLength(16384).clock(CLOCK).build();
    }
    private static @NonNull String raw(@NonNull OAuthStoreEntry row, @NonNull StateSealer s, int format) throws Exception {
        return SealedStateAccess.get().unseal(s, SealedStateType.AS_RECORD, row.toSealedForm(),
                "revetsec/as-record/v" + format + ':' + row.getKey().getStorageKey(), CLOCK);
    }
    private static @NonNull String rawSeal(int k, @NonNull OAuthStoreKey address, @NonNull Instant retention, @NonNull String text) throws Exception {
        String kid = "k".repeat(k), context = OAuthStoreRecordCodecV2.context(address);
        var key = SealerV1.Key.fromMasterKey(kid, Base64.getDecoder().decode(MASTER));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(utf8(text + kid));
        String sealed = SealerV1.seal(key, SealedStateType.AS_RECORD, context, retention.getEpochSecond(), utf8(text),
                java.util.Arrays.copyOfRange(digest, 0, 16), java.util.Arrays.copyOfRange(digest, 16, 28));
        assertEquals(text, SealerV1.open(sealed, sealed.length(), Map.of(kid, key), SealedStateType.AS_RECORD, context, NOW));
        return sealed;
    }
    private static byte @NonNull [] loadBytes() {
        try (var in = Objects.requireNonNull(OAuthIssuerCapacityGoldenTests.class.getResourceAsStream(RESOURCE))) {
            return in.readAllBytes();
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static @NonNull Properties loadProperties() {
        var result = new Properties();
        try (var in = new ByteArrayInputStream(GOLDEN)) { result.load(in); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
        return result;
    }
}
