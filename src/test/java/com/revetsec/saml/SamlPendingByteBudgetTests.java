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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class SamlPendingByteBudgetTests {
    private static final Instant NOW = Instant.parse("2026-11-02T00:00:00.123456789Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration BUDGET = Duration.ofSeconds(5);

    @TestFactory @NonNull Stream<@NonNull DynamicTest> entityBuildersAndCodecAgreeOnUnicodeAndMalformedText() {
        return Stream.of("é".repeat(1024) + "a", "界".repeat(683), "😀".repeat(512) + "a", "bad\ud800", "bad\udc00")
                .flatMap(text -> Stream.of(false, true).map(idp -> DynamicTest.dynamicTest(
                        (idp ? "IdP" : "SP") + " bytes=" + text.getBytes(StandardCharsets.UTF_8).length
                                + " units=" + text.length(), () -> {
                    if (text.contains("\ud800") || text.contains("\udc00")) {
                        if (idp) assertThrows(IllegalArgumentException.class, () -> SamlIdentityProvider.withEntityId(text));
                        else assertThrows(IllegalArgumentException.class, () -> SamlServiceProvider.withEntityId(text));
                    } else {
                        if (idp) SamlIdentityProvider.withEntityId(text); else SamlServiceProvider.withEntityId(text);
                        PendingSamlAuthentication pending = fields(idp ? "sp" : text, "c", idp ? text : "idp", "https://sp.test/acs", defaults());
                        StateSealer sealer = sealer(16384, 1);
                        var resolved = assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                                PendingSamlAuthenticationSource.fromSealedForm(pending.toSealedForm(sealer, "cookie"), sealer, "cookie")
                                        .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
                        assertEquals(text, idp ? resolved.pending().idpEntityId() : resolved.pending().spEntityId());
                    }
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> validEntityByteBoundariesRoundTripExactly() {
        return Stream.of("a".repeat(2048), "é".repeat(1024), "界".repeat(682) + "aa", "😀".repeat(512))
                .map(text -> DynamicTest.dynamicTest("entity units=" + text.length(), () -> {
                    SamlServiceProvider.withEntityId(text);
                    SamlIdentityProvider.withEntityId(text);
                    PendingSamlAuthentication pending = fields(text, "c", text, "https://sp.test/acs", defaults());
                    PendingSamlAuthentication decoded = PendingSamlAuthenticationCodec.decode(PendingSamlAuthenticationCodec.encode(pending));
                    assertNotNull(decoded);
                    assertEquals(text, decoded.spEntityId());
                    assertEquals(text, decoded.idpEntityId());
                }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> connectionBuilderAndCodecAgreeOnUnicodeAndMalformedText() throws Exception {
        KeyPair key = rsa();
        return Stream.of("é".repeat(128) + "a", "界".repeat(86), "😀".repeat(64) + "a", "bad\ud800")
                .map(text -> DynamicTest.dynamicTest("connection units=" + text.length(), () -> {
                    if (text.contains("\ud800")) assertThrows(IllegalStateException.class, () -> idp(text, key));
                    else {
                        idp(text, key);
                        PendingSamlAuthentication pending = fields("sp", text, "idp", "https://sp.test/acs", defaults());
                        var decoded = PendingSamlAuthenticationCodec.decode(PendingSamlAuthenticationCodec.encode(pending));
                        assertNotNull(decoded);
                        assertEquals(text, decoded.connectionId());
                    }
                }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> maximumCharacterFieldsUseBoundedUtf8Expansion() {
        return Stream.of(0, 1, 2).flatMap(field -> Stream.of(false, true).map(logout -> DynamicTest.dynamicTest(
                "maximum UTF-8 field=" + field + " logout=" + logout, () -> {
            String text = "界".repeat(field == 1 ? 256 : 2048);
            var pending = fields(field == 0 ? text : "sp", field == 1 ? text : "c", field == 2 ? text : "idp",
                    "https://sp.test/acs", defaults());
            String encoded = PendingSamlAuthenticationCodec.encode(pending);
            java.nio.file.Files.writeString(java.nio.file.Path.of("target/pending-wire-" + field + ".txt"), encoded);
            StateSealer sealer = sealer(16384, 1);
            var store = InMemoryPendingSamlAuthenticationStore.fromLimit(CLOCK, 1);
            assertEquals(SamlPendingSaveResult.SAVED, logout
                    ? new PendingSamlLogout(pending).saveToResult(store, sealer, "app", "browser", BUDGET)
                    : pending.saveToResult(store, sealer, "app", "browser", BUDGET));
            PendingSamlAuthentication restored;
            if (logout) restored = assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                    PendingSamlLogoutSource.fromStore(store, "browser", sealer, "app")
                            .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET)).pending();
            else restored = assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                    PendingSamlAuthenticationSource.fromStore(store, "browser", sealer, "app")
                            .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET)).pending();
            assertEquals(encoded, PendingSamlAuthenticationCodec.encode(restored));
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedCallbackTextRejectsBeforeAsciiConversion() throws Exception {
        KeyPair key = rsa();
        URI malformed = URI.create("https://sp.test/bad\ud800");
        return Stream.of(0, 1, 2).map(mode -> DynamicTest.dynamicTest("malformed callback=" + mode,
                () -> assertThrows(IllegalStateException.class, () -> sp(malformed, key, mode))));
    }

    @Test void individuallyValidUnicodeFieldsCanExceedTheWholeEnvelopeBudget() {
        var options = SamlAuthenticationRequestOptions.builder().requestedAuthnContextClassRefs(
                Collections.nCopies(8, "urn:" + "界".repeat(508))).build();
        var pending = fields("界".repeat(2048), "界".repeat(256), "界".repeat(2048), "https://sp.test/acs", options);
        var calls = new AtomicInteger();
        assertEquals(SamlPendingSaveResult.UNAVAILABLE, assertDoesNotThrow(() ->
                pending.saveToResult(counting(calls, SamlPendingSaveResult.SAVED), sealer(16384, 64), "app", "browser", BUDGET)));
        assertEquals(0, calls.get());
        assertEquals(SamlPendingSaveResult.UNAVAILABLE, assertDoesNotThrow(() ->
                new PendingSamlLogout(pending).saveToResult(counting(calls, SamlPendingSaveResult.SAVED), sealer(16384, 64), "app", "browser", BUDGET)));
        assertEquals(0, calls.get());
    }

    @Test void maximumUnicodeConnectionRemainsExactThroughCookieAndStore() throws Exception {
        KeyPair key = rsa();
        String connection = "😀".repeat(64);
        SamlIdentityProvider idp = idp(connection, key);
        var prepared = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp(URI.create("https://sp.test/acs"), key, 0).beginAuthenticationResult(idp));
        PendingSamlAuthentication pending = prepared.getPendingAuthentication();
        StateSealer sealer = sealer(3800, 1);
        var store = InMemoryPendingSamlAuthenticationStore.fromLimit(CLOCK, 1);
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer, "app", "browser", BUDGET));
        var resolved = assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                PendingSamlAuthenticationSource.fromStore(store, "browser", sealer, "app")
                        .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
        assertEquals(connection, resolved.pending().connectionId());
        assertEquals(pending.getRequestId(), resolved.pending().getRequestId());
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> callbackBudgetsUseAsciiUriForAllThreeSpReceivers() throws Exception {
        KeyPair key = rsa();
        // URI text is short, but toASCIIString expands each non-ASCII path character.
        URI tooLong = URI.create("https://sp.test/" + "界".repeat(230));
        assertTrue(tooLong.toString().length() < 2048);
        assertTrue(tooLong.toASCIIString().length() > 2048);
        return Stream.of(0, 1, 2).map(mode -> DynamicTest.dynamicTest("callback mode=" + mode,
                () -> assertThrows(IllegalStateException.class, () -> sp(tooLong, key, mode))));
    }

    @Test void exactAsciiCallbackBudgetWorksForLoginAndBothLogoutBindings() throws Exception {
        KeyPair key = rsa();
        String prefix = "https://sp.test/";
        URI exact = URI.create(prefix + "a".repeat(2048 - prefix.length()));
        SamlServiceProvider sp = sp(exact, key, 3);
        SamlIdentityProvider idp = idp("c", key);
        var login = assertInstanceOf(SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(idp));
        assertEquals(exact.toASCIIString(), login.getPendingAuthentication().acs());
        var session = new SamlSessionReference("c", idp.getEntityId(), new SamlNameId("name", null, null, null, null), null, null);
        var redirect = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class, sp.beginLogoutResult(idp, session));
        var post = assertInstanceOf(SamlLogoutPostResult.Prepared.class, sp.beginPostLogoutResult(idp, session));
        for (PendingSamlLogout pending : List.of(redirect.getPendingLogout(), post.getPendingLogout())) {
            String seal = pending.toSealedForm(sealer(16384, 1), "cookie");
            var resolved = assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                    PendingSamlLogoutSource.fromSealedForm(seal, sealer(16384, 1), "cookie")
                            .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
            assertEquals(exact.toASCIIString(), resolved.pending().acs());
        }
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> encoderCannotIssueUnreadableOrLossilyEncodedFields() {
        return Stream.of(0, 1, 2, 3, 4).map(field -> DynamicTest.dynamicTest("invalid encoder field=" + field, () -> {
            String sp = field == 0 ? "a".repeat(2049) : field == 4 ? "bad\ud800" : "sp";
            String connection = field == 1 ? "a".repeat(257) : "c";
            String idp = field == 2 ? "a".repeat(2049) : "idp";
            String acs = field == 3 ? "https://sp.test/" + "a".repeat(2048) : "https://sp.test/acs";
            PendingSamlAuthentication pending = fields(sp, connection, idp, acs, defaults());
            assertThrows(IllegalArgumentException.class, () -> pending.toSealedForm(sealer(16384, 1), "cookie"));
        }));
    }

    @Test void malformedContextClassIsNotSilentlyReplacedInPendingState() {
        assertThrows(IllegalArgumentException.class, () -> SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(List.of("urn:test:bad\ud800")));
    }

    @Test void allAllowedUnicodeContextsRoundTripWhenEnvelopeFits() {
        String context = "urn:" + "界".repeat(508);
        var options = SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(Collections.nCopies(5, context)).build();
        PendingSamlAuthentication pending = fields("sp", "c", "idp", "https://sp.test/acs", options);
        String seal = pending.toSealedForm(sealer(16384, 1), "cookie");
        var resolved = assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                PendingSamlAuthenticationSource.fromSealedForm(seal, sealer(16384, 1), "cookie")
                        .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
        assertEquals(options.getRequestedAuthnContextClassRefs(), resolved.pending().options().getRequestedAuthnContextClassRefs());
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> sizeRefusalBeforeStoreForEveryCapKeyLengthAndPendingType() {
        return Stream.of(1024, 3800, 16384).flatMap(cap -> Stream.of(1, 64).flatMap(keyLength ->
                Stream.of(false, true).map(logout -> DynamicTest.dynamicTest(
                        "size cap=" + cap + " key=" + keyLength + " logout=" + logout, () -> {
                    StateSealer sealer = sealer(cap, keyLength);
                    PendingSamlAuthentication pending = largest();
                    AtomicInteger calls = new AtomicInteger();
                    PendingSamlAuthenticationStore store = counting(calls, SamlPendingSaveResult.SAVED);
                    SamlPendingSaveResult result = assertDoesNotThrow(() -> logout
                            ? new PendingSamlLogout(pending).saveToResult(store, sealer, "app", "browser", BUDGET)
                            : pending.saveToResult(store, sealer, "app", "browser", BUDGET));
                    assertEquals(SamlPendingSaveResult.UNAVAILABLE, result);
                    assertEquals(0, calls.get());
                    assertThrows(IllegalArgumentException.class, () -> {
                        if (logout) new PendingSamlLogout(pending).toSealedForm(sealer, "cookie");
                        else pending.toSealedForm(sealer, "cookie");
                    });
                    assertThrows(IllegalArgumentException.class, () -> {
                        if (logout) new PendingSamlLogout(pending).saveToResult(store, sealer, "x".repeat(257), "browser", BUDGET);
                        else pending.saveToResult(store, sealer, "x".repeat(257), "browser", BUDGET);
                    });
                    assertEquals(0, calls.get());
                }))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> exactSealBoundaryUsesBase64RoundingAndKeyIdLength() {
        return Stream.of(1024, 3800, 16384).flatMap(cap -> Stream.of(1, 64).flatMap(keyLength ->
                Stream.of(false, true).map(logout -> DynamicTest.dynamicTest(
                        "exact cap=" + cap + " key=" + keyLength + " logout=" + logout, () -> {
                    StateSealer sealer = sealer(cap, keyLength);
                    PendingSamlAuthentication last = fitting(cap, keyLength);
                    String encoded = PendingSamlAuthenticationCodec.encode(last);
                    assertTrue(wireLength(keyLength, encoded.length()) <= cap);
                    assertTrue(wireLength(keyLength, encoded.length() + 1) > cap);
                    var store = InMemoryPendingSamlAuthenticationStore.fromLimit(CLOCK, 1);
                    SamlPendingSaveResult result = logout
                            ? new PendingSamlLogout(last).saveToResult(store, sealer, "app", "browser", BUDGET)
                            : last.saveToResult(store, sealer, "app", "browser", BUDGET);
                    assertEquals(SamlPendingSaveResult.SAVED, result);
                    PendingSamlAuthentication restored;
                    if (logout) restored = assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                            PendingSamlLogoutSource.fromStore(store, "browser", sealer, "app")
                                    .resolve(CLOCK, last.getRelayStateHandle(), BUDGET)).pending();
                    else restored = assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                            PendingSamlAuthenticationSource.fromStore(store, "browser", sealer, "app")
                                    .resolve(CLOCK, last.getRelayStateHandle(), BUDGET)).pending();
                    assertEquals(encoded, PendingSamlAuthenticationCodec.encode(restored));
                    PendingSamlAuthentication over = atLength(encoded.length() + 1);
                    var calls = new AtomicInteger();
                    SamlPendingSaveResult refused = assertDoesNotThrow(() -> logout
                            ? new PendingSamlLogout(over).saveToResult(counting(calls, SamlPendingSaveResult.SAVED), sealer, "app", "browser", BUDGET)
                            : over.saveToResult(counting(calls, SamlPendingSaveResult.SAVED), sealer, "app", "browser", BUDGET));
                    assertEquals(SamlPendingSaveResult.UNAVAILABLE, refused);
                    assertEquals(0, calls.get());
                }))));
    }

    @Test void savedPendingRetainsTypeContextExpiryAndCommitOutcomes() {
        PendingSamlAuthentication pending = fields("sp", "c", "idp", "https://sp.test/acs", defaults());
        StateSealer sealer = sealer(3800, 1);
        String seal = pending.toSealedForm(sealer, "cookie");
        assertInstanceOf(PendingSamlAuthenticationSource.Rejected.class,
                PendingSamlAuthenticationSource.fromSealedForm(seal, sealer, "other")
                        .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
        assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                PendingSamlLogoutSource.fromSealedForm(seal, sealer, "cookie")
                        .resolve(CLOCK, pending.getRelayStateHandle(), BUDGET));
        assertInstanceOf(PendingSamlAuthenticationSource.Rejected.class,
                PendingSamlAuthenticationSource.fromSealedForm(seal, sealer, "cookie")
                        .resolve(Clock.fixed(pending.expiresAt().plusSeconds(1), ZoneOffset.UTC), pending.getRelayStateHandle(), BUDGET));
        for (SamlPendingSaveResult outcome : SamlPendingSaveResult.values()) {
            var calls = new AtomicInteger();
            assertEquals(outcome, pending.saveToResult(counting(calls, outcome), sealer, "app", "browser", BUDGET));
            assertEquals(1, calls.get());
        }
        var calls = new AtomicInteger();
        assertEquals(SamlPendingSaveResult.INDETERMINATE,
                pending.saveToResult(counting(calls, null), sealer, "app", "browser", BUDGET));
    }

    @Test void legacyVersionOneAndTwoKeepTheirExistingGrammar() {
        String[] v3 = PendingSamlAuthenticationCodec.encode(fields("sp", "c", "idp", "https://sp.test/acs", defaults())).split("\\.", -1);
        v3[7] = NOW.toString(); v3[8] = NOW.plusSeconds(300).toString();
        // Legacy time fields have no fractional seconds because dots are frame separators.
        v3[7] = Instant.parse("2026-11-02T00:00:00Z").toString();
        v3[8] = Instant.parse("2026-11-02T00:05:00Z").toString();
        v3[0] = "2";
        assertNotNull(PendingSamlAuthenticationCodec.decode(String.join(".", v3)));
        assertNotNull(PendingSamlAuthenticationCodec.decode("1." + String.join(".", java.util.Arrays.copyOfRange(v3, 1, 9))));
    }

    private static @NonNull PendingSamlAuthentication fitting(int cap, int keyLength) {
        int target = cap / 4 * 3 - 54 - keyLength;
        return atLength(target);
    }
    private static @NonNull PendingSamlAuthentication atLength(int target) {
        for (int contexts = 0; contexts <= 8; contexts++) {
            for (boolean hint : new boolean[] {false, true}) {
                var options = SamlAuthenticationRequestOptions.builder().requestedAuthnContextClassRefs(
                        Collections.nCopies(contexts, "urn:" + "a".repeat(508))).applicationData(hint ? "" : null).build();
                String acs = target > 3000 ? "https://sp.test/" + "a".repeat(2048 - "https://sp.test/".length()) : "https://sp.test/acs";
                int fixed = PendingSamlAuthenticationCodec.encode(fields("s", "c", "i", acs, options)).length() - 4;
                for (int sp = 1; sp <= 2048; sp++) {
                    int needed = target - fixed - (4 * sp + 2) / 3;
                    int approximate = needed / 4 * 3;
                    for (int idp = Math.max(1, approximate - 3); idp <= Math.min(2048, approximate + 3); idp++) {
                        if ((4 * idp + 2) / 3 != needed) continue;
                        var candidate = fields("s".repeat(sp), "c", "i".repeat(idp), acs, options);
                        if (PendingSamlAuthenticationCodec.encode(candidate).length() == target) return candidate;
                    }
                }
            }
        }
        throw new AssertionError("No legal pending frame at " + target);
    }
    private static long wireLength(int keyLength, int plaintextLength) {
        return (4L * (54 + keyLength + plaintextLength) + 2) / 3;
    }
    private static @NonNull PendingSamlAuthentication largest() {
        var options = SamlAuthenticationRequestOptions.builder().requestedAuthnContextClassRefs(
                Collections.nCopies(8, "urn:" + "a".repeat(508))).applicationData("x".repeat(512)).build();
        return fields("s".repeat(2048), "c".repeat(256), "i".repeat(2048),
                "https://sp.test/" + "a".repeat(2048 - "https://sp.test/".length()), options);
    }
    private static @NonNull PendingSamlAuthentication fields(@NonNull String sp, @NonNull String connection, @NonNull String idp, @NonNull String acs,
            @NonNull SamlAuthenticationRequestOptions options) {
        return new PendingSamlAuthentication(sp, "_" + "r".repeat(40), "h".repeat(22), connection,
                idp, acs, NOW, NOW.plusSeconds(300), options);
    }
    private static @NonNull SamlAuthenticationRequestOptions defaults() { return SamlAuthenticationRequestOptions.builder().build(); }
    private static @NonNull StateSealer sealer(int cap, int keyLength) {
        return StateSealer.withActiveKey(TestSealers.fixedKey("k".repeat(keyLength))).clock(CLOCK)
                .maximumSealedLength(cap).build();
    }
    private static @NonNull PendingSamlAuthenticationStore counting(@NonNull AtomicInteger calls, @org.jspecify.annotations.Nullable SamlPendingSaveResult outcome) {
        return new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browser, @NonNull String relay, @NonNull String sealed, @NonNull Instant expiry, @NonNull Duration budget) {
                calls.incrementAndGet(); return unchecked(outcome);
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browser, @NonNull String relay, @NonNull Duration budget) {
                fail("unexpected consume"); return SamlPendingConsumeResult.Unavailable.INSTANCE;
            }
        };
    }
    @SuppressWarnings("NullAway") // Deliberately broken custom SPI result.
    private static @NonNull SamlPendingSaveResult unchecked(@org.jspecify.annotations.Nullable SamlPendingSaveResult outcome) { return outcome; }
    private static @NonNull KeyPair rsa() throws Exception { return KeyPairGenerator.getInstance("RSA").generateKeyPair(); }
    private static @NonNull SamlIdentityProvider idp(@NonNull String connection, @NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId("idp").connectionId(connection)
                .redirectSingleSignOnService(URI.create("https://idp.test/sso"))
                .postSingleSignOnService(URI.create("https://idp.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.test/logout"))
                .postSingleLogoutService(URI.create("https://idp.test/logout"))
                .signingKeys(List.of(key.getPublic())).build();
    }
    private static @NonNull SamlServiceProvider sp(@NonNull URI endpoint, @NonNull KeyPair key, int mode) {
        return SamlServiceProvider.withEntityId("sp").assertionConsumerServiceUrl(mode == 0 || mode == 3 ? endpoint : URI.create("https://sp.test/acs"))
                .singleLogoutServiceUrl(mode == 1 || mode == 3 ? endpoint : null)
                .postSingleLogoutServiceUrl(mode == 2 || mode == 3 ? endpoint : null)
                .replayCache(InMemorySamlReplayCache.fromLimit(CLOCK, 10)).signingPrivateKey(key.getPrivate()).clock(CLOCK).build();
    }
}
