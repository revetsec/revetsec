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

import com.revetsec.StateSealer;
import com.revetsec.internal.pem.Pem;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Independent boundary checks for trusted context and atomic pending-state failure contracts. */
final class SamlRc3CloseoutBoundaryTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull String ACS = "https://sp.example.test/acs";
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
    private static final @NonNull SamlReplayCache REPLAY = (key, expires, remaining) -> SamlReplayCache.MarkResult.MARKED;

    @Test void trustedContextsRejectEmptyIdentityInvalidTimePolicyAndPartialPendingBindings() {
        List<Executable> invalid = List.of(
                () -> expectation("", "tenant", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", "", ACS, Duration.ZERO, BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, "", Duration.ZERO, BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ofNanos(-1), BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ofMinutes(5).plusNanos(1), BUDGET, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, Duration.ZERO, BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, Duration.ofNanos(-1), BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, Duration.ofMinutes(15).plusNanos(1), BUDGET, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, Duration.ZERO, "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, Duration.ofNanos(-1), "request", "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, null, "relay", CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, "request", null, CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, null, null, CLOCK.instant()),
                () -> expectation(SP, "tenant", IDP, ACS, Duration.ZERO, BUDGET, BUDGET, "request", "relay", null));
        for (Executable value : invalid) assertThrows(IllegalArgumentException.class, value);
        assertDoesNotThrow(() -> expectation(SP, "tenant", IDP, ACS, Duration.ofMinutes(5), Duration.ofMinutes(15), BUDGET, null, null, null));
    }

    @Test void postLogoutConfigurationRejectsUnsafeReceiverAndNullSettersRestoreDefaults() throws Exception {
        for (String value : List.of("http://sp.example.test/logout", "https:///logout", "https://u@sp.example.test/logout", "https://sp.example.test/logout#fragment", "https://sp.example.test/logout?", "https://sp.example.test/logout?SAMLRequest=shadow"))
            assertThrows(IllegalStateException.class, () -> sp().postSingleLogoutServiceUrl(URI.create(value)).build(), value);
        assertThrows(IllegalArgumentException.class, () -> SamlServiceProvider.withEntityId("x".repeat(2049)));
        SamlIdentityProvider identity = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant")
                .postSingleSignOnService(URI.create("https://idp.example.test/post"))
                .signingKeys(List.of(Pem.parseCertificate(Files.readString(keys("idp-signing-rsa-2048-cert.pem"))).getPublicKey())).build();
        SamlServiceProvider provider = sp().clock(null).random(null).clockSkew(null)
                .maximumResponseAge(null).pendingAuthenticationLifetime(null).replayBudget(null)
                .signingCredential(null).decryptionCredentials(null).build();
        assertInstanceOf(SamlAuthenticationRequestResult.PostPrepared.class, provider.beginPostAuthenticationResult(identity));
        assertThrows(IllegalStateException.class, () -> sp().signingPrivateKey(
                Pem.parsePrivateKey(Files.readString(keys("idp-signing-ec-p256-key.pem")))).build());
    }

    @Test void credentialPairingRefusesWeakMismatchedAndNonRsaEntries() throws Exception {
        var certificate = Pem.parseCertificate(Files.readString(keys("sp-signing-rsa-2048-cert.pem")));
        var privateKey = Pem.parsePrivateKey(Files.readString(keys("sp-signing-rsa-2048-key.pem")));
        SamlCredential valid = SamlCredential.fromPrivateKeyAndCertificate(privateKey, certificate);
        assertArrayEquals(certificate.getEncoded(), valid.getCertificate().getEncoded());
        for (String key : List.of("negative-rsa-1024-key.pem", "negative-attacker-rsa-2048-key.pem", "idp-signing-ec-p256-key.pem"))
            assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromPrivateKeyAndCertificate(Pem.parsePrivateKey(Files.readString(keys(key))), certificate), key);
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromPrivateKeyAndCertificate(privateKey,
                Pem.parseCertificate(Files.readString(keys("idp-signing-ec-p256-cert.pem")))));
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromPem("not pem", "not pem"));
        KeyStore empty = KeyStore.getInstance("PKCS12"); empty.load(null, null);
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromKeyStore(empty, "absent", new char[0]));
        empty.setCertificateEntry("certificate-only", certificate);
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromKeyStore(empty, "certificate-only", new char[0]));
        empty.setKeyEntry("signing", privateKey, new char[0], new java.security.cert.Certificate[]{certificate});
        assertArrayEquals(certificate.getEncoded(), SamlCredential.fromKeyStore(empty, "signing", new char[0]).getCertificate().getEncoded());
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromKeyStore(empty, "signing", "wrong".toCharArray()));
    }

    @Test void malformedPendingFieldsCannotRecoverPartiallyDecodedIdentityOrFlags() {
        String encoded = PendingSamlAuthenticationCodec.encode(pending());
        String[] fields = encoded.split("\\.", -1);
        for (int index : List.of(2, 3, 4, 5, 6, 7, 8)) {
            String[] altered = fields.clone(); altered[index] = "!";
            assertNull(PendingSamlAuthenticationCodec.decode(String.join(".", altered)), "invalid field " + index);
        }
        String[] oversized = fields.clone(); oversized[4] = b64("x".repeat(259));
        assertNull(PendingSamlAuthenticationCodec.decode(String.join(".", oversized)));
        String[] passive = fields.clone(); passive[9] = "0"; passive[10] = "1";
        assertTrue(requireNonNull(PendingSamlAuthenticationCodec.decode(String.join(".", passive))).options().isPassive());
        String legacyUnknown = "9." + String.join(".", List.of(fields).subList(1, 7)) + "." + CLOCK.instant() + "." + CLOCK.instant().plusSeconds(60);
        assertNull(PendingSamlAuthenticationCodec.decode(legacyUnknown));
    }

    @Test void interruptedAndInvalidStoreAdmissionsLeaveHealthyStateUsable() {
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 2);
        Instant expiry = CLOCK.instant().plusSeconds(60);
        for (String[] fields : List.of(new String[]{"", "handle", "sealed"}, new String[]{"browser", "", "sealed"}, new String[]{"browser", "handle", ""}))
            assertThrows(IllegalArgumentException.class, () -> store.save(fields[0], fields[1], fields[2], expiry, BUDGET));
        assertThrows(IllegalArgumentException.class, () -> store.consume("browser", "", BUDGET));
        for (int capacity : List.of(0, 1000001)) assertThrows(IllegalArgumentException.class, () -> InMemorySamlReplayCache.withLimit(CLOCK, capacity));
        InMemorySamlReplayCache cache = InMemorySamlReplayCache.withLimit(CLOCK, 2);
        assertThrows(IllegalArgumentException.class, () -> cache.markIfAbsent("", expiry, BUDGET));
        for (Duration budget : List.of(Duration.ZERO, Duration.ofNanos(-1)))
            assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, cache.markIfAbsent("key", expiry, budget));
        Thread.currentThread().interrupt();
        try {
            assertEquals(SamlPendingSaveResult.UNAVAILABLE, store.save("browser", "handle", "sealed", expiry, BUDGET));
            assertInstanceOf(SamlPendingConsumeResult.Unavailable.class, store.consume("browser", "handle", BUDGET));
            assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, cache.markIfAbsent("key", expiry, BUDGET));
        } finally { Thread.interrupted(); }
        assertEquals(SamlPendingSaveResult.SAVED, store.save("browser", "handle", "sealed", expiry, BUDGET));
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class, store.consume("browser", "handle", BUDGET)).getSealedRecord());
        assertEquals(SamlReplayCache.MarkResult.MARKED, cache.markIfAbsent("key", expiry, Duration.ofDays(100000)));
        assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT, cache.markIfAbsent("key", expiry, BUDGET));
    }

    @Test void nonpositiveAndUncertainPendingSavesHaveNoFalseSuccessForLoginOrLogout() {
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-closeout-store")).clock(CLOCK).build();
        PendingSamlAuthentication login = pending(); PendingSamlLogout logout = new PendingSamlLogout(login);
        AtomicInteger saves = new AtomicInteger();
        PendingSamlAuthenticationStore uncertain = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browser, @NonNull String handle, @NonNull String sealed, @NonNull Instant expires, @NonNull Duration budget) { saves.incrementAndGet(); throw new IllegalStateException("uncertain save"); }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browser, @NonNull String handle, @NonNull Duration budget) { return SamlPendingConsumeResult.Unavailable.INSTANCE; }
        };
        for (Duration budget : List.of(Duration.ZERO, Duration.ofNanos(-1))) {
            assertEquals(SamlPendingSaveResult.UNAVAILABLE, login.saveToResult(uncertain, sealer, "ctx", "browser", budget));
            assertEquals(SamlPendingSaveResult.UNAVAILABLE, logout.saveToResult(uncertain, sealer, "ctx", "browser", budget));
        }
        assertEquals(0, saves.get());
        assertEquals(SamlPendingSaveResult.INDETERMINATE, login.saveToResult(uncertain, sealer, "ctx", "browser", BUDGET));
        assertEquals(SamlPendingSaveResult.INDETERMINATE, logout.saveToResult(uncertain, sealer, "ctx", "browser", BUDGET));
        assertEquals(2, saves.get());
    }

    private static SamlResponseSemantics.@NonNull Expectation expectation(@NonNull String sp, @NonNull String connection, @NonNull String idp, @NonNull String acs, @NonNull Duration skew, @NonNull Duration age, @NonNull Duration budget, @org.jspecify.annotations.Nullable String request, @org.jspecify.annotations.Nullable String relay, @org.jspecify.annotations.Nullable Instant expiry) {
        return new SamlResponseSemantics.Expectation(sp, connection, idp, acs, request, relay, expiry, CLOCK, skew, age, false, List.of(), REPLAY, budget);
    }
    private static SamlServiceProvider.@NonNull Builder sp() { return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(URI.create(ACS)).replayCache(REPLAY); }
    private static @NonNull PendingSamlAuthentication pending() { return new PendingSamlAuthentication(SP, "_" + "r".repeat(40), "h".repeat(22), "tenant", IDP, ACS, CLOCK.instant(), CLOCK.instant().plusSeconds(60)); }
    private static @NonNull Path keys(@NonNull String name) { return Path.of("src/test/resources/fixtures/keys").resolve(name); }
    private static @NonNull String b64(@NonNull String value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
}
