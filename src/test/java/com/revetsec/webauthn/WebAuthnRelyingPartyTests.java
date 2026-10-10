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

package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestClock;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnRelyingPartyTests {
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final String NAMESPACE = "tenant";
    private static final byte[] HANDLE = {4, 5, 6};
    private static final byte[] CREDENTIAL_ID = {1, 2, 3};
    private static final byte[] BINDING = filled(65);
    private static final String BINDING_TEXT = Base64Url.encode(BINDING);
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T12:00:00Z"), ZoneOffset.UTC);
    private static final WebAuthnRecoveryGate ADMIT = remaining -> new WebAuthnRecoveryGate.Permit() {
        @Override public boolean isCurrent() { return true; }
        @Override public void close() { }
    };

    @Test void publicEnrollmentSignInAndPinnedReauthenticationUseCommittedState() throws Exception {
        WebAuthnStore store = InMemoryWebAuthnStore.withLimits(128, 2_000_000);
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        byte[] altered = options.getUserHandle(); altered[0] ^= 1;
        assertArrayEquals(HANDLE, options.getUserHandle());

        var enrollment = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        var registrationRequest = enrollment.getRequest();
        JsonObject creation = registrationRequest.getPublicKeyOptions();
        assertEquals(RP, ((JsonObject) creation.find("rp").orElseThrow()).findString("id").orElseThrow());
        assertEquals("required", ((JsonObject) creation.find("authenticatorSelection").orElseThrow())
                .findString("residentKey").orElseThrow());
        assertEquals(Boolean.TRUE, ((JsonObject) creation.find("extensions").orElseThrow())
                .findBoolean("credProps").orElseThrow());
        assertTrue(((JsonArray) creation.find("excludeCredentials").orElseThrow()).getElements().isEmpty());
        JsonArray algorithms = (JsonArray) creation.find("pubKeyCredParams").orElseThrow();
        assertEquals(List.of(-7L, -8L, -257L), algorithms.getElements().stream()
                .map(value -> ((JsonObject) value).findLong("alg").orElseThrow()).toList());
        assertTrue(registrationRequest.getJson().contains("\"publicKey\""));
        assertFalse(registrationRequest.toString().contains("alice"));
        String challenge = creation.findString("challenge").orElseThrow();
        assertEquals(32, Base64Url.decode(challenge).length);
        var registered = assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,
                rp.completeRegistrationResult(registrationRequest.getCeremonyId(),
                        registrationJson(pair, challenge), BINDING_TEXT));
        assertArrayEquals(HANDLE, registered.getRegistration().getUserHandle());
        assertArrayEquals(CREDENTIAL_ID, registered.getRegistration().getCredentialId());
        assertEquals(NAMESPACE, registered.getRegistration().getCredentialNamespace());
        assertFalse(registered.getRegistration().toString().contains(Base64Url.encode(CREDENTIAL_ID)));
        assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(registrationRequest.getCeremonyId(),
                        registrationJson(pair, challenge), BINDING_TEXT));
        var laterEnrollment = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        JsonArray exclusions = (JsonArray) laterEnrollment.getRequest().getPublicKeyOptions()
                .find("excludeCredentials").orElseThrow();
        assertEquals(1, exclusions.getElements().size());
        assertEquals(Base64Url.encode(CREDENTIAL_ID), ((JsonObject) exclusions.getElements().get(0))
                .findString("id").orElseThrow());

        var signIn = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING_TEXT));
        JsonObject request = signIn.getRequest().getPublicKeyOptions();
        assertFalse(request.getMembers().containsKey("allowCredentials"));
        String assertionChallenge = request.findString("challenge").orElseThrow();
        String wrongBinding = Base64Url.encode(filled(99));
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(signIn.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), assertionChallenge, 1), wrongBinding));
        KeyPair attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(signIn.getRequest().getCeremonyId(),
                        assertionJson(attacker.getPrivate(), assertionChallenge, 1), BINDING_TEXT));
        var authenticated = assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(signIn.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), assertionChallenge, 1), BINDING_TEXT));
        assertArrayEquals(HANDLE, authenticated.getAuthentication().getUserHandle());
        assertEquals(WebAuthnAuthentication.Kind.SIGN_IN, authenticated.getAuthentication().getKind());
        assertTrue(authenticated.getAuthentication().getActionPurpose().isEmpty());

        var stepUp = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginReauthenticationResult(HANDLE, "transfer", BINDING_TEXT));
        var stepUpProof = assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(stepUp.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), stepUp.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), 2), BINDING_TEXT));
        assertEquals(WebAuthnAuthentication.Kind.REAUTHENTICATION,
                stepUpProof.getAuthentication().getKind());
        assertEquals("transfer", stepUpProof.getAuthentication().getActionPurpose().orElseThrow());
    }

    @Test void configurationAndUncertainBeginDoNotReleaseBrowserOptions() {
        MemoryStore store = new MemoryStore();
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnRelyingParty.withRelyingPartyId("EXAMPLE.com"));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnRelyingParty.withRelyingPartyId("example.com")
                        .allowedOrigins(Set.of("https://other.example.com")));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnRelyingParty.withRelyingPartyId(RP)
                        .allowedOrigins(Set.of(ORIGIN + "/path")));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnRelyingParty.withRelyingPartyId(RP)
                        .allowedOrigins(Set.of("http://" + RP)));
        assertThrows(NullPointerException.class,
                () -> WebAuthnRelyingParty.withRelyingPartyId(RP)
                        .relyingPartyName("Name").allowedOrigins(Set.of(ORIGIN))
                        .credentialNamespace(NAMESPACE).store(store).stateSealer(sealer()).build());
        store.nextCommit = WebAuthnStoreCommitResult.UNKNOWN;
        var unknown = relyingParty(store, ADMIT).beginAuthenticationResult(BINDING_TEXT);
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Indeterminate.class, unknown);
        assertFalse(unknown.toString().contains("challenge"));
        int reads = store.reads;
        WebAuthnRelyingParty denied = relyingParty(store, remaining -> null);
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Unavailable.class,
                denied.beginAuthenticationResult(BINDING_TEXT));
        assertEquals(reads, store.reads);
        assertThrows(IllegalArgumentException.class, () -> denied.beginAuthenticationResult("not-random"));
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                denied.completeAuthenticationResult("not-a-ceremony", new byte[] {1}, BINDING_TEXT));
    }

    @Test void configuredCeremonyLifetimeAndExclusionCapAffectCommittedRequests() throws Exception {
        MemoryStore store = new MemoryStore();
        TestClock clock = TestClock.fromInstant(CLOCK.instant());
        WebAuthnSettings settings = WebAuthnSettings.builder().ceremonyLifetime(Duration.ofSeconds(30))
                .maximumExcludedCredentials(1).build();
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT, settings, clock);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        var expiring = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        assertEquals(30_000L, expiring.getRequest().getPublicKeyOptions()
                .findLong("timeout").orElseThrow());
        clock.advance(Duration.ofSeconds(31));
        assertInstanceOf(WebAuthnRegistrationResult.Unavailable.class,
                rp.completeRegistrationResult(expiring.getRequest().getCeremonyId(),
                        registrationJson(pair, expiring.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow()), BINDING_TEXT));
        enroll(rp, pair, options);
        assertInstanceOf(WebAuthnRegistrationRequestResult.Unavailable.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        var signIn = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING_TEXT));
        assertEquals(30_000L, signIn.getRequest().getPublicKeyOptions()
                .findLong("timeout").orElseThrow());
    }

    @Test void configuredParserCapsRejectOversizedBrowserComponents() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        byte[] auth = registrationAuth(pair);
        byte[] att = attestation(auth);
        String sampleChallenge = Base64Url.encode(filled(10));
        byte[] body = registrationJson(pair, sampleChallenge);
        int clientBytes = clientJson("webauthn.create", sampleChallenge).length;
        List<WebAuthnSettings> constrained = List.of(
                WebAuthnSettings.builder().maximumResponseBodyBytes(body.length - 1).build(),
                WebAuthnSettings.builder().maximumClientDataJsonBytes(clientBytes - 1).build(),
                WebAuthnSettings.builder().maximumAttestationObjectBytes(att.length - 1).build(),
                WebAuthnSettings.builder().maximumAuthenticatorDataBytes(auth.length - 1).build());
        for (WebAuthnSettings settings : constrained) {
            WebAuthnRelyingParty rp = relyingParty(new MemoryStore(), ADMIT, settings, CLOCK);
            var started = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                    rp.beginRegistrationResult(options, BINDING_TEXT));
            assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                    rp.completeRegistrationResult(started.getRequest().getCeremonyId(),
                            registrationJson(pair, started.getRequest().getPublicKeyOptions()
                                    .findString("challenge").orElseThrow()), BINDING_TEXT));
        }

        MemoryStore authenticatedStore = new MemoryStore();
        enroll(relyingParty(authenticatedStore, ADMIT), pair, options);
        int assertionClientBytes = clientJson("webauthn.get", sampleChallenge).length;
        WebAuthnSettings strict = WebAuthnSettings.builder()
                .maximumClientDataJsonBytes(assertionClientBytes - 1).build();
        WebAuthnRelyingParty authentication = relyingParty(authenticatedStore, ADMIT, strict, CLOCK);
        var started = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                authentication.beginAuthenticationResult(BINDING_TEXT));
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                authentication.completeAuthenticationResult(started.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), started.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), 1), BINDING_TEXT));
    }

    @Test void configuredOperationBudgetIsPassedToStore() {
        AtomicReference<Duration> observed = new AtomicReference<>();
        WebAuthnStore store = new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(
                    @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remainingBudget) {
                observed.set(remainingBudget);
                return WebAuthnStoreReadResult.Unavailable.get();
            }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
                    @NonNull WebAuthnStoreWrite write, @NonNull Duration remainingBudget) {
                throw new AssertionError("No commit after unavailable read");
            }
        };
        WebAuthnSettings settings = WebAuthnSettings.builder()
                .operationTimeout(Duration.ofMillis(100)).build();
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Unavailable.class,
                relyingParty(store, ADMIT, settings, CLOCK).beginAuthenticationResult(BINDING_TEXT));
        Duration received = observed.get();
        assertTrue(received != null && !received.isNegative() && !received.isZero()
                && received.compareTo(Duration.ofMillis(100)) <= 0);
    }

    @Test void removalRevokesPendingAssertionsAndPermanentlyReservesCredentialId() throws Exception {
        MemoryStore store = new MemoryStore();
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        enroll(rp, pair, options);

        var listed = assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE));
        assertEquals(1, listed.getCredentialIds().size());
        byte[] leaked = listed.getCredentialIds().get(0);
        assertArrayEquals(CREDENTIAL_ID, leaked);
        leaked[0] ^= 1;
        assertArrayEquals(CREDENTIAL_ID, listed.getCredentialIds().get(0));

        var pending = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING_TEXT));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Removed.class,
                rp.removeCredentialResult(HANDLE, CREDENTIAL_ID));
        assertTrue(assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE)).getCredentialIds().isEmpty());
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(pending.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), pending.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), 1), BINDING_TEXT));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Absent.class,
                rp.removeCredentialResult(HANDLE, CREDENTIAL_ID));

        var reenroll = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(reenroll.getRequest().getCeremonyId(),
                        registrationJson(pair, reenroll.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow()), BINDING_TEXT));
    }

    @Test void disablingAccountFencesPendingCeremoniesButStillAllowsRemoval() throws Exception {
        MemoryStore store = new MemoryStore();
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        enroll(rp, pair, options);
        var pending = assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING_TEXT));
        assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class, rp.disableAccountResult(HANDLE));
        assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class, rp.disableAccountResult(HANDLE));
        assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(pending.getRequest().getCeremonyId(),
                        assertionJson(pair.getPrivate(), pending.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), 1), BINDING_TEXT));
        assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Rejected.class,
                rp.beginReauthenticationResult(HANDLE, "transfer", BINDING_TEXT));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Removed.class,
                rp.removeCredentialResult(HANDLE, CREDENTIAL_ID));
    }

    @Test void disablingBeforeEnrollmentCreatesAResistantFence() {
        MemoryStore store = new MemoryStore();
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT);
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class, rp.disableAccountResult(HANDLE));
        assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        assertTrue(assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE)).getCredentialIds().isEmpty());
    }

    @Test void managementUncertaintyAndRecoveryDenialWithholdConfirmedState() throws Exception {
        MemoryStore store = new MemoryStore();
        WebAuthnRelyingParty rp = relyingParty(store, ADMIT);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        enroll(rp, pair, options);
        store.nextCommit = WebAuthnStoreCommitResult.UNKNOWN;
        assertInstanceOf(WebAuthnCredentialRemovalResult.Indeterminate.class,
                rp.removeCredentialResult(HANDLE, CREDENTIAL_ID));
        assertEquals(1, assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE)).getCredentialIds().size());
        store.nextCommit = WebAuthnStoreCommitResult.CONFLICT;
        assertInstanceOf(WebAuthnAccountDisableResult.Unavailable.class,
                rp.disableAccountResult(HANDLE));
        WebAuthnRelyingParty denied = relyingParty(store, remaining -> null);
        int before = store.reads;
        assertInstanceOf(WebAuthnCredentialListResult.Unavailable.class,
                denied.listCredentialsResult(HANDLE));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Unavailable.class,
                denied.removeCredentialResult(HANDLE, CREDENTIAL_ID));
        assertInstanceOf(WebAuthnAccountDisableResult.Unavailable.class,
                denied.disableAccountResult(HANDLE));
        assertEquals(before, store.reads);
    }

    private static void enroll(@NonNull WebAuthnRelyingParty rp, @NonNull KeyPair pair,
            @NonNull WebAuthnRegistrationOptions options) throws Exception {
        var started = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING_TEXT));
        assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,
                rp.completeRegistrationResult(started.getRequest().getCeremonyId(),
                        registrationJson(pair, started.getRequest().getPublicKeyOptions()
                                .findString("challenge").orElseThrow()), BINDING_TEXT));
    }

    private static @NonNull WebAuthnRelyingParty relyingParty(@NonNull WebAuthnStore store,
            @NonNull WebAuthnRecoveryGate gate) {
        return relyingParty(store, gate, WebAuthnSettings.builder().build(), CLOCK);
    }

    private static @NonNull WebAuthnRelyingParty relyingParty(@NonNull WebAuthnStore store,
            @NonNull WebAuthnRecoveryGate gate, @NonNull WebAuthnSettings settings,
            @NonNull Clock clock) {
        return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Example")
                .allowedOrigins(Set.of(ORIGIN)).credentialNamespace(NAMESPACE)
                .store(store).stateSealer(sealer()).recoveryGate(gate).settings(settings)
                .clockForTesting(clock).build();
    }

    private static @NonNull StateSealer sealer() {
        byte[] material = filled(1);
        return StateSealer.withActiveKey(SealingKey.fromBase64("k",
                Base64.getEncoder().encodeToString(material))).clock(CLOCK).build();
    }

    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair,
            @NonNull String challenge) {
        byte[] auth = registrationAuth(pair);
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"attestationObject\":\"" + Base64Url.encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    private static byte @NonNull [] assertionJson(@NonNull PrivateKey key,
            @NonNull String challenge, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(clientJson("webauthn.get", challenge)));
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"signature\":\"" + Base64Url.encode(signer.sign())
                + "\",\"userHandle\":\"" + Base64Url.encode(HANDLE)
                + "\"},\"clientExtensionResults\":{}}");
    }

    private static byte @NonNull [] clientJson(@NonNull String type, @NonNull String challenge) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}");
    }

    private static byte @NonNull [] registrationAuth(@NonNull KeyPair pair) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(CREDENTIAL_ID.length); out.writeBytes(CREDENTIAL_ID);
        out.writeBytes(edKey(pair));
        return out.toByteArray();
    }

    private static byte @NonNull [] assertionAuth(long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII))); out.write(0x05);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }
    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }
    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
    private static byte @NonNull [] filled(int first) {
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte) (first + i);
        return result;
    }

    private static final class MemoryStore implements WebAuthnStore {
        private final @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull Stored> records = new HashMap<>();
        private int version;
        private int reads;
        private @Nullable WebAuthnStoreCommitResult nextCommit;

        @Override public synchronized @NonNull WebAuthnStoreReadResult read(
                @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remainingBudget) {
            this.reads++;
            Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>();
            for (WebAuthnStoreKey key : keys) {
                Stored current = this.records.get(key);
                entries.put(key, current == null ? WebAuthnStoreEntry.Absent.confirmed()
                        : WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        current.version, current.sealed));
            }
            return WebAuthnStoreReadResult.Available.fromSnapshot(
                    WebAuthnStoreSnapshot.fromEntries(keys, entries));
        }

        @Override public synchronized @NonNull WebAuthnStoreCommitResult compareAndCommit(
                @NonNull WebAuthnStoreWrite write, @NonNull Duration remainingBudget) {
            if (this.nextCommit != null) {
                WebAuthnStoreCommitResult forced = this.nextCommit;
                this.nextCommit = null;
                return forced;
            }
            for (var observed : write.getSnapshot().getEntries().entrySet()) {
                Stored actual = this.records.get(observed.getKey());
                WebAuthnStoreEntry entry = observed.getValue();
                if ((entry instanceof WebAuthnStoreEntry.Absent && actual != null)
                        || (entry instanceof WebAuthnStoreEntry.Present present
                        && (actual == null || !Arrays.equals(actual.version, present.getVersion()))))
                    return WebAuthnStoreCommitResult.CONFLICT;
            }
            for (var mutation : write.getMutations()) {
                if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.DELETE)
                    this.records.remove(mutation.getKey());
                else this.records.put(mutation.getKey(), new Stored(
                        ByteBuffer.allocate(4).putInt(++this.version).array(),
                        mutation.getSealedBytes().orElseThrow()));
            }
            return WebAuthnStoreCommitResult.COMMITTED;
        }

        private static final class Stored {
            private final byte @NonNull [] version;
            private final byte @NonNull [] sealed;
            private Stored(byte @NonNull [] version, byte @NonNull [] sealed) {
                this.version = version.clone(); this.sealed = sealed.clone();
            }
        }
    }
}
