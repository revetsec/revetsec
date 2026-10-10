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
package example.pending;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.WebAuthnAuthentication;
import com.revetsec.webauthn.WebAuthnAuthenticationRequestResult;
import com.revetsec.webauthn.WebAuthnAuthenticationResult;
import com.revetsec.webauthn.WebAuthnCredentialListResult;
import com.revetsec.webauthn.WebAuthnCredentialRemovalResult;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRegistrationOptions;
import com.revetsec.webauthn.WebAuthnRegistrationRequestResult;
import com.revetsec.webauthn.WebAuthnRegistrationResult;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/** Synthetic authenticator over the public RP API and the real PostgreSQL store, one JVM per command. */
public final class WebAuthnFlowProbe {
    private static final @NonNull String NAMESPACE = "fixture_wa_flow";
    private static final @NonNull String RP = "login.example.com";
    private static final @NonNull String ORIGIN = "https://" + RP;
    private static final byte @NonNull [] HANDLE = { 4, 5, 6 };
    private static final byte @NonNull [] CREDENTIAL_ID = { 1, 2, 3 };
    private static final @NonNull String BINDING = url(filled(65));

    private WebAuthnFlowProbe() { }

    private static @NonNull WebAuthnRelyingParty party(boolean loseCommitAcknowledgement) {
        return partyFor(NAMESPACE, loseCommitAcknowledgement);
    }

    static @NonNull WebAuthnRelyingParty partyFor(@NonNull String namespace,
            boolean loseCommitAcknowledgement) {
        return partyFor(namespace, loseCommitAcknowledgement, gateFor(namespace));
    }

    static @NonNull WebAuthnRelyingParty partyFor(@NonNull String namespace,
            boolean loseCommitAcknowledgement, @NonNull WebAuthnRecoveryGate fixtureGate) {
        String key = System.getenv("REVETSEC_TEST_WA_SEAL_KEY");
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("fixture", key)).build();
        WebAuthnStore regular = new PostgresqlWebAuthnStore(namespace, WebAuthnStoreProbe::connection, 256);
        WebAuthnStore selected = loseCommitAcknowledgement ? new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(
                    @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remainingBudget) {
                return regular.read(keys, remainingBudget);
            }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
                    @NonNull WebAuthnStoreWrite write, @NonNull Duration remainingBudget) {
                return new PostgresqlWebAuthnStore(namespace,
                        WebAuthnStoreProbe::lostCommitAcknowledgement, 256)
                        .compareAndCommit(write, remainingBudget);
            }
        } : regular;
        return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Example")
                .allowedOrigins(Set.of(ORIGIN)).credentialNamespace(namespace)
                .store(selected)
                .stateSealer(sealer).recoveryGate(fixtureGate).build();
    }

    private static @NonNull WebAuthnRecoveryGate gate() {
        return gateFor(NAMESPACE);
    }

    private static @NonNull WebAuthnRecoveryGate gateFor(@NonNull String namespace) {
        return new WebAuthnFixtureRecoveryGate(namespace,
                Path.of(System.getenv("REVETSEC_TEST_WA_MARKER_FILE")),
                Path.of(System.getenv("REVETSEC_TEST_WA_LOCK_FILE")),
                System.getenv("REVETSEC_TEST_WA_SEAL_KEY"));
    }

    private static void beginRegister(@NonNull WebAuthnRelyingParty party) {
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        WebAuthnRegistrationRequestResult result = party.beginRegistrationResult(options, BINDING);
        if (!(result instanceof WebAuthnRegistrationRequestResult.Prepared prepared))
            throw new IllegalStateException("Registration preparation did not commit: " + result);
        var request = prepared.getRequest();
        String challenge = request.getPublicKeyOptions().findString("challenge").orElseThrow();
        System.out.println("BEGIN " + request.getCeremonyId() + " " + challenge);
    }

    private static void completeRegister(@NonNull WebAuthnRelyingParty party,
            @NonNull String ceremony, @NonNull String challenge, boolean replay) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        WebAuthnRegistrationResult result = party.completeRegistrationResult(ceremony,
                registrationJson(pair, challenge), BINDING);
        if (replay) {
            if (!(result instanceof WebAuthnRegistrationResult.Rejected))
                throw new IllegalStateException("Registration replay was not rejected: " + result);
            System.out.println("REGISTRATION_REJECTED");
            return;
        }
        if (!(result instanceof WebAuthnRegistrationResult.Succeeded succeeded)
                || !Arrays.equals(succeeded.getRegistration().getCredentialId(), CREDENTIAL_ID)
                || !Arrays.equals(succeeded.getRegistration().getUserHandle(), HANDLE))
            throw new IllegalStateException("Registration did not return verified proof: " + result);
        // The runner captures this test-only private key in memory and passes it to later JVMs by environment.
        System.out.println("REGISTERED " + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
    }

    private static void beginAuthentication(@NonNull WebAuthnRelyingParty party, boolean pinned) {
        WebAuthnAuthenticationRequestResult result = pinned
                ? party.beginReauthenticationResult(HANDLE, "transfer", BINDING)
                : party.beginAuthenticationResult(BINDING);
        if (!(result instanceof WebAuthnAuthenticationRequestResult.Prepared prepared))
            throw new IllegalStateException("Authentication preparation did not commit: " + result);
        var request = prepared.getRequest();
        String challenge = request.getPublicKeyOptions().findString("challenge").orElseThrow();
        System.out.println("BEGIN " + request.getCeremonyId() + " " + challenge);
    }

    private static void completeAuthentication(@NonNull WebAuthnRelyingParty party,
            @NonNull String ceremony, @NonNull String challenge, long counter, boolean race) throws Exception {
        if (race) {
            System.out.println("READY");
            System.out.flush();
            if (new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine() == null)
                throw new IllegalStateException("Race barrier closed");
        }
        byte[] encoded = Base64.getDecoder().decode(System.getenv("REVETSEC_TEST_WA_AUTH_KEY"));
        PrivateKey privateKey = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        WebAuthnAuthenticationResult result = party.completeAuthenticationResult(ceremony,
                assertionJson(privateKey, challenge, counter), BINDING);
        if (result instanceof WebAuthnAuthenticationResult.Succeeded succeeded) {
            WebAuthnAuthentication authentication = succeeded.getAuthentication();
            if (!Arrays.equals(authentication.getUserHandle(), HANDLE))
                throw new IllegalStateException("Unexpected verified account");
            if (authentication.getKind() == WebAuthnAuthentication.Kind.REAUTHENTICATION) {
                if (!authentication.getActionPurpose().orElseThrow().equals("transfer"))
                    throw new IllegalStateException("Unexpected reauthentication purpose");
                System.out.println("SUCCEEDED_REAUTHENTICATION");
            } else {
                if (authentication.getKind() != WebAuthnAuthentication.Kind.SIGN_IN)
                    throw new IllegalStateException("Unexpected authentication kind");
                System.out.println("SUCCEEDED_SIGN_IN");
            }
        } else if (result instanceof WebAuthnAuthenticationResult.Rejected) {
            System.out.println("REJECTED");
        } else if (race && result instanceof WebAuthnAuthenticationResult.Unavailable) {
            // The public completion maps a stale conditional commit to a bounded unavailable outcome.
            System.out.println("UNAVAILABLE");
        } else if (result instanceof WebAuthnAuthenticationResult.Indeterminate) {
            System.out.println("INDETERMINATE");
        } else {
            throw new IllegalStateException("Authentication was not resolved: " + result);
        }
    }

    private static void list(@NonNull WebAuthnRelyingParty party, int expected) {
        WebAuthnCredentialListResult result = party.listCredentialsResult(HANDLE);
        if (!(result instanceof WebAuthnCredentialListResult.Listed listed)
                || listed.getCredentialIds().size() != expected)
            throw new IllegalStateException("Unexpected active credential list: " + result);
        if (expected == 1 && !Arrays.equals(listed.getCredentialIds().get(0), CREDENTIAL_ID))
            throw new IllegalStateException("Unexpected active credential ID");
        System.out.println("LISTED_" + expected);
    }

    private static void remove(@NonNull WebAuthnRelyingParty party) {
        WebAuthnCredentialRemovalResult result = party.removeCredentialResult(HANDLE, CREDENTIAL_ID);
        if (!(result instanceof WebAuthnCredentialRemovalResult.Removed))
            throw new IllegalStateException("Credential removal did not commit: " + result);
        System.out.println("REMOVED");
    }

    private static void outage(@NonNull WebAuthnRelyingParty party) {
        WebAuthnAuthenticationRequestResult result = party.beginAuthenticationResult(BINDING);
        if (!(result instanceof WebAuthnAuthenticationRequestResult.Unavailable))
            throw new IllegalStateException("Primary outage released browser options: " + result);
        System.out.println("FLOW_OUTAGE_CLOSED");
    }

    private static void holdAdmission() throws Exception {
        WebAuthnRecoveryGate.Permit permit = gate().acquire(java.time.Duration.ofSeconds(20));
        if (permit == null) throw new IllegalStateException("Fixture admission could not be acquired");
        try (permit) {
            System.out.println("ADMITTED");
            System.out.flush();
            if (new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine() == null)
                throw new IllegalStateException("Admission barrier closed");
        }
    }

    private static void restoredClosed(@NonNull WebAuthnRelyingParty party,
            @NonNull String ceremony, @NonNull String challenge) throws Exception {
        if (!(party.beginAuthenticationResult(BINDING) instanceof WebAuthnAuthenticationRequestResult.Unavailable)
                || !(party.listCredentialsResult(HANDLE) instanceof WebAuthnCredentialListResult.Unavailable))
            throw new IllegalStateException("Restored database reopened WebAuthn admission");
        byte[] encoded = Base64.getDecoder().decode(System.getenv("REVETSEC_TEST_WA_AUTH_KEY"));
        PrivateKey privateKey = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        WebAuthnAuthenticationResult result = party.completeAuthenticationResult(ceremony,
                assertionJson(privateKey, challenge, 6), BINDING);
        if (!(result instanceof WebAuthnAuthenticationResult.Unavailable))
            throw new IllegalStateException("Restored consumed ceremony released a result: " + result);
        System.out.println("RESTORED_CLOSED");
    }

    private static void rawStateHash(@NonNull String ceremony) {
        WebAuthnStoreKey ceremonyKey = WebAuthnStoreKey.forCeremony(NAMESPACE, RP,
                Base64.getUrlDecoder().decode(ceremony));
        List<WebAuthnStoreKey> keys = List.of(ceremonyKey,
                WebAuthnStoreKey.forAccountCredentialIndex(NAMESPACE, RP, HANDLE),
                WebAuthnStoreKey.forCredential(NAMESPACE, RP, CREDENTIAL_ID));
        WebAuthnStoreReadResult result = new PostgresqlWebAuthnStore(NAMESPACE,
                WebAuthnStoreProbe::connection, 256).read(Set.copyOf(keys), java.time.Duration.ofSeconds(5));
        if (!(result instanceof WebAuthnStoreReadResult.Available available))
            throw new IllegalStateException("Could not inspect fixture state");
        WebAuthnStoreSnapshot snapshot = available.getSnapshot();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (WebAuthnStoreKey key : keys) {
                if (!(snapshot.getEntry(key) instanceof WebAuthnStoreEntry.Present present))
                    throw new IllegalStateException("Fixture state is incomplete");
                digest.update(key.getKind().name().getBytes(StandardCharsets.US_ASCII));
                digest.update(present.getVersion());
                digest.update(present.getSealedBytes());
            }
            System.out.println("RAW_HASH " + url(digest.digest()));
        } catch (java.security.NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }

    static byte @NonNull [] registrationJson(@NonNull KeyPair pair, @NonNull String challenge) {
        byte[] auth = registrationAuth(pair);
        String id = url(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + url(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + url(auth)
                + "\",\"attestationObject\":\"" + url(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    static byte @NonNull [] assertionJson(@NonNull PrivateKey key,
            @NonNull String challenge, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(clientJson("webauthn.get", challenge)));
        String id = url(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + url(clientJson("webauthn.get", challenge))
                + "\",\"authenticatorData\":\"" + url(auth)
                + "\",\"signature\":\"" + url(signer.sign())
                + "\",\"userHandle\":\"" + url(HANDLE)
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
        catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }

    private static byte @NonNull [] filled(int first) {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (first + i);
        return bytes;
    }

    private static @NonNull String url(byte @NonNull [] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte @NonNull [] json(@NonNull String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String @NonNull [] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("Expected flow command");
        WebAuthnRelyingParty party = party(args[0].equals("complete-auth-unknown"));
        switch (args[0]) {
            case "begin-register" -> beginRegister(party);
            case "complete-register" -> completeRegister(party, args[1], args[2], false);
            case "replay-register" -> completeRegister(party, args[1], args[2], true);
            case "begin-auth" -> beginAuthentication(party, false);
            case "begin-reauth" -> beginAuthentication(party, true);
            case "complete-auth" -> completeAuthentication(party, args[1], args[2],
                    Long.parseLong(args[3]), false);
            case "complete-auth-unknown" -> completeAuthentication(party, args[1], args[2],
                    Long.parseLong(args[3]), false);
            case "race-auth" -> completeAuthentication(party, args[1], args[2],
                    Long.parseLong(args[3]), true);
            case "list-one" -> list(party, 1);
            case "list-zero" -> list(party, 0);
            case "remove" -> remove(party);
            case "outage" -> outage(party);
            case "hold-admission" -> holdAdmission();
            case "restored-closed" -> restoredClosed(party, args[1], args[2]);
            case "raw-hash" -> rawStateHash(args[1]);
            default -> throw new IllegalArgumentException("Unknown flow command");
        }
    }
}
