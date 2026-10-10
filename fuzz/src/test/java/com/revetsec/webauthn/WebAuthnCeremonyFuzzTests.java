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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/** Stateful WebAuthn ceremony checks driven through the public relying-party API.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class WebAuthnCeremonyFuzzTests {
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final byte[] HANDLE = {4, 5, 6};
    private static final String BINDING = Base64Url.encode(filled(65));
    private static final String WRONG_BINDING = Base64Url.encode(filled(99));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T12:00:00Z"), ZoneOffset.UTC);
    private static final WebAuthnRecoveryGate GATE = remaining -> new WebAuthnRecoveryGate.Permit() {
        @Override public boolean isCurrent() { return true; }
        @Override public void close() { }
    };
    private static final KeyPair KEY = edKeyPair();
    private static final KeyPair OTHER_KEY = edKeyPair();
    private static final KeyPair ES_KEY = ecKeyPair();
    private static final KeyPair RSA_KEY = rsaKeyPair();

    /** A rejected registration cannot consume a challenge or create a credential proof. */
    @FuzzTest(maxDuration = "5m")
    public void registrationRejectsChangedBrowserEvidenceWithoutConsumingTheValidCeremony(
            byte @NonNull [] input) throws Exception {
        byte[] id = credentialId(input);
        WebAuthnRelyingParty rp = relyingParty();
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        var prepared = Assertions.assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING)).getRequest();
        String challenge = prepared.getPublicKeyOptions().findString("challenge").orElseThrow();
        byte[] valid = registration(id, challenge, ORIGIN, 0x45, true, -8, false, false);
        int change = unsigned(input, 0) % 9;
        byte[] altered = switch (change) {
            case 0 -> registration(id, changed(challenge), ORIGIN, 0x45, true, -8, false, false);
            case 1 -> registration(id, challenge, "https://evil.example.com", 0x45, true, -8, false, false);
            case 2 -> registration(id, challenge, ORIGIN, 0x41, true, -8, false, false);
            case 3 -> registration(id, challenge, ORIGIN, 0x45, false, -8, false, false);
            case 4 -> registration(id, challenge, ORIGIN, 0x45, true, -7, false, false);
            case 5 -> registration(id, challenge, ORIGIN, 0x45, true, -8, true, false);
            case 6 -> registration(id, challenge, ORIGIN, 0x45, true, -8, false, true);
            case 7 -> duplicateRootType(valid);
            default -> valid;
        };
        String binding = change == 8 ? WRONG_BINDING : BINDING;
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(prepared.getCeremonyId(), altered, binding));
        var registered = Assertions.assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,
                rp.completeRegistrationResult(prepared.getCeremonyId(), valid, BINDING));
        Assertions.assertArrayEquals(id, registered.getRegistration().getCredentialId());
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(prepared.getCeremonyId(), valid, BINDING));
        Assertions.assertEquals(1, Assertions.assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE)).getCredentialIds().size());
    }

    /** A changed assertion cannot release proof; replay, stale counters and removal remain fenced. */
    @FuzzTest(maxDuration = "5m")
    public void assertionBindsTheSignedInputsAndAuthoritativeCredentialState(
            byte @NonNull [] input) throws Exception {
        byte[] id = credentialId(input);
        WebAuthnRelyingParty rp = relyingParty();
        enroll(rp, id);
        var prepared = Assertions.assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING)).getRequest();
        String challenge = prepared.getPublicKeyOptions().findString("challenge").orElseThrow();
        byte[] valid = assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                HANDLE, false, false);
        int change = unsigned(input, 0) % 12;
        byte[] altered = switch (change) {
            case 0 -> assertion(id, OTHER_KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, false, false);
            case 1 -> assertion(id, KEY.getPrivate(), changed(challenge), ORIGIN, 0x05, 1,
                    HANDLE, false, false);
            case 2 -> assertion(id, KEY.getPrivate(), challenge, "https://evil.example.com", 0x05, 1,
                    HANDLE, false, false);
            case 3 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x01, 1,
                    HANDLE, false, false);
            case 4 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    flipped(HANDLE), false, false);
            case 5 -> assertion(flipped(id), KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, false, false);
            case 6 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, true, false);
            case 7 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, false, true);
            case 8 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, false, false, true);
            case 9 -> assertion(id, KEY.getPrivate(), challenge, ORIGIN, 0x05, 1,
                    HANDLE, false, false, false, true);
            case 11 -> corruptSignature(valid);
            default -> valid;
        };
        String binding = change == 10 ? WRONG_BINDING : BINDING;
        WebAuthnAuthenticationResult alteredResult =
                rp.completeAuthenticationResult(prepared.getCeremonyId(), altered, binding);
        if (change == 11)
            Assertions.assertTrue(alteredResult instanceof WebAuthnAuthenticationResult.Rejected
                    || alteredResult instanceof WebAuthnAuthenticationResult.Unavailable);
        else
            Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class, alteredResult);
        var authenticated = Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(prepared.getCeremonyId(), valid, BINDING));
        Assertions.assertArrayEquals(HANDLE, authenticated.getAuthentication().getUserHandle());
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(prepared.getCeremonyId(), valid, BINDING));

        var stale = Assertions.assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING)).getRequest();
        String next = stale.getPublicKeyOptions().findString("challenge").orElseThrow();
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(stale.getCeremonyId(),
                        assertion(id, KEY.getPrivate(), next, ORIGIN, 0x05, 1,
                                HANDLE, false, false), BINDING));
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(stale.getCeremonyId(),
                        assertion(id, KEY.getPrivate(), next, ORIGIN, 0x05, 2,
                                HANDLE, false, false), BINDING));

        var pinned = Assertions.assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginReauthenticationResult(HANDLE, "transfer", BINDING)).getRequest();
        var stepUp = Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(pinned.getCeremonyId(),
                        assertion(id, KEY.getPrivate(), pinned.getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), ORIGIN, 0x05, 3,
                                HANDLE, false, false), BINDING));
        Assertions.assertEquals(WebAuthnAuthentication.Kind.REAUTHENTICATION,
                stepUp.getAuthentication().getKind());
        Assertions.assertEquals("transfer", stepUp.getAuthentication().getActionPurpose().orElseThrow());

        var pending = Assertions.assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING)).getRequest();
        Assertions.assertInstanceOf(WebAuthnCredentialRemovalResult.Removed.class,
                rp.removeCredentialResult(HANDLE, id));
        Assertions.assertTrue(Assertions.assertInstanceOf(WebAuthnCredentialListResult.Listed.class,
                rp.listCredentialsResult(HANDLE)).getCredentialIds().isEmpty());
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(pending.getCeremonyId(),
                        assertion(id, KEY.getPrivate(), pending.getPublicKeyOptions()
                                .findString("challenge").orElseThrow(), ORIGIN, 0x05, 4,
                                HANDLE, false, false), BINDING));

        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        var retry = Assertions.assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING)).getRequest();
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(retry.getCeremonyId(),
                        registration(id, retry.getPublicKeyOptions().findString("challenge").orElseThrow(),
                                ORIGIN, 0x45, true, -8, false, false), BINDING));
    }

    /** ES256, Ed25519 and RS256 use only the key committed at enrollment and the exact signed bytes. */
    @FuzzTest(maxDuration = "5m")
    public void allSupportedAlgorithmsBindTheCommittedKeyAndExactSignedBytes(
            byte @NonNull [] input) throws Exception {
        int selected = unsigned(input, 0) % 3;
        KeyPair pair = switch (selected) {
            case 0 -> ES_KEY;
            case 1 -> KEY;
            default -> RSA_KEY;
        };
        int algorithm = switch (selected) {
            case 0 -> -7;
            case 1 -> -8;
            default -> -257;
        };
        String jcaAlgorithm = switch (selected) {
            case 0 -> "SHA256withECDSA";
            case 1 -> "Ed25519";
            default -> "SHA256withRSA";
        };
        byte[] cose = switch (selected) {
            case 0 -> esCose((ECPublicKey) pair.getPublic());
            case 1 -> edCose(pair);
            default -> rsaCose((RSAPublicKey) pair.getPublic());
        };
        byte[] id = credentialId(input);
        WebAuthnRelyingParty rp = relyingParty();
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        var enrollment = Assertions.assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING)).getRequest();
        String challenge = enrollment.getPublicKeyOptions().findString("challenge").orElseThrow();
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,
                rp.completeRegistrationResult(enrollment.getCeremonyId(),
                        registration(id, challenge, ORIGIN, 0x45, true,
                                algorithm == -8 ? -7 : -8, false, false, cose), BINDING));
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,
                rp.completeRegistrationResult(enrollment.getCeremonyId(),
                        registration(id, challenge, ORIGIN, 0x45, true,
                                algorithm, false, false, cose), BINDING));

        var request = Assertions.assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,
                rp.beginAuthenticationResult(BINDING)).getRequest();
        String assertionChallenge = request.getPublicKeyOptions().findString("challenge").orElseThrow();
        byte[] auth = assertionAuth(0x05, 1);
        byte[] client = client("webauthn.get", assertionChallenge, ORIGIN, false, false);
        byte[] wrongClient = client("webauthn.get", changed(assertionChallenge), ORIGIN, false, false);
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(request.getCeremonyId(),
                        assertionBody(id, auth, client, HANDLE,
                                sign(jcaAlgorithm, pair.getPrivate(), auth, wrongClient)), BINDING));
        byte[] valid = assertionBody(id, auth, client, HANDLE,
                sign(jcaAlgorithm, pair.getPrivate(), auth, client));
        var succeeded = Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Succeeded.class,
                rp.completeAuthenticationResult(request.getCeremonyId(), valid, BINDING));
        Assertions.assertArrayEquals(HANDLE, succeeded.getAuthentication().getUserHandle());
        Assertions.assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,
                rp.completeAuthenticationResult(request.getCeremonyId(), valid, BINDING));
    }

    private static @NonNull WebAuthnRelyingParty relyingParty() {
        byte[] material = filled(1);
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("k",
                Base64.getEncoder().encodeToString(material))).clock(CLOCK).build();
        return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Example")
                .allowedOrigins(Set.of(ORIGIN)).credentialNamespace("fuzz")
                .store(InMemoryWebAuthnStore.withLimits(128, 2_000_000))
                .stateSealer(sealer).recoveryGate(GATE).clockForTesting(CLOCK).build();
    }

    private static void enroll(@NonNull WebAuthnRelyingParty rp, byte @NonNull [] id) {
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions.withUserHandle(HANDLE)
                .userName("alice").userDisplayName("Alice Example").build();
        var prepared = Assertions.assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,
                rp.beginRegistrationResult(options, BINDING)).getRequest();
        Assertions.assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,
                rp.completeRegistrationResult(prepared.getCeremonyId(),
                        registration(id, prepared.getPublicKeyOptions().findString("challenge").orElseThrow(),
                                ORIGIN, 0x45, true, -8, false, false), BINDING));
    }

    private static byte @NonNull [] registration(byte @NonNull [] id, @NonNull String challenge,
            @NonNull String origin, int flags, boolean resident, int algorithm,
            boolean nonemptyStatement, boolean mismatchedAuthenticatorData) {
        return registration(id, challenge, origin, flags, resident, algorithm,
                nonemptyStatement, mismatchedAuthenticatorData, edCose(KEY));
    }

    private static byte @NonNull [] registration(byte @NonNull [] id, @NonNull String challenge,
            @NonNull String origin, int flags, boolean resident, int algorithm,
            boolean nonemptyStatement, boolean mismatchedAuthenticatorData, byte @NonNull [] cose) {
        byte[] auth = registrationAuth(id, flags, cose);
        byte[] outerAuth = auth.clone();
        if (mismatchedAuthenticatorData) outerAuth[36] ^= 1;
        byte[] attestation = attestation(auth, nonemptyStatement);
        String rawId = Base64Url.encode(id);
        return json("{\"id\":\"" + rawId + "\",\"rawId\":\"" + rawId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(client("webauthn.create", challenge, origin, false, false))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(outerAuth)
                + "\",\"attestationObject\":\"" + Base64Url.encode(attestation)
                + "\",\"publicKeyAlgorithm\":" + algorithm + ",\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":" + resident + "}}}");
    }

    private static byte @NonNull [] assertion(byte @NonNull [] id, @NonNull PrivateKey key,
            @NonNull String challenge, @NonNull String origin, int flags, long counter,
            byte @NonNull [] handle, boolean crossOrigin, boolean topOrigin) throws Exception {
        return assertion(id, key, challenge, origin, flags, counter, handle, crossOrigin, topOrigin,
                false, false);
    }

    private static byte @NonNull [] assertion(byte @NonNull [] id, @NonNull PrivateKey key,
            @NonNull String challenge, @NonNull String origin, int flags, long counter,
            byte @NonNull [] handle, boolean crossOrigin, boolean topOrigin,
            boolean wrongRpHash) throws Exception {
        return assertion(id, key, challenge, origin, flags, counter, handle, crossOrigin, topOrigin,
                wrongRpHash, false);
    }

    private static byte @NonNull [] assertion(byte @NonNull [] id, @NonNull PrivateKey key,
            @NonNull String challenge, @NonNull String origin, int flags, long counter,
            byte @NonNull [] handle, boolean crossOrigin, boolean topOrigin,
            boolean wrongRpHash, boolean duplicateClientType) throws Exception {
        byte[] auth = assertionAuth(flags, counter);
        if (wrongRpHash) auth[0] ^= 1;
        byte[] client = client("webauthn.get", challenge, origin, crossOrigin, topOrigin,
                duplicateClientType);
        return assertionBody(id, auth, client, handle, sign("Ed25519", key, auth, client));
    }

    private static byte @NonNull [] assertionBody(byte @NonNull [] id, byte @NonNull [] auth,
            byte @NonNull [] client, byte @NonNull [] handle, byte @NonNull [] signature) {
        String encodedId = Base64Url.encode(id);
        return json("{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(client) + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"signature\":\"" + Base64Url.encode(signature)
                + "\",\"userHandle\":\"" + Base64Url.encode(handle)
                + "\"},\"clientExtensionResults\":{}}");
    }

    private static byte @NonNull [] sign(@NonNull String algorithm, @NonNull PrivateKey key,
            byte @NonNull [] auth, byte @NonNull [] client) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(client));
        return signer.sign();
    }

    private static byte @NonNull [] client(@NonNull String type, @NonNull String challenge,
            @NonNull String origin, boolean crossOrigin, boolean topOrigin) {
        return client(type, challenge, origin, crossOrigin, topOrigin, false);
    }

    private static byte @NonNull [] client(@NonNull String type, @NonNull String challenge,
            @NonNull String origin, boolean crossOrigin, boolean topOrigin, boolean duplicateType) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":" + crossOrigin
                + (topOrigin ? ",\"topOrigin\":\"" + origin + "\"" : "")
                + (duplicateType ? ",\"\\u0074ype\":\"" + type + "\"" : "") + "}");
    }

    private static byte @NonNull [] registrationAuth(byte @NonNull [] id, int flags,
            byte @NonNull [] cose) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(flags);
        out.writeBytes(new byte[4]);
        out.writeBytes(new byte[16]);
        out.write(id.length >>> 8); out.write(id.length);
        out.writeBytes(id);
        out.writeBytes(cose);
        return out.toByteArray();
    }

    private static byte @NonNull [] edCose(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static byte @NonNull [] esCose(@NonNull ECPublicKey key) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa5); out.write(1); out.write(2); out.write(3); out.write(0x26);
        out.write(0x20); out.write(1);
        out.write(0x21); bytes(out, fixed(key.getW().getAffineX(), 32));
        out.write(0x22); bytes(out, fixed(key.getW().getAffineY(), 32));
        return out.toByteArray();
    }

    private static byte @NonNull [] rsaCose(@NonNull RSAPublicKey key) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(3); out.write(3); out.write(0x39); out.write(1); out.write(0);
        out.write(0x20); bytes(out, unsigned(key.getModulus()));
        out.write(0x21); bytes(out, unsigned(key.getPublicExponent()));
        return out.toByteArray();
    }

    private static byte @NonNull [] fixed(@NonNull BigInteger value, int length) {
        byte[] integer = unsigned(value);
        byte[] fixed = new byte[length];
        System.arraycopy(integer, 0, fixed, length - integer.length, integer.length);
        return fixed;
    }

    private static byte @NonNull [] unsigned(@NonNull BigInteger value) {
        byte[] signed = value.toByteArray();
        return signed[0] == 0 ? Arrays.copyOfRange(signed, 1, signed.length) : signed;
    }

    private static byte @NonNull [] assertionAuth(int flags, long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII))); out.write(flags);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth, boolean nonemptyStatement) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt");
        out.write(nonemptyStatement ? 0xa1 : 0xa0);
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

    private static byte @NonNull [] credentialId(byte @NonNull [] input) {
        int length = 1 + unsigned(input, 1) % 64;
        byte[] id = new byte[length];
        for (int i = 0; i < id.length; i++) id[i] = (byte) unsigned(input, i + 2);
        return id;
    }

    private static int unsigned(byte @NonNull [] input, int position) {
        return position < input.length ? input[position] & 0xff : 0;
    }

    private static @NonNull String changed(@NonNull String input) {
        return (input.charAt(0) == 'A' ? "B" : "A") + input.substring(1);
    }

    private static byte @NonNull [] flipped(byte @NonNull [] input) {
        byte[] result = input.clone(); result[0] ^= 1; return result;
    }

    private static byte @NonNull [] filled(int first) {
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte) (first + i);
        return result;
    }

    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static byte @NonNull [] json(@NonNull String input) {
        return input.getBytes(StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] duplicateRootType(byte @NonNull [] valid) {
        String text = new String(valid, StandardCharsets.UTF_8);
        return json(text.substring(0, text.length() - 1) + ",\"type\":\"public-key\"}");
    }

    private static byte @NonNull [] corruptSignature(byte @NonNull [] valid) {
        String text = new String(valid, StandardCharsets.UTF_8);
        int position = text.indexOf("\"signature\":\"") + "\"signature\":\"".length();
        return json(text.substring(0, position) + (text.charAt(position) == 'A' ? "B" : "A")
                + text.substring(position + 1));
    }

    private static @NonNull KeyPair edKeyPair() {
        try { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static @NonNull KeyPair ecKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static @NonNull KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2_048);
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
