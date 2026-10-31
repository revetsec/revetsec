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
package com.revetsec.internal.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit decoded-input and authenticated-record rejection boundaries; no browser proof. */
final class WebAuthnCloseoutBoundaryTests {
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final Instant EXPIRY = NOW.plusSeconds(300);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final byte[] RANDOM = new byte[32];
    private static final byte[] HANDLE = {4, 5, 6};
    private static final byte[] ID = {1, 2, 3};

    @Test void cborRejectsWrongTypesNonminimalLengthsAndOutOfRangeIntegers() throws Exception {
        for (byte[] value : new byte[][] {{0x40}, {0x18, 0x17}, {0x19, 0, (byte) 0xff},
                {0x1a, 0, 0, (byte) 0xff, (byte) 0xff}, {0x1b}, {0x1f},
                {0x1a, (byte) 0x80, 0, 0, 0}, {0x3a, (byte) 0x80, 0, 0, 1}})
            assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(value, 0).integer());
        assertEquals(Integer.MAX_VALUE, new WebAuthnCborReader(new byte[] {0x1a, 0x7f, -1, -1, -1}, 0).integer());
        assertEquals(Integer.MIN_VALUE, new WebAuthnCborReader(new byte[] {0x3a, 0x7f, -1, -1, -1}, 0).integer());
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(new byte[] {0x3a, (byte) 0x80, 0, 0, 0}, 0).integer());
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(new byte[] {0x42, 1}, 0).bytes(2));
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(new byte[] {0x61, 0x1f}, 0).ascii(1));
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(new byte[] {0x61, 0x7f}, 0).ascii(1));
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(ID, 0).rawBytes(-1));
        assertThrows(WebAuthnCborException.class, () -> new WebAuthnCborReader(ID, 0).rawBytes(4));
        assertArrayEquals(ID, new WebAuthnCborReader(ID, 0).rawBytes(3));
    }

    @Test void strictDerRejectsEachInvalidIntegerAndSequenceShape() {
        byte[] valid = {0x30, 6, 2, 1, 1, 2, 1, 2};
        byte[] expected = new byte[64]; expected[31] = 1; expected[63] = 2;
        assertArrayEquals(expected, requireNonNull(WebAuthnEcdsaDer.toP1363(valid)));
        for (byte[] invalid : new byte[][] {new byte[7], new byte[73], change(valid, 0, 0x31),
                change(valid, 1, 5), change(valid, 2, 3), change(valid, 3, 0), change(valid, 3, 34),
                change(valid, 3, 9), change(valid, 5, 3), change(valid, 6, 0), change(valid, 6, 34),
                change(valid, 6, 2), change(valid, 4, 0x80), change(valid, 7, 0x80),
                {0x30, 7, 2, 2, 0, 1, 2, 1, 1}, {0x30, 7, 2, 1, 1, 2, 2, 0, 1},
                der(new byte[33], new byte[] {1}), der(new byte[] {1}, new byte[33]),
                der(filled(33, 1), new byte[] {1}), der(new byte[] {1}, filled(33, 1))})
            assertNull(WebAuthnEcdsaDer.toP1363(invalid));
        byte[] padded = filled(33, 0x80); padded[0] = 0;
        byte[] fixed = requireNonNull(WebAuthnEcdsaDer.toP1363(der(padded, padded)));
        assertArrayEquals(filled(64, 0x80), fixed);
    }

    @Test void noneAttestationChecksConfiguredCapsDuplicatesAndNoTrailingCarrier() throws Exception {
        byte[] auth = filled(37, 0); byte[] valid = attestation(auth);
        assertArrayEquals(auth, WebAuthnNoneAttestation.parse(valid).getAuthenticatorData());
        for (int[] limits : new int[][] {{0, 37}, {65537, 37}, {16384, 36}, {16384, 32769}})
            assertThrows(IllegalArgumentException.class, () -> WebAuthnNoneAttestation.parse(valid, limits[0], limits[1]));
        assertThrows(WebAuthnCborException.class, () -> WebAuthnNoneAttestation.parse(valid, valid.length - 1, 37));
        for (byte[] value : new byte[][] {attestation(new byte[36]), concat(valid, new byte[] {0}),
                noneMembers("authData", "authData", "fmt"), noneMembers("attStmt", "attStmt", "fmt"),
                noneMembers("fmt", "fmt", "authData")})
            assertThrows(WebAuthnCborException.class, () -> WebAuthnNoneAttestation.parse(value));
    }

    @Test void clientPolicyRejectsEveryIndependentAddressAndLimitViolation() {
        for (String id : List.of("a." + "b".repeat(252), ".example.com", "example.com.", "-a.example", "a-.example",
                "a..example", "a".repeat(64) + ".example", "UPPER.example", "a_1.example", "127.0.0.1"))
            assertThrows(IllegalArgumentException.class, () -> new WebAuthnClientData(id, Set.of("https://" + id), 8192));
        for (String origin : List.of("https:" + RP, ORIGIN + ":0", ORIGIN + ":65536", ORIGIN + ":0443", ORIGIN + ":-1",
                "https://user@" + RP, ORIGIN + "?a=b", ORIGIN + "#fragment", "https://[", ORIGIN + "/"))
            assertThrows(IllegalArgumentException.class, () -> new WebAuthnClientData(RP, Set.of(origin), 8192));
        assertThrows(IllegalArgumentException.class, () -> new WebAuthnClientData(RP, Set.of(), 8192));
        assertThrows(IllegalArgumentException.class, () -> new WebAuthnClientData(RP, Set.of(ORIGIN), 0));
        assertThrows(IllegalArgumentException.class, () -> new WebAuthnClientData(RP, Set.of(ORIGIN), 16385));
        // Numeric labels in a DNS name remain valid; an overflowing decimal label is not an IPv4 address.
        assertEquals(32, new WebAuthnClientData("a-1.256.123456.example", Set.of("https://a-1.256.123456.example:65535"), 8192).relyingPartyIdHash().length);

    }

    @Test void ceremonyStateRejectsContradictoryBindingsAndComparesEveryPinnedField() {
        var baseline = state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false);
        assertTrue(baseline.samePendingAs(state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false)));
        byte[] altered = RANDOM.clone(); altered[0] = 1;
        for (WebAuthnCeremonyState other : List.of(baseline.consume(),
                state(altered, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false),
                state(RANDOM, altered, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false),
                state(RANDOM, RANDOM, altered, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false),
                state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN + ":443"), HANDLE, null, NOW, EXPIRY, false),
                state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), new byte[] {9}, null, NOW, EXPIRY, false),
                state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW.plusSeconds(1), EXPIRY, false),
                state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY.plusSeconds(1), false),
                WebAuthnCeremonyState.discoverableAuthentication(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), NOW, EXPIRY)))
            assertFalse(baseline.samePendingAs(other));
        assertFalse(baseline.consume().samePendingAs(baseline));
        assertFalse(baseline.matchesBrowserBinding(new byte[31]));
        for (Set<String> origins : List.of(Set.<String>of(), Set.of("a".repeat(268)), Set.of("é"),
                Set.of("1", "2", "3", "4", "5", "6", "7", "8", "9")))
            assertThrows(IllegalArgumentException.class, () -> state(RANDOM, RANDOM, RANDOM, origins, HANDLE, null, NOW, EXPIRY, false));
        for (byte[] handle : new byte[][] {new byte[0], new byte[65]})
            assertThrows(IllegalArgumentException.class, () -> state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), handle, null, NOW, EXPIRY, false));
        assertThrows(IllegalArgumentException.class, () -> state(new byte[31], RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false));
        assertThrows(IllegalArgumentException.class, () -> state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), null, null, NOW, EXPIRY, false));
        assertThrows(IllegalArgumentException.class, () -> state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, "unexpected", NOW, EXPIRY, false));
        assertThrows(IllegalArgumentException.class, () -> state(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, NOW.plusSeconds(601), false));
        for (String purpose : List.of("", "x".repeat(129), "\u001f", "\u007f"))
            assertThrows(IllegalArgumentException.class, () -> WebAuthnCeremonyState.accountReauthentication(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, purpose, NOW, EXPIRY));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnCeremonyState.restored(WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION,
                RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, null, NOW, EXPIRY, false));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnCeremonyState.restored(WebAuthnCeremonyState.Kind.DISCOVERABLE_AUTHENTICATION,
                RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), null, "unexpected", NOW, EXPIRY, false));
        var stepUp = WebAuthnCeremonyState.accountReauthentication(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, "one", NOW, EXPIRY);
        assertFalse(stepUp.samePendingAs(WebAuthnCeremonyState.accountReauthentication(RANDOM, RANDOM, RANDOM, Set.of(ORIGIN), HANDLE, "two", NOW, EXPIRY)));
    }

    @Test void credentialIndexRejectsAuthenticatedBadLengthsOrderingAndAddresses() throws Exception {
        var records = records(); var codec = new WebAuthnCredentialIndex("tenant", RP, records);
        var state = codec.empty(HANDLE).withAdded(ID).withAdded(new byte[] {9});
        assertTrue(state.contains(ID)); assertFalse(state.contains(new byte[] {8}));
        assertEquals(2, codec.decode(codec.encode(state, NOW).key(), codec.encode(state, NOW).sealedBytes(), CLOCK).size());
        assertThrows(IllegalArgumentException.class, () -> codec.empty(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> codec.empty(new byte[65]));
        assertThrows(IllegalArgumentException.class, () -> state.withAdded(ID));
        assertThrows(IllegalArgumentException.class, () -> state.withAdded(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> state.withAdded(new byte[1024]));
        assertThrows(IllegalArgumentException.class, () -> state.without(new byte[] {8}));
        var full = codec.empty(HANDLE);
        for (int i = 0; i < 64; i++) full = full.withAdded(new byte[] {(byte) i});
        var saturated = full;
        assertThrows(IllegalArgumentException.class, () -> saturated.withAdded(new byte[] {99}));
        var key = WebAuthnStoreKey.forAccountCredentialIndex("tenant", RP, HANDLE);
        byte[] valid = indexPayload(HANDLE, ID, new byte[] {9});
        for (byte[] bad : new byte[][] {new byte[3], new byte[65700], change(valid, 0, 2), change(valid, 1, 0),
                change(valid, 1, 65), change(valid, 2, 65), change(valid, 2, 3),
                change(valid, 6, 4), change(valid, 7, 0),
                indexPayload(HANDLE, ID, ID), indexPayload(HANDLE, new byte[] {9}, ID),
                indexPayload(new byte[] {9}, ID), concat(valid, new byte[] {0}), Arrays.copyOf(valid, valid.length - 1)}) {
            byte[] sealed = malformed(key, bad, EXPIRY);
            assertEquals("Invalid WebAuthn store record.", assertThrows(WebAuthnRecordException.class,
                    () -> codec.decode(key, sealed, CLOCK)).getMessage());
        }
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(WebAuthnStoreKey.forCredential("tenant", RP, ID), new byte[] {1}, CLOCK));
    }

    @Test void accountFenceAndNamespaceTimeRejectAuthenticatedInvalidRecords() {
        var records = records(); var codec = new WebAuthnAccountFence("tenant", RP, records);
        var key = WebAuthnStoreKey.forAccountFence("tenant", RP, HANDLE);
        for (byte[] bad : new byte[][] {new byte[3], new byte[68], {2, 1, 3, 4, 5, 6}, {1, -1, 3, 4, 5, 6},
                {1, 2, 3, 4, 5, 6}, {1, 1, 2, 4, 5, 6}, {1, 1, 3, 4, 5, 7}}) {
            byte[] sealed = malformed(key, bad, EXPIRY);
            assertThrows(WebAuthnRecordException.class, () -> codec.decode(key, sealed, CLOCK));
        }
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(WebAuthnStoreKey.forCredential("tenant", RP, ID), new byte[] {1}, CLOCK));
        var time = new WebAuthnNamespaceClock("tenant", RP, records);
        byte[] negativeNanos = ByteBuffer.allocate(13).put((byte) 1).putLong(NOW.getEpochSecond()).putInt(-1).array();
        assertThrows(WebAuthnRecordException.class, () -> time.decode(time.key(), malformed(time.key(), negativeNanos, EXPIRY), CLOCK));
    }

    @Test void credentialPayloadCapsAndRevokedOwnershipAreIndependentlyChecked() {
        var records = records(); var codec = new WebAuthnCredentialRecordCodec("tenant", RP, records);
        var key = WebAuthnStoreKey.forCredential("tenant", RP, ID);
        byte[] header = ByteBuffer.allocate(20).put((byte) 1).putShort((short) -8).putInt(0).put((byte) 0)
                .putShort((short) 3).put((byte) 3).putShort((short) 1).put(ID).put(HANDLE).put((byte) 0).array();
        for (byte[] bad : new byte[][] {change(header, 8, 0), change(header, 9, 0), change(header, 8, 4), change(header, 9, 0),
                change(header, 10, 0), change(header, 10, 65), change(header, 11, 4), change(header, 12, 1),
                {2}, {2, 0, 0, 3, 4, 5, 6}, {2, 4, 0, 3, 1, 2, 3, 4, 5, 6},
                {2, 0, 3, 0, 1, 2, 3}, {2, 0, 3, 65, 1, 2, 3, 4, 5, 6}}) {
            byte[] sealed = malformed(key, bad, EXPIRY);
            assertThrows(WebAuthnRecordException.class, () -> codec.decodeRecord(key, sealed, CLOCK));
        }
        for (byte[] handle : new byte[][] {new byte[0], new byte[65]})
            assertThrows(IllegalArgumentException.class, () -> codec.encodeRevoked(ID, handle, NOW));
    }

    @Test void ceremonyPayloadRejectsEveryCountLengthAndCanonicalOrderViolation() throws Exception {
        var records = records(); var codec = new WebAuthnCeremonyRecordCodec("tenant", RP, records);
        var key = WebAuthnStoreKey.forCeremony("tenant", RP, RANDOM);
        byte[] valid = ceremonyPayload(ORIGIN, ORIGIN + ":443");
        assertEquals(Set.of(ORIGIN, ORIGIN + ":443"), codec.decode(key, malformed(key, valid, EXPIRY), CLOCK).allowedOrigins());
        byte[] originControl = valid.clone(); originControl[131] = 0x20;
        byte[] originHigh = valid.clone(); originHigh[131] = 0x7f;
        byte[] nanosNegative = valid.clone(); ByteBuffer.wrap(nanosNegative).putInt(107, -1);
        byte[] expired = valid.clone(); ByteBuffer.wrap(expired).putLong(111, NOW.getEpochSecond());
        byte[] hugeSeconds = valid.clone(); ByteBuffer.wrap(hugeSeconds).putLong(99, Long.MAX_VALUE);
        byte[] shortSecond = Arrays.copyOf(ceremonyPayload(ORIGIN), ceremonyPayload(ORIGIN).length + 1); shortSecond[125] = 2;
        for (byte[] bad : new byte[][] {new byte[125], new byte[2401], change(valid, 2, 4), change(valid, 123, 65),
                change(valid, 124, 129), change(valid, 125, 0), change(valid, 125, 9), change(valid, 125, 8),
                change(valid, 129, 1), change(valid, 130, 0), change(valid, 130, 255),
                ceremonyPayload(ORIGIN, ORIGIN), ceremonyPayload(ORIGIN + ":443", ORIGIN), originControl, originHigh,
                nanosNegative, expired, hugeSeconds, shortSecond}) {
            byte[] sealed = malformed(key, bad, EXPIRY);
            assertThrows(WebAuthnRecordException.class, () -> codec.decode(key, sealed, CLOCK));
        }
        byte[] purposeControl = ceremonyPayload(ORIGIN);
        purposeControl = concat(Arrays.copyOf(purposeControl, 129), concat(new byte[] {0x1f}, Arrays.copyOfRange(purposeControl, 129, purposeControl.length)));
        purposeControl[2] = 3; purposeControl[124] = 1;
        byte[] controlSealed = malformed(key, purposeControl, EXPIRY);
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(key, controlSealed, CLOCK));
        purposeControl[129] = 0x7f;
        byte[] highSealed = malformed(key, purposeControl, EXPIRY);
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(key, highSealed, CLOCK));
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(WebAuthnStoreKey.forCredential("tenant", RP, ID), new byte[] {1}, CLOCK));
    }

    @Test void coseKeyRejectsOversizeTrailingWrongCurveAndRsaParameterProfiles() throws Exception {
        byte[] x = Arrays.copyOfRange(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded(), 12, 44);
        byte[] key = edKey(x);
        assertEquals(-8, WebAuthnCoseKey.parse(key).algorithm());
        for (byte[] invalid : new byte[][] {new byte[1025], concat(key, new byte[] {0}), change(key, 0, 0xa5),
                change(key, 2, 2), change(key, 6, 5), change(key, 1, 2),
                rsaKey(new byte[255], new byte[] {1,0,1}), rsaKey(new byte[256], new byte[] {3}),
                rsaKey(new byte[256], new byte[] {1,0,1}),
                { (byte)0xa5, 1, 2, 3, 0x26, 0x20, 2, 0x21, 0x40, 0x22, 0x40 }})
            assertThrows(WebAuthnCborException.class, () -> WebAuthnCoseKey.parse(invalid));
        assertThrows(WebAuthnCborException.class, () -> WebAuthnCredentialState.checked(ID,HANDLE,key,-8,-1,false,false));
        var state = WebAuthnCredentialState.checked(ID,HANDLE,key,-8,0,false,false);
        assertEquals(0, state.counter());
    }

    private static byte @NonNull [] ceremonyPayload(@NonNull String @NonNull ... origins) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(126).put((byte)1).put((byte)0).put((byte)1)
                .put(RANDOM).put(RANDOM).put(RANDOM).putLong(NOW.getEpochSecond()).putInt(0)
                .putLong(EXPIRY.getEpochSecond()).putInt(0).put((byte)HANDLE.length).put((byte)0).put((byte)origins.length).array());
        out.writeBytes(HANDLE);
        for(String origin:origins){byte[] ascii=origin.getBytes(StandardCharsets.US_ASCII);out.write(ascii.length>>>8);out.write(ascii.length);out.writeBytes(ascii);}
        return out.toByteArray();
    }
    private static byte @NonNull [] edKey(byte @NonNull [] x) {
        ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes(new byte[] {(byte)0xa4,1,1,3,0x27,0x20,6,0x21});bytes(out,x);return out.toByteArray();
    }
    private static byte @NonNull [] rsaKey(byte @NonNull [] modulus,byte @NonNull [] exponent) {
        ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes(new byte[] {(byte)0xa4,1,3,3,0x39,1,0,0x20});bytes(out,modulus);out.write(0x21);bytes(out,exponent);return out.toByteArray();
    }

    private static @NonNull WebAuthnCeremonyState state(byte @NonNull [] id, byte @NonNull [] challenge,
            byte @NonNull [] binding, @NonNull Set<@NonNull String> origins, byte @org.jspecify.annotations.Nullable [] handle,
            @org.jspecify.annotations.Nullable String purpose, @NonNull Instant issued, @NonNull Instant expires, boolean consumed) {
        return WebAuthnCeremonyState.restored(WebAuthnCeremonyState.Kind.REGISTRATION, id, challenge, binding, origins, handle, purpose, issued, expires, consumed);
    }
    private static @NonNull WebAuthnRecordCodec records() {
        return new WebAuthnRecordCodec(StateSealer.withActiveKey(SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(sealingMaterial()))).clock(CLOCK).build());
    }
    private static byte @NonNull [] sealingMaterial() {
        byte[] value = new byte[32]; for (int i = 0; i < 32; i++) value[i] = (byte) (i + 1); return value;
    }
    private static byte @NonNull [] change(byte @NonNull [] value, int offset, int replacement) {
        byte[] copy = value.clone(); copy[offset] = (byte) replacement; return copy;
    }
    private static byte @NonNull [] filled(int length, int value) {
        byte[] result = new byte[length]; Arrays.fill(result, (byte) value); return result;
    }
    private static byte @NonNull [] concat(byte @NonNull [] left, byte @NonNull [] right) {
        byte[] value = Arrays.copyOf(left, left.length + right.length); System.arraycopy(right, 0, value, left.length, right.length); return value;
    }
    private static byte @NonNull [] der(byte @NonNull [] r, byte @NonNull [] s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.write(0x30); out.write(4 + r.length + s.length);
        out.write(2); out.write(r.length); out.writeBytes(r); out.write(2); out.write(s.length); out.writeBytes(s); return out.toByteArray();
    }
    private static byte @NonNull [] indexPayload(byte @NonNull [] handle, byte @NonNull [] @NonNull ... ids) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.write(1); out.write(handle.length); out.write(ids.length); out.writeBytes(handle);
        for (byte[] id : ids) { out.write(id.length >>> 8); out.write(id.length); out.writeBytes(id); } return out.toByteArray();
    }
    private static byte @NonNull [] noneMembers(@NonNull String first, @NonNull String second, @NonNull String third) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.write(0xa3);
        for (String name : List.of(first, second, third)) {
            text(out, name);
            if (name.equals("fmt")) text(out, "none"); else if (name.equals("attStmt")) out.write(0xa0); else bytes(out, new byte[37]);
        } return out.toByteArray();
    }
    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0); return out.toByteArray();
    }
    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] ascii = value.getBytes(StandardCharsets.US_ASCII); out.write(0x60 | ascii.length); out.writeBytes(ascii);
    }
    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length); else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); } out.writeBytes(value);
    }



    private static byte @NonNull [] malformed(@NonNull WebAuthnStoreKey key,byte @NonNull [] inner,@NonNull Instant expires){
        return WebAuthnTestPayloads.seal(key,inner,expires,NOW);
    }

}
