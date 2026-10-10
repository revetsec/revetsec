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

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/** Structured browser-data and CBOR fuzz checks for the initial WebAuthn profile.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class WebAuthnFuzzTests {
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    /** Gate 25: a none-attestation carrier is exact, bounded, copied and never a proof. */
    @FuzzTest(maxDuration = "5m")
    public void noneAttestationAcceptsOnlyTheExactBoundedCarrier(byte @NonNull [] input) throws Exception {
        if (input.length <= WebAuthnNoneAttestation.MAXIMUM_INPUT_BYTES) {
            try {
                WebAuthnNoneAttestation.Parsed parsed = WebAuthnNoneAttestation.parse(input);
                int length = parsed.getAuthenticatorData().length;
                Assertions.assertTrue(length >= WebAuthnNoneAttestation.MINIMUM_AUTHENTICATOR_DATA_BYTES
                        && length <= WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES);
            } catch (WebAuthnCborException rejected) {
                fixed(rejected);
            }
        } else {
            fixed(Assertions.assertThrows(WebAuthnCborException.class,
                    () -> WebAuthnNoneAttestation.parse(input)));
        }

        int length = 37 + (unsigned(input, 0) * 256 + unsigned(input, 1)) % 512;
        byte[] data = new byte[length];
        for (int i = 0; i < data.length; i++) data[i] = (byte) unsigned(input, i + 2);
        byte[] carrier = carrier(data, false);
        WebAuthnNoneAttestation.Parsed accepted = WebAuthnNoneAttestation.parse(carrier);
        Assertions.assertArrayEquals(data, accepted.getAuthenticatorData());
        Assertions.assertArrayEquals(data,
                WebAuthnNoneAttestation.parse(carrier(data, true)).getAuthenticatorData());
        byte first = data[0];
        data[0] ^= 1;
        carrier[data.length < 256 ? 21 : 22] ^= 1;
        Assertions.assertEquals(first, accepted.getAuthenticatorData()[0]);
        byte[] released = accepted.getAuthenticatorData();
        released[0] ^= 1;
        Assertions.assertEquals(first, accepted.getAuthenticatorData()[0]);

        List<byte[]> invalid = new ArrayList<>();
        byte[] valid = carrier(data, false);
        byte[] missingMember = valid.clone(); missingMember[0] = (byte) 0xa2;
        invalid.add(missingMember);
        byte[] nonminimalCount = new byte[valid.length + 1];
        nonminimalCount[0] = (byte) 0xb8; nonminimalCount[1] = 3;
        System.arraycopy(valid, 1, nonminimalCount, 2, valid.length - 1);
        invalid.add(nonminimalCount);
        byte[] indefiniteCount = valid.clone(); indefiniteCount[0] = (byte) 0xbf;
        invalid.add(indefiniteCount);
        byte[] nonemptyStatement = valid.clone();
        nonemptyStatement[nonemptyStatement.length - 1] = (byte) 0xa1;
        invalid.add(nonemptyStatement);
        invalid.add(Arrays.copyOf(valid, valid.length - 1));
        invalid.add(Arrays.copyOf(valid, valid.length + 1));
        for (byte[] value : invalid)
            fixed(Assertions.assertThrows(WebAuthnCborException.class,
                    () -> WebAuthnNoneAttestation.parse(value)));
    }

    /** Gate 25: origin, type, challenge and cross-origin binding survive arbitrary challenge bytes. */
    @FuzzTest(maxDuration = "5m")
    public void clientDataBindsTheExactBrowserContext(byte @NonNull [] input) throws Exception {
        WebAuthnClientData policy = new WebAuthnClientData(RP, Set.of(ORIGIN),
                WebAuthnClientData.DEFAULT_MAXIMUM_BYTES);
        byte[] challenge = MessageDigest.getInstance("SHA-256")
                .digest(Arrays.copyOf(input, Math.min(input.length, 512)));
        String encoded = URL.encodeToString(challenge);
        for (WebAuthnClientData.Ceremony ceremony : WebAuthnClientData.Ceremony.values()) {
            String wireType = ceremony == WebAuthnClientData.Ceremony.REGISTRATION
                    ? "webauthn.create" : "webauthn.get";
            String valid = "{\"challenge\":\"" + encoded + "\",\"origin\":\"" + ORIGIN
                    + "\",\"type\":\"" + wireType + "\",\"crossOrigin\":false}";
            policy.verify(valid.getBytes(StandardCharsets.US_ASCII), ceremony, challenge);
            List<String> altered = List.of(
                    valid.replace(wireType, "webauthn.other"),
                    valid.replace(ORIGIN, "https://evil.example.com"),
                    valid.replace(encoded, URL.encodeToString(flipped(challenge, unsigned(input, 3) % 32))),
                    valid.replace("false", "true"),
                    valid.substring(0, valid.length() - 1) + ",\"topOrigin\":\"" + ORIGIN + "\"}",
                    valid.substring(0, valid.length() - 1) + ",\"\\u0074ype\":\"" + wireType + "\"}");
            for (String candidate : altered)
                fixed(Assertions.assertThrows(WebAuthnClientDataException.class,
                        () -> policy.verify(candidate.getBytes(StandardCharsets.US_ASCII),
                                ceremony, challenge)));
            try {
                policy.verify(input, ceremony, challenge);
            } catch (WebAuthnClientDataException rejected) {
                fixed(rejected);
            }
        }
    }

    private static byte @NonNull [] carrier(byte @NonNull [] data, boolean reversed) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3);
        if (reversed) {
            text(out, "attStmt"); out.write(0xa0);
            text(out, "authData"); bytes(out, data);
            text(out, "fmt"); text(out, "none");
        } else {
            text(out, "fmt"); text(out, "none");
            text(out, "authData"); bytes(out, data);
            text(out, "attStmt"); out.write(0xa0);
        }
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length);
        out.writeBytes(bytes);
    }

    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }

    private static int unsigned(byte @NonNull [] input, int position) {
        return position < input.length ? input[position] & 0xff : 0;
    }

    private static byte @NonNull [] flipped(byte @NonNull [] original, int position) {
        byte[] changed = original.clone();
        changed[position] ^= 1;
        return changed;
    }

    private static void fixed(@NonNull Exception rejected) {
        Assertions.assertNull(rejected.getCause());
        Assertions.assertEquals(0, rejected.getSuppressed().length);
        Assertions.assertEquals(0, rejected.getStackTrace().length);
        Assertions.assertTrue(rejected.getMessage().startsWith("WebAuthn "));
    }
}
