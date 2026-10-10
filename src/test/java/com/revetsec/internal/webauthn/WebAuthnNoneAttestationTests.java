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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnNoneAttestationTests {
    @Test void acceptsOrderVariationAndCopiesUnverifiedData() throws WebAuthnCborException {
        byte[] data = new byte[37];
        data[0] = 42;
        byte[] input = object(data, true);
        var parsed = WebAuthnNoneAttestation.parse(input);
        data[0] = 0;
        input[20] = 0;
        assertEquals(42, parsed.getAuthenticatorData()[0]);
        byte[] released = parsed.getAuthenticatorData();
        released[0] = 1;
        assertEquals(42, parsed.getAuthenticatorData()[0]);
        assertEquals("WebAuthnNoneAttestation.Parsed{<unverified>}", parsed.toString());
    }

    @Test void acceptsMaximumDefaultAuthenticatorDataWithoutTreatingItAsAProof() throws WebAuthnCborException {
        byte[] data = new byte[WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES];
        data[0] = 7;
        assertArrayEquals(data, WebAuthnNoneAttestation.parse(object(data, false)).getAuthenticatorData());
    }

    @Test void configuredCapCanAdmitLargerBoundedCarrierWhileDefaultRejectsIt() throws Exception {
        byte[] data = new byte[WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES + 1];
        byte[] encoded = object(data, false);
        rejected(encoded);
        assertArrayEquals(data, WebAuthnNoneAttestation.parse(encoded, 64 * 1_024,
                32 * 1_024).getAuthenticatorData());
        assertThrows(WebAuthnCborException.class, () -> WebAuthnNoneAttestation.parse(
                encoded, encoded.length - 1, 32 * 1_024));
        assertThrows(WebAuthnCborException.class, () -> WebAuthnNoneAttestation.parse(
                encoded, 64 * 1_024, data.length - 1));
    }

    @Test void rejectsDuplicateUnknownAndNonemptyAttestationStatements() {
        ByteArrayOutputStream duplicate = new ByteArrayOutputStream();
        duplicate.write(0xa3);
        text(duplicate, "fmt"); text(duplicate, "none");
        text(duplicate, "fmt"); text(duplicate, "none");
        text(duplicate, "attStmt"); duplicate.write(0xa0);
        rejected(duplicate.toByteArray());

        ByteArrayOutputStream unknown = new ByteArrayOutputStream();
        unknown.write(0xa3);
        text(unknown, "fmt"); text(unknown, "none");
        text(unknown, "authData"); bytes(unknown, new byte[37]);
        text(unknown, "other"); unknown.write(0xa0);
        rejected(unknown.toByteArray());

        byte[] nonempty = object(new byte[37], false);
        nonempty[nonempty.length - 1] = (byte) 0xa1;
        rejected(nonempty);
    }

    @Test void rejectsIndefiniteNonminimalTruncatedAndTrailingCbor() {
        byte[] valid = object(new byte[37], false);
        byte[] indefinite = valid.clone();
        indefinite[0] = (byte) 0xbf;
        rejected(indefinite);
        byte[] nonminimal = new byte[valid.length + 1];
        nonminimal[0] = (byte) 0xb8;
        nonminimal[1] = 3;
        System.arraycopy(valid, 1, nonminimal, 2, valid.length - 1);
        rejected(nonminimal);
        rejected(Arrays.copyOf(valid, valid.length - 1));
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        rejected(trailing);
        byte[] tagged = new byte[valid.length + 1];
        tagged[0] = (byte) 0xc0;
        System.arraycopy(valid, 0, tagged, 1, valid.length);
        rejected(tagged);
    }

    @Test void rejectsUnsupportedFormatAndBinaryBounds() {
        ByteArrayOutputStream packed = new ByteArrayOutputStream();
        packed.write(0xa3);
        text(packed, "fmt"); text(packed, "packed");
        text(packed, "authData"); bytes(packed, new byte[37]);
        text(packed, "attStmt"); packed.write(0xa0);
        rejected(packed.toByteArray());
        rejected(object(new byte[36], false));
        rejected(object(new byte[WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES + 1], false));
        rejected(new byte[WebAuthnNoneAttestation.MAXIMUM_INPUT_BYTES + 1]);
    }

    @Test void rejectsNonAsciiNamesAndWrongValueTypes() {
        byte[] badName = object(new byte[37], false);
        badName[2] = (byte) 0xff;
        rejected(badName);
        byte[] wrongType = object(new byte[37], false);
        wrongType[5] = 0x44;
        rejected(wrongType);
    }

    private static void rejected(byte @NonNull [] input) {
        var failure = assertThrows(WebAuthnCborException.class, () -> WebAuthnNoneAttestation.parse(input));
        assertEquals("WebAuthn binary input rejected.", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
        assertEquals(0, failure.getStackTrace().length);
    }

    private static byte @NonNull [] object(byte @NonNull [] data, boolean reversed) {
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
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        assertTrue(encoded.length < 24);
        out.write(0x60 | encoded.length);
        out.writeBytes(encoded);
    }

    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) {out.write(0x58); out.write(value.length);}
        else {out.write(0x59); out.write(value.length >>> 8); out.write(value.length);}
        out.writeBytes(value);
    }
}
