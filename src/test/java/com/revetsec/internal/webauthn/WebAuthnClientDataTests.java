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

import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

final class WebAuthnClientDataTests {
    private static final byte[] CHALLENGE = new byte[32];
    private static final String ENCODED_CHALLENGE = Base64Url.encode(CHALLENGE);
    private static final String ORIGIN = "https://login.example.com";

    @Test
    void acceptsBothCeremoniesReorderedMembersAndBoundedFutureFields() throws Exception {
        WebAuthnClientData verifier = policy();
        verifier.verify(json("{\"type\":\"webauthn.create\",\"challenge\":\"" + ENCODED_CHALLENGE
                + "\",\"origin\":\"" + ORIGIN + "\"}"), WebAuthnClientData.Ceremony.REGISTRATION, CHALLENGE);
        verifier.verify(json("{\"unknown\":{\"nested\":[1,true]},\"crossOrigin\":false,\"origin\":\""
                + ORIGIN + "\",\"challenge\":\"" + ENCODED_CHALLENGE + "\",\"type\":\"webauthn.get\"}"),
                WebAuthnClientData.Ceremony.AUTHENTICATION, CHALLENGE);
        verifier.verify(json("{\"\\u0074ype\":\"webauthn.get\",\"challenge\":\"" + ENCODED_CHALLENGE
                + "\",\"origin\":\"" + ORIGIN + "\"}"), WebAuthnClientData.Ceremony.AUTHENTICATION,
                CHALLENGE);
    }

    @Test
    void rejectsMalformedJsonAndAmbiguousMembers() {
        String valid = document("webauthn.get", ENCODED_CHALLENGE, ORIGIN);
        for (String candidate : new String[]{"[]", "null", "{}", valid + "{}", valid + "x",
                "{\"type\":\"webauthn.get\",\"\\u0074ype\":\"webauthn.get\",\"challenge\":\""
                        + ENCODED_CHALLENGE + "\",\"origin\":\"" + ORIGIN + "\"}",
                "{\"type\":1,\"challenge\":\"" + ENCODED_CHALLENGE + "\",\"origin\":\"" + ORIGIN + "\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"" + ENCODED_CHALLENGE + "\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"" + ENCODED_CHALLENGE
                        + "\",\"origin\":null}"}) {
            rejects(json(candidate));
        }
        byte[] malformedUtf8 = json(valid);
        malformedUtf8[malformedUtf8.length - 2] = (byte) 0xc0;
        rejects(malformedUtf8);
        rejects(new byte[]{(byte) 0xef, (byte) 0xbb, (byte) 0xbf, '{', '}'});
        rejects(new byte[8_193]);
    }

    @Test
    void rejectsWrongTypeAndChallengeForms() {
        rejects(json(document("webauthn.create", ENCODED_CHALLENGE, ORIGIN)));
        rejects(json(document("webauthn.get", ENCODED_CHALLENGE + "=", ORIGIN)));
        rejects(json(document("webauthn.get", ENCODED_CHALLENGE.substring(0, 42) + "B", ORIGIN)));
        rejects(json(document("webauthn.get", Base64Url.encode(new byte[31]), ORIGIN)));
        rejects(json(document("webauthn.get", Base64Url.encode(new byte[33]), ORIGIN)));
        byte[] otherChallenge = CHALLENGE.clone();
        otherChallenge[0] = 1;
        rejects(json(document("webauthn.get", Base64Url.encode(otherChallenge), ORIGIN)));
        Assertions.assertThrows(IllegalArgumentException.class, () -> policy().verify(
                json(document("webauthn.get", ENCODED_CHALLENGE, ORIGIN)),
                WebAuthnClientData.Ceremony.AUTHENTICATION, new byte[31]));
    }

    @Test
    void rejectsUntrustedAndCrossOriginContext() {
        for (String origin : new String[]{"http://login.example.com", "https://sub.login.example.com",
                "https://login.example.com:443", "https://login.example.com/", "https://LOGIN.example.com",
                "https://login.example.com.", "https://login.example.com@evil.example.com"}) {
            rejects(json(document("webauthn.get", ENCODED_CHALLENGE, origin)));
        }
        String base = document("webauthn.get", ENCODED_CHALLENGE, ORIGIN);
        for (String extra : new String[]{"\"crossOrigin\":true", "\"crossOrigin\":null",
                "\"crossOrigin\":\"false\"", "\"topOrigin\":\"https://login.example.com\"",
                "\"topOrigin\":null"}) {
            rejects(json(base.substring(0, base.length() - 1) + "," + extra + "}"));
        }
    }

    @Test
    void validatesAndSnapshotsTrustedOriginConfiguration() throws Exception {
        Set<String> origins = new HashSet<>(Set.of(ORIGIN, ORIGIN + ":8443"));
        WebAuthnClientData verifier = new WebAuthnClientData("login.example.com", origins, 16_384);
        origins.clear();
        verifier.verify(json(document("webauthn.get", ENCODED_CHALLENGE, ORIGIN + ":8443")),
                WebAuthnClientData.Ceremony.AUTHENTICATION, CHALLENGE);
        for (String bad : new String[]{"http://login.example.com", "HTTPS://login.example.com",
                "https://LOGIN.example.com", "https://sub.login.example.com", "https://login.example.com/",
                "https://login.example.com?", "https://login.example.com#fragment",
                "https://user@login.example.com", "https://login.example.com:",
                "https://login.example.com:0", "https://login.example.com:65536",
                "https://login.example.com:0443", "https://login.example.com%2e"}) {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new WebAuthnClientData("login.example.com", Set.of(bad), 8_192), bad);
        }
        for (String bad : new String[]{"localhost", "127.0.0.1", "Login.example.com", "login.example.com.",
                "*.example.com", "-login.example.com", "login..com", "login_example.com"}) {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new WebAuthnClientData(bad, Set.of(ORIGIN), 8_192), bad);
        }
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new WebAuthnClientData("login.example.com", Set.of(), 8_192));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new WebAuthnClientData("login.example.com", Set.of(ORIGIN), 16_385));
    }

    @Test
    void rejectionDoesNotExposeInput() {
        WebAuthnClientDataException rejection = Assertions.assertThrows(WebAuthnClientDataException.class,
                () -> policy().verify(json(document("webauthn.get", ENCODED_CHALLENGE,
                        "https://secret.example.com")), WebAuthnClientData.Ceremony.AUTHENTICATION, CHALLENGE));
        Assertions.assertEquals("WebAuthn client data rejected.", rejection.getMessage());
        Assertions.assertNull(rejection.getCause());
        Assertions.assertEquals(0, rejection.getStackTrace().length);
    }

    private static @NonNull WebAuthnClientData policy() {
        return new WebAuthnClientData("login.example.com", Set.of(ORIGIN), 8_192);
    }

    private static void rejects(byte @NonNull [] clientDataJson) {
        Assertions.assertThrows(WebAuthnClientDataException.class,
                () -> policy().verify(clientDataJson, WebAuthnClientData.Ceremony.AUTHENTICATION, CHALLENGE));
    }

    private static @NonNull String document(@NonNull String type, @NonNull String challenge, @NonNull String origin) {
        return "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin + "\"}";
    }

    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
