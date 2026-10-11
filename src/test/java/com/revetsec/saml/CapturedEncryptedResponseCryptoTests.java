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

import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.XmlEncryptionDecryptor;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Actual IdP ciphertexts exercise the decryptor independently of their outer XML signatures. */
final class CapturedEncryptedResponseCryptoTests {
    private static final @NonNull Path FIXTURES = Path.of("src/test/resources/fixtures");
    private static final @NonNull Path KEYS = FIXTURES.resolve("keys");
    private static final @NonNull Set<@NonNull String> DETERMINISTIC_CBC_FAILURES = Set.of(
            "data-truncated", "duplicate-wrapped-key-cipher", "duplicate-data-cipher",
            "empty-wrapped-key-cipher", "empty-data-cipher", "rsa-v1-5-key-transport",
            "wrong-aes-key-length", "wrong-aes-mode");

    @Test void realProviderCiphertextsKeepEncryptionAndSignatureBoundariesSeparate() throws Exception {
        PrivateKey key = SamlCredential.fromPem(
                Files.readString(KEYS.resolve("sp-encryption-rsa-2048-key.pem")),
                Files.readString(KEYS.resolve("sp-encryption-rsa-2048-cert.pem"))).privateKey();
        for (String fixture : List.of("shibboleth/gcm-response.xml",
                "shibboleth/cbc-response.xml",
                "simplesamlphp/cbc-response-signed-response.xml")) {
            String xml = Files.readString(FIXTURES.resolve(fixture));
            boolean cbc = fixture.contains("cbc");
            Element encrypted = encryptedAssertion(xml);
            byte[] baseline = XmlEncryptionDecryptor.decrypt(encrypted, List.of(key),
                    true, true, rejectionRandom());
            assertNotNull(baseline, fixture + " baseline decrypts");
            try {
                Element assertion = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                        SecureXmlParser.parseResponse(baseline), fixture)
                        .getDocument().getDocumentElement();
                assertEquals("urn:oasis:names:tc:SAML:2.0:assertion", assertion.getNamespaceURI(), fixture);
                assertEquals("Assertion", assertion.getLocalName(), fixture);
                if (cbc) {
                    assertNull(XmlEncryptionDecryptor.decrypt(encrypted, List.of(key), false, true,
                            rejectionRandom()), fixture + " CBC requires a signed Response");
                    assertNull(XmlEncryptionDecryptor.decrypt(encrypted, List.of(key), true, false,
                            rejectionRandom()), fixture + " CBC requires explicit IdP opt-in");
                }
                for (CapturedEncryptedResponseMutations.Mutation mutation :
                        CapturedEncryptedResponseMutations.cryptographicFrom(xml)) {
                    String label = fixture + ":" + mutation.name();
                    assertNotEquals(xml, mutation.xml(), label + " must alter the capture");
                    byte[] changed = XmlEncryptionDecryptor.decrypt(encryptedAssertion(mutation.xml()),
                            List.of(key), true, true, rejectionRandom());
                    try {
                        if (!cbc || DETERMINISTIC_CBC_FAILURES.contains(mutation.name()))
                            assertNull(changed, label);
                        else if (changed != null)
                            assertFalse(Arrays.equals(baseline, changed), label
                                    + " CBC plaintext has no intrinsic integrity guarantee");
                    } finally {
                        if (changed != null) Arrays.fill(changed, (byte) 0);
                    }
                }
            } finally { Arrays.fill(baseline, (byte) 0); }
        }
    }

    private static @NonNull Element encryptedAssertion(@NonNull String xml) {
        var parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)));
        var carriers = parsed.getDocument().getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion");
        assertEquals(1, carriers.getLength(), "one encrypted assertion carrier");
        return assertInstanceOf(Element.class, carriers.item(0));
    }

    private static @NonNull SecureRandom rejectionRandom() {
        // A fixed substitute CEK keeps CBC's unauthenticated failure path reproducible.
        return new SecureRandom() {
            @Override public void nextBytes(byte @NonNull [] bytes) {
                Arrays.fill(bytes, (byte) 0xa5);
            }
        };
    }
}
