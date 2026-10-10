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

import com.revetsec.internal.pem.Pem;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/** Offline replay of fixed-key, on-demand scripted-IdP output. */
final class SamlScriptedMintedFixtureTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";

    @Test void signedAndEncryptedMatrixCompletes() throws Exception {
        for (String name : List.of("response-rsa256", "both-rsa384",
                "assertion-rsa512-encrypted", "assertion-ec256-encrypted-id",
                "assertion-ec384", "assertion-ec521", "assertion-signxml",
                "encrypted-aes128-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes128-gcm-rsa-oaep-mgf1p",
                "encrypted-aes192-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes192-gcm-rsa-oaep-mgf1p",
                "encrypted-aes256-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes256-gcm-rsa-oaep-mgf1p")) {
            String cert = name.contains("rsa384") || name.contains("rsa512")
                    ? "idp-signing-rsa-3072-cert.pem"
                    : name.contains("ec256") ? "idp-signing-ec-p256-cert.pem"
                    : name.contains("ec384") ? "idp-signing-ec-p384-cert.pem"
                    : name.contains("ec521") ? "idp-signing-ec-p521-cert.pem"
                    : "idp-signing-rsa-2048-cert.pem";
            SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider(cert, false));
            SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class, result, name + ": " + result);
            assertEquals("scripted-mint", success.getAuthentication().getIdentityProviderConnectionId());
        }
    }

    @Test void everySupportedSignatureAndDigestPairAtEachCoveragePlacementCompletes() throws Exception {
        for (String placement : List.of("response", "assertion", "both")) {
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512")) {
                String certificate = algorithm.startsWith("rsa-")
                        ? algorithm.equals("rsa-sha256") ? "idp-signing-rsa-2048-cert.pem"
                                : "idp-signing-rsa-3072-cert.pem"
                        : algorithm.equals("ecdsa-sha256") ? "idp-signing-ec-p256-cert.pem"
                        : algorithm.equals("ecdsa-sha384") ? "idp-signing-ec-p384-cert.pem"
                                : "idp-signing-ec-p521-cert.pem";
                for (String digest : List.of("sha256", "sha384", "sha512")) {
                    String name = "matrix-" + placement + "-" + algorithm + "-" + digest;
                    SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                            message(name), identityProvider(certificate, false));
                    assertInstanceOf(SamlAuthenticationResult.Succeeded.class, result,
                            name + ": " + result);
                }
            }
        }
    }

    @Test void oaepDigestMgfAndGcmMatrixCompletesAtEveryCoveragePlacement() throws Exception {
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm")) {
            for (String transport : List.of("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                    "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1")) {
                for (String placement : List.of("response", "assertion", "both")) {
                    String name = "oaep-" + data + "-" + transport + "-" + placement;
                    SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                            message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false));
                    SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                            SamlAuthenticationResult.Succeeded.class, result, name + ": " + result);
                    assertEquals(true, success.getAuthentication().isAssertionEncrypted(), name);
                    assertEquals(!placement.equals("assertion"),
                            success.getAuthentication().isResponseSigned(), name);
                    assertEquals(!placement.equals("response"),
                            success.getAuthentication().isAssertionSigned(), name);
                }
            }
        }
    }

    @Test void siblingKeyPlacementAndMultipleCandidatesComplete() throws Exception {
        for (String name : List.of("key-sibling-retrieval", "key-sibling-implicit",
                "key-sibling-implicit-multi", "encrypted-id-sibling-retrieval",
                "encrypted-id-sibling-implicit")) {
            SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false));
            SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class, result, name + ": " + result);
            assertEquals("minted-user", success.getAuthentication().getNameId().orElseThrow().getValue(), name);
            assertEquals(name.startsWith("key-"), success.getAuthentication().isAssertionEncrypted(), name);
        }
    }

    @Test void signedEncryptionNegativesFailAtDecryptionBoundary() throws Exception {
        for (String name : List.of("negative-rsa-1_5", "negative-mgf-under-mgf1p",
                "negative-nonempty-oaep-params", "negative-cipher-bit-flip")) {
            SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false));
            assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, result,
                            name + ": " + result).getReason(), name);
        }
    }

    @Test void unsignedAndSha1DefaultAreRejected() throws Exception {
        for (String name : List.of("unsigned", "unsigned-encrypted", "assertion-rsa-sha1",
                "digest-rsa256-sha1")) {
            SamlAuthenticationResult result = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false));
            assertInstanceOf(SamlAuthenticationResult.Rejected.class, result, name + ": " + result);
        }
        SamlAuthenticationResult allowed = provider().completeUnsolicitedAuthenticationResult(
                message("assertion-rsa-sha1"),
                identityProvider("idp-signing-rsa-2048-cert.pem", true));
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class, allowed, allowed.toString());
        SamlAuthenticationResult allowedDigest = provider().completeUnsolicitedAuthenticationResult(
                message("digest-rsa256-sha1"),
                identityProvider("idp-signing-rsa-2048-cert.pem", true));
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                allowedDigest, allowedDigest.toString());
    }

    @Test void cbcNeedsOptInAndVerifiedResponseSignature() throws Exception {
        for (String data : List.of("aes128-cbc", "aes192-cbc", "aes256-cbc")) {
            String name = "encrypted-" + data + "-response";
            SamlAuthenticationResult defaultResult = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false));
            assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, defaultResult).getReason());
            SamlAuthenticationResult allowed = provider().completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider("idp-signing-rsa-2048-cert.pem", false, true));
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class, allowed, name + ": " + allowed);
        }
        SamlAuthenticationResult unsignedResponse = provider().completeUnsolicitedAuthenticationResult(
                message("encrypted-aes128-cbc-assertion"),
                identityProvider("idp-signing-rsa-2048-cert.pem", false, true));
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class, unsignedResponse).getReason());
    }

    private static @NonNull SamlServiceProvider provider() throws Exception {
        SamlCredential credential = SamlCredential.fromPem(
                resource("keys/sp-encryption-rsa-2048-key.pem"),
                resource("keys/sp-encryption-rsa-2048-cert.pem"));
        return SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .decryptionCredentials(List.of(credential)).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull String certificate,
            boolean sha1) throws Exception {
        return identityProvider(certificate, sha1, false);
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull String certificate,
            boolean sha1, boolean cbc) throws Exception {
        EnumSet<SamlCompatibilityMode> modes = EnumSet.of(
                SamlCompatibilityMode.UNSOLICITED_RESPONSES);
        if (sha1) modes.add(SamlCompatibilityMode.SHA1_SIGNATURES);
        if (cbc) modes.add(SamlCompatibilityMode.AES_CBC_ENCRYPTION);
        return SamlIdentityProvider.withEntityId(IDP).connectionId("scripted-mint")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(resource("keys/" + certificate)).getPublicKey()))
                .compatibility(Set.copyOf(modes)).build();
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String name) throws Exception {
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                bytes("scripted-idp/" + name + ".xml")), StandardCharsets.UTF_8);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        return new String(bytes(name), StandardCharsets.US_ASCII);
    }

    private static byte @NonNull [] bytes(@NonNull String name) throws IOException {
        try (var input = SamlScriptedMintedFixtureTests.class.getResourceAsStream("/fixtures/" + name)) {
            return java.util.Objects.requireNonNull(input).readAllBytes();
        }
    }
}
