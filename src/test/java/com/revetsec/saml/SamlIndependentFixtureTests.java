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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/** Replays expired, independently minted libxmlsec1 and signxml fixtures offline. */
final class SamlIndependentFixtureTests {
    private static final @NonNull String ROOT = "/fixtures/saml-independent/";
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";

    @Test void libxmlsecAndSignxmlAcceptedFixtures() throws Exception {
        SamlServiceProvider sp = serviceProvider();
        for (String name : List.of("case1-response-assertion-rsa-sha256",
                "case3-assertion-ecdsa-p256", "case3-assertion-ecdsa-p384",
                "case3-assertion-ecdsa-p521", "case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256",
                "case6-encrypted-id-gcm-rsa-oaep-sha256-mgf1sha256",
                "extra-signxml-assertion-rsa-sha256")) {
            String cert = name.contains("p256") ? "idp-ec-p256.crt"
                    : name.contains("p384") ? "idp-ec-p384.crt"
                    : name.contains("p521") ? "idp-ec-p521.crt" : "idp-rsa-2048.crt";
            SamlAuthenticationResult result = sp.completeUnsolicitedAuthenticationResult(
                    message(name), identityProvider(cert));
            SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class, result, name + ": " + result);
            assertEquals("independent-fixture", success.getAuthentication().getIdentityProviderConnectionId());
        }
    }

    @Test void independentlyMintedSha1AndRsa15RemainRejected() throws Exception {
        SamlServiceProvider sp = serviceProvider();
        SamlAuthenticationResult sha1 = sp.completeUnsolicitedAuthenticationResult(
                message("case2-assertion-rsa-sha1"), identityProvider("idp-rsa-2048.crt"));
        assertEquals(SamlAuthenticationResult.Reason.SIGNATURE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class, sha1).getReason());
        SamlAuthenticationResult allowedSha1 = sp.completeUnsolicitedAuthenticationResult(
                message("case2-assertion-rsa-sha1"), identityProvider("idp-rsa-2048.crt", true));
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class, allowedSha1,
                allowedSha1.toString());
        SamlAuthenticationResult rsa15 = sp.completeUnsolicitedAuthenticationResult(
                message("case5-encrypted-assertion-gcm-rsa-1_5"),
                identityProvider("idp-rsa-2048.crt"));
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class, rsa15).getReason());
    }

    private static @NonNull SamlServiceProvider serviceProvider() throws Exception {
        SamlCredential credential = SamlCredential.fromPem(
                resource("keys/sp-rsa-2048.key"), resource("keys/sp-rsa-2048.crt"));
        return SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .decryptionCredentials(List.of(credential)).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull String certificate)
            throws Exception {
        return identityProvider(certificate, false);
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull String certificate,
            boolean sha1) throws Exception {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("independent-fixture")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(resource("keys/" + certificate)).getPublicKey()))
                .allowUnsolicitedResponses(true)
                .compatibility(sha1 ? Set.of(SamlCompatibilityMode.SHA1_SIGNATURES) : Set.of()).build();
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String name) throws Exception {
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                bytes(name + ".xml")), StandardCharsets.UTF_8);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        return new String(bytes(name), StandardCharsets.US_ASCII);
    }

    private static byte @NonNull [] bytes(@NonNull String name) throws IOException {
        try (var input = SamlIndependentFixtureTests.class.getResourceAsStream(ROOT + name)) {
            return java.util.Objects.requireNonNull(input).readAllBytes();
        }
    }
}
