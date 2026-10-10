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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.fail;

/** Wrapping and identity mutations across the independently signed RSA/ECDSA fixture matrix. */
final class SamlXswMutationTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull Pattern SIGNATURE = Pattern.compile(
            "<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL);

    @Test void wrappingAndIdentityInjectionsNeverReleaseAttackerFields() throws Exception {
        List<String> seeds = new ArrayList<>(List.of(
                "assertion-signxml", "assertion-ec384", "assertion-rsa-sha1"));
        for (String placement : List.of("response", "assertion", "both"))
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"))
                for (String digest : List.of("sha256", "sha384", "sha512"))
                    seeds.add("matrix-" + placement + "-" + algorithm + "-" + digest);
        for (String name : seeds) {
            boolean sha1 = name.endsWith("sha1");
            String certificate = certificateFor(name);
            String original = resource("scripted-idp/" + name + ".xml");
            SamlAuthentication baseline = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    check(original, certificate, sha1)).getAuthentication();
            String assertion = section(original, "<saml:Assertion ", "</saml:Assertion>");
            String attacker = SIGNATURE.matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace("_mint_assertion_", "_attacker_assertion_");
            String duplicateId = SIGNATURE.matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user");
            java.util.regex.Matcher signatureMatch = SIGNATURE.matcher(original);
            if (!signatureMatch.find()) throw new IllegalArgumentException("fixture signature missing");
            String copiedSignature = signatureMatch.group();
            String issuer = "<saml:Issuer>https://attacker.example.test/</saml:Issuer>";
            String extension = "<samlp:Extensions>" + attacker + "</samlp:Extensions>";
            String responseClose = "</samlp:Response>";
            List<String> mutants = new ArrayList<>();
            mutants.add(original.replace(assertion, attacker + assertion));
            mutants.add(original.replace(assertion, assertion + attacker));
            mutants.add(original.replace(assertion, duplicateId + assertion));
            mutants.add(original.replace(assertion, assertion + duplicateId));
            mutants.add(original.replace("<samlp:Status>", extension + "<samlp:Status>"));
            mutants.add(original.replace(assertion, extension + attacker));
            mutants.add(original.replace(assertion, "<samlp:Extensions>" + assertion
                    + "</samlp:Extensions>" + attacker));
            mutants.add(original.replace(assertion, "<ds:Object xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                    + assertion + "</ds:Object>" + attacker));
            mutants.add(original.replace("<samlp:Status>", issuer + "<samlp:Status>"));
            mutants.add(original.replace(responseClose, attacker + responseClose));
            mutants.add(original.replace("minted-user", "attacker-user"));
            mutants.add(original.replace("https://sp.test/acs", "https://attacker.example.test/acs"));
            mutants.add(original.replace("<saml:Subject>", "<saml:Subject>"
                    + "<saml:NameID>attacker-user</saml:NameID>"));
            mutants.add(original.replace("<samlp:Status>",
                    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
                    + "</samlp:Status><samlp:Status>"));
            int fragileLockStart = mutants.size();
            // PortSwigger's Fragile Lock classes: namespace-qualified ID pollution, a copied
            // Signature under an extension with xml:xmlns confusion, and relative-namespace
            // canonicalization with an attacker-controlled sibling Assertion.
            mutants.add(original.replace("<samlp:Response ",
                    "<samlp:Response samlp:ID='_attacker_response' "));
            mutants.add(original.replace("<saml:Assertion ",
                    "<saml:Assertion saml:ID='_attacker_assertion' "));
            mutants.add(original.replace("<samlp:Status>",
                    "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                    + "<Child xml:xmlns='#other'>" + copiedSignature
                    + "</Child></Parent></samlp:Extensions><samlp:Status>"));
            mutants.add(original.replace("<samlp:Response ",
                    "<samlp:Response xmlns:ns='1' ")
                    .replace(assertion, attacker + assertion));
            mutants.add(original.replace("minted-user", "minted-<!-- -->attacker"));
            for (int index = 0; index < mutants.size(); index++) {
                assertNotEquals(original, mutants.get(index), name + ":" + index + " did not mutate XML");
                SamlAuthenticationResult result = check(mutants.get(index), certificate, sha1);
                if (index >= fragileLockStart)
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, result,
                            name + ":" + index + " must reject the polluted envelope");
                if (result instanceof SamlAuthenticationResult.Succeeded succeeded) {
                    SamlAuthentication authentication = succeeded.getAuthentication();
                    assertEquals(baseline.getIdentityProviderConnectionId(),
                            authentication.getIdentityProviderConnectionId(), name + ":" + index);
                    assertEquals(baseline.getIdentityProviderEntityId(),
                            authentication.getIdentityProviderEntityId(), name + ":" + index);
                    assertEquals(baseline.getAssertionId(), authentication.getAssertionId(),
                            name + ":" + index);
                    assertEquals(baseline.getNameId().orElseThrow().getValue(),
                            authentication.getNameId().orElseThrow().getValue(), name + ":" + index);
                    assertEquals(baseline.getNameId().orElseThrow().getFormat(),
                            authentication.getNameId().orElseThrow().getFormat(), name + ":" + index);
                    assertEquals(baseline.getNameId().orElseThrow().getNameQualifier(),
                            authentication.getNameId().orElseThrow().getNameQualifier(), name + ":" + index);
                    assertEquals(baseline.getNameId().orElseThrow().getSpNameQualifier(),
                            authentication.getNameId().orElseThrow().getSpNameQualifier(), name + ":" + index);
                    assertEquals(baseline.getSubjectKey().orElseThrow().toStableString(),
                            authentication.getSubjectKey().orElseThrow().toStableString(), name + ":" + index);
                    assertEquals(baseline.getSubjectId(), authentication.getSubjectId(), name + ":" + index);
                    assertEquals(baseline.getPairwiseId(), authentication.getPairwiseId(), name + ":" + index);
                    assertEquals(baseline.getAuthnInstant(), authentication.getAuthnInstant(),
                            name + ":" + index);
                    assertEquals(baseline.getSessionIndex(), authentication.getSessionIndex(),
                            name + ":" + index);
                    assertEquals(baseline.getSessionNotOnOrAfter(), authentication.getSessionNotOnOrAfter(),
                            name + ":" + index);
                    assertEquals(baseline.getAuthnContextClassRef(), authentication.getAuthnContextClassRef(),
                            name + ":" + index);
                    assertEquals(baseline.getAttributes(), authentication.getAttributes(),
                            name + ":" + index);
                    assertEquals(baseline.isResponseSigned(), authentication.isResponseSigned(),
                            name + ":" + index);
                    assertEquals(baseline.isAssertionSigned(), authentication.isAssertionSigned(),
                            name + ":" + index);
                } else if (!(result instanceof SamlAuthenticationResult.Rejected)) {
                    fail(name + ":" + index + " produced " + result);
                }
            }
        }
    }

    private static @NonNull String certificateFor(@NonNull String name) {
        if (name.contains("ecdsa-sha256")) return "idp-signing-ec-p256-cert.pem";
        if (name.contains("ecdsa-sha384") || name.contains("ec384"))
            return "idp-signing-ec-p384-cert.pem";
        if (name.contains("ecdsa-sha512")) return "idp-signing-ec-p521-cert.pem";
        if (name.contains("rsa-sha384") || name.contains("rsa-sha512"))
            return "idp-signing-rsa-3072-cert.pem";
        return "idp-signing-rsa-2048-cert.pem";
    }

    private static @NonNull String section(@NonNull String xml, @NonNull String opening,
            @NonNull String closing) {
        int start = xml.indexOf(opening);
        int end = xml.indexOf(closing, start);
        if (start < 0 || end < 0) throw new IllegalArgumentException("fixture shape changed");
        return xml.substring(start, end + closing.length());
    }

    private static @NonNull SamlAuthenticationResult check(@NonNull String xml,
            @NonNull String certificate, boolean sha1) throws Exception {
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("xsw-fixture")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(resource("keys/" + certificate)).getPublicKey()))
                .allowUnsolicitedResponses(true)
                .compatibility(sha1 ? java.util.Set.of(SamlCompatibilityMode.SHA1_SIGNATURES)
                        : java.util.Set.of()).build();
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return sp.completeUnsolicitedAuthenticationResult(message, idp);
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        try (var input = SamlXswMutationTests.class.getResourceAsStream("/fixtures/" + name)) {
            return new String(java.util.Objects.requireNonNull(input).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }
}
