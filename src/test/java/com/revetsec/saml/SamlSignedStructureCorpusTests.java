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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Validly signed hostile structure fixtures, independently minted and checked by libxmlsec1. */
final class SamlSignedStructureCorpusTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String PREFIX = "scripted-idp/signed-structure/";
    private static final @NonNull String ASSERTION_PREFIX =
            "scripted-idp/signed-assertion-structure/";
    private static final @NonNull String ATTRIBUTE_PREFIX =
            "scripted-idp/signed-attribute-values/";
    private static final @NonNull String IDENTITY_PREFIX =
            "scripted-idp/signed-identity-shape/";
    private static final @NonNull String BOUNDARY_PREFIX =
            "scripted-idp/signed-boundary-shape/";
    private static final @NonNull List<@NonNull String> NEGATIVES = List.of(
            "duplicate-assertion-before", "duplicate-assertion-after",
            "nested-assertion-advice", "attacker-assertion-extension",
            "duplicate-status", "duplicate-issuer", "assertion-before-status",
            "qualified-response-id", "qualified-assertion-id", "saml1-assertion-shadow",
            "duplicate-subject", "duplicate-nameid", "duplicate-status-code",
            "signature-under-extension");
    private static final @NonNull List<@NonNull String> ASSERTION_NEGATIVES = List.of(
            "duplicate-issuer", "duplicate-subject", "duplicate-nameid",
            "nested-nameid", "duplicate-confirmation-data", "duplicate-conditions",
            "contradictory-audience-restriction", "duplicate-authn-statement",
            "duplicate-authn-context", "duplicate-class-ref", "nested-class-ref",
            "assertion-nil", "assertion-type-string", "issuer-after-subject",
            "conditions-before-subject", "advice-after-authn", "duplicate-advice",
            "attribute-before-conditions", "attribute-statement-nil", "attribute-nil",
            "attribute-type-string", "attribute-direct-text", "authn-statement-nil");
    private static final @NonNull List<@NonNull String> ASSERTION_POSITIVES = List.of(
            "comment-split-nameid", "cdata-nameid", "advice-before-authn",
            "typed-attribute-statement", "attribute-before-authn");
    private static final @NonNull List<@NonNull String> TEXT_ATTRIBUTES = List.of(
            "clean", "type-xs-string", "type-alias-string", "nil-false", "nil-zero");
    private static final @NonNull List<@NonNull String> OPAQUE_ATTRIBUTES = List.of(
            "nil-true", "nil-one", "nil-invalid", "type-boolean", "type-and-nil",
            "spoof-string-type", "mixed-element");
    private static final @NonNull List<@NonNull String> IDENTITY_POSITIVES = List.of(
            "clean", "subject-nameid-type", "assertion-issuer-type", "audience-type",
            "authn-class-ref-type", "subject-nameid-nil-false",
            "authn-locality-before-context");
    private static final @NonNull List<@NonNull String> IDENTITY_NEGATIVES = List.of(
            "assertion-version-old", "assertion-version-missing",
            "subject-nameid-nil", "subject-nameid-type-string",
            "assertion-issuer-nil", "assertion-issuer-type-string",
            "audience-nil", "audience-type-string", "authn-class-ref-nil",
            "subject-nameid-after-confirmation", "authn-locality-after-context",
            "authn-duplicate-locality", "authn-unknown-child");
    private static final @NonNull List<@NonNull String> BOUNDARY_POSITIVES = List.of(
            "clean", "matching-confirmation-nameid", "one-time-and-proxy",
            "typed-confirmation-data");
    private static final @NonNull List<@NonNull String> BOUNDARY_NEGATIVES = List.of(
            "subject-nil", "confirmation-nil", "data-nil", "data-wrong-type",
            "confirmation-extra-child", "data-direct-text", "inverted-bearer-window",
            "mismatched-confirmation-nameid", "conditions-nil", "conditions-wrong-type",
            "audience-restriction-nil", "one-time-child", "proxy-negative-count",
            "proxy-child", "proxy-nil");

    @Test void signedHostileStructuresNeverReleaseAnIdentity() throws Exception {
        Map<String, String> manifest = manifest(PREFIX);
        assertEquals(NEGATIVES.size() + 1, manifest.size());
        SamlAuthentication baseline = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                check(fixture(PREFIX, "clean", manifest))).getAuthentication();
        assertEquals("minted-user", baseline.getNameId().orElseThrow().getValue());
        assertTrue(baseline.isResponseSigned());
        for (String name : NEGATIVES) {
            SamlAuthenticationResult result = check(fixture(PREFIX, name, manifest));
            assertInstanceOf(SamlAuthenticationResult.Rejected.class, result, name);
        }
    }

    @Test void assertionSignedAmbiguitiesRejectButEquivalentTextKeepsIdentity() throws Exception {
        Map<String, String> manifest = manifest(ASSERTION_PREFIX);
        assertEquals(1 + ASSERTION_NEGATIVES.size() + ASSERTION_POSITIVES.size(),
                manifest.size());
        SamlAuthentication baseline = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                check(fixture(ASSERTION_PREFIX, "clean", manifest))).getAuthentication();
        assertEquals("minted-user", baseline.getNameId().orElseThrow().getValue());
        assertFalse(baseline.isResponseSigned());
        assertTrue(baseline.isAssertionSigned());
        for (String name : ASSERTION_NEGATIVES)
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    check(fixture(ASSERTION_PREFIX, name, manifest)), name);
        for (String name : ASSERTION_POSITIVES) {
            SamlAuthentication actual = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    check(fixture(ASSERTION_PREFIX, name, manifest)), name).getAuthentication();
            assertEquals(baseline.getNameId().orElseThrow().getValue(),
                    actual.getNameId().orElseThrow().getValue(), name);
            if (name.equals("typed-attribute-statement") || name.equals("attribute-before-authn")) {
                assertEquals("minted@example.test", actual.getSubjectId().orElseThrow(), name);
                assertTrue(actual.getSubjectKey().isPresent(), name);
            } else assertEquals(baseline.getSubjectKey().orElseThrow().toStableString(),
                    actual.getSubjectKey().orElseThrow().toStableString(), name);
        }
    }

    @Test void signedSchemaHintsCannotTurnOpaqueAttributesIntoAccountKeys() throws Exception {
        Map<String, String> manifest = manifest(ATTRIBUTE_PREFIX);
        assertEquals(TEXT_ATTRIBUTES.size() + OPAQUE_ATTRIBUTES.size(), manifest.size());
        for (String name : TEXT_ATTRIBUTES) {
            SamlAuthentication authentication = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    check(fixture(ATTRIBUTE_PREFIX, name, manifest)), name).getAuthentication();
            assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
            assertFalse(authentication.isResponseSigned(), name);
            assertTrue(authentication.isAssertionSigned(), name);
            assertEquals("minted@example.test", authentication.getSubjectId().orElseThrow(), name);
            assertTrue(authentication.getSubjectKey().isPresent(), name);
            assertEquals(List.of("minted@example.test"),
                    authentication.getAttributeValues("urn:example:display-email"), name);
            assertEquals(SamlAttributeValue.Kind.TEXT,
                    authentication.getAttributes().get(1).getTypedValues().get(0).getKind(), name);
        }
        for (String name : OPAQUE_ATTRIBUTES) {
            SamlAuthentication authentication = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    check(fixture(ATTRIBUTE_PREFIX, name, manifest)), name).getAuthentication();
            assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
            assertTrue(authentication.getSubjectId().isEmpty(), name);
            assertTrue(authentication.getSubjectKey().isEmpty(), name);
            assertEquals(List.of(),
                    authentication.getAttributeValues("urn:example:display-email"), name);
            assertEquals(1, authentication.getAttributes().size(), name);
            assertEquals(SamlAttributeValue.Kind.COMPLEX,
                    authentication.getAttributes().get(0).getTypedValues().get(0).getKind(), name);
        }
    }

    @Test void signedIdentityAndAudienceShapeCannotChangeCheckedPrincipal() throws Exception {
        Map<String, String> manifest = manifest(IDENTITY_PREFIX);
        assertEquals(IDENTITY_POSITIVES.size() + IDENTITY_NEGATIVES.size(), manifest.size());
        for (String name : IDENTITY_POSITIVES) {
            SamlAuthentication authentication = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    check(fixture(IDENTITY_PREFIX, name, manifest)), name).getAuthentication();
            assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
            assertTrue(authentication.getSubjectKey().isPresent(), name);
            assertFalse(authentication.isResponseSigned(), name);
            assertTrue(authentication.isAssertionSigned(), name);
        }
        for (String name : IDENTITY_NEGATIVES)
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    check(fixture(IDENTITY_PREFIX, name, manifest)), name);
    }

    @Test void signedBearerAndConditionsShapeCannotReleaseAmbiguousPrincipal() throws Exception {
        Map<String, String> manifest = manifest(BOUNDARY_PREFIX);
        assertEquals(BOUNDARY_POSITIVES.size() + BOUNDARY_NEGATIVES.size(), manifest.size());
        for (String name : BOUNDARY_POSITIVES) {
            SamlAuthentication authentication = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    check(fixture(BOUNDARY_PREFIX, name, manifest)), name).getAuthentication();
            assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
            assertTrue(authentication.getSubjectKey().isPresent(), name);
            assertFalse(authentication.isResponseSigned(), name);
            assertTrue(authentication.isAssertionSigned(), name);
        }
        for (String name : BOUNDARY_NEGATIVES)
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    check(fixture(BOUNDARY_PREFIX, name, manifest)), name);
    }

    private static @NonNull SamlAuthenticationResult check(@NonNull String xml) throws Exception {
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider
                .withEntityId("https://idp.scripted-idp.test/")
                .connectionId("signed-structure-corpus")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(
                        new String(resource("keys/idp-signing-rsa-2048-cert.pem"),
                                StandardCharsets.UTF_8)).getPublicKey()))
                .authorizedIdentifierScopes(List.of("example.test"))
                .allowUnsolicitedResponses(true).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return sp.completeUnsolicitedAuthenticationResult(message, idp);
    }

    private static @NonNull Map<@NonNull String, @NonNull String> manifest(
            @NonNull String prefix) throws IOException {
        String lines = new String(resource(prefix + "sha256.txt"), StandardCharsets.US_ASCII);
        Map<String, String> result = new LinkedHashMap<>();
        for (String line : lines.lines().toList()) {
            int separator = line.indexOf(' ');
            assertTrue(separator > 0 && separator == line.lastIndexOf(' '),
                    "invalid corpus manifest line");
            assertNull(result.put(line.substring(0, separator), line.substring(separator + 1)),
                    "duplicate corpus name");
        }
        return Map.copyOf(result);
    }

    private static @NonNull String fixture(@NonNull String prefix, @NonNull String name,
            @NonNull Map<@NonNull String, @NonNull String> manifest) throws Exception {
        byte[] bytes = resource(prefix + name + ".xml");
        String digest = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(bytes));
        assertEquals(manifest.get(name), digest, name + " changed without re-minting");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] resource(@NonNull String name) throws IOException {
        try (var input = SamlSignedStructureCorpusTests.class.getResourceAsStream("/fixtures/" + name)) {
            return java.util.Objects.requireNonNull(input, name).readAllBytes();
        }
    }
}
