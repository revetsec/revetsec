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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import java.util.function.UnaryOperator;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlConfigurationBoundaryTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI SSO = URI.create("https://idp.example.test/sso");

    @Test void serviceProviderRejectsUnsafeReceiverAndMissingReplayPolicy() {
        assertThrows(IllegalStateException.class, () -> SamlServiceProvider.withEntityId(SP).build());
        assertThrows(IllegalStateException.class, () -> SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).build());
        for (String endpoint : List.of("http://sp.example.test/acs", "https://user@sp.example.test/acs",
                "https://sp.example.test/acs#fragment", "https:///acs")) {
            assertThrows(IllegalStateException.class, () -> validSp().assertionConsumerServiceUrl(
                    URI.create(endpoint)).build(), endpoint);
            assertThrows(IllegalStateException.class, () -> validSp().singleLogoutServiceUrl(
                    URI.create(endpoint)).build(), endpoint);
        }
        assertThrows(IllegalStateException.class, () -> validSp()
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout")).build());
    }

    @Test void disabledGlobalSignatureValidationRequiresAnObservedAcknowledgment() {
        String property = "org.jcp.xml.dsig.secureValidation";
        String original = System.getProperty(property);
        AtomicInteger observed = new AtomicInteger();
        SamlObserver observer = new SamlObserver() {
            @Override public void didAcknowledgeGlobalSecureValidationDisabled() {
                observed.incrementAndGet();
            }
        };
        try {
            System.setProperty(property, "false");
            assertThrows(IllegalStateException.class, () -> validSp().build());
            assertThrows(IllegalStateException.class, () -> validSp()
                    .acknowledgeGlobalSecureValidationDisabled(true)
                    .acknowledgeGlobalSecureValidationDisabled(null).build());
            assertDoesNotThrow(() -> validSp().observer(observer)
                    .acknowledgeGlobalSecureValidationDisabled(true).build());
            org.junit.jupiter.api.Assertions.assertEquals(1, observed.get());
            System.setProperty(property, "true");
            assertDoesNotThrow(() -> validSp().observer(observer).build());
            org.junit.jupiter.api.Assertions.assertEquals(1, observed.get());
        } finally {
            if (original == null) System.clearProperty(property);
            else System.setProperty(property, original);
        }
    }

    @Test void serviceProviderRejectsWeakKeysAndOutOfRangeTimePolicies() throws Exception {
        KeyPair weak = rsa(1024);
        KeyPair strong = rsa(2048);
        assertThrows(IllegalStateException.class,
                () -> validSp().signingPrivateKey(weak.getPrivate()).build());
        assertDoesNotThrow(() -> validSp().signingPrivateKey(strong.getPrivate())
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout")).build());
        List<UnaryOperator<SamlServiceProvider.Builder>> invalid = List.of(
                builder -> builder.clockSkew(Duration.ofNanos(-1)),
                builder -> builder.clockSkew(Duration.ofMinutes(5).plusNanos(1)),
                builder -> builder.maximumResponseAge(Duration.ZERO),
                builder -> builder.maximumResponseAge(Duration.ofMinutes(15).plusNanos(1)),
                builder -> builder.pendingAuthenticationLifetime(Duration.ZERO),
                builder -> builder.pendingAuthenticationLifetime(Duration.ofMinutes(15).plusNanos(1)),
                builder -> builder.replayBudget(Duration.ZERO),
                builder -> builder.replayBudget(Duration.ofSeconds(30).plusNanos(1)));
        for (UnaryOperator<SamlServiceProvider.Builder> change : invalid) {
            SamlServiceProvider.Builder builder = change.apply(validSp());
            assertThrows(IllegalStateException.class, builder::build);
        }
        assertDoesNotThrow(() -> validSp().clockSkew(Duration.ZERO)
                .maximumResponseAge(Duration.ofSeconds(1))
                .pendingAuthenticationLifetime(Duration.ofMinutes(15))
                .replayBudget(Duration.ofSeconds(30)).build());
        assertDoesNotThrow(() -> validSp().clockSkew(Duration.ofMinutes(5)).build());
        assertDoesNotThrow(() -> validSp().maximumResponseAge(Duration.ofMinutes(15)).build());
        assertDoesNotThrow(() -> validSp().pendingAuthenticationLifetime(Duration.ofSeconds(1)).build());
        assertDoesNotThrow(() -> validSp().replayBudget(Duration.ofMillis(1)).build());
    }

    @Test void serviceProviderAllowsFourDecryptionCredentialsButRejectsFive() throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        SamlCredential credential = SamlCredential.fromPem(
                Files.readString(keys.resolve("sp-encryption-rsa-2048-key.pem")),
                Files.readString(keys.resolve("sp-encryption-rsa-2048-cert.pem")));
        assertDoesNotThrow(() -> validSp().decryptionCredentials(
                Collections.nCopies(4, credential)).build());
        assertThrows(IllegalStateException.class, () -> validSp().decryptionCredentials(
                Collections.nCopies(5, credential)).build());
    }

    @Test void identityProviderRejectsUnsafeEndpointsAndUntrustedKeySets() throws Exception {
        KeyPair strong = rsa(2048);
        KeyPair weak = rsa(1024);
        assertThrows(IllegalStateException.class,
                () -> SamlIdentityProvider.withEntityId(IDP).build());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).connectionId("").build());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).connectionId("x".repeat(257)).build());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).redirectSingleSignOnService(null).build());
        for (String endpoint : List.of("http://idp.example.test/sso", "https://user@idp.example.test/sso",
                "https://idp.example.test/sso#fragment", "https:///sso")) {
            assertThrows(IllegalStateException.class, () -> validIdp(strong)
                    .redirectSingleSignOnService(URI.create(endpoint)).build(), endpoint);
            assertThrows(IllegalStateException.class, () -> validIdp(strong)
                    .postSingleSignOnService(URI.create(endpoint)).build(), endpoint);
            assertThrows(IllegalStateException.class, () -> validIdp(strong)
                    .redirectSingleLogoutService(URI.create(endpoint)).build(), endpoint);
        }
        assertThrows(IllegalStateException.class, () -> validIdp(strong).signingKeys(List.of()).build());
        assertThrows(IllegalStateException.class, () -> validIdp(strong)
                .signingKeys(Collections.nCopies(9, strong.getPublic())).build());
        assertThrows(IllegalStateException.class, () -> validIdp(strong)
                .signingKeys(List.of(weak.getPublic())).build());
        assertDoesNotThrow(() -> validIdp(strong).postSingleSignOnService(SSO)
                .redirectSingleSignOnService(null).build());
    }

    @Test void identityProviderRequiresExactBoundedIdentifierScopes() throws Exception {
        KeyPair strong = rsa(2048);
        for (String scope : List.of("", "bad@scope", "bad*scope", "bad scope", "x".repeat(256)))
            assertThrows(IllegalStateException.class, () -> validIdp(strong)
                    .authorizedIdentifierScopes(List.of(scope)).build(), scope);
        assertThrows(IllegalStateException.class, () -> validIdp(strong)
                .authorizedIdentifierScopes(Collections.nCopies(33, "example.test")).build());
        assertDoesNotThrow(() -> validIdp(strong).authorizedIdentifierScopes(List.of("example.test")).build());
    }

    @Test void idpConnectionAndAuthorizedScopeLimitsAcceptTheirExactMaxima() throws Exception {
        KeyPair strong = rsa(2048);
        assertEquals(256, validIdp(strong).connectionId("c".repeat(256)).build().getConnectionId().length());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).connectionId("c".repeat(257)).build());

        List<String> scopes = IntStream.range(0, 32).mapToObj(i -> "scope" + i).toList();
        assertEquals(scopes, validIdp(strong).authorizedIdentifierScopes(scopes)
                .build().authorizedIdentifierScopes());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).authorizedIdentifierScopes(IntStream.range(0, 33)
                        .mapToObj(i -> "scope" + i).toList()).build());
        assertEquals(List.of("s".repeat(255)), validIdp(strong)
                .authorizedIdentifierScopes(List.of("s".repeat(255)))
                .build().authorizedIdentifierScopes());
        assertThrows(IllegalStateException.class,
                () -> validIdp(strong).authorizedIdentifierScopes(List.of("s".repeat(256))).build());
    }

    @Test void requestContextCountAndUriLengthAcceptTheirExactMaxima() {
        String context = "urn:example:" + "x".repeat(512 - "urn:example:".length());
        assertEquals(512, context.length());
        assertEquals(List.of(context), SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(List.of(context)).build()
                .getRequestedAuthnContextClassRefs());
        assertThrows(IllegalArgumentException.class, () -> SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(List.of(context + "x")));
        assertEquals(8, SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(Collections.nCopies(8, "urn:example:password"))
                .build().getRequestedAuthnContextClassRefs().size());
        assertThrows(IllegalArgumentException.class, () -> SamlAuthenticationRequestOptions.builder()
                .requestedAuthnContextClassRefs(Collections.nCopies(9, "urn:example:password")));
    }

    @Test void browserBindingAcceptsItsExactMaximumButRejectsTheNextCharacter() {
        assertTrue(SamlPendingBinding.context("application", "b".repeat(4096))
                .startsWith("application|saml-store-v1|"));
        assertThrows(IllegalArgumentException.class,
                () -> SamlPendingBinding.context("application", "b".repeat(4097)));
    }

    @Test void postFormRejectsHostileNonceAndEscapesActionAndFields() {
        SamlPostForm form = new SamlPostForm(URI.create("https://idp.example.test/post?a=1&b=2"),
                "request\"<&'", "relay\"<&'");
        String html = form.toHtml(null);
        assertTrue(html.contains("action=\"https://idp.example.test/post?a=1&amp;b=2\""));
        assertTrue(html.contains("request&quot;&lt;&amp;&#39;"));
        assertTrue(html.contains("relay&quot;&lt;&amp;&#39;"));
        assertThrows(IllegalArgumentException.class, () -> form.toHtml("bad\" onload=\"alert(1)"));
        assertTrue(form.toHtml("abcdefghijklmnop").contains("nonce=\"abcdefghijklmnop\""));
    }

    @Test void malformedXsiTypeCannotSupplyAnEmptyNamespacePrefix() {
        String xml = "<v xmlns='http://www.w3.org/2001/XMLSchema' "
                + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type=':string'>x</v>";
        Element value = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocument().getDocumentElement();
        assertTrue(!SamlResponseSemantics.scalarDeclarationAllowed(value,
                "http://www.w3.org/2001/XMLSchema", "string"));
    }

    private static SamlServiceProvider.@NonNull Builder validSp() {
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(Clock.systemUTC(), 4));
    }

    private static SamlIdentityProvider.@NonNull Builder validIdp(@NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("connection")
                .redirectSingleSignOnService(SSO).signingKeys(List.of(key.getPublic()));
    }

    private static @NonNull KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }
}
