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

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SamlSecurityBranchMutationTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String ACS = "https://sp.example.test/acs";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    @Test void signedAttributeWithWrongValueElementCannotReleaseScopedIdentityOrMarkReplay()
            throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String malformed = SamlResponseSemanticsTests.BASE.replace("</a:Assertion>",
                "<a:AttributeStatement><a:Attribute Name='urn:oasis:names:tc:SAML:attribute:subject-id'>"
                        + "<a:Other>alice@example.test</a:Other></a:Attribute></a:AttributeStatement>"
                        + "</a:Assertion>");
        SamlResponseSemantics.Rejected rejected = assertInstanceOf(SamlResponseSemantics.Rejected.class,
                SamlResponseSemantics.validate(verified(malformed, key), expected(CLOCK, cache)));
        assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE, rejected.reason());
        assertEquals(0, writes.get());
    }

    @Test void clockFaultReturnsUnavailableBeforeReplayInsertion() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        Clock failing = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() { throw new IllegalStateException("clock unavailable"); }
        };
        assertInstanceOf(SamlResponseSemantics.Unavailable.class,
                SamlResponseSemantics.validate(verified(SamlResponseSemanticsTests.BASE, key),
                        expected(failing, cache)));
        assertEquals(0, writes.get());
    }

    @Test void replayStoreFaultReturnsIndeterminateWithoutIdentity() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache faulting = (replayKey, expiresAt, remaining) -> {
            throw new IllegalStateException("replay store unavailable");
        };
        assertInstanceOf(SamlResponseSemantics.Indeterminate.class,
                SamlResponseSemantics.validate(verified(SamlResponseSemanticsTests.BASE, key),
                        expected(CLOCK, faulting)));
    }

    @Test void errorResponseWithoutAssertionHasSealedSignatureRejection() {
        String xml = SamlResponseSemanticsTests.BASE;
        xml = xml.substring(0, xml.indexOf("<a:Assertion")) + "</p:Response>";
        xml = xml.replace("urn:oasis:names:tc:SAML:2.0:status:Success",
                "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
        SamlInboundResponse.Accepted accepted = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(xml), List.of("application/x-www-form-urlencoded"), null));
        SamlInboundResponse.SignatureRejected rejected = assertInstanceOf(
                SamlInboundResponse.SignatureRejected.class,
                SamlInboundResponse.verifySuccessSignatures(accepted, List.of()));
        assertEquals("ASSERTION_NOT_AVAILABLE", rejected.reason());
    }

    @Test void sealedPendingAuthenticationCannotCrossServiceProviderEntityBoundary() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider origin = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create(ACS))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4)).clock(CLOCK).build();
        SamlServiceProvider other = SamlServiceProvider.withEntityId("https://other.example.test/saml")
                .assertionConsumerServiceUrl(URI.create(ACS))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                origin.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-pending-entity"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-pending-entity"), sealer, "saml-pending-entity");
        String body = new String(form("<not-xml"), StandardCharsets.UTF_8)
                .replace("RelayState=relay", "RelayState=" + pending.getRelayStateHandle());
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(body.getBytes(StandardCharsets.UTF_8),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        SamlAuthenticationResult.Rejected rejected = assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                other.completeAuthenticationResult(message, source, idp));
        assertEquals(SamlAuthenticationResult.Reason.PENDING, rejected.getReason());
    }

    private static SamlInboundResponse.@NonNull SignaturesVerified verified(@NonNull String xml,
            @NonNull KeyPair key) throws Exception {
        String signed = SamlResponseSemanticsTests.signedXml(xml, true, false, key.getPrivate());
        SamlInboundResponse.Accepted inbound = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(signed),
                        List.of("application/x-www-form-urlencoded"), null));
        return assertInstanceOf(SamlInboundResponse.SignaturesVerified.class,
                SamlInboundResponse.verifySuccessSignatures(inbound, List.of(key.getPublic())));
    }

    private static SamlResponseSemantics.@NonNull Expectation expected(@NonNull Clock clock,
            @NonNull SamlReplayCache replayCache) {
        return new SamlResponseSemantics.Expectation(SP, "tenant-one", IDP, ACS, "_request", "relay",
                Instant.parse("2026-10-09T00:10:00Z"), clock, Duration.ofMinutes(3),
                Duration.ofMinutes(5), false, List.of("example.test"), replayCache, Duration.ofSeconds(5));
    }

    private static byte @NonNull [] form(@NonNull String xml) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return ("SAMLResponse=" + encoded + "&RelayState=relay").getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
