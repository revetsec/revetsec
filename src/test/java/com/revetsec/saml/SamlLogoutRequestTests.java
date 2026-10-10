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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SamlLogoutRequestTests {
    @Test void signedRequestReleasesOnlyCheckedSessionIdentifiersOnce() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8)).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_logout1' Version='2.0' "
                + "IssueInstant='2026-10-09T00:01:00Z' Destination='https://sp.example.test/logout'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer>"
                + "<a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' "
                + "NameQualifier='https://idp.example.test/saml'>alice</a:NameID>"
                + "<p:SessionIndex>session-123</p:SessionIndex></p:LogoutRequest>";
        SamlRedirectBindingMessage message = signed(xml, idpKey);
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(message, idp)).getRequest();
        assertEquals("tenant-one", accepted.getIdentityProviderConnectionId());
        assertEquals("alice", accepted.getNameId().getValue());
        assertEquals(List.of("session-123"), accepted.getSessionIndexes());
        SamlLogoutResponseRedirectResult.Prepared response = assertInstanceOf(
                SamlLogoutResponseRedirectResult.Prepared.class,
                sp.respondToLogoutRequestResult(accepted, idp, SamlLogoutStatus.SUCCESS));
        SamlRedirectBindingMessage responseMessage = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(response.getRedirectUri().getRawQuery()))
                .getMessage();
        assertEquals(SamlRedirectBindingMessage.Kind.RESPONSE, responseMessage.getKind());
        org.junit.jupiter.api.Assertions.assertTrue(responseMessage.verify(List.of(idpKey.getPublic())));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(message, idp));
    }

    @Test void spInitiatedLogoutBindsPendingResponseAndReplay() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair spKey = generator.generateKeyPair();
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(spKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8)).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        SamlSessionReference session = new SamlSessionReference("tenant-one",
                "https://idp.example.test/saml", new SamlNameId("alice",
                        SamlNameId.PERSISTENT, "https://idp.example.test/saml", null),
                "session-123", null);
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, session));
        SamlRedirectBindingMessage outbound = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(begin.getRedirectUri().getRawQuery()))
                .getMessage();
        org.junit.jupiter.api.Assertions.assertTrue(outbound.verify(List.of(spKey.getPublic())));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-pending"))
                .clock(clock).build();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "saml-logout-cookie"),
                sealer, "saml-logout-cookie");
        URI idpResponse = SamlRedirectLogout.response(URI.create("https://sp.example.test/logout"),
                "https://idp.example.test/saml", "_idp-response",
                begin.getPendingLogout().getRequestId(), begin.getPendingLogout().getRelayStateHandle(),
                clock.instant(), SamlLogoutStatus.SUCCESS, idpKey.getPrivate());
        SamlRedirectBindingMessage response = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        java.util.Objects.requireNonNull(idpResponse).getRawQuery())).getMessage();
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(response, source, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(response, source, idp));
    }

    @Test void logoutStoreIsSingleUseAndSealTypeIsDistinctFromLogin() {
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        String requestId = SamlRedirectLogout.id(new SecureRandom());
        String relay = SamlRedirectLogout.relay(new SecureRandom());
        PendingSamlAuthentication fields = new PendingSamlAuthentication("https://sp.example.test/saml",
                requestId, relay, "tenant-one", "https://idp.example.test/saml",
                "https://sp.example.test/logout", clock.instant(), clock.instant().plusSeconds(300));
        PendingSamlLogout pending = new PendingSamlLogout(fields);
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-store"))
                .clock(clock).build();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 4);
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer, "slo-store",
                "browser-one", Duration.ofSeconds(5)));
        PendingSamlLogoutSource wrong = PendingSamlLogoutSource.fromStore(store, "browser-two", sealer,
                "slo-store");
        assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                wrong.resolve(clock, relay, Duration.ofSeconds(5)));
        PendingSamlLogoutSource correct = PendingSamlLogoutSource.fromStore(store, "browser-one", sealer,
                "slo-store");
        assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                correct.resolve(clock, relay, Duration.ofSeconds(5)));
        assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                correct.resolve(clock, relay, Duration.ofSeconds(5)));
        assertInstanceOf(PendingSamlAuthenticationSource.Rejected.class,
                PendingSamlAuthenticationSource.fromSealedForm(
                        pending.toSealedForm(sealer, "slo-cookie"), sealer, "slo-cookie")
                        .resolve(clock, relay, Duration.ofSeconds(5)));
    }

    private static @NonNull SamlRedirectBindingMessage signed(@NonNull String xml, @NonNull KeyPair key)
            throws Exception {
        byte[] plain = xml.getBytes(StandardCharsets.UTF_8);
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] buffer = new byte[16384];
        deflater.setInput(plain);
        deflater.finish();
        int length = deflater.deflate(buffer);
        deflater.end();
        String query = "SAMLRequest=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOf(buffer, length)), StandardCharsets.UTF_8)
                + "&SigAlg=" + URLEncoder.encode(
                        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key.getPrivate());
        signer.update(query.getBytes(StandardCharsets.US_ASCII));
        query += "&Signature=" + URLEncoder.encode(Base64.getEncoder().encodeToString(signer.sign()),
                StandardCharsets.UTF_8);
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
    }
}
