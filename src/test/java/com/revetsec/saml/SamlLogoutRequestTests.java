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
import org.jspecify.annotations.Nullable;
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
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SamlLogoutRequestTests {
    @Test void signedLogoutRequestStopsAtExactReplayExpiryBeforeStoreAccess() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache replay = (key, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate()).replayCache(replay).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        String expired = logoutRequest(idp.getEntityId(), "_exact-expiry")
                .replace("2026-10-09T00:01:00Z", "2026-10-08T23:53:00Z");
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(signed(expired, idpKey), idp));
        assertEquals(0, writes.get());
        String live = logoutRequest(idp.getEntityId(), "_before-expiry")
                .replace("2026-10-09T00:01:00Z", "2026-10-08T23:53:00.000000001Z");
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(signed(live, idpKey), idp));
        assertEquals(1, writes.get());
    }

    @Test void signedLogoutRequestWithAnOverflowingClockReturnsAResult() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.MAX.minusSeconds(1), ZoneOffset.UTC);
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache replay = (key, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate()).replayCache(replay).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(signed(logoutRequest(idp.getEntityId(), "_clock-overflow"),
                        idpKey), idp));
        assertEquals(0, writes.get());
    }

    @Test void signedLogoutRequestRejectsTemporalIdentityAndSessionMutationsBeforeReplay() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache replay = (key, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate()).replayCache(replay).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        String issuer = "<a:Issuer>https://idp.example.test/saml</a:Issuer>";
        String nameId = "<a:NameID>alice</a:NameID>";
        String index = "<p:SessionIndex>session-123</p:SessionIndex>";
        String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_logout-boundary' Version='2.0' "
                + "IssueInstant='2026-10-09T00:01:00Z' Destination='https://sp.example.test/logout'>"
                + issuer + nameId + index + "</p:LogoutRequest>";
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("wrong version", xml.replace("Version='2.0'", "Version='1.1'")),
                Map.entry("wrong destination", xml.replace("Destination='https://sp.example.test/logout'",
                        "Destination='https://attacker.example.test/logout'")),
                Map.entry("missing request ID", xml.replace("ID='_logout-boundary'", "")),
                Map.entry("oversized request ID", xml.replace("_logout-boundary", "_" + "x".repeat(256))),
                Map.entry("future issue instant", xml.replace("2026-10-09T00:01:00Z",
                        "2026-10-09T00:10:00Z")),
                Map.entry("stale issue instant", xml.replace("2026-10-09T00:01:00Z",
                        "2026-10-08T00:01:00Z")),
                Map.entry("expired logout request", xml.replace("Version='2.0'",
                        "Version='2.0' NotOnOrAfter='2026-10-09T00:00:00Z'")),
                Map.entry("malformed expiry", xml.replace("Version='2.0'",
                        "Version='2.0' NotOnOrAfter='not-a-time'")),
                Map.entry("wrong IdP issuer", xml.replace(issuer,
                        "<a:Issuer>https://attacker.example.test/idp</a:Issuer>")),
                Map.entry("wrong issuer format", xml.replace(issuer,
                        "<a:Issuer Format='urn:example:unsupported'>https://idp.example.test/saml</a:Issuer>")),
                Map.entry("missing NameID", xml.replace(nameId, "")),
                Map.entry("empty NameID", xml.replace(nameId, "<a:NameID/>")),
                Map.entry("oversized NameID", xml.replace(nameId,
                        "<a:NameID>" + "x".repeat(4097) + "</a:NameID>")),
                Map.entry("oversized qualifier", xml.replace(nameId,
                        "<a:NameID SPProvidedID='" + "x".repeat(2049) + "'>alice</a:NameID>")),
                Map.entry("oversized session index", xml.replace(index,
                        "<p:SessionIndex>" + "x".repeat(2049) + "</p:SessionIndex>")),
                Map.entry("too many session indexes", xml.replace(index, index.repeat(33))),
                Map.entry("ambiguous issuer", xml.replace(issuer, issuer + issuer)),
                Map.entry("non-XML whitespace text", xml.replace(nameId,
                        nameId + "&#x2003;")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(signed(caseUnderTest.getValue(), idpKey), idp),
                    caseUnderTest.getKey());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(signed(xml, idpKey), idp));
        for (String boundary : List.of(
                xml.replace("_logout-boundary", "_" + "x".repeat(255)),
                xml.replace("_logout-boundary", "_name-limit").replace(nameId,
                        "<a:NameID>" + "x".repeat(4096) + "</a:NameID>"),
                xml.replace("_logout-boundary", "_index-limit").replace(index, index.repeat(32)),
                xml.replace("_logout-boundary", "_index-text-limit").replace(index,
                        "<p:SessionIndex>" + "x".repeat(2048) + "</p:SessionIndex>"),
                xml.replace("_logout-boundary", "_qualifier-limit").replace(nameId,
                        "<a:NameID SPProvidedID='" + "x".repeat(2048) + "'>alice</a:NameID>")))
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                    sp.acceptLogoutRequestResult(signed(boundary, idpKey), idp));
        assertEquals(6, writes.get());
    }

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
                + "NameQualifier='https://idp.example.test/saml' SPProvidedID='sp-original'>"
                + "alice</a:NameID>"
                + "<p:SessionIndex>session-123</p:SessionIndex></p:LogoutRequest>";
        SamlRedirectBindingMessage message = signed(xml, idpKey);
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(message, idp)).getRequest();
        assertEquals("tenant-one", accepted.getIdentityProviderConnectionId());
        assertEquals("alice", accepted.getNameId().getValue());
        assertEquals("sp-original", accepted.getNameId().getSpProvidedId().orElseThrow());
        assertEquals(List.of("session-123"), accepted.getSessionIndexes());
        String emptyProvidedId = xml.replace("_logout1", "_logout1-empty")
                .replace("SPProvidedID='sp-original'", "SPProvidedID=''");
        SamlLogoutRequest empty = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(signed(emptyProvidedId, idpKey), idp)).getRequest();
        org.junit.jupiter.api.Assertions.assertTrue(empty.getNameId().getSpProvidedId().isPresent());
        assertEquals("", empty.getNameId().getSpProvidedId().orElseThrow());
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

    @Test void logoutReplayKeysSeparateEqualLengthIdsAndFieldBoundaries() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8)).clock(clock).build();
        String firstEntity = "https://idp.example.test/saml_";
        String secondEntity = "https://idp.example.test/saml";
        SamlIdentityProvider firstIdp = SamlIdentityProvider.withEntityId(firstEntity)
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        SamlIdentityProvider secondIdp = SamlIdentityProvider.withEntityId(secondEntity)
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        SamlRedirectBindingMessage first = signed(logoutRequest(firstEntity, "_identity"), idpKey);
        SamlRedirectBindingMessage second = signed(logoutRequest(secondEntity, "__identity"), idpKey);
        SamlRedirectBindingMessage third = signed(logoutRequest(secondEntity, "__identitx"), idpKey);
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(first, firstIdp));
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(second, secondIdp));
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(third, secondIdp));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(first, firstIdp));
    }

    private static @NonNull String logoutRequest(@NonNull String issuer, @NonNull String id) {
        return "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                + "ID='" + id + "' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout'>"
                + "<a:Issuer>" + issuer + "</a:Issuer><a:NameID>alice</a:NameID>"
                + "</p:LogoutRequest>";
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
                        SamlNameId.PERSISTENT, "https://idp.example.test/saml", null,
                        "sp-original"),
                "session-123", null);
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, session));
        SamlRedirectBindingMessage outbound = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(begin.getRedirectUri().getRawQuery()))
                .getMessage();
        org.junit.jupiter.api.Assertions.assertTrue(outbound.verify(List.of(spKey.getPublic())));
        org.junit.jupiter.api.Assertions.assertTrue(new String(outbound.xml(), StandardCharsets.UTF_8)
                .contains("SPProvidedID=\"sp-original\""));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-pending"))
                .clock(clock).build();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "saml-logout-cookie"),
                sealer, "saml-logout-cookie");
        String otherKindSameReplayText = "<p:LogoutRequest "
                + "xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                + "ID='response:_idp-response' Version='2.0' "
                + "IssueInstant='2026-10-09T00:01:00Z' Destination='https://sp.example.test/logout'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer>"
                + "<a:NameID>alice</a:NameID></p:LogoutRequest>";
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(signed(otherKindSameReplayText, idpKey), idp));
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(signed(otherKindSameReplayText.replace(
                        "response:_idp-response", "_idp-response"), idpKey), idp));
        URI idpResponse = SamlRedirectLogout.response(URI.create("https://sp.example.test/logout"),
                "https://idp.example.test/saml", "_idp-response",
                begin.getPendingLogout().getRequestId(), begin.getPendingLogout().getRelayStateHandle(),
                clock.instant(), SamlLogoutStatus.SUCCESS, idpKey.getPrivate());
        for (String relay : List.of("wrong-browser-relay",
                begin.getPendingLogout().getRelayStateHandle() + "x")) {
            URI mismatched = SamlRedirectLogout.response(URI.create("https://sp.example.test/logout"),
                    "https://idp.example.test/saml", "_idp-response",
                    begin.getPendingLogout().getRequestId(), relay,
                    clock.instant(), SamlLogoutStatus.SUCCESS, idpKey.getPrivate());
            SamlRedirectBindingMessage mismatchedMessage = assertInstanceOf(
                    SamlRedirectBindingParseResult.Parsed.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(
                            java.util.Objects.requireNonNull(mismatched).getRawQuery())).getMessage();
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(mismatchedMessage, source, idp), relay);
        }
        URI missingRelay = SamlRedirectLogout.response(URI.create("https://sp.example.test/logout"),
                "https://idp.example.test/saml", "_idp-response",
                begin.getPendingLogout().getRequestId(), null,
                clock.instant(), SamlLogoutStatus.SUCCESS, idpKey.getPrivate());
        SamlRedirectBindingMessage missingRelayMessage = assertInstanceOf(
                SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        java.util.Objects.requireNonNull(missingRelay).getRawQuery())).getMessage();
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(missingRelayMessage, source, idp));
        SamlRedirectBindingMessage response = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        java.util.Objects.requireNonNull(idpResponse).getRawQuery())).getMessage();
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(response, source, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(response, source, idp));
    }

    @Test void signedLogoutResponseStopsAtExactReplayExpiryBeforeStoreAccess() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair spKey = generator.generateKeyPair();
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache replay = (key, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(spKey.getPrivate()).replayCache(replay).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        SamlSessionReference session = new SamlSessionReference("tenant-one",
                idp.getEntityId(), new SamlNameId("alice", null, null, null), null, null);
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, session));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-expiry-boundary"))
                .clock(clock).build();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "saml-logout-cookie"),
                sealer, "saml-logout-cookie");
        for (Instant issued : List.of(Instant.parse("2026-10-08T23:53:00Z"),
                Instant.parse("2026-10-08T23:53:00.000000001Z"))) {
            URI redirect = java.util.Objects.requireNonNull(SamlRedirectLogout.response(
                    URI.create("https://sp.example.test/logout"), idp.getEntityId(),
                    "_response-boundary", begin.getPendingLogout().getRequestId(),
                    begin.getPendingLogout().getRelayStateHandle(), issued,
                    SamlLogoutStatus.SUCCESS, idpKey.getPrivate()));
            SamlRedirectBindingMessage message = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(redirect.getRawQuery())).getMessage();
            SamlLogoutResult result = sp.completeLogoutResult(message, source, idp);
            if (issued.getNano() == 0) assertInstanceOf(SamlLogoutResult.Rejected.class, result);
            else assertInstanceOf(SamlLogoutResult.Succeeded.class, result);
        }
        URI maximumId = java.util.Objects.requireNonNull(SamlRedirectLogout.response(
                URI.create("https://sp.example.test/logout"), idp.getEntityId(),
                "_" + "x".repeat(255), begin.getPendingLogout().getRequestId(),
                begin.getPendingLogout().getRelayStateHandle(),
                Instant.parse("2026-10-08T23:53:00.000000001Z"),
                SamlLogoutStatus.SUCCESS, idpKey.getPrivate()));
        SamlRedirectBindingMessage maximumIdMessage = assertInstanceOf(
                SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(maximumId.getRawQuery())).getMessage();
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(maximumIdMessage, source, idp));
        assertEquals(2, writes.get());
    }

    @Test void signedNonSuccessLogoutStatusMayCarryMessageAndDetail() throws Exception {
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
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-status-message"))
                .clock(clock).build();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "saml-logout-cookie"),
                sealer, "saml-logout-cookie");
        String xml = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                + "ID='_idp-response-message' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout' InResponseTo='"
                + begin.getPendingLogout().getRequestId() + "'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer>"
                + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Responder'/>"
                + "<p:StatusMessage>Session not found</p:StatusMessage>"
                + "<p:StatusDetail><x:Hint xmlns:x='urn:example:status'/></p:StatusDetail>"
                + "</p:Status></p:LogoutResponse>";
        SamlRedirectBindingMessage reply = signed(xml, idpKey, "SAMLResponse",
                begin.getPendingLogout().getRelayStateHandle());
        assertEquals(SamlLogoutResult.StatusReceived.NON_SUCCESS,
                sp.completeLogoutResult(reply, source, idp));
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

    @Test void unsignedRedirectMutationCannotConsumeStoredPendingLogout() throws Exception {
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
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-verify-first"))
                .clock(clock).build();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 4);
        assertEquals(SamlPendingSaveResult.SAVED, begin.getPendingLogout().saveToResult(store, sealer,
                "slo-store", "browser-one", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-one", sealer,
                "slo-store");
        URI redirect = SamlRedirectLogout.response(URI.create("https://sp.example.test/logout"),
                "https://idp.example.test/saml", "_idp-response",
                begin.getPendingLogout().getRequestId(), begin.getPendingLogout().getRelayStateHandle(),
                clock.instant(), SamlLogoutStatus.SUCCESS, idpKey.getPrivate());
        String validQuery = java.util.Objects.requireNonNull(redirect).getRawQuery();
        String changedQuery = validQuery.replace("%3A", ":");
        org.junit.jupiter.api.Assertions.assertNotEquals(validQuery, changedQuery);
        SamlRedirectBindingMessage changed = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(changedQuery)).getMessage();
        SamlRedirectBindingMessage valid = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(validQuery)).getMessage();
        assertEquals(valid.getRelayState(), changed.getRelayState());
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(changed, source, idp));
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(valid, source, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(valid, source, idp));
    }

    @Test void outboundLogoutPreservesSafeIdpEndpointQueryWithoutSigningIt() throws Exception {
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
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout?tenant=one"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        SamlSessionReference session = new SamlSessionReference("tenant-one",
                "https://idp.example.test/saml", new SamlNameId("alice",
                        SamlNameId.PERSISTENT, "https://idp.example.test/saml", null),
                "session-123", null);
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, session));
        String requestQuery = begin.getRedirectUri().getRawQuery();
        org.junit.jupiter.api.Assertions.assertTrue(requestQuery.startsWith("tenant=one&SAMLRequest="));
        SamlRedirectBindingMessage request = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(requestQuery.substring("tenant=one&".length())))
                .getMessage();
        org.junit.jupiter.api.Assertions.assertTrue(request.verify(List.of(spKey.getPublic())));
        org.junit.jupiter.api.Assertions.assertTrue(new String(request.xml(), StandardCharsets.UTF_8)
                .contains("Destination=\"https://idp.example.test/logout?tenant=one\""));

        String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_incoming-query' "
                + "Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout'>"
                + "<a:Issuer>https://idp.example.test/saml</a:Issuer>"
                + "<a:NameID>alice</a:NameID></p:LogoutRequest>";
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(signed(xml, idpKey), idp)).getRequest();
        SamlLogoutResponseRedirectResult.Prepared response = assertInstanceOf(
                SamlLogoutResponseRedirectResult.Prepared.class,
                sp.respondToLogoutRequestResult(accepted, idp, SamlLogoutStatus.SUCCESS));
        String responseQuery = response.getRedirectUri().getRawQuery();
        org.junit.jupiter.api.Assertions.assertTrue(responseQuery.startsWith("tenant=one&SAMLResponse="));
        SamlRedirectBindingMessage responseMessage = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(responseQuery.substring("tenant=one&".length())))
                .getMessage();
        org.junit.jupiter.api.Assertions.assertTrue(responseMessage.verify(List.of(spKey.getPublic())));

        SamlIdentityProvider reserved = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout?%53AMLRequest=shadow"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        assertEquals(SamlLogoutRedirectResult.Rejected.CONFIGURATION,
                sp.beginLogoutResult(reserved, session));
        assertEquals(SamlLogoutResponseRedirectResult.Rejected.INSTANCE,
                sp.respondToLogoutRequestResult(accepted, reserved, SamlLogoutStatus.SUCCESS));
        for (String malformedQuery : List.of("%FF=broken", "tenant=%FF", "tenant=%C0%AF",
                "=unnamed", "tenant=one&", "SAMLRequest%00=shadow", "tenant=%0Aevil")) {
            SamlIdentityProvider malformed = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                    .connectionId("tenant-one")
                    .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                    .redirectSingleLogoutService(URI.create("https://idp.example.test/logout?"
                            + malformedQuery))
                    .signingKeys(List.of(idpKey.getPublic())).build();
            assertEquals(SamlLogoutRedirectResult.Rejected.CONFIGURATION,
                    sp.beginLogoutResult(malformed, session));
            assertEquals(SamlLogoutResponseRedirectResult.Rejected.INSTANCE,
                    sp.respondToLogoutRequestResult(accepted, malformed, SamlLogoutStatus.SUCCESS));
        }
    }

    @Test void signedOutOfOrderOrNilledLogoutIdentitiesCannotSelectSessions() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(idpKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 16)).clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpKey.getPublic())).build();
        String issuer = "<a:Issuer>https://idp.example.test/saml</a:Issuer>";
        String nameId = "<a:NameID>alice</a:NameID>";
        String session = "<p:SessionIndex>session-123</p:SessionIndex>";
        List<String> hostileChildren = List.of(
                nameId + issuer + session,
                issuer + session + nameId,
                "<a:Issuer xsi:nil='true'>https://idp.example.test/saml</a:Issuer>" + nameId + session,
                issuer + "<a:NameID xsi:type='xs:string'>alice</a:NameID>" + session,
                issuer + nameId + "<p:SessionIndex xsi:nil='true'>session-123</p:SessionIndex>",
                issuer + nameId + "attacker-text" + session);
        for (int index = 0; index < hostileChildren.size(); index++) {
            String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                    + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                    + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                    + "xmlns:xs='http://www.w3.org/2001/XMLSchema' ID='_logout-hostile-" + index + "' "
                    + "Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                    + "Destination='https://sp.example.test/logout'>"
                    + hostileChildren.get(index) + "</p:LogoutRequest>";
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(signed(xml, idpKey), idp), "variant " + index);
        }
    }

    @Test void signedMalformedLogoutResponsesCannotCompleteLogout() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair spKey = generator.generateKeyPair();
        KeyPair idpKey = generator.generateKeyPair();
        Clock clock = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(spKey.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 16)).clock(clock).build();
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
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-logout-shape"))
                .clock(clock).build();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "saml-logout-cookie"),
                sealer, "saml-logout-cookie");
        String issuer = "<a:Issuer>https://idp.example.test/saml</a:Issuer>";
        String status = "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                + "</p:Status>";
        List<String> hostileChildren = List.of(
                status + issuer,
                "<a:Issuer xsi:nil='true'>https://idp.example.test/saml</a:Issuer>" + status,
                issuer + "<p:Status xsi:nil='true'><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>",
                issuer + "<p:Status><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'>"
                        + "<p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Responder'/>"
                        + "</p:StatusCode></p:Status>",
                issuer + "attacker-text" + status);
        for (int index = 0; index < hostileChildren.size(); index++) {
            String xml = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                    + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                    + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                    + "ID='_response-hostile-" + index + "' Version='2.0' "
                    + "IssueInstant='2026-10-09T00:01:00Z' "
                    + "Destination='https://sp.example.test/logout' InResponseTo='"
                    + begin.getPendingLogout().getRequestId() + "'>"
                    + hostileChildren.get(index) + "</p:LogoutResponse>";
            SamlRedirectBindingMessage message = signed(xml, idpKey, "SAMLResponse",
                    begin.getPendingLogout().getRelayStateHandle());
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(message, source, idp), "variant " + index);
        }
        String valid = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                + "ID='_response-boundary' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' "
                + "Destination='https://sp.example.test/logout' InResponseTo='"
                + begin.getPendingLogout().getRequestId() + "'>" + issuer + status + "</p:LogoutResponse>";
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("wrong root", valid.replace("LogoutResponse", "Response")),
                Map.entry("wrong version", valid.replace("Version='2.0'", "Version='1.1'")),
                Map.entry("wrong destination", valid.replace("https://sp.example.test/logout",
                        "https://attacker.example.test/logout")),
                Map.entry("wrong request", valid.replace(begin.getPendingLogout().getRequestId(), "_wrong")),
                Map.entry("missing response ID", valid.replace("ID='_response-boundary'", "")),
                Map.entry("long response ID", valid.replace("_response-boundary", "_" + "x".repeat(256))),
                Map.entry("future issue instant", valid.replace("2026-10-09T00:01:00Z",
                        "2026-10-09T00:10:00Z")),
                Map.entry("stale issue instant", valid.replace("2026-10-09T00:01:00Z",
                        "2026-10-08T00:01:00Z")),
                Map.entry("malformed issue instant", valid.replace("2026-10-09T00:01:00Z", "invalid")),
                Map.entry("missing issuer", valid.replace(issuer, "")),
                Map.entry("wrong issuer", valid.replace(issuer,
                        "<a:Issuer>https://attacker.example.test/idp</a:Issuer>")),
                Map.entry("missing status", valid.replace(status, "")),
                Map.entry("nested status", valid.replace(status,
                        status.replace("/>", "><p:StatusCode Value='urn:example:other'/></p:StatusCode>"))));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(signed(caseUnderTest.getValue(), idpKey, "SAMLResponse",
                            begin.getPendingLogout().getRelayStateHandle()), source, idp),
                    caseUnderTest.getKey());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(signed(valid, idpKey, "SAMLResponse",
                        begin.getPendingLogout().getRelayStateHandle()), source, idp));
    }

    private static @NonNull SamlRedirectBindingMessage signed(@NonNull String xml, @NonNull KeyPair key)
            throws Exception {
        return signed(xml, key, "SAMLRequest", null);
    }

    private static @NonNull SamlRedirectBindingMessage signed(@NonNull String xml, @NonNull KeyPair key,
            @NonNull String field, @Nullable String relay) throws Exception {
        byte[] plain = xml.getBytes(StandardCharsets.UTF_8);
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] buffer = new byte[16384];
        deflater.setInput(plain);
        deflater.finish();
        int length = deflater.deflate(buffer);
        deflater.end();
        String query = field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOf(buffer, length)), StandardCharsets.UTF_8);
        if (relay != null) query += "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8);
        query += "&SigAlg=" + URLEncoder.encode(
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
