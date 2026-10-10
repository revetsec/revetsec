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
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.w3c.dom.Element;
import com.revetsec.internal.xml.SecureXmlParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlServiceProviderTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    @Test void fractionalClockPendingStateOpensForLoginAndLogout() throws Exception {
        Clock fractional = Clock.fixed(Instant.parse("2026-10-09T00:01:00.123456789Z"), ZoneOffset.UTC);
        KeyPair signing = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/logout"))
                .signingPrivateKey(signing.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(fractional, 4))
                .clock(fractional).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("fractional-clock")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.example.test/logout"))
                .signingKeys(List.of(signing.getPublic()))
                .build();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-fractional"))
                .clock(fractional).build();
        PendingSamlAuthentication login = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        PendingSamlAuthenticationSource.Resolved loginState = assertInstanceOf(
                PendingSamlAuthenticationSource.Resolved.class,
                PendingSamlAuthenticationSource.fromSealedForm(
                        login.toSealedForm(sealer, "fractional-login"), sealer, "fractional-login")
                        .resolve(fractional, login.getRelayStateHandle(), Duration.ofSeconds(1)));
        assertEquals(login.getRequestId(), loginState.pending().getRequestId());

        SamlSessionReference session = new SamlSessionReference("fractional-clock", IDP,
                new SamlNameId("alice", SamlNameId.PERSISTENT, IDP, null), "session-1", null);
        PendingSamlLogout logout = assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, session)).getPendingLogout();
        PendingSamlLogoutSource.Resolved logoutState = assertInstanceOf(
                PendingSamlLogoutSource.Resolved.class,
                PendingSamlLogoutSource.fromSealedForm(
                        logout.toSealedForm(sealer, "fractional-logout"), sealer, "fractional-logout")
                        .resolve(fractional, logout.getRelayStateHandle(), Duration.ofSeconds(1)));
        assertEquals(logout.getRequestId(), logoutState.pending().getRequestId());
    }

    @Test void sealedBrowserLoginCompletesOnlyAfterSignatureAndReplayAdmission() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache replay = InMemorySamlReplayCache.withLimit(CLOCK, 4);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(replay).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("tenant-one").redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        SamlAuthenticationRequestResult.Prepared begin = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));
        assertTrue(begin.getRedirectUri().toASCIIString().contains("SAMLRequest="));
        PendingSamlAuthentication pending = begin.getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-pending"))
                .clock(CLOCK).build();
        String sealed = pending.toSealedForm(sealer, "saml-cookie");
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(sealed,
                sealer, "saml-cookie");
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        SamlPostBindingMessage message = message(SamlResponseSemanticsTests.signedXml(xml, true,
                false, key.getPrivate()), pending.getRelayStateHandle());
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message, source, idp));
        assertEquals("alice", success.getAuthentication().getNameId().orElseThrow().getValue());
        assertTrue(success.getAuthentication().getSubjectKey().isEmpty());
        assertEquals("tenant-one", success.getAuthentication().getIdentityProviderConnectionId());
        assertEquals(SamlAuthenticationResult.Reason.REPLAYED,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message, source, idp)).getReason());
    }

    @Test void persistentNameIdKeepsQualifiersInStableSubjectKey() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-persistent"))
                .clock(CLOCK).build();
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("<a:NameID>alice</a:NameID>",
                        "<a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' "
                        + "NameQualifier='https://idp.example.test/' SPNameQualifier='https://sp.example.test/'>"
                        + "alice</a:NameID>");
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(xml, true,
                        false, key.getPrivate()), pending.getRelayStateHandle()),
                        PendingSamlAuthenticationSource.fromSealedForm(
                                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie"), idp));
        SamlAuthentication identity = success.getAuthentication();
        assertEquals("https://idp.example.test/", identity.getNameId().orElseThrow()
                .getNameQualifier().orElseThrow());
        assertTrue(identity.getSubjectKey().orElseThrow().toStableString().contains("alice"));
        assertTrue(identity.getSubjectKey().orElseThrow().toString().contains("<redacted>"));
    }

    @Test void pendingFailurePrecedesXmlParsingAndCannotReleaseIdentity() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-pending-2"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource wrong = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "wrong-context");
        SamlPostBindingMessage malformed = message("<not-xml", pending.getRelayStateHandle());
        assertEquals(SamlAuthenticationResult.Reason.PENDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(malformed, wrong, idp)).getReason());
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(malformed, source, idp)).getReason());
    }

    @Test void atomicPendingStoreConsumesOnceAndBindsBrowserBeforeXml() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-store"))
                .clock(CLOCK).build();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 2);
        assertEquals(SamlPendingSaveResult.SAVED,
                pending.saveToResult(store, sealer, "saml-store-context", "browser-one",
                        java.time.Duration.ofSeconds(5)));
        assertEquals(SamlPendingSaveResult.ALREADY_PRESENT,
                pending.saveToResult(store, sealer, "saml-store-context", "browser-one",
                        java.time.Duration.ofSeconds(5)));
        SamlPostBindingMessage malformed = message("<not-xml", pending.getRelayStateHandle());
        PendingSamlAuthenticationSource wrong = PendingSamlAuthenticationSource.fromStore(
                store, "browser-two", sealer, "saml-store-context");
        assertEquals(SamlAuthenticationResult.Reason.PENDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(malformed, wrong, idp)).getReason());
        PendingSamlAuthenticationSource correct = PendingSamlAuthenticationSource.fromStore(
                store, "browser-one", sealer, "saml-store-context");
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(malformed, correct, idp)).getReason());
        assertEquals(SamlAuthenticationResult.Reason.PENDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(malformed, correct, idp)).getReason());
    }

    @Test void requestBoundNonSuccessStatusDistinguishesSignatureCoverage() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-status"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("status:Success", "status:AuthnFailed");
        xml = xml.substring(0, xml.indexOf("<a:Assertion")) + "</p:Response>";
        SamlAuthenticationResult.StatusReceived unsigned = assertInstanceOf(
                SamlAuthenticationResult.StatusReceived.class,
                sp.completeAuthenticationResult(message(xml, pending.getRelayStateHandle()), source, idp));
        assertEquals(SamlAuthenticationResult.StatusCode.AUTHN_FAILED, unsigned.getStatusCode());
        assertEquals(false, unsigned.isAuthenticated());
        SamlAuthenticationResult.StatusReceived signed = assertInstanceOf(
                SamlAuthenticationResult.StatusReceived.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(xml, true,
                        false, key.getPrivate()), pending.getRelayStateHandle()), source, idp));
        assertTrue(signed.isAuthenticated());
        String wrong = xml.replace(pending.getRequestId(), "_different");
        assertEquals(SamlAuthenticationResult.Reason.REQUEST_BINDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(wrong, pending.getRelayStateHandle()),
                                source, idp)).getReason());
    }

    @Test void postAuthnRequestCarriesVerifiableXmlSignatureAndSafeForm() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .signingPrivateKey(key.getPrivate()).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .postSingleSignOnService(URI.create("https://idp.example.test/post"))
                .signingKeys(List.of(key.getPublic())).wantAuthnRequestsSigned(true).build();
        SamlAuthenticationRequestResult.PostPrepared prepared = assertInstanceOf(
                SamlAuthenticationRequestResult.PostPrepared.class, sp.beginPostAuthenticationResult(idp));
        SamlPostForm form = prepared.getPostForm();
        assertEquals(URI.create("https://idp.example.test/post"), form.getAction());
        assertEquals("no-store", form.getHeaders().get("Cache-Control"));
        assertTrue(form.toHtml("abcdefghijklmnopqrstuvwxyz012345").contains("document.forms[0].submit()"));
        byte[] xml = Base64.getDecoder().decode(form.getFields().get("SAMLRequest"));
        Element request = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml)).getDocument().getDocumentElement();
        assertEquals(prepared.getPendingAuthentication().getRequestId(), request.getAttribute("ID"));
        request.setIdAttributeNS(null, "ID", true);
        Element signature = (Element) request.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        DOMValidateContext context = new DOMValidateContext(key.getPublic(), signature);
        context.setProperty("org.jcp.xml.dsig.secureValidation", true);
        assertTrue(XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context));
    }

    @Test void requestPolicySurvivesSealAndChecksFreshnessAndContext() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .postSingleSignOnService(URI.create("https://idp.example.test/post"))
                .signingKeys(List.of(key.getPublic())).build();
        SamlAuthenticationRequestOptions options = SamlAuthenticationRequestOptions.builder()
                .forceAuthn(true).requestedAuthnContextClassRefs(List.of("urn:example:password"))
                .applicationData("/local-home").build();
        SamlAuthenticationRequestResult.PostPrepared begin = assertInstanceOf(
                SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(idp, options));
        PendingSamlAuthentication pending = begin.getPendingAuthentication();
        byte[] requestXml = Base64.getDecoder().decode(begin.getPostForm().getFields().get("SAMLRequest"));
        Element request = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(requestXml)).getDocument().getDocumentElement();
        assertEquals("true", request.getAttribute("ForceAuthn"));
        assertEquals(1, request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion",
                "AuthnContextClassRef").getLength());
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-policy"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        String valid = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("<a:AuthnStatement AuthnInstant='2026-10-09T00:01:00Z'/>",
                        "<a:AuthnStatement AuthnInstant='2026-10-09T00:01:00Z'>"
                        + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:password"
                        + "</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>");
        String stale = valid.replace("AuthnInstant='2026-10-09T00:01:00Z'",
                "AuthnInstant='2026-10-08T23:50:00Z'");
        assertEquals(SamlAuthenticationResult.Reason.AUTHN_STATEMENT,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                                stale, true, false, key.getPrivate()), pending.getRelayStateHandle()),
                                source, idp)).getReason());
        assertEquals(SamlAuthenticationResult.Reason.AUTHN_STATEMENT,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                                valid.replace("urn:example:password", "urn:example:other"), true,
                                false, key.getPrivate()), pending.getRelayStateHandle()),
                                source, idp)).getReason());
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                        valid, true, false, key.getPrivate()), pending.getRelayStateHandle()), source, idp));
        assertEquals("/local-home", success.getApplicationData().orElseThrow());
    }

    @Test void unsolicitedLoginIsOptInAndNeverAcceptsRelayState() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider denied = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        SamlIdentityProvider enabled = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).allowUnsolicitedResponses(true).build();
        String xml = SamlResponseSemanticsTests.BASE.replace(" InResponseTo='_request'", "")
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        String signed = SamlResponseSemanticsTests.signedXml(xml, true, false, key.getPrivate());
        SamlPostBindingMessage noRelay = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse="
                        + java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                                signed.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8))
                        .getBytes(StandardCharsets.UTF_8),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        assertEquals(SamlAuthenticationResult.Reason.REQUEST_BINDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeUnsolicitedAuthenticationResult(noRelay, denied)).getReason());
        assertEquals(SamlAuthenticationResult.Reason.REQUEST_BINDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeUnsolicitedAuthenticationResult(message(signed, "some-relay"), enabled))
                        .getReason());
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeUnsolicitedAuthenticationResult(noRelay, enabled));
        assertTrue(success.getAuthentication().isUnsolicited());
    }

    @Test void signedAttributesAndSessionFieldsAreReleasedTogether() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-attributes"))
                .clock(CLOCK).build();
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("<a:AuthnStatement AuthnInstant='2026-10-09T00:01:00Z'/>",
                        "<a:AuthnStatement AuthnInstant='2026-10-09T00:01:00Z' SessionIndex='session-123' "
                        + "SessionNotOnOrAfter='2026-10-09T01:00:00Z'>"
                        + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:mfa</a:AuthnContextClassRef>"
                        + "</a:AuthnContext></a:AuthnStatement>"
                        + "<a:AttributeStatement><a:Attribute Name='department'>"
                        + "<a:AttributeValue>Engineering</a:AttributeValue>"
                        + "</a:Attribute></a:AttributeStatement>");
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(xml, true,
                        false, key.getPrivate()), pending.getRelayStateHandle()),
                        PendingSamlAuthenticationSource.fromSealedForm(
                                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie"), idp));
        SamlAuthentication identity = success.getAuthentication();
        assertEquals(List.of("Engineering"), identity.getAttributeValues("department"));
        assertEquals("session-123", identity.getSessionReference().getSessionIndex().orElseThrow());
        assertEquals("urn:example:mfa", identity.getAuthnContextClassRef().orElseThrow());
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String xml, @NonNull String relay) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded + "&RelayState=" + relay)
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
