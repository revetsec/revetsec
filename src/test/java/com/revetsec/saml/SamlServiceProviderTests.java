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
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.w3c.dom.Element;
import com.revetsec.internal.xml.SecureXmlParser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlServiceProviderTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    @Test void serviceProviderAndIdentityProviderEntityIdsEnforceExactMaximum() {
        String maximum = "x".repeat(2048);
        assertInstanceOf(SamlServiceProvider.Builder.class, SamlServiceProvider.withEntityId(maximum));
        assertInstanceOf(SamlIdentityProvider.Builder.class, SamlIdentityProvider.withEntityId(maximum));
        String tooLong = maximum + "x";
        assertThrows(IllegalArgumentException.class, () -> SamlServiceProvider.withEntityId(tooLong));
        assertThrows(IllegalArgumentException.class, () -> SamlIdentityProvider.withEntityId(tooLong));
    }

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
        AtomicReference<SamlObserver.Outcome> completionOutcome = new AtomicReference<>();
        SamlObserver observer = new SamlObserver() {
            @Override public void didHandleOperation(@NonNull Operation operation,
                    @NonNull Outcome outcome, @NonNull Duration elapsed) {
                if (operation == Operation.COMPLETE_AUTHENTICATION) completionOutcome.set(outcome);
            }
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(replay).clock(CLOCK).observer(observer).build();
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
        assertEquals(SamlObserver.Outcome.SUCCEEDED, completionOutcome.get());
        assertEquals("alice", success.getAuthentication().getNameId().orElseThrow().getValue());
        assertEquals(false, success.getAuthentication().isUnsolicited());
        assertTrue(success.getAuthentication().getSubjectKey().isEmpty());
        assertEquals("tenant-one", success.getAuthentication().getIdentityProviderConnectionId());
        assertEquals(SamlAuthenticationResult.Reason.REPLAYED,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message, source, idp)).getReason());
    }

    @Test void signedResponseCannotSatisfyIdpSignedAssertionRequirement() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider strict = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("signed-assertion-policy")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).requireSignedAssertions(true).build();
        SamlIdentityProvider responseSigned = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("signed-assertion-policy")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(strict)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-assertion-policy"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        SamlPostBindingMessage responseOnly = message(SamlResponseSemanticsTests.signedXml(
                xml, true, false, key.getPrivate()), pending.getRelayStateHandle());
        assertEquals(SamlAuthenticationResult.Reason.SIGNATURE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(responseOnly, source, strict)).getReason());
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(responseOnly, source, responseSigned));
    }

    @Test void idpRequestSignaturePolicyRejectsUnsignedBeginWithoutSpKey() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider requiresSignedRequests = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("signed-request-policy")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).wantAuthnRequestsSigned(true).build();
        SamlIdentityProvider permitsUnsignedRequests = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("signed-request-policy")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        assertEquals(SamlAuthenticationRequestResult.Rejected.CONFIGURATION,
                sp.beginAuthenticationResult(requiresSignedRequests));
        SamlAuthenticationRequestResult.Prepared unsigned = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(permitsUnsignedRequests));
        assertTrue(!unsigned.getRedirectUri().toASCIIString().contains("Signature="));
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
        assertTrue(!SamlSubjectKey.fromPersistentNameId(new SamlNameId("alice", SamlNameId.PERSISTENT,
                "https://idp.example.test/", "https://sp.example.test/", "sp-original"))
                .toStableString().equals(identity.getSubjectKey().orElseThrow().toStableString()));
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
        String status = "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/></p:Status>";
        assertTrue(xml.contains(status));
        for (String malformedStatus : List.of(
                "<p:Status>unexpected<p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/></p:Status>",
                "<p:Status><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'>"
                        + "<p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                        + "</p:StatusCode></p:Status>",
                "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true'><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/></p:Status>",
                "<p:Status><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/>"
                        + "<p:StatusMessage>first</p:StatusMessage>"
                        + "<p:StatusMessage>second</p:StatusMessage></p:Status>",
                "<p:Status><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/>"
                        + "<p:StatusDetail/><p:StatusMessage>out of order</p:StatusMessage></p:Status>")) {
            assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            sp.completeAuthenticationResult(message(xml.replace(status, malformedStatus),
                                    pending.getRelayStateHandle()), source, idp)).getReason());
        }
        for (String malformedResponse : List.of(
                xml.replace(" InResponseTo='", " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true' InResponseTo='"),
                xml.replace("</p:Response>", "&#x2003;</p:Response>"))) {
            assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            sp.completeAuthenticationResult(message(malformedResponse,
                                    pending.getRelayStateHandle()), source, idp)).getReason());
        }
        for (String malformedIssuer : List.of(
                "<a:Issuer xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true'>" + IDP + "</a:Issuer>",
                "<a:Issuer Format='urn:example:wrong'>" + IDP + "</a:Issuer>")) {
            assertEquals(SamlAuthenticationResult.Reason.ISSUER,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            sp.completeAuthenticationResult(message(xml.replace(
                                    "<a:Issuer>" + IDP + "</a:Issuer>", malformedIssuer),
                                    pending.getRelayStateHandle()), source, idp)).getReason());
        }
        String duplicateMessage = xml.replace(status, "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/>"
                + "<p:StatusMessage>first</p:StatusMessage>"
                + "<p:StatusMessage>second</p:StatusMessage></p:Status>");
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                                duplicateMessage, true, false, key.getPrivate()),
                                pending.getRelayStateHandle()), source, idp)).getReason());
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
        String withDetail = xml.replace(status, "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/>"
                + "<p:StatusMessage>Partner detail</p:StatusMessage>"
                + "<p:StatusDetail><x:Hint xmlns:x='urn:example:status'/></p:StatusDetail>"
                + "</p:Status>");
        assertEquals(SamlAuthenticationResult.StatusCode.AUTHN_FAILED,
                assertInstanceOf(SamlAuthenticationResult.StatusReceived.class,
                        sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                                withDetail, true, false, key.getPrivate()), pending.getRelayStateHandle()),
                                source, idp)).getStatusCode());
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

    @Test void nonSuccessStatusKeepsEveryClassificationAndEnvelopeBoundary() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("status-boundary")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-status-boundary"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "status-cookie"), sealer, "status-cookie");
        String base = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("status:Success", "status:AuthnFailed");
        base = base.substring(0, base.indexOf("<a:Assertion")) + "</p:Response>";
        for (Map.Entry<String, SamlAuthenticationResult.StatusCode> entry : Map.ofEntries(
                Map.entry("AuthnFailed", SamlAuthenticationResult.StatusCode.AUTHN_FAILED),
                Map.entry("NoAuthnContext", SamlAuthenticationResult.StatusCode.NO_AUTHN_CONTEXT),
                Map.entry("RequestDenied", SamlAuthenticationResult.StatusCode.REQUEST_DENIED),
                Map.entry("Requester", SamlAuthenticationResult.StatusCode.REQUESTER),
                Map.entry("Responder", SamlAuthenticationResult.StatusCode.RESPONDER),
                Map.entry("VersionMismatch", SamlAuthenticationResult.StatusCode.VERSION_MISMATCH),
                Map.entry("UnknownPartnerStatus", SamlAuthenticationResult.StatusCode.OTHER)).entrySet()) {
            String xml = base.replace("status:AuthnFailed", "status:" + entry.getKey());
            SamlAuthenticationResult.StatusReceived result = assertInstanceOf(
                    SamlAuthenticationResult.StatusReceived.class,
                    sp.completeAuthenticationResult(message(xml, pending.getRelayStateHandle()), source, idp),
                    entry.getKey());
            assertEquals(entry.getValue(), result.getStatusCode(), entry.getKey());
        }
        String status = "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'/></p:Status>";
        String signedWithoutDestination = SamlResponseSemanticsTests.signedXml(
                base.replace(" Destination='" + ACS + "'", ""), true, false, key.getPrivate());
        assertEquals(SamlAuthenticationResult.Reason.REQUEST_BINDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(base.replace(pending.getRequestId(), "_wrong"),
                                pending.getRelayStateHandle()), source, idp)).getReason());
        for (String xml : List.of(
                base.replace("<a:Issuer>" + IDP + "</a:Issuer>", "<a:Issuer>https://other.test/</a:Issuer>"),
                base.replace("<a:Issuer>" + IDP + "</a:Issuer>", "")))
            assertEquals(SamlAuthenticationResult.Reason.ISSUER,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            sp.completeAuthenticationResult(message(xml, pending.getRelayStateHandle()),
                                    source, idp)).getReason());
        assertEquals(SamlAuthenticationResult.Reason.DESTINATION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(base.replace(ACS.toString(),
                                "https://other.test/acs"), pending.getRelayStateHandle()), source, idp))
                        .getReason());
        assertEquals(SamlAuthenticationResult.Reason.RESPONSE_AGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(base.replace("2026-10-09T00:01:00Z",
                                "2026-10-09T00:20:00Z"), pending.getRelayStateHandle()), source, idp))
                        .getReason());
        assertEquals(SamlAuthenticationResult.Reason.RESPONSE_AGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(base.replace("2026-10-09T00:01:00Z",
                                "2026-10-08T23:00:00Z"), pending.getRelayStateHandle()), source, idp))
                        .getReason());
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(base.replace(status, status.replace(
                                "status:AuthnFailed", "status:Success")), pending.getRelayStateHandle()),
                                source, idp)).getReason());
        assertEquals(SamlAuthenticationResult.Reason.DESTINATION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(signedWithoutDestination,
                                pending.getRelayStateHandle()), source, idp)).getReason());
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
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
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

    @Test void unsolicitedLoginHonorsTheShorterOfConfiguredAndTwoMinuteResponseAge() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache replay = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("age-boundary")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).allowUnsolicitedResponses(true).build();
        String response = SamlResponseSemanticsTests.BASE.replace(" InResponseTo='_request'", "");
        SamlServiceProvider longLimit = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(replay)
                .clock(CLOCK).clockSkew(Duration.ZERO).maximumResponseAge(Duration.ofMinutes(5)).build();
        String old = response.replace("2026-10-09T00:00:00Z", "2026-10-08T23:58:00Z");
        assertEquals(SamlAuthenticationResult.Reason.RESPONSE_AGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        longLimit.completeUnsolicitedAuthenticationResult(unsolicitedMessage(
                                SamlResponseSemanticsTests.signedXml(old, true, false, key.getPrivate())),
                                idp)).getReason());
        assertEquals(0, writes.get());

        SamlServiceProvider shortLimit = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS).replayCache(replay)
                .clock(CLOCK).clockSkew(Duration.ZERO).maximumResponseAge(Duration.ofSeconds(30)).build();
        String recent = SamlResponseSemanticsTests.signedXml(response, true, false, key.getPrivate());
        assertEquals(SamlAuthenticationResult.Reason.RESPONSE_AGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        shortLimit.completeUnsolicitedAuthenticationResult(unsolicitedMessage(recent),
                                idp)).getReason());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                longLimit.completeUnsolicitedAuthenticationResult(unsolicitedMessage(recent), idp));
        assertEquals(1, writes.get());
    }

    @Test void unsolicitedLoginRetainsReplayAcrossDisjointBearerConfirmationWindows() throws Exception {
        KeyPair key = rsa();
        AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-09T00:01:00Z"));
        Clock clock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
                return Clock.fixed(now.get(), zone);
            }
            @Override public @NonNull Instant instant() { return java.util.Objects.requireNonNull(now.get()); }
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 4))
                .clock(clock).clockSkew(Duration.ZERO).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).allowUnsolicitedResponses(true).build();
        String original = "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
                + "<a:SubjectConfirmationData Recipient='" + ACS + "' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'/></a:SubjectConfirmation>";
        String early = original.replace("00:05:00Z", "00:01:10Z");
        String future = original.replace("NotOnOrAfter='2026-10-09T00:05:00Z'",
                "NotBefore='2026-10-09T00:01:20Z' "
                        + "NotOnOrAfter='2026-10-09T00:01:50Z'");
        String xml = SamlResponseSemanticsTests.BASE.replace(" InResponseTo='_request'", "")
                .replace(original, early + future);
        SamlPostBindingMessage message = unsolicitedMessage(
                SamlResponseSemanticsTests.signedXml(xml, true, false, key.getPrivate()));

        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeUnsolicitedAuthenticationResult(message, idp));
        now.set(Instant.parse("2026-10-09T00:01:21Z"));
        assertEquals(SamlAuthenticationResult.Reason.REPLAYED,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeUnsolicitedAuthenticationResult(message, idp)).getReason());
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
                .replace(SamlResponseSemanticsTests.AUTHN.replace("2026-10-09T00:00:00Z",
                                "2026-10-09T00:01:00Z"),
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
        assertEquals(Instant.parse("2026-10-09T01:00:00Z"),
                identity.getSessionNotOnOrAfter().orElseThrow());
        assertEquals(identity.getSessionNotOnOrAfter(),
                identity.getSessionReference().getSessionNotOnOrAfter());
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

    private static @NonNull SamlPostBindingMessage unsolicitedMessage(@NonNull String xml) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
