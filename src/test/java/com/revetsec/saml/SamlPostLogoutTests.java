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
import com.revetsec.internal.xml.SamlXmlWriter;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.*;

/** POST logout qualification independent of the outbound production signer. */
final class SamlPostLogoutTests {
    private static final @NonNull String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final @NonNull String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final @NonNull String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull URI SP_LOGOUT = URI.create("https://sp.example.test/logout");
    private static final @NonNull URI IDP_LOGOUT = URI.create("https://idp.example.test/logout");
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String ISSUER = "<a:Issuer>" + IDP + "</a:Issuer>";
    private static final @NonNull String NAME = "<a:NameID Format='" + SamlNameId.PERSISTENT
            + "' NameQualifier='" + IDP + "' SPNameQualifier='" + SP
            + "' SPProvidedID='original'>alice</a:NameID>";
    private static final @NonNull String INDEX = "<p:SessionIndex>session-123</p:SessionIndex>";

    @Test void logoutDecoderPreservesKindWithoutOpeningTheLoginRequestBoundary() {
        for (String field : List.of("SAMLRequest", "SAMLResponse")) {
            byte[] body = formBody(field, "<x/>", "opaque");
            SamlPostBindingMessage parsed = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                    SamlPostBindingMessage.fromLogoutFormBodyResult(body,
                            List.of("application/x-www-form-urlencoded; charset=UTF-8"), null)).getMessage();
            assertEquals(field.equals("SAMLRequest") ? SamlPostBindingMessage.Kind.REQUEST
                    : SamlPostBindingMessage.Kind.RESPONSE, parsed.getKind());
            assertEquals("opaque", parsed.getRelayState().orElseThrow());
            assertFalse(parsed.toString().contains("opaque"));
            assertFalse(parsed.toString().contains("<x/>"));
        }
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                SamlPostBindingMessage.fromFormBodyResult(formBody("SAMLRequest", "<x/>", null),
                        List.of("application/x-www-form-urlencoded"), null));
        assertEquals(SamlPostBindingMessage.Kind.RESPONSE,
                assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                        SamlPostBindingMessage.fromFormBodyResult(formBody("SAMLResponse", "<x/>", null),
                                List.of("application/x-www-form-urlencoded"), null)).getMessage().getKind());
        String response = new String(formBody("SAMLResponse", "<x/>", null), StandardCharsets.UTF_8);
        String request = new String(formBody("SAMLRequest", "<x/>", null), StandardCharsets.UTF_8);
        for (String invalid : List.of(response + "&" + request, request + "&" + request,
                request + "&RelayState=one&RelayState=two", request + "&SigAlg=x", request + "&"))
            assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                    SamlPostBindingMessage.fromLogoutFormBodyResult(invalid.getBytes(StandardCharsets.UTF_8),
                            List.of("application/x-www-form-urlencoded"), null), invalid);
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(formBody("SAMLRequest", "<x/>", null),
                        List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"), null));
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(formBody("SAMLRequest", "<x/>", null),
                        List.of("application/x-www-form-urlencoded"), "SAMLResponse=x"));
    }

    @Test void outboundPostRequestIsRootSignedAndCarriesExactSessionAndPendingState() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
        SamlIdentityProvider idp = identityProvider(key);
        SamlLogoutPostResult.Prepared begin = begin(sp, idp);
        SamlPostForm form = begin.getPostForm();
        assertEquals(IDP_LOGOUT, form.getAction());
        assertEquals(List.of("RelayState", "SAMLRequest"), form.getFields().keySet().stream().sorted().toList());
        assertEquals(begin.getPendingLogout().getRelayStateHandle(), form.getFields().get("RelayState"));
        Element root = verifyRoot(Base64.getDecoder().decode(form.getFields().get("SAMLRequest")), key.getPublic());
        assertEquals("LogoutRequest", root.getLocalName());
        assertEquals(begin.getPendingLogout().getRequestId(), root.getAttribute("ID"));
        assertEquals(IDP_LOGOUT.toASCIIString(), root.getAttribute("Destination"));
        assertEquals(SP, root.getElementsByTagNameNS(ASSERTION, "Issuer").item(0).getTextContent());
        Element name = assertInstanceOf(Element.class, root.getElementsByTagNameNS(ASSERTION, "NameID").item(0));
        assertEquals("alice", name.getTextContent());
        assertEquals(SamlNameId.PERSISTENT, name.getAttribute("Format"));
        assertEquals(IDP, name.getAttribute("NameQualifier"));
        assertEquals(SP, name.getAttribute("SPNameQualifier"));
        assertEquals("original", name.getAttribute("SPProvidedID"));
        assertEquals("session-123", root.getElementsByTagNameNS(PROTOCOL, "SessionIndex").item(0).getTextContent());
        assertEquals("no-store", form.getHeaders().get("Cache-Control"));
        assertEquals("no-referrer", form.getHeaders().get("Referrer-Policy"));
        assertTrue(form.toHtml(null).contains("name=\"SAMLRequest\""));
        assertFalse(form.toString().contains("alice"));
        assertInstanceOf(SamlLogoutPostResult.Rejected.class, sp.beginPostLogoutResult(idp,
                new SamlSessionReference("other-tenant", IDP, session().getNameId(), "session-123", null)));
    }

    @Test void postRequestReleasesOnlyCheckedSessionIdentifiersAfterAtomicReplayAdmission() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
        SamlIdentityProvider idp = identityProvider(key);
        SamlPostBindingMessage input = post("SAMLRequest", signed(request("_idp-request"), key.getPrivate()),
                "opaque-state");
        SamlLogoutRequest checked = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(input, idp)).getRequest();
        assertEquals("tenant-one", checked.getIdentityProviderConnectionId());
        assertEquals("_idp-request", checked.getRequestId());
        assertEquals("alice", checked.getNameId().getValue());
        assertEquals("original", checked.getNameId().getSpProvidedId().orElseThrow());
        assertEquals(List.of("session-123"), checked.getSessionIndexes());
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class, sp.acceptLogoutRequestResult(input, idp));
        SamlPostForm response = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                sp.respondToPostLogoutRequestResult(checked, idp, SamlLogoutStatus.SUCCESS)).getPostForm();
        assertEquals(IDP_LOGOUT, response.getAction());
        assertEquals("opaque-state", response.getFields().get("RelayState"));
        assertFalse(response.getFields().containsKey("SAMLRequest"));
        Element root = verifyRoot(Base64.getDecoder().decode(response.getFields().get("SAMLResponse")), key.getPublic());
        assertEquals("LogoutResponse", root.getLocalName());
        assertEquals("_idp-request", root.getAttribute("InResponseTo"));
        assertEquals(SamlLogoutStatus.SUCCESS.uri(),
                assertInstanceOf(Element.class, root.getElementsByTagNameNS(PROTOCOL, "StatusCode").item(0))
                        .getAttribute("Value"));
        assertTrue(response.toHtml(null).contains("name=\"SAMLResponse\""));
    }

    @Test void signedRequestSemanticMutationsNeverReachTheReplayStore() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        SamlIdentityProvider idp = identityProvider(key);
        String valid = request("_request-mutations");
        List<String> invalid = List.of(
                valid.replace("Version='2.0'", "Version='1.1'"),
                valid.replace(SP_LOGOUT.toASCIIString(), SP_LOGOUT + "-suffix"),
                valid.replace("_request-mutations", "invalid:id"),
                valid.replace("_request-mutations", "_" + "x".repeat(256)),
                valid.replace("2026-10-09T00:01:00Z", "2026-10-09T00:10:00Z"),
                valid.replace("2026-10-09T00:01:00Z", "2026-10-08T23:53:00Z"),
                valid.replace("Version='2.0'", "Version='2.0' NotOnOrAfter='2026-10-09T00:01:00Z'"),
                valid.replace(ISSUER, "<a:Issuer>" + IDP + "-suffix</a:Issuer>"),
                valid.replace(ISSUER, "<a:Issuer Format='urn:example:wrong'>" + IDP + "</a:Issuer>"),
                valid.replace(ISSUER, ISSUER + ISSUER),
                valid.replace(NAME, ""),
                valid.replace(NAME, "<a:NameID/>"),
                valid.replace("alice", "a".repeat(4097)),
                valid.replace("SPProvidedID='original'", "SPProvidedID='" + "a".repeat(2049) + "'"),
                valid.replace(INDEX, INDEX.repeat(33)),
                valid.replace("session-123", "a".repeat(2049)),
                valid.replace(INDEX, "<p:SessionIndex/>"),
                valid.replace(NAME, NAME + "&#x2003;"),
                valid.replace(NAME, "<a:NameID xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true'>alice</a:NameID>"));
        for (int i = 0; i < invalid.size(); i++)
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(post("SAMLRequest", signed(invalid.get(i), key.getPrivate()), null), idp),
                    "mutation " + i);
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed(valid, key.getPrivate()), null), idp));
        assertEquals(1, writes.get());
    }

    @Test void unsignedTamperedUntrustedAndWrappedSignaturesCannotAdmitARequest() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        SamlIdentityProvider idp = identityProvider(key);
        String valid = request("_signature-boundary");
        String signed = signed(valid, key.getPrivate());
        String signature = signature(signed);
        List<String> invalid = List.of(valid, signed.replace("alice", "mallory"),
                signed(valid, rsa().getPrivate()),
                signed.replace(signature, signature + signature),
                signed.replace(signature, "").replace("</p:LogoutRequest>", signature + "</p:LogoutRequest>"),
                signed.replace("URI=\"#_signature-boundary\"", "URI=\"#not-the-root\""),
                signed.replace("URI=\"#_signature-boundary\"", "URI=\"https://attacker.example.test/root\""),
                signed.replace("URI=\"#_signature-boundary\"", "URI=\"\""),
                valid.replace(NAME, NAME + "<p:Extensions>" + signed.replace("_signature-boundary", "_nested")
                        + "</p:Extensions>"),
                "<p:Extensions xmlns:p='" + PROTOCOL + "'>" + signed + "</p:Extensions>",
                signed.replace(INDEX, "<p:SessionIndex ID=\"_signature-boundary\">session-123</p:SessionIndex>"));
        for (int i = 0; i < invalid.size(); i++)
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(post("SAMLRequest", invalid.get(i), null), idp), "signature case " + i);
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed, null), idp));
        assertEquals(1, writes.get());
    }

    @Test void validSignatureCoveringADescendantCannotAuthorizeAnUnsignedLogoutRoot() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        String inner = signed(request("_inner"), key.getPrivate());
        String wrapped = request("_outer").replace(NAME, NAME + "<p:Extensions>" + inner + "</p:Extensions>");
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", wrapped, null), identityProvider(key)));
        assertEquals(0, writes.get());
    }

    @Test void postCompletionCorrelatesBrowserStateResponseAndIdpBeforeReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        SamlIdentityProvider idp = identityProvider(key);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        PendingSamlLogoutSource source = source(pending);
        String valid = response("_response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        for (String invalid : List.of(
                valid.replace(SP_LOGOUT.toASCIIString(), SP_LOGOUT + "-suffix"),
                valid.replace(pending.getRequestId(), "_wrong-request"),
                valid.replace("_response", "_" + "x".repeat(256)),
                valid.replace(ISSUER, "<a:Issuer>" + IDP + "-suffix</a:Issuer>"),
                valid.replace(ISSUER, ISSUER + ISSUER),
                valid.replace("2026-10-09T00:01:00Z", "2026-10-08T00:01:00Z"),
                valid.replace("Version='2.0'", "Version='1.1'"),
                valid.replace("<p:Status>", "<p:Status>attacker"),
                valid.replace("<p:Status>", "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:nil='true'>")))
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(post("SAMLResponse", signed(invalid, key.getPrivate()),
                            pending.getRelayStateHandle()), source, idp));
        String signed = signed(valid, key.getPrivate());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(post("SAMLResponse", signed, "wrong-state"), source, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(post("SAMLResponse", signed, null), source, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(post("SAMLRequest", signed, pending.getRelayStateHandle()), source, idp));
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(post("SAMLResponse", signed, pending.getRelayStateHandle()), source, idp));
        assertEquals(1, writes.get());
    }

    @Test void responseSignatureFailuresDoNotConsumeAtomicPendingState() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        AtomicInteger consumes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        SamlIdentityProvider idp = identityProvider(key);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        StateSealer sealer = sealer();
        InMemoryPendingSamlAuthenticationStore backing = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 8);
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(backing, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlAuthenticationStore store = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull String record, @NonNull Instant expiresAt,
                    @NonNull Duration remaining) {
                return backing.save(browserBinding, handle, record, expiresAt, remaining);
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Duration remaining) {
                SamlPendingConsumeResult result = backing.consume(browserBinding, handle, remaining);
                if (result instanceof SamlPendingConsumeResult.Consumed) consumes.incrementAndGet();
                return result;
            }
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Predicate<@NonNull String> matches,
                    @NonNull Duration remaining) {
                SamlPendingConsumeResult result = backing.consumeIfMatches(browserBinding, handle, matches, remaining);
                if (result instanceof SamlPendingConsumeResult.Consumed) consumes.incrementAndGet();
                return result;
            }
        };
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
        String valid = response("_atomic-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        String signed = signed(valid, key.getPrivate());
        for (String invalid : List.of(valid, signed.replace("Value=\"" + SamlLogoutStatus.SUCCESS.uri() + "\"",
                "Value=\"urn:example:tampered\""), signed(valid, rsa().getPrivate()),
                signed.replace(signature(signed), signature(signed) + signature(signed))))
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(post("SAMLResponse", invalid, pending.getRelayStateHandle()), source, idp));
        assertEquals(0, consumes.get());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(post("SAMLResponse", signed, pending.getRelayStateHandle()), source, idp));
        assertEquals(1, consumes.get());
        assertEquals(1, writes.get());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(post("SAMLResponse", signed, pending.getRelayStateHandle()), source, idp));
        assertEquals(1, writes.get());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> signedInvalidResponsesPreserveAtomicPendingState() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            for (String mutation : List.of("issuer", "destination", "version", "malformed ID", "oversized ID",
                    "expired age", "future issue", "missing status", "empty status code", "nested status",
                    "nilled status", "misdeclared status", "duplicate issuer", "issuer order", "unexpected text",
                    "wrong root", "response type", "InResponseTo"))
                tests.add(DynamicTest.dynamicTest((usePost ? "POST" : "Redirect") + ": " + mutation,
                        () -> invalidResponsePreservesPending(mutation, usePost)));
        return tests;
    }

    private static void invalidResponsePreservesPending(@NonNull String mutation, boolean usePost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        TrackingPendingStore store = new TrackingPendingStore();
        StateSealer sealer = sealer();
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
        String valid = response("_semantic-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        String invalid = switch (mutation) {
            case "issuer" -> valid.replace(ISSUER, "<a:Issuer>" + IDP + "-other</a:Issuer>");
            case "destination" -> valid.replace(SP_LOGOUT.toASCIIString(), SP_LOGOUT + "-other");
            case "version" -> valid.replace("Version='2.0'", "Version='1.1'");
            case "malformed ID" -> valid.replace("ID='_semantic-response'", "ID='invalid:id'");
            case "oversized ID" -> valid.replace("ID='_semantic-response'", "ID='" + "_" + "x".repeat(256) + "'");
            case "expired age" -> valid.replace(CLOCK.instant().toString(), "2026-10-08T23:53:00Z");
            case "future issue" -> valid.replace(CLOCK.instant().toString(), "2026-10-09T00:04:00.000000001Z");
            case "missing status" -> valid.replace("<p:Status><p:StatusCode Value='" + SamlLogoutStatus.SUCCESS.uri()
                    + "'/></p:Status>", "");
            case "empty status code" -> valid.replace("Value='" + SamlLogoutStatus.SUCCESS.uri() + "'", "Value=''");
            case "nested status" -> valid.replace("<p:StatusCode Value='" + SamlLogoutStatus.SUCCESS.uri() + "'/>",
                    "<p:StatusCode Value='" + SamlLogoutStatus.SUCCESS.uri() + "'><p:StatusCode Value='"
                            + SamlLogoutStatus.RESPONDER.uri() + "'/></p:StatusCode>");
            case "nilled status" -> valid.replace("<p:Status>",
                    "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:nil='true'>");
            case "misdeclared status" -> valid.replace("<p:Status>",
                    "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>");
            case "duplicate issuer" -> valid.replace(ISSUER, ISSUER + ISSUER);
            case "issuer order" -> valid.replace(ISSUER, "").replace("</p:Status>", "</p:Status>" + ISSUER);
            case "unexpected text" -> valid.replace("<p:Status>", "<p:Status>attacker");
            case "wrong root" -> valid.replace("p:LogoutResponse", "p:LogoutRequest");
            case "response type" -> valid.replace("Version='2.0'",
                    "Version='2.0' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'");
            case "InResponseTo" -> valid.replace("InResponseTo='" + pending.getRequestId() + "'", "InResponseTo='_wrong-request'");
            default -> throw new IllegalArgumentException("Unknown response mutation");
        };
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, invalid, key, usePost));
        assertEquals(0, store.consumes.get(), "a rejected response must leave the pending record intact");
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, valid, key, usePost));
        assertEquals(1, store.consumes.get());
        assertEquals(1, writes.get());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, valid, key, usePost));
        assertEquals(1, store.consumes.get());
        assertEquals(1, writes.get());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> mismatchedPendingBindingsPreserveAtomicPendingState() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            for (String mismatch : List.of("SP entity", "connection", "IdP entity", "endpoint", "context", "browser binding"))
                tests.add(DynamicTest.dynamicTest((usePost ? "POST" : "Redirect") + ": " + mismatch,
                        () -> mismatchedPendingPreservesState(mismatch, usePost)));
        return tests;
    }

    private static void mismatchedPendingPreservesState(@NonNull String mismatch, boolean usePost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes));
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        TrackingPendingStore store = new TrackingPendingStore();
        StateSealer sealer = sealer();
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
        SamlServiceProvider wrongSp = sp;
        SamlIdentityProvider wrongIdp = idp;
        PendingSamlLogoutSource wrongSource = source;
        String valid = response("_pending-binding-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        String candidate = valid;
        switch (mismatch) {
            case "SP entity" -> wrongSp = SamlServiceProvider.withEntityId(SP + "-other")
                    .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                    .singleLogoutServiceUrl(SP_LOGOUT).postSingleLogoutServiceUrl(SP_LOGOUT)
                    .signingPrivateKey(key.getPrivate()).replayCache(counting(writes)).clock(CLOCK).build();
            case "connection", "IdP entity" -> {
                String wrongEntity = mismatch.equals("IdP entity") ? IDP + "-other" : IDP;
                String wrongConnection = mismatch.equals("connection") ? "tenant-two" : "tenant-one";
                wrongIdp = SamlIdentityProvider.withEntityId(wrongEntity).connectionId(wrongConnection)
                        .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                        .redirectSingleLogoutService(IDP_LOGOUT).postSingleLogoutService(IDP_LOGOUT)
                        .signingKeys(List.of(key.getPublic())).build();
                if (mismatch.equals("IdP entity")) candidate = valid.replace(ISSUER,
                        "<a:Issuer>" + wrongEntity + "</a:Issuer>");
            }
            case "endpoint" -> {
                URI wrongEndpoint = URI.create(SP_LOGOUT + "-other");
                wrongSp = SamlServiceProvider.withEntityId(SP)
                        .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                        .singleLogoutServiceUrl(wrongEndpoint).postSingleLogoutServiceUrl(wrongEndpoint)
                        .signingPrivateKey(key.getPrivate()).replayCache(counting(writes)).clock(CLOCK).build();
                candidate = valid.replace(SP_LOGOUT.toASCIIString(), wrongEndpoint.toASCIIString());
            }
            case "context" -> wrongSource = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "wrong-context");
            case "browser binding" -> wrongSource = PendingSamlLogoutSource.fromStore(store, "wrong-browser", sealer, "post-logout");
            default -> throw new IllegalArgumentException("Unknown pending mismatch");
        }
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(wrongSp, wrongIdp, pending, wrongSource, candidate, key, usePost));
        assertEquals(0, store.consumes.get());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, valid, key, usePost));
        assertEquals(1, store.consumes.get());
        assertEquals(1, writes.get());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, valid, key, usePost));
        assertEquals(1, store.consumes.get());
        assertEquals(1, writes.get());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> responsesExpiringDuringPendingValidationPreserveState() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            tests.add(DynamicTest.dynamicTest(usePost ? "POST" : "Redirect",
                    () -> responseExpiringDuringPendingValidation(usePost)));
        return tests;
    }

    private static void responseExpiringDuringPendingValidation(boolean usePost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        MutableClock clock = new MutableClock(CLOCK.instant());
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes), clock, Duration.ofSeconds(1), Duration.ZERO);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        TrackingPendingStore backing = new TrackingPendingStore(clock);
        AtomicInteger lookups = new AtomicInteger();
        PendingSamlAuthenticationStore store = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull String record, @NonNull Instant expiresAt,
                    @NonNull Duration remaining) {
                return backing.save(browserBinding, handle, record, expiresAt, remaining);
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Duration remaining) {
                advanceBeforeFirstLookup();
                return backing.consume(browserBinding, handle, remaining);
            }
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Predicate<@NonNull String> matches,
                    @NonNull Duration remaining) {
                advanceBeforeFirstLookup();
                return backing.consumeIfMatches(browserBinding, handle, matches, remaining);
            }
            private void advanceBeforeFirstLookup() {
                if (lookups.getAndIncrement() == 0) clock.set(CLOCK.instant().plusSeconds(1));
            }
        };
        StateSealer sealer = sealer();
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
        String expiring = response("_expiring-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, expiring, key, usePost));
        assertEquals(CLOCK.instant().plusSeconds(1), clock.instant());
        assertEquals(0, backing.consumes.get());
        assertEquals(0, writes.get());
        String fresh = response("_fresh-after-expiry", pending.getRequestId(), SamlLogoutStatus.SUCCESS)
                .replace(CLOCK.instant().toString(), clock.instant().toString());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, fresh, key, usePost));
        assertEquals(1, backing.consumes.get());
        assertEquals(1, writes.get());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, fresh, key, usePost));
        assertEquals(1, backing.consumes.get());
        assertEquals(1, writes.get());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedNonSuccessStatusesConsumePendingOnce() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            tests.add(DynamicTest.dynamicTest(usePost ? "POST" : "Redirect", () -> {
                KeyPair key = rsa();
                SamlIdentityProvider idp = identityProvider(key);
                AtomicInteger writes = new AtomicInteger();
                SamlServiceProvider sp = provider(key, counting(writes));
                PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
                TrackingPendingStore store = new TrackingPendingStore();
                StateSealer sealer = sealer();
                assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                        "post-logout", "browser-secret", Duration.ofSeconds(5)));
                PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
                String nonSuccess = response("_non-success-store", pending.getRequestId(), SamlLogoutStatus.RESPONDER);
                assertInstanceOf(SamlLogoutResult.StatusReceived.class,
                        completeCryptographicallyCheckedLogout(sp, idp, pending, source, nonSuccess, key, usePost));
                assertEquals(1, store.consumes.get());
                assertEquals(1, writes.get());
                assertInstanceOf(SamlLogoutResult.Rejected.class,
                        completeCryptographicallyCheckedLogout(sp, idp, pending, source, nonSuccess, key, usePost));
                assertEquals(1, store.consumes.get());
                assertEquals(1, writes.get());
            }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> failuresAfterConfirmedPendingConsumptionAreIndeterminate() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            for (boolean clockFailure : List.of(false, true))
                tests.add(DynamicTest.dynamicTest((usePost ? "POST" : "Redirect") + ": "
                        + (clockFailure ? "clock failure" : "response expiry"),
                        () -> postConsumptionFailure(usePost, clockFailure)));
        return tests;
    }

    private static void postConsumptionFailure(boolean usePost, boolean clockFailure) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        class PostConsumptionClock extends Clock {
            private @NonNull Instant now = CLOCK.instant();
            private boolean failing;
            @Override public @NonNull Instant instant() {
                if (failing) throw new IllegalStateException("Clock unavailable after pending consumption");
                return now;
            }
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        }
        PostConsumptionClock clock = new PostConsumptionClock();
        AtomicInteger writes = new AtomicInteger();
        SamlServiceProvider sp = provider(key, counting(writes), clock, Duration.ofSeconds(1), Duration.ZERO);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        TrackingPendingStore backing = new TrackingPendingStore(clock);
        PendingSamlAuthenticationStore store = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull String record, @NonNull Instant expiresAt,
                    @NonNull Duration remaining) {
                return backing.save(browserBinding, handle, record, expiresAt, remaining);
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Duration remaining) {
                return failAfterConsumption(backing.consume(browserBinding, handle, remaining));
            }
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Predicate<@NonNull String> matches,
                    @NonNull Duration remaining) {
                return failAfterConsumption(backing.consumeIfMatches(browserBinding, handle, matches, remaining));
            }
            private @NonNull SamlPendingConsumeResult failAfterConsumption(@NonNull SamlPendingConsumeResult result) {
                if (result instanceof SamlPendingConsumeResult.Consumed) {
                    if (clockFailure) clock.failing = true;
                    else clock.now = CLOCK.instant().plusSeconds(1);
                }
                return result;
            }
        };
        StateSealer sealer = sealer();
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(store, "browser-secret", sealer, "post-logout");
        String response = response("_post-consumption-failure", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        assertInstanceOf(SamlLogoutResult.Indeterminate.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, response, key, usePost));
        assertEquals(1, backing.consumes.get());
        assertEquals(0, writes.get());
        clock.failing = false;
        String fresh = response("_fresh-after-consumption", pending.getRequestId(), SamlLogoutStatus.SUCCESS)
                .replace(CLOCK.instant().toString(), clock.instant().toString());
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                completeCryptographicallyCheckedLogout(sp, idp, pending, source, fresh, key, usePost));
        assertEquals(1, backing.consumes.get());
        assertEquals(0, writes.get());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> replayFailuresPreserveConfirmedPendingConsumptionOutcome() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            for (boolean useStore : List.of(false, true))
                for (String failure : List.of("already present", "capacity refused", "unavailable", "indeterminate", "null", "throws"))
                    tests.add(DynamicTest.dynamicTest((usePost ? "POST" : "Redirect") + ": "
                            + (useStore ? "stored pending" : "sealed pending") + ", " + failure,
                            () -> replayFailureAfterPendingConsumption(usePost, useStore, failure)));
        return tests;
    }

    private static void replayFailureAfterPendingConsumption(boolean usePost, boolean useStore,
            @NonNull String failure) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        AtomicInteger replayCalls = new AtomicInteger();
        SamlReplayCache replay = (cacheKey, expiresAt, remaining) -> {
            replayCalls.incrementAndGet();
            return switch (failure) {
                case "already present" -> SamlReplayCache.MarkResult.ALREADY_PRESENT;
                case "capacity refused" -> SamlReplayCache.MarkResult.CAPACITY_REFUSED;
                case "unavailable" -> SamlReplayCache.MarkResult.UNAVAILABLE;
                case "indeterminate" -> SamlReplayCache.MarkResult.INDETERMINATE;
                case "null" -> returningNullReplayCache().markIfAbsent(cacheKey, expiresAt, remaining);
                case "throws" -> throw new IllegalStateException("Uncertain replay-cache write");
                default -> throw new IllegalArgumentException("Unknown replay failure");
            };
        };
        SamlServiceProvider sp = provider(key, replay);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        TrackingPendingStore store = new TrackingPendingStore();
        StateSealer sealer = sealer();
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer,
                "post-logout", "browser-secret", Duration.ofSeconds(5)));
        PendingSamlLogoutSource source = useStore ? PendingSamlLogoutSource.fromStore(store,
                "browser-secret", sealer, "post-logout") : source(pending);
        String response = response("_replay-failure", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
        SamlLogoutResult result = completeCryptographicallyCheckedLogout(sp, idp, pending, source, response, key, usePost);
        if (useStore || List.of("indeterminate", "null", "throws").contains(failure))
            assertInstanceOf(SamlLogoutResult.Indeterminate.class, result);
        else if (failure.equals("already present")) assertInstanceOf(SamlLogoutResult.Rejected.class, result);
        else assertInstanceOf(SamlLogoutResult.Unavailable.class, result);
        assertEquals(useStore ? 1 : 0, store.consumes.get());
        assertEquals(1, replayCalls.get());
        if (useStore) {
            String fresh = response("_fresh-after-replay-failure", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    completeCryptographicallyCheckedLogout(sp, idp, pending, source, fresh, key, usePost));
            assertEquals(1, store.consumes.get());
            assertEquals(1, replayCalls.get());
        }
    }

    @Test void requestAndResponseReplaysShareFencesAcrossPostAndRedirectBindings() throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        for (boolean postFirst : List.of(true, false)) {
            SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
            String xml = request("_shared-request");
            SamlPostBindingMessage post = post("SAMLRequest", signed(xml, key.getPrivate()), null);
            SamlRedirectBindingMessage redirect = redirect("SAMLRequest", xml, null, key.getPrivate());
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class, postFirst
                    ? sp.acceptLogoutRequestResult(post, idp) : sp.acceptLogoutRequestResult(redirect, idp));
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class, postFirst
                    ? sp.acceptLogoutRequestResult(redirect, idp) : sp.acceptLogoutRequestResult(post, idp));
            PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
            PendingSamlLogoutSource source = source(pending);
            String response = response("_shared-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
            SamlPostBindingMessage postResponse = post("SAMLResponse", signed(response, key.getPrivate()), pending.getRelayStateHandle());
            SamlRedirectBindingMessage redirectResponse = redirect("SAMLResponse", response, pending.getRelayStateHandle(), key.getPrivate());
            assertInstanceOf(SamlLogoutResult.Succeeded.class, postFirst
                    ? sp.completeLogoutResult(postResponse, source, idp) : sp.completeLogoutResult(redirectResponse, source, idp));
            assertInstanceOf(SamlLogoutResult.Rejected.class, postFirst
                    ? sp.completeLogoutResult(redirectResponse, source, idp) : sp.completeLogoutResult(postResponse, source, idp));
        }
    }

    @Test void uncertainOrFailedReplayAdmissionCannotReleaseRequestsOrSuccess() throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        for (SamlReplayCache.MarkResult outcome : SamlReplayCache.MarkResult.values()) {
            SamlServiceProvider sp = provider(key, (replayKey, expiry, remaining) -> outcome);
            SamlLogoutRequestResult request = sp.acceptLogoutRequestResult(post("SAMLRequest",
                    signed(request("_store-request"), key.getPrivate()), null), idp);
            PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
            SamlLogoutResult response = sp.completeLogoutResult(post("SAMLResponse",
                    signed(response("_store-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS), key.getPrivate()),
                    pending.getRelayStateHandle()), source(pending), idp);
            switch (outcome) {
                case MARKED -> {
                    assertInstanceOf(SamlLogoutRequestResult.Accepted.class, request);
                    assertInstanceOf(SamlLogoutResult.Succeeded.class, response);
                }
                case ALREADY_PRESENT -> {
                    assertInstanceOf(SamlLogoutRequestResult.Rejected.class, request);
                    assertInstanceOf(SamlLogoutResult.Rejected.class, response);
                }
                case CAPACITY_REFUSED, UNAVAILABLE -> {
                    assertInstanceOf(SamlLogoutRequestResult.Unavailable.class, request);
                    assertInstanceOf(SamlLogoutResult.Unavailable.class, response);
                }
                case INDETERMINATE -> {
                    assertInstanceOf(SamlLogoutRequestResult.Indeterminate.class, request);
                    assertInstanceOf(SamlLogoutResult.Indeterminate.class, response);
                }
            }
        }
        for (SamlReplayCache replay : List.of(
                returningNullReplayCache(),
                (SamlReplayCache) (replayKey, expiry, remaining) -> { throw new IllegalStateException("uncertain write"); })) {
            SamlServiceProvider sp = provider(key, replay);
            assertInstanceOf(SamlLogoutRequestResult.Indeterminate.class,
                    sp.acceptLogoutRequestResult(post("SAMLRequest", signed(request("_uncertain"), key.getPrivate()), null), idp));
            PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
            assertInstanceOf(SamlLogoutResult.Indeterminate.class,
                    sp.completeLogoutResult(post("SAMLResponse", signed(response("_uncertain-response", pending.getRequestId(),
                            SamlLogoutStatus.SUCCESS), key.getPrivate()), pending.getRelayStateHandle()), source(pending), idp));
        }
    }

    @Test void postRequestsRequirePostConfigurationAndPreserveAbsentRelayState() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider redirectOnly = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(SP_LOGOUT).signingPrivateKey(key.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8)).clock(CLOCK).build();
        SamlIdentityProvider idp = identityProvider(key);
        assertInstanceOf(SamlLogoutPostResult.Rejected.class, redirectOnly.beginPostLogoutResult(idp, session()));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                redirectOnly.acceptLogoutRequestResult(post("SAMLRequest", signed(request("_post-disabled"), key.getPrivate()), null), idp));
        SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
        SamlLogoutRequest checked = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed(request("_without-relay"), key.getPrivate()), null), idp)).getRequest();
        SamlPostForm form = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                sp.respondToPostLogoutRequestResult(checked, idp, SamlLogoutStatus.SUCCESS)).getPostForm();
        assertFalse(form.getFields().containsKey("RelayState"));
        assertThrows(IllegalStateException.class, () -> SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .postSingleLogoutServiceUrl(SP_LOGOUT).replayCache(counting(new AtomicInteger())).build());
        assertThrows(IllegalStateException.class, () -> SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .postSingleLogoutServiceUrl(URI.create("http://sp.example.test/logout"))
                .signingPrivateKey(key.getPrivate()).replayCache(counting(new AtomicInteger())).build());
    }

    @Test void postLogoutIsStrictByDefaultButHonorsExplicitSha1Compatibility() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
        SamlPostBindingMessage message = post("SAMLRequest", signed(request("_legacy-sha1"),
                key.getPrivate(), SignatureMethod.RSA_SHA1, DigestMethod.SHA1), null);
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class, sp.acceptLogoutRequestResult(message, identityProvider(key)));
        SamlIdentityProvider legacy = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .postSingleLogoutService(IDP_LOGOUT).signingKeys(List.of(key.getPublic()))
                .compatibility(java.util.Set.of(SamlCompatibilityMode.SHA1_SIGNATURES)).build();
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class, sp.acceptLogoutRequestResult(message, legacy));
    }

    @Test void requestKindCannotConsumeLoginPendingOrEnterUnsolicitedAuthentication() throws Exception {
        KeyPair key = rsa();
        SamlServiceProvider sp = provider(key, InMemorySamlReplayCache.withLimit(CLOCK, 8));
        AtomicInteger consumes = new AtomicInteger();
        PendingSamlAuthenticationStore store = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browser,
                    @NonNull String handle, @NonNull String sealed, @NonNull Instant expires,
                    @NonNull Duration remaining) { return SamlPendingSaveResult.UNAVAILABLE; }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browser,
                    @NonNull String handle, @NonNull Duration remaining) {
                consumes.incrementAndGet();
                return SamlPendingConsumeResult.Missing.INSTANCE;
            }
        };
        SamlPostBindingMessage request = post("SAMLRequest", "<untrusted/>", "relay-state");
        SamlAuthenticationResult.Rejected rejected = assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                sp.completeAuthenticationResult(request, PendingSamlAuthenticationSource.fromStore(store,
                        "browser-secret", sealer(), "post-logout"), identityProvider(key)));
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE, rejected.getReason());
        assertEquals(0, consumes.get());
        assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeUnsolicitedAuthenticationResult(request, identityProvider(key))).getReason());
    }

    @Test void postLogoutReportsRedactedOperationPairsAndFencesNonSuccessStatuses() throws Exception {
        KeyPair key = rsa();
        List<String> events = new ArrayList<>();
        SamlObserver observer = new SamlObserver() {
            @Override public void willHandleOperation(@NonNull Operation operation) {
                events.add("will:" + operation);
            }
            @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                    @NonNull Duration elapsed) {
                assertFalse(elapsed.isNegative());
                events.add("did:" + operation + ":" + outcome);
            }
        };
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .postSingleLogoutServiceUrl(SP_LOGOUT).signingPrivateKey(key.getPrivate())
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8)).clock(CLOCK).observer(observer).build();
        SamlIdentityProvider idp = identityProvider(key);
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        SamlLogoutRequest checked = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed(request("_observer-request"),
                        key.getPrivate()), null), idp)).getRequest();
        assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                sp.respondToPostLogoutRequestResult(checked, idp, SamlLogoutStatus.RESPONDER));
        SamlPostBindingMessage nonSuccess = post("SAMLResponse", signed(response("_observer-response",
                pending.getRequestId(), SamlLogoutStatus.RESPONDER), key.getPrivate()), pending.getRelayStateHandle());
        assertInstanceOf(SamlLogoutResult.StatusReceived.class, sp.completeLogoutResult(nonSuccess, source(pending), idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(nonSuccess, source(pending), idp));
        assertEquals(List.of("will:BEGIN_LOGOUT", "did:BEGIN_LOGOUT:SUCCEEDED",
                "will:ACCEPT_LOGOUT_REQUEST", "did:ACCEPT_LOGOUT_REQUEST:SUCCEEDED",
                "will:RESPOND_TO_LOGOUT_REQUEST", "did:RESPOND_TO_LOGOUT_REQUEST:SUCCEEDED",
                "will:COMPLETE_LOGOUT", "did:COMPLETE_LOGOUT:STATUS_RECEIVED",
                "will:COMPLETE_LOGOUT", "did:COMPLETE_LOGOUT:REJECTED"), events);
    }

    @Test void postReplayExpiryKeepsTheExactNanosecondBoundary() throws Exception {
        KeyPair key = rsa();
        List<Instant> expiries = new ArrayList<>();
        SamlReplayCache replay = (cacheKey, expiresAt, remaining) -> {
            expiries.add(expiresAt);
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = provider(key, replay);
        String expired = request("_expiry").replace("2026-10-09T00:01:00Z", "2026-10-08T23:53:00Z");
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed(expired, key.getPrivate()), null), identityProvider(key)));
        assertEquals(List.of(), expiries);
        String live = expired.replace("2026-10-08T23:53:00Z", "2026-10-08T23:53:00.000000001Z");
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(post("SAMLRequest", signed(live, key.getPrivate()), null), identityProvider(key)));
        assertEquals(List.of(CLOCK.instant().plus(Duration.ofMinutes(12)).plusNanos(1)), expiries);
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> logoutReplaysRetainAcrossBindingsAndTimePolicies() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean response : List.of(false, true))
            for (boolean widenSkew : List.of(false, true))
                for (boolean firstPost : List.of(false, true))
                    for (boolean replayPost : List.of(false, true)) {
                        String name = (response ? "response" : "request") + ": "
                                + (widenSkew ? "wider skew" : "wider age") + ", "
                                + (firstPost ? "POST" : "Redirect") + " then "
                                + (replayPost ? "POST" : "Redirect");
                        tests.add(DynamicTest.dynamicTest(name,
                                () -> mixedPolicyReplay(response, widenSkew, firstPost, replayPost)));
                    }
        return tests;
    }

    private static void mixedPolicyReplay(boolean response, boolean widenSkew,
            boolean firstPost, boolean replayPost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        MutableClock clock = new MutableClock(CLOCK.instant());
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 8);
        Duration broadAge = widenSkew ? Duration.ofSeconds(1) : Duration.ofMinutes(5);
        Duration broadSkew = widenSkew ? Duration.ofSeconds(5) : Duration.ZERO;
        SamlServiceProvider narrow = provider(key, cache, clock, Duration.ofSeconds(1), Duration.ZERO);
        SamlServiceProvider broad = provider(key, cache, clock, broadAge, broadSkew);
        SamlServiceProvider control = provider(key, InMemorySamlReplayCache.withLimit(clock, 8),
                clock, broadAge, broadSkew);
        if (response) {
            PendingSamlLogout pending = firstPost ? begin(narrow, idp).getPendingLogout()
                    : assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                            narrow.beginLogoutResult(idp, session())).getPendingLogout();
            // Reuse sealed state so an atomic pending store cannot mask a replay-cache failure.
            PendingSamlLogoutSource source = source(pending);
            String xml = response("_mixed-policy-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS);
            assertInstanceOf(SamlLogoutResult.Succeeded.class,
                    completeLogout(narrow, idp, pending, source, xml, key, firstPost));
            clock.set(CLOCK.instant().plusSeconds(2));
            assertInstanceOf(SamlLogoutResult.Succeeded.class,
                    completeLogout(control, idp, pending, source, xml, key, replayPost),
                    "a fresh cache confirms the later response satisfies the broader policy and binding");
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    completeLogout(broad, idp, pending, source, xml, key, replayPost));
        } else {
            String xml = request("_mixed-policy-request");
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                    acceptLogout(narrow, idp, xml, key, firstPost));
            clock.set(CLOCK.instant().plusSeconds(2));
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                    acceptLogout(control, idp, xml, key, replayPost),
                    "a fresh cache confirms the later request satisfies the broader policy and binding");
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    acceptLogout(broad, idp, xml, key, replayPost));
        }
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> logoutLocalTimeChecksPrecedeReplayAdmission() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean response : List.of(false, true))
            for (boolean usePost : List.of(false, true))
                tests.add(DynamicTest.dynamicTest((response ? "response" : "request") + ": "
                        + (usePost ? "POST" : "Redirect"), () -> localTimeChecks(response, usePost)));
        return tests;
    }

    private static void localTimeChecks(boolean response, boolean usePost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        List<Instant> expiries = new ArrayList<>();
        SamlReplayCache replay = (cacheKey, expiresAt, remaining) -> {
            expiries.add(expiresAt);
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlServiceProvider sp = provider(key, replay, CLOCK, Duration.ofSeconds(1), Duration.ofMinutes(5));
        PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
        PendingSamlLogoutSource source = source(pending);
        String xml = response ? response("_time-check-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS)
                : request("_time-check-request");
        Instant localExpiryIssue = CLOCK.instant().minus(Duration.ofMinutes(5)).minusSeconds(1);
        Instant latestIssue = CLOCK.instant().plus(Duration.ofMinutes(5));
        for (Instant issue : List.of(localExpiryIssue, latestIssue.plusNanos(1))) {
            String invalid = xml.replace(CLOCK.instant().toString(), issue.toString());
            if (response) assertInstanceOf(SamlLogoutResult.Rejected.class,
                    completeLogout(sp, idp, pending, source, invalid, key, usePost));
            else assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    acceptLogout(sp, idp, invalid, key, usePost));
            assertEquals(List.of(), expiries);
        }
        for (Instant issue : List.of(localExpiryIssue.plusNanos(1), latestIssue)) {
            String valid = xml.replace(CLOCK.instant().toString(), issue.toString());
            if (response) assertInstanceOf(SamlLogoutResult.Succeeded.class,
                    completeLogout(sp, idp, pending, source, valid, key, usePost));
            else assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                    acceptLogout(sp, idp, valid, key, usePost));
        }
        assertEquals(List.of(localExpiryIssue.plusNanos(1).plus(Duration.ofMinutes(20)),
                CLOCK.instant().plus(Duration.ofMinutes(25))), expiries);
        if (!response) {
            String expired = xml.replace("Version='2.0'", "Version='2.0' NotOnOrAfter='" + CLOCK.instant() + "'");
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    acceptLogout(sp, idp, expired, key, usePost));
            assertEquals(2, expiries.size());
            String live = expired.replace("NotOnOrAfter='" + CLOCK.instant() + "'",
                    "NotOnOrAfter='" + CLOCK.instant().plusNanos(1) + "'");
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                    acceptLogout(sp, idp, live, key, usePost));
            assertEquals(CLOCK.instant().plus(Duration.ofMinutes(20)), expiries.get(2));
        }
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> logoutCacheRetainsUntilTheExactUniversalDeadline() {
        List<DynamicTest> tests = new ArrayList<>();
        for (boolean usePost : List.of(false, true))
            tests.add(DynamicTest.dynamicTest(usePost ? "POST" : "Redirect", () -> universalCacheDeadline(usePost)));
        return tests;
    }

    private static void universalCacheDeadline(boolean usePost) throws Exception {
        KeyPair key = rsa();
        SamlIdentityProvider idp = identityProvider(key);
        MutableClock clock = new MutableClock(CLOCK.instant());
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 1);
        SamlServiceProvider narrow = provider(key, cache, clock, Duration.ofSeconds(1), Duration.ZERO);
        SamlServiceProvider broad = provider(key, cache, clock, Duration.ofMinutes(15), Duration.ofMinutes(5));
        String captured = request("_universal-deadline").replace(CLOCK.instant().toString(),
                CLOCK.instant().plusNanos(1).toString());
        // Admit at IssueInstant so the zero-skew policy does not reject the future nanosecond.
        clock.set(CLOCK.instant().plusNanos(1));
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                acceptLogout(narrow, idp, captured, key, usePost));
        Instant deadline = CLOCK.instant().plus(Duration.ofMinutes(20)).plusNanos(1);
        clock.set(deadline.minusNanos(1));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                acceptLogout(broad, idp, captured, key, usePost));
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                acceptLogout(provider(key, InMemorySamlReplayCache.withLimit(clock, 1), clock,
                        Duration.ofMinutes(15), Duration.ofMinutes(5)), idp, captured, key, usePost),
                "the captured message remains locally valid one nanosecond before the universal deadline");
        clock.set(deadline);
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                acceptLogout(broad, idp, captured, key, usePost));
        String fresh = request("_after-universal-deadline").replace(CLOCK.instant().toString(), deadline.toString());
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                acceptLogout(broad, idp, fresh, key, usePost),
                "at the exact deadline, the expired record releases the cache's only slot");
    }

    @Test void postLogoutAcceptsConfiguredRolloverAndSupportedEllipticCurveKeys() throws Exception {
        KeyPair spKey = rsa();
        KeyPair oldKey = rsa();
        for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            KeyPair idpKey = generator.generateKeyPair();
            String algorithm = curve.equals("secp256r1") ? SignatureMethod.ECDSA_SHA256
                    : curve.equals("secp384r1") ? SignatureMethod.ECDSA_SHA384 : SignatureMethod.ECDSA_SHA512;
            String digest = curve.equals("secp256r1") ? DigestMethod.SHA256
                    : curve.equals("secp384r1") ? DigestMethod.SHA384 : DigestMethod.SHA512;
            SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                    .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                    .postSingleLogoutService(IDP_LOGOUT).signingKeys(List.of(oldKey.getPublic(), idpKey.getPublic())).build();
            SamlServiceProvider sp = provider(spKey, InMemorySamlReplayCache.withLimit(CLOCK, 8));
            assertInstanceOf(SamlLogoutRequestResult.Accepted.class, sp.acceptLogoutRequestResult(post("SAMLRequest",
                    signed(request("_curve-" + curve), idpKey.getPrivate(), algorithm, digest), null), idp), curve);
            PendingSamlLogout pending = begin(sp, idp).getPendingLogout();
            assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(post("SAMLResponse",
                    signed(response("_curve-response", pending.getRequestId(), SamlLogoutStatus.SUCCESS),
                            idpKey.getPrivate(), algorithm, digest), pending.getRelayStateHandle()), source(pending), idp), curve);
        }
    }

    private static @NonNull SamlServiceProvider provider(@NonNull KeyPair key, @NonNull SamlReplayCache replay) {
        return provider(key, replay, CLOCK, Duration.ofMinutes(5), Duration.ofMinutes(3));
    }

    private static @NonNull SamlServiceProvider provider(@NonNull KeyPair key, @NonNull SamlReplayCache replay,
            @NonNull Clock clock, @NonNull Duration age, @NonNull Duration skew) {
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(SP_LOGOUT).postSingleLogoutServiceUrl(SP_LOGOUT)
                .signingPrivateKey(key.getPrivate()).replayCache(replay).clock(clock)
                .maximumResponseAge(age).clockSkew(skew).build();
    }

    private static @NonNull SamlLogoutRequestResult acceptLogout(@NonNull SamlServiceProvider sp,
            @NonNull SamlIdentityProvider idp, @NonNull String xml, @NonNull KeyPair key,
            boolean usePost) throws Exception {
        return usePost ? sp.acceptLogoutRequestResult(post("SAMLRequest", signed(xml, key.getPrivate()), null), idp)
                : sp.acceptLogoutRequestResult(redirect("SAMLRequest", xml, null, key.getPrivate()), idp);
    }

    private static @NonNull SamlLogoutResult completeLogout(@NonNull SamlServiceProvider sp,
            @NonNull SamlIdentityProvider idp, @NonNull PendingSamlLogout pending,
            @NonNull PendingSamlLogoutSource source, @NonNull String xml, @NonNull KeyPair key,
            boolean usePost) throws Exception {
        String relay = pending.getRelayStateHandle();
        return usePost ? sp.completeLogoutResult(post("SAMLResponse", signed(xml, key.getPrivate()), relay), source, idp)
                : sp.completeLogoutResult(redirect("SAMLResponse", xml, relay, key.getPrivate()), source, idp);
    }

    private static @NonNull SamlLogoutResult completeCryptographicallyCheckedLogout(@NonNull SamlServiceProvider sp,
            @NonNull SamlIdentityProvider idp, @NonNull PendingSamlLogout pending,
            @NonNull PendingSamlLogoutSource source, @NonNull String xml, @NonNull KeyPair key,
            boolean usePost) throws Exception {
        String relay = pending.getRelayStateHandle();
        if (usePost) {
            String signed = signed(xml, key.getPrivate());
            verifyRoot(signed.getBytes(StandardCharsets.UTF_8), key.getPublic());
            return sp.completeLogoutResult(post("SAMLResponse", signed, relay), source, idp);
        }
        SamlRedirectBindingMessage message = redirect("SAMLResponse", xml, relay, key.getPrivate());
        assertTrue(message.verify(idp.signingKeys(), idp.allowSha1Signatures()),
                "the semantic mutation retains a valid signature from the selected IdP");
        return sp.completeLogoutResult(message, source, idp);
    }

    private static final class TrackingPendingStore implements PendingSamlAuthenticationStore {
        private final @NonNull InMemoryPendingSamlAuthenticationStore backing;
        private final @NonNull AtomicInteger consumes = new AtomicInteger();

        private TrackingPendingStore() { this(CLOCK); }
        private TrackingPendingStore(@NonNull Clock clock) {
            backing = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 8);
        }

        @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                @NonNull String handle, @NonNull String record, @NonNull Instant expiresAt,
                @NonNull Duration remaining) {
            return backing.save(browserBinding, handle, record, expiresAt, remaining);
        }

        @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                @NonNull String handle, @NonNull Duration remaining) {
            SamlPendingConsumeResult result = backing.consume(browserBinding, handle, remaining);
            if (result instanceof SamlPendingConsumeResult.Consumed) consumes.incrementAndGet();
            return result;
        }

        @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                @NonNull String handle, @NonNull Predicate<@NonNull String> matches,
                @NonNull Duration remaining) {
            SamlPendingConsumeResult result = backing.consumeIfMatches(browserBinding, handle, matches, remaining);
            if (result instanceof SamlPendingConsumeResult.Consumed) consumes.incrementAndGet();
            return result;
        }
    }

    private static final class MutableClock extends Clock {
        private @NonNull Instant now;

        private MutableClock(@NonNull Instant now) { this.now = now; }
        private void set(@NonNull Instant now) { this.now = now; }
        @Override public @NonNull Instant instant() { return now; }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
            return zone.equals(ZoneOffset.UTC) ? this : Clock.fixed(now, zone);
        }
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .redirectSingleLogoutService(IDP_LOGOUT).postSingleLogoutService(IDP_LOGOUT)
                .signingKeys(List.of(key.getPublic())).build();
    }

    private static @NonNull SamlSessionReference session() {
        return new SamlSessionReference("tenant-one", IDP,
                new SamlNameId("alice", SamlNameId.PERSISTENT, IDP, SP, "original"), "session-123", null);
    }

    private static SamlLogoutPostResult.@NonNull Prepared begin(@NonNull SamlServiceProvider sp, @NonNull SamlIdentityProvider idp) {
        return assertInstanceOf(SamlLogoutPostResult.Prepared.class, sp.beginPostLogoutResult(idp, session()));
    }

    private static @NonNull StateSealer sealer() {
        return StateSealer.withActiveKey(TestSealers.fixedKey("saml-post-logout")).clock(CLOCK).build();
    }

    private static @NonNull PendingSamlLogoutSource source(@NonNull PendingSamlLogout pending) {
        StateSealer sealer = sealer();
        return PendingSamlLogoutSource.fromSealedForm(pending.toSealedForm(sealer, "post-logout"), sealer, "post-logout");
    }

    private static @NonNull SamlReplayCache counting(@NonNull AtomicInteger writes) {
        return (key, expiry, remaining) -> { writes.incrementAndGet(); return SamlReplayCache.MarkResult.MARKED; };
    }

    // Simulate a broken external store despite the provider's declared nonnull return contract.
    @SuppressWarnings("NullAway")
    private static @NonNull SamlReplayCache returningNullReplayCache() {
        return (key, expiry, remaining) -> null;
    }

    private static @NonNull String request(@NonNull String id) {
        return "<p:LogoutRequest xmlns:p='" + PROTOCOL + "' xmlns:a='" + ASSERTION
                + "' ID='" + id + "' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' Destination='"
                + SP_LOGOUT + "'>" + ISSUER + NAME + INDEX + "</p:LogoutRequest>";
    }

    private static @NonNull String response(@NonNull String id, @NonNull String inResponseTo, @NonNull SamlLogoutStatus status) {
        return "<p:LogoutResponse xmlns:p='" + PROTOCOL + "' xmlns:a='" + ASSERTION
                + "' ID='" + id + "' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' Destination='"
                + SP_LOGOUT + "' InResponseTo='" + inResponseTo + "'>" + ISSUER
                + "<p:Status><p:StatusCode Value='" + status.uri() + "'/></p:Status></p:LogoutResponse>";
    }

    private static byte @NonNull [] formBody(@NonNull String field, @NonNull String xml, @Nullable String relay) {
        String body = field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        if (relay != null) body += "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8);
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull SamlPostBindingMessage post(@NonNull String field, @NonNull String xml, @Nullable String relay) {
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(formBody(field, xml, relay),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull String signed(@NonNull String xml, @NonNull PrivateKey key) throws Exception {
        return signed(xml, key, SignatureMethod.RSA_SHA256, DigestMethod.SHA256);
    }

    private static @NonNull String signed(@NonNull String xml, @NonNull PrivateKey key,
            @NonNull String signatureMethod, @NonNull String digestMethod) throws Exception {
        Document document = parse(xml.getBytes(StandardCharsets.UTF_8));
        Element root = document.getDocumentElement();
        root.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + root.getAttribute("ID"), factory.newDigestMethod(digestMethod, null),
                List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)), null, null);
        var info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null), factory.newSignatureMethod(signatureMethod, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(key, root);
        context.setProperty("org.jcp.xml.dsig.secureValidation", false);
        context.setDefaultNamespacePrefix("ds");
        Node next = root.getFirstChild().getNextSibling();
        if (next != null) context.setNextSibling(next);
        factory.newXMLSignature(info, null).sign(context);
        return new String(SamlXmlWriter.serialize(document), StandardCharsets.UTF_8);
    }

    private static @NonNull Document parse(byte @NonNull [] xml) {
        return assertInstanceOf(SecureXmlParser.Result.Accepted.class, SecureXmlParser.parseResponse(xml)).getDocument();
    }

    private static @NonNull Element verifyRoot(byte @NonNull [] xml, @NonNull PublicKey key) throws Exception {
        Document document = parse(xml);
        Element root = document.getDocumentElement();
        assertEquals(1, root.getElementsByTagNameNS(DSIG, "Signature").getLength());
        Element signature = assertInstanceOf(Element.class, root.getElementsByTagNameNS(DSIG, "Signature").item(0));
        assertTrue(signature.getParentNode().isSameNode(root));
        root.setIdAttributeNS(null, "ID", true);
        DOMValidateContext context = new DOMValidateContext(key, signature);
        context.setProperty("org.jcp.xml.dsig.secureValidation", true);
        XMLSignature checked = XMLSignatureFactory.getInstance("DOM", "XMLDSig").unmarshalXMLSignature(context);
        assertEquals("#" + root.getAttribute("ID"), checked.getSignedInfo().getReferences().get(0).getURI());
        assertTrue(checked.validate(context));
        return root;
    }

    private static @NonNull String signature(@NonNull String xml) {
        int start = xml.indexOf("<ds:Signature ");
        int end = xml.indexOf("</ds:Signature>", start);
        assertTrue(start >= 0 && end > start);
        return xml.substring(start, end + "</ds:Signature>".length());
    }

    private static @NonNull SamlRedirectBindingMessage redirect(@NonNull String field, @NonNull String xml,
            @Nullable String relay, @NonNull PrivateKey key) throws Exception {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] compressed = new byte[32_768];
        int length;
        try {
            deflater.setInput(xml.getBytes(StandardCharsets.UTF_8));
            deflater.finish();
            length = deflater.deflate(compressed);
            assertTrue(deflater.finished());
        } finally { deflater.end(); }
        String query = field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOf(compressed, length)), StandardCharsets.UTF_8);
        if (relay != null) query += "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8);
        query += "&SigAlg=" + URLEncoder.encode(SignatureMethod.RSA_SHA256, StandardCharsets.UTF_8);
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(query.getBytes(StandardCharsets.US_ASCII));
        query += "&Signature=" + URLEncoder.encode(Base64.getEncoder().encodeToString(signature.sign()), StandardCharsets.UTF_8);
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
