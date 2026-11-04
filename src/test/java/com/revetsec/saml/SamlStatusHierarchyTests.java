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
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.*;

/** Same source runs on entry and final production; the additive enum outcome is compared by name. */
final class SamlStatusHierarchyTests {
    private static final String PREFIX = "urn:oasis:names:tc:SAML:2.0:status:";
    private static final String SP = "https://sp.example.test/saml";
    private static final URI ACS = URI.create("https://sp.example.test/acs");
    private static final URI LOGOUT = URI.create("https://sp.example.test/logout");
    private static final String IDP = "https://idp.example.test/saml";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final TestJwk.Fixture KEY = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
    private static final PrivateKey WRONG = TestJwk.Fixture.IDP_SIGNING_RSA_3072.getKeyPair().getPrivate();
    private static final String PRIVATE = "PRIVATE-STATUS-DATA";
    private enum Binding { REDIRECT, POST }
    private record AuthCase(String label, List<String> codes, SamlAuthenticationResult.StatusCode expected) {}

    @TestFactory Stream<DynamicTest> loginUsesTheImmediateDiagnosticAndRetainsProvenance() {
        List<AuthCase> cases = List.of(
                auth("responder authn", "AUTHN_FAILED", "Responder", "AuthnFailed"),
                auth("responder context", "NO_AUTHN_CONTEXT", "Responder", "NoAuthnContext"),
                auth("responder denied", "REQUEST_DENIED", "Responder", "RequestDenied"),
                auth("requester denied", "REQUEST_DENIED", "Requester", "RequestDenied"),
                auth("unknown detail falls back to primary", "RESPONDER", "Responder", "urn:example:" + PRIVATE),
                auth("deeper diagnostic does not override immediate detail", "RESPONDER", "Responder", "urn:example:detail", "AuthnFailed"),
                auth("immediate diagnostic survives deeper detail", "AUTHN_FAILED", "Responder", "AuthnFailed", "urn:example:" + PRIVATE),
                auth("version primary is retained", "VERSION_MISMATCH", "VersionMismatch", "AuthnFailed"),
                auth("unknown primary is not promoted by a child", "OTHER", "urn:example:primary", "AuthnFailed"),
                auth("flat compatibility", "AUTHN_FAILED", "AuthnFailed"),
                auth("flat unknown compatibility", "OTHER", "urn:example:" + PRIVATE),
                auth("flat requester", "REQUESTER", "Requester"));
        return cases.stream().flatMap(c -> Stream.of(false, true).map(signed -> DynamicTest.dynamicTest(
                c.label() + "; signed=" + signed, () -> {
                    Fixture f = new Fixture(Binding.POST, false);
                    PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                            f.sp.beginAuthenticationResult(f.idp)).getPendingAuthentication();
                    PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                            pending.toSealedForm(f.sealer, "login-status"), f.sealer, "login-status");
                    String xml = loginResponse(pending, status(c.codes()), false);
                    if (signed) xml = sign(xml, KEY.getKeyPair().getPrivate());
                    f.resetEvents();
                    SamlAuthenticationResult.StatusReceived result = assertInstanceOf(SamlAuthenticationResult.StatusReceived.class,
                            f.sp.completeAuthenticationResult(post(xml, pending.getRelayStateHandle()), source, f.idp));
                    assertEquals(c.expected(), result.getStatusCode());
                    assertEquals(signed, result.isAuthenticated());
                    assertFalse(result.toString().contains(PRIVATE));
                    assertEquals(0, f.replayAttempts);
                    f.observed(SamlObserver.Outcome.STATUS_RECEIVED);
                })));
    }

    @TestFactory Stream<DynamicTest> partialIsVerifiedDistinctAndReplayFencedAcrossBindings() {
        return fixtures().map(pair -> DynamicTest.dynamicTest(pair.toString(), () -> {
            Fixture f = new Fixture(pair.binding(), pair.stored());
            String xml = f.logout(status(List.of("Success", "PartialLogout")));
            SamlLogoutResult result = f.complete(xml, KEY.getKeyPair().getPrivate());
            assertEquals("PARTIAL_LOGOUT", assertInstanceOf(SamlLogoutResult.StatusReceived.class, result).name());
            assertFalse(result.toString().contains(PRIVATE));
            f.observed(SamlObserver.Outcome.STATUS_RECEIVED);
            assertEquals(pair.stored() ? 1 : 0, f.store.consumes);
            assertEquals(1, f.replayAttempts); assertEquals(1, f.replayWrites);
            Binding other = pair.binding() == Binding.POST ? Binding.REDIRECT : Binding.POST;
            assertSame(SamlLogoutResult.Rejected.INSTANCE, f.completeAs(other, xml, KEY.getKeyPair().getPrivate()));
            assertEquals(1, f.replayWrites);
            assertEquals(pair.stored() ? 1 : 2, f.replayAttempts);
            assertEquals(pair.stored() ? 1 : 0, f.store.consumes);
            assertEquals(0, f.store.unconditional);
            f.observed(SamlObserver.Outcome.REJECTED);
        }));
    }

    @TestFactory Stream<DynamicTest> logoutClassificationDoesNotTurnOtherHierarchyIntoSuccess() {
        List<List<String>> cases = List.of(List.of("Success"), List.of("Responder", "PartialLogout"),
                List.of("Requester", "RequestDenied"), List.of("VersionMismatch"),
                List.of("Responder", "urn:example:" + PRIVATE), List.of("PartialLogout"));
        return cases.stream().flatMap(c -> fixtures().map(pair -> DynamicTest.dynamicTest(c + "; " + pair, () -> {
            Fixture f = new Fixture(pair.binding(), pair.stored());
            SamlLogoutResult result = f.complete(f.logout(status(c)), KEY.getKeyPair().getPrivate());
            if (c.equals(List.of("Success"))) {
                assertSame(SamlLogoutResult.Succeeded.INSTANCE, result); f.observed(SamlObserver.Outcome.SUCCEEDED);
            } else {
                assertSame(SamlLogoutResult.StatusReceived.NON_SUCCESS, result); f.observed(SamlObserver.Outcome.STATUS_RECEIVED);
            }
            assertEquals(1, f.replayWrites); assertEquals(pair.stored() ? 1 : 0, f.store.consumes);
        })));
    }

    @TestFactory Stream<DynamicTest> malformedStatusPreservesLogoutPendingAndReplayState() {
        String partial = code(List.of("Success", "PartialLogout"));
        List<String> malformed = List.of(
                status(List.of("Success", "Responder")), status(List.of("Success", "PartialLogout", "Success")),
                status(List.of("Responder", "Success")), status(List.of("Responder", "AuthnFailed", "Success")),
                "<p:Status>" + partial + partial + "</p:Status>",
                "<p:Status><p:StatusCode Value='" + PREFIX + "Responder'><p:StatusCode Value='" + PREFIX
                        + "AuthnFailed'/><p:StatusCode Value='" + PREFIX + "RequestDenied'/></p:StatusCode></p:Status>",
                "<p:Status><p:StatusCode Value='" + PREFIX + "Responder'><other:StatusCode xmlns:other='urn:other' Value='"
                        + PREFIX + "AuthnFailed'/></p:StatusCode></p:Status>",
                "<p:Status><p:StatusCode Value='" + PREFIX + "Responder'><p:StatusCode/></p:StatusCode></p:Status>",
                "<p:Status><p:StatusCode Value='" + PREFIX + "Responder'>" + PRIVATE + "</p:StatusCode></p:Status>",
                "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'><p:StatusCode Value='" + PREFIX
                        + "Responder'><p:StatusCode xsi:nil='true' Value='" + PREFIX + "AuthnFailed'/></p:StatusCode></p:Status>",
                "<p:Status>" + partial + "<p:StatusMessage>one</p:StatusMessage><p:StatusMessage>two</p:StatusMessage></p:Status>",
                "<p:Status>" + partial + "<p:StatusDetail/><p:StatusMessage>late</p:StatusMessage></p:Status>");
        return Stream.iterate(0, i -> i + 1).limit(malformed.size()).flatMap(i -> fixtures().map(pair ->
                DynamicTest.dynamicTest("malformed " + i + "; " + pair, () -> {
                    Fixture f = new Fixture(pair.binding(), pair.stored());
                    assertSame(SamlLogoutResult.Rejected.INSTANCE, f.complete(f.logout(malformed.get(i)), KEY.getKeyPair().getPrivate()));
                    assertEquals(0, f.store.consumes); assertEquals(0, f.replayAttempts);
                    f.observed(SamlObserver.Outcome.REJECTED);
                    assertSame(SamlLogoutResult.Succeeded.INSTANCE,
                            f.complete(f.logout(status(List.of("Success"))), KEY.getKeyPair().getPrivate()));
                    assertEquals(1, f.replayWrites); assertEquals(pair.stored() ? 1 : 0, f.store.consumes);
                })));
    }

    @TestFactory Stream<DynamicTest> hierarchyDepthIsBoundedIncludingThePrimary() {
        return Stream.of(32, 33).flatMap(depth -> fixtures().map(pair -> DynamicTest.dynamicTest(depth + "; " + pair, () -> {
            Fixture f = new Fixture(pair.binding(), pair.stored());
            List<String> codes = new ArrayList<>(List.of("Success", "PartialLogout"));
            while (codes.size() < depth) codes.add("urn:example:detail-" + codes.size());
            SamlLogoutResult result = f.complete(f.logout(status(codes)), KEY.getKeyPair().getPrivate());
            if (depth == 32) {
                assertEquals("PARTIAL_LOGOUT", assertInstanceOf(SamlLogoutResult.StatusReceived.class, result).name());
                assertEquals(1, f.replayWrites);
            } else {
                assertSame(SamlLogoutResult.Rejected.INSTANCE, result);
                assertEquals(0, f.store.consumes); assertEquals(0, f.replayAttempts);
            }
        })));
    }

    @TestFactory Stream<DynamicTest> aPartialStatusCannotBypassSignatureOrPendingBindings() {
        return Stream.of("signature", "request", "destination", "issuer", "age").flatMap(fault -> fixtures().map(pair ->
                DynamicTest.dynamicTest(fault + "; " + pair, () -> {
                    Fixture f = new Fixture(pair.binding(), pair.stored());
                    String xml = f.logout(status(List.of("Success", "PartialLogout")));
                    xml = switch (fault) {
                        case "request" -> xml.replace(f.pending.getRequestId(), "_other_request");
                        case "destination" -> xml.replace(LOGOUT.toASCIIString(), "https://sp.example.test/other");
                        case "issuer" -> xml.replace(IDP, "https://other.example.test/idp");
                        case "age" -> xml.replace("2026-10-09T00:01:00Z", "2026-10-08T00:01:00Z");
                        default -> xml;
                    };
                    assertSame(SamlLogoutResult.Rejected.INSTANCE, f.complete(xml, fault.equals("signature") ? WRONG : KEY.getKeyPair().getPrivate()));
                    assertEquals(0, f.store.consumes); assertEquals(0, f.replayAttempts);
                    assertSame(SamlLogoutResult.Succeeded.INSTANCE,
                            f.complete(f.logout(status(List.of("Success"))), KEY.getKeyPair().getPrivate()));
                    assertEquals(1, f.replayWrites);
                })));
    }

    @TestFactory Stream<DynamicTest> partialRequiresSuccessfulReplayAdmission() {
        return Stream.of(SamlReplayCache.MarkResult.ALREADY_PRESENT, SamlReplayCache.MarkResult.CAPACITY_REFUSED,
                SamlReplayCache.MarkResult.UNAVAILABLE, SamlReplayCache.MarkResult.INDETERMINATE).flatMap(mark ->
                fixtures().map(pair -> DynamicTest.dynamicTest(mark + "; " + pair, () -> {
                    Fixture f = new Fixture(pair.binding(), pair.stored()); f.forced = mark;
                    SamlLogoutResult result = f.complete(f.logout(status(List.of("Success", "PartialLogout"))), KEY.getKeyPair().getPrivate());
                    SamlLogoutResult expected = mark == SamlReplayCache.MarkResult.INDETERMINATE || pair.stored()
                            ? SamlLogoutResult.Indeterminate.INSTANCE
                            : mark == SamlReplayCache.MarkResult.ALREADY_PRESENT ? SamlLogoutResult.Rejected.INSTANCE
                            : SamlLogoutResult.Unavailable.INSTANCE;
                    assertSame(expected, result); assertEquals(1, f.replayAttempts); assertEquals(0, f.replayWrites);
                    assertEquals(pair.stored() ? 1 : 0, f.store.consumes);
                })));
    }

    @TestFactory Stream<DynamicTest> statusCannotAuthenticateAnAssertionOrAnInvalidSignature() {
        return Stream.of("partial", "refusal", "bad signature").flatMap(scenario -> Stream.of("response", "assertion", "both")
                .filter(coverage -> !scenario.equals("bad signature") || coverage.equals("response"))
                .map(coverage -> DynamicTest.dynamicTest(scenario + "; " + coverage, () -> {
                    Fixture f = new Fixture(Binding.POST, false);
                    PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                            f.sp.beginAuthenticationResult(f.idp)).getPendingAuthentication();
                    PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                            pending.toSealedForm(f.sealer, "login-status"), f.sealer, "login-status");
                    String xml = loginResponse(pending, status(scenario.equals("partial")
                            ? List.of("Success", "PartialLogout") : List.of("Responder", "AuthnFailed")), !scenario.equals("bad signature"));
                    xml = SamlResponseSemanticsTests.signedXml(xml, !coverage.equals("assertion"),
                            !coverage.equals("response") && !scenario.equals("bad signature"),
                            scenario.equals("bad signature") ? WRONG : KEY.getKeyPair().getPrivate());
                    SamlAuthenticationResult result = f.sp.completeAuthenticationResult(post(xml, pending.getRelayStateHandle()), source, f.idp);
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, result);
                    assertEquals(0, f.replayAttempts);
                })));
    }

    private record Pair(Binding binding, boolean stored) {}
    private static Stream<Pair> fixtures() { return Stream.of(Binding.values()).flatMap(b -> Stream.of(false, true).map(s -> new Pair(b, s))); }
    private static AuthCase auth(String label, String expected, String... codes) {
        return new AuthCase(label, List.of(codes), SamlAuthenticationResult.StatusCode.valueOf(expected));
    }
    private static String code(List<String> values) {
        String nested = "";
        for (int i = values.size() - 1; i >= 0; i--) {
            String value = values.get(i).contains(":") ? values.get(i) : PREFIX + values.get(i);
            nested = "<p:StatusCode Value='" + value + "'>" + nested + "</p:StatusCode>";
        }
        return nested;
    }
    private static String status(List<String> codes) {
        return "<p:Status>" + code(codes) + "<p:StatusMessage>" + PRIVATE + "</p:StatusMessage>"
                + "<p:StatusDetail><other:Detail xmlns:other='urn:example'>" + PRIVATE + "</other:Detail></p:StatusDetail></p:Status>";
    }
    private static String loginResponse(PendingSamlAuthentication pending, String status, boolean assertion) {
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        if (!assertion) xml = xml.substring(0, xml.indexOf("<a:Assertion")) + "</p:Response>";
        return xml.replace("<p:Status><p:StatusCode Value='" + PREFIX + "Success'/></p:Status>", status);
    }
    private static String sign(String xml, PrivateKey key) throws Exception {
        return SamlResponseSemanticsTests.signedXml(xml, true, false, key);
    }
    private static SamlPostBindingMessage post(String xml, String relay) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class, SamlPostBindingMessage.fromFormBodyResult(
                ("SAMLResponse=" + encoded + "&RelayState=" + relay).getBytes(StandardCharsets.UTF_8),
                List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }
    private static SamlRedirectBindingMessage redirect(String xml, String relay, PrivateKey key) throws Exception {
        Deflater compressor = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] compressed;
        try {
            compressor.setInput(xml.getBytes(StandardCharsets.UTF_8)); compressor.finish();
            ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] buffer = new byte[4096];
            while (!compressor.finished()) { int n = compressor.deflate(buffer); output.write(buffer, 0, n); }
            compressed = output.toByteArray();
        } finally { compressor.end(); }
        String query = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(compressed), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8)
                + "&SigAlg=" + URLEncoder.encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA"); signer.initSign(key);
        signer.update(query.getBytes(StandardCharsets.US_ASCII));
        query += "&Signature=" + URLEncoder.encode(Base64.getEncoder().encodeToString(signer.sign()), StandardCharsets.UTF_8);
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class, SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
    }

    private static final class CountingStore implements PendingSamlAuthenticationStore {
        private final PendingSamlAuthenticationStore delegate = InMemoryPendingSamlAuthenticationStore.fromLimit(CLOCK, 8);
        private int consumes;
        private int unconditional;
        @Override public @NonNull SamlPendingSaveResult save(@NonNull String browser, @NonNull String relay,
                @NonNull String record, @NonNull Instant expiresAt, @NonNull Duration budget) {
            return delegate.save(browser, relay, record, expiresAt, budget);
        }
        @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browser, @NonNull String relay, @NonNull Duration budget) {
            unconditional++; return delegate.consume(browser, relay, budget);
        }
        @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browser, @NonNull String relay,
                @NonNull Predicate<@NonNull String> predicate, @NonNull Duration budget) {
            SamlPendingConsumeResult result = delegate.consumeIfMatches(browser, relay, predicate, budget);
            if (result instanceof SamlPendingConsumeResult.Consumed) consumes++;
            return result;
        }
    }
    private static final class Fixture {
        final Binding binding;
        final SamlServiceProvider sp;
        final SamlIdentityProvider idp;
        final StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-status-state")).clock(CLOCK).build();
        final CountingStore store = new CountingStore();
        final PendingSamlLogout pending;
        final PendingSamlLogoutSource source;
        final List<SamlObserver.Outcome> ends = new ArrayList<>();
        int starts;
        int replayAttempts;
        int replayWrites;
        SamlReplayCache.@Nullable MarkResult forced;
        Fixture(Binding binding, boolean stored) {
            this.binding = binding;
            SamlReplayCache cache = InMemorySamlReplayCache.fromLimit(CLOCK, 32);
            sp = SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                    .singleLogoutServiceUrl(LOGOUT).postSingleLogoutServiceUrl(LOGOUT)
                    .signingPrivateKey(KEY.getKeyPair().getPrivate()).clock(CLOCK)
                    .replayCache((key, expiry, budget) -> {
                        replayAttempts++;
                        SamlReplayCache.MarkResult override = forced;
                        SamlReplayCache.MarkResult result = override == null ? cache.markIfAbsent(key, expiry, budget) : override;
                        if (result == SamlReplayCache.MarkResult.MARKED) replayWrites++;
                        return result;
                    }).observer(new SamlObserver() {
                        @Override public void willHandleOperation(@NonNull Operation operation) { starts++; }
                        @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                                @NonNull Duration elapsed) { ends.add(outcome); }
                    }).build();
            idp = SamlIdentityProvider.withEntityId(IDP).connectionId("status-connection")
                    .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                    .redirectSingleLogoutService(URI.create("https://idp.example.test/logout"))
                    .postSingleLogoutService(URI.create("https://idp.example.test/logout"))
                    .signingKeys(List.of(KEY.getPublicKey())).build();
            SamlSessionReference session = new SamlSessionReference("status-connection", IDP,
                    new SamlNameId("alice", SamlNameId.PERSISTENT, IDP, SP), "session-one", null);
            pending = binding == Binding.POST ? assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                    sp.beginPostLogoutResult(idp, session)).getPendingLogout() : assertInstanceOf(SamlLogoutRedirectResult.Prepared.class,
                    sp.beginLogoutResult(idp, session)).getPendingLogout();
            if (stored) {
                assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer, "logout-status", "browser-one", Duration.ofSeconds(5)));
                source = PendingSamlLogoutSource.fromStore(store, "browser-one", sealer, "logout-status");
            } else source = PendingSamlLogoutSource.fromSealedForm(pending.toSealedForm(sealer, "logout-status"), sealer, "logout-status");
        }
        String logout(String status) {
            return "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'"
                    + " ID='_status_response' Version='2.0' IssueInstant='2026-10-09T00:01:00Z' Destination='" + LOGOUT
                    + "' InResponseTo='" + pending.getRequestId() + "'><a:Issuer>" + IDP + "</a:Issuer>" + status + "</p:LogoutResponse>";
        }
        SamlLogoutResult complete(String xml, PrivateKey key) throws Exception { return completeAs(binding, xml, key); }
        SamlLogoutResult completeAs(Binding selected, String xml, PrivateKey key) throws Exception {
            resetEvents();
            SamlLogoutResult result = selected == Binding.POST
                    ? sp.completeLogoutResult(post(sign(xml, key), pending.getRelayStateHandle()), source, idp)
                    : sp.completeLogoutResult(redirect(xml, pending.getRelayStateHandle(), key), source, idp);
            assertEquals(1, starts); assertEquals(1, ends.size()); return result;
        }
        void resetEvents() { starts = 0; ends.clear(); }
        void observed(SamlObserver.Outcome expected) { assertEquals(1, starts); assertEquals(List.of(expected), ends); }
    }
}
