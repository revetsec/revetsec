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
package example.playground;

import com.revetsec.saml.SamlReplayCache;
import com.revetsec.saml.SamlServiceProvider;
import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import com.soklet.SokletSimulator;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.http.HttpClient;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** The application boundary keeps metadata, browser state, and logout input separate. */
final class PlaygroundSamlTests {
    @TempDir Path directory;
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-10T00:00:00Z"), ZoneOffset.UTC);

    @Test void startupUsesASelectedTrustedMetadataFileAndPublishesSpMetadata() throws IOException {
        assertNull(PlaygroundSaml.fromEnvironment(Map.of(), PlaygroundConfig.fromEnvironment(Map.of()),
                new BrowserSessions(CLOCK, 4), new SafeViews(LocalSecrets.randomBytes()), CLOCK));
        Fixture fixture = fixture();
        Request request = Request.withPath(HttpMethod.GET, "/saml/metadata")
                .headers(Map.of("Host", List.of("localhost:8443"))).build();
        Response metadata = fixture.resources.samlMetadata(request);
        assertEquals(200, metadata.getStatusCode());
        assertTrue(metadata.getBody().orElseThrow().toString().contains("https://localhost:8443/saml/metadata"));
        assertEquals(403, fixture.resources.samlMetadata(Request.withPath(HttpMethod.GET, "/saml/metadata")
                .headers(Map.of("Host", List.of("foreign.example"))).build()).getStatusCode());
        Path metadataFile = directory.resolve("idp.xml");
        String approvedMetadata = Files.readString(metadataFile);
        Files.writeString(metadataFile, approvedMetadata.replaceAll(
                "<md:SingleLogoutService[^>]*/>", ""));
        assertThrows(IllegalArgumentException.class, () -> PlaygroundSaml.fromEnvironment(fixture.environment,
                fixture.config, fixture.sessions, fixture.views, CLOCK));
        Files.writeString(directory.resolve("idp.xml"), "<not-metadata/>");
        assertThrows(IllegalArgumentException.class, () -> PlaygroundSaml.fromEnvironment(fixture.environment,
                fixture.config, fixture.sessions, fixture.views, CLOCK));
    }

    @Test void beginRequiresAppCsrfAndARejectedAcsConsumesBrowserPendingState() throws IOException {
        Fixture fixture = fixture();
        BrowserSessions.Session session = fixture.sessions.begin();
        Request begin = form("/saml/begin", session, "csrf=" + session.csrf);
        assertEquals(403, fixture.resources.samlBegin(form("/saml/begin", session, "csrf=wrong")).getStatusCode());
        Response started = fixture.resources.samlBegin(begin);
        assertEquals(302, started.getStatusCode());
        assertTrue(started.getHeaders().get("Location").get(0).startsWith("https://idp.example.test/sso?"));
        ResponseCookie pending = started.getCookies().get(0);
        assertEquals(PlaygroundSaml.LOGIN_COOKIE, pending.getName());
        assertTrue(pending.getSecure());
        assertTrue(pending.getHttpOnly());
        assertEquals(ResponseCookie.SameSite.NONE, pending.getSameSite().orElseThrow());

        Request malformed = Request.withPath(HttpMethod.POST, "/saml/acs")
                .headers(Map.of("Host", List.of("localhost:8443"),
                        "Origin", List.of("https://idp.example.test"),
                        "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id + "; "
                                + pending.getName() + "=" + pending.getValue().orElseThrow()),
                        "Content-Type", List.of("application/x-www-form-urlencoded")))
                .body("SAMLResponse=%25".getBytes(StandardCharsets.US_ASCII)).build();
        Response rejected = fixture.resources.samlAcs(malformed);
        assertEquals(400, rejected.getStatusCode());
        assertNull(session.identity);
        assertNull(session.samlFlow);
        assertTrue(rejected.getCookies().stream().anyMatch(cookie -> cookie.getName().equals(PlaygroundSaml.LOGIN_COOKIE)
                && cookie.getMaxAge().orElseThrow().isZero()));
        assertEquals(400, fixture.resources.samlAcs(malformed).getStatusCode());
    }

    @Test void callbackRejectsForeignOriginAndMalformedLogoutWithoutChangingSession() throws IOException {
        Fixture fixture = fixture();
        BrowserSessions.Session session = fixture.sessions.begin();
        Response started = fixture.resources.samlBegin(form("/saml/begin", session, "csrf=" + session.csrf));
        assertEquals(302, started.getStatusCode());
        Request foreign = Request.withPath(HttpMethod.POST, "/saml/acs")
                .headers(Map.of("Host", List.of("localhost:8443"),
                        "Origin", List.of("https://foreign.example"),
                        "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id),
                        "Content-Type", List.of("application/x-www-form-urlencoded")))
                .body("SAMLResponse=%25".getBytes(StandardCharsets.US_ASCII)).build();
        assertEquals(403, fixture.resources.samlAcs(foreign).getStatusCode());
        assertNotNull(session.samlFlow);
        assertEquals(400, fixture.resources.samlLogoutCallback(Request.withPath(HttpMethod.GET, "/saml/slo")
                .headers(Map.of("Host", List.of("localhost:8443"))).build()).getStatusCode());
        assertNotNull(session.samlFlow);
    }

    @Test void opaqueOriginOnAcsReachesPendingAndProtocolChecks() throws IOException {
        Fixture fixture = fixture();
        BrowserSessions.Session session = fixture.sessions.begin();
        Response started = fixture.resources.samlBegin(form("/saml/begin", session, "csrf=" + session.csrf));
        assertEquals(302, started.getStatusCode());
        ResponseCookie pending = started.getCookies().get(0);
        Request malformed = Request.withPath(HttpMethod.POST, "/saml/acs")
                .headers(Map.of("Host", List.of("localhost:8443"), "Origin", List.of("null"),
                        "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id + "; "
                                + pending.getName() + "=" + pending.getValue().orElseThrow()),
                        "Content-Type", List.of("application/x-www-form-urlencoded")))
                .body("SAMLResponse=%25".getBytes(StandardCharsets.US_ASCII)).build();
        assertEquals(400, fixture.resources.samlAcs(malformed).getStatusCode());
        assertNull(session.identity);
        assertNull(session.samlFlow);
        assertEquals(400, fixture.resources.samlAcs(malformed).getStatusCode());
        assertEquals(403, fixture.resources.samlLogoutCallback(Request.withPath(HttpMethod.GET, "/saml/slo")
                .headers(Map.of("Host", List.of("localhost:8443"), "Origin", List.of("null")))
                .build()).getStatusCode());
    }

    @Test void sokletRoutesDeliverMetadataAndBeginResponse() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session session = fixture.sessions.begin();
        SokletSimulator.run(Playground.sokletConfig(fixture.config, fixture.resources, fixture.views), simulator -> {
            Response metadata = simulator.performHttpRequest(Request.withPath(HttpMethod.GET, "/saml/metadata")
                    .headers(Map.of("Host", List.of("localhost:8443"))).build()).getResponse().orElseThrow();
            assertEquals(200, metadata.getStatusCode());
            Response begin = simulator.performHttpRequest(form("/saml/begin", session, "csrf=" + session.csrf))
                    .getResponse().orElseThrow();
            assertEquals(302, begin.getStatusCode());
            assertEquals(PlaygroundSaml.LOGIN_COOKIE, begin.getCookies().get(0).getName());
            Response rejected = simulator.performHttpRequest(Request.withPath(HttpMethod.POST, "/saml/acs")
                    .headers(Map.of("Host", List.of("localhost:8443"),
                            "Content-Type", List.of("application/x-www-form-urlencoded")))
                    .body("SAMLResponse=%25".getBytes(StandardCharsets.US_ASCII)).build())
                    .getResponse().orElseThrow();
            assertEquals(400, rejected.getStatusCode());
        });
    }

    @Test void verifiedLogoutWithAnotherSessionIndexDoesNotEndTheBrowserSession() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session loggedIn = authenticatedSession(fixture);
        Response unmatched = fixture.resources.samlLogoutCallback(signedLogoutRequest(
                "_unmatched-playground-logout", "session-other", idpPrivateKey()));
        assertEquals(302, unmatched.getStatusCode());
        assertNotNull(loggedIn.identity);
        assertNotNull(loggedIn.samlReference);

        Response matched = fixture.resources.samlLogoutCallback(signedLogoutRequest(
                "_matched-playground-logout", "session-123", idpPrivateKey()));
        assertEquals(302, matched.getStatusCode());
        assertNull(loggedIn.identity);
        assertNull(loggedIn.samlReference);
    }

    @Test void rejectedLogoutCallbacksPreserveTheAttemptUntilAGenuineResponseSucceeds() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session session = authenticatedSession(fixture);
        Response started = beginLogout(fixture, session);
        PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
        String genuine = logoutResponseQuery(started, "_genuine-completion",
                "https://localhost:8443/saml/slo", "Success");
        List<String> rejected = List.of("", genuine.substring(0, genuine.indexOf("&SigAlg=")),
                genuine.substring(0, genuine.indexOf("&Signature=") + "&Signature=".length())
                        + URLEncoder.encode(Base64.getEncoder().encodeToString(new byte[256]), StandardCharsets.UTF_8),
                logoutResponseQuery(started, "_wrong-destination", "https://localhost:8443/other", "Success"));
        for (String query : rejected) {
            Response response = fixture.resources.samlLogoutCallback(logoutCallback(session, query, flow.sealed));
            assertEquals(400, response.getStatusCode());
            assertPreserved(session, flow, response);
        }
        Response completed = fixture.resources.samlLogoutCallback(logoutCallback(session, genuine, flow.sealed));
        assertEquals(302, completed.getStatusCode());
        assertNull(session.samlLogout);
        assertLogoutCookieCleared(completed);
        assertNull(session.identity);
        assertNull(session.samlReference);
    }

    @Test void missingWrongOrDuplicatePendingCookiesDoNotBurnTheLogoutAttempt() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session session = authenticatedSession(fixture);
        Response started = beginLogout(fixture, session);
        PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
        String genuine = logoutResponseQuery(started, "_cookie-bound-completion",
                "https://localhost:8443/saml/slo", "Success");
        for (String cookie : List.of("", "wrong", flow.sealed + "; " + PlaygroundSaml.LOGOUT_COOKIE + "=duplicate")) {
            Response rejected = fixture.resources.samlLogoutCallback(logoutCallback(session, genuine,
                    cookie.isEmpty() ? null : cookie));
            assertEquals(400, rejected.getStatusCode());
            assertPreserved(session, flow, rejected);
        }
        Response completed = fixture.resources.samlLogoutCallback(logoutCallback(session, genuine, flow.sealed));
        assertEquals(302, completed.getStatusCode());
        assertNull(session.samlLogout);
        assertLogoutCookieCleared(completed);
    }

    @Test void verifiedNonSuccessStatusEndsTheAttemptAndClearsItsCookie() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session session = authenticatedSession(fixture);
        Response started = beginLogout(fixture, session);
        PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
        String query = logoutResponseQuery(started, "_non-success-completion",
                "https://localhost:8443/saml/slo", "Responder");
        Response completed = fixture.resources.samlLogoutCallback(logoutCallback(session, query, flow.sealed));
        assertEquals(400, completed.getStatusCode());
        assertTrue(completed.getBody().orElseThrow().toString().contains("unsuccessful logout"));
        assertNull(session.samlLogout);
        assertLogoutCookieCleared(completed);
        assertNull(session.identity);
        assertNull(session.samlReference);
    }

    @Test void expiredLogoutAttemptClearsStateAndCookieOnEitherCallbackPath() throws Exception {
        for (boolean malformed : new boolean[] {false, true}) {
            MutableClock clock = new MutableClock(CLOCK.instant());
            Fixture fixture = fixture(clock);
            BrowserSessions.Session session = authenticatedSession(fixture);
            Response started = beginLogout(fixture, session);
            PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
            String query = malformed ? "" : logoutResponseQuery(started, "_expired-completion",
                    "https://localhost:8443/saml/slo", "Success");
            clock.now.set(flow.expires);
            Response rejected = fixture.resources.samlLogoutCallback(logoutCallback(session, query, flow.sealed));
            assertEquals(400, rejected.getStatusCode());
            assertNull(session.samlLogout);
            assertLogoutCookieCleared(rejected);
            assertNull(session.identity);
            assertNull(session.samlReference);
        }
    }

    @Test void unavailableOrUncertainReplayAdmissionPreservesStateWithoutRestoringLocalAccess() throws Exception {
        for (SamlReplayCache.MarkResult outcome : List.of(SamlReplayCache.MarkResult.UNAVAILABLE,
                SamlReplayCache.MarkResult.INDETERMINATE)) {
            Fixture fixture = fixture();
            BrowserSessions.Session session = authenticatedSession(fixture);
            Response started = beginLogout(fixture, session);
            PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
            String query = logoutResponseQuery(started, "_store-fault-completion",
                    "https://localhost:8443/saml/slo", "Success");
            Field spField = PlaygroundSaml.class.getDeclaredField("sp");
            spField.setAccessible(true);
            SamlServiceProvider sp = assertInstanceOf(SamlServiceProvider.class, spField.get(fixture.saml));
            Field replayField = SamlServiceProvider.class.getDeclaredField("replayCache");
            replayField.setAccessible(true);
            SamlReplayCache original = assertInstanceOf(SamlReplayCache.class, replayField.get(sp));
            try {
                // Inject a storage fault after genuine login/begin, at the application's completion boundary.
                replayField.set(sp, (SamlReplayCache) (key, expiry, remaining) -> outcome);
                Response failed = fixture.resources.samlLogoutCallback(logoutCallback(session, query, flow.sealed));
                assertEquals(503, failed.getStatusCode());
                assertPreserved(session, flow, failed);
            } finally {
                replayField.set(sp, original);
            }
            Response completed = fixture.resources.samlLogoutCallback(logoutCallback(session, query, flow.sealed));
            assertEquals(302, completed.getStatusCode());
            assertNull(session.samlLogout);
            assertLogoutCookieCleared(completed);
            assertNull(session.identity);
            assertNull(session.samlReference);
        }
    }

    @Test void concurrentGenuineCallbacksReportOnlyOneVerifiedCompletion() throws Exception {
        Fixture fixture = fixture();
        BrowserSessions.Session session = authenticatedSession(fixture);
        Response started = beginLogout(fixture, session);
        PlaygroundSaml.LogoutFlow flow = requireNonNull(session.samlLogout);
        String query = logoutResponseQuery(started, "_concurrent-completion",
                "https://localhost:8443/saml/slo", "Success");
        Request callback = logoutCallback(session, query, flow.sealed);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch gate = new CountDownLatch(1);
        try {
            List<Future<Response>> responses = List.of(workers.submit(() -> {
                assertTrue(gate.await(5, TimeUnit.SECONDS));
                return fixture.resources.samlLogoutCallback(callback);
            }), workers.submit(() -> {
                assertTrue(gate.await(5, TimeUnit.SECONDS));
                return fixture.resources.samlLogoutCallback(callback);
            }));
            gate.countDown();
            int successes = 0;
            for (Future<Response> future : responses) {
                Response response = future.get(5, TimeUnit.SECONDS);
                if (response.getStatusCode() == 302) successes++;
                else assertEquals(400, response.getStatusCode());
            }
            assertEquals(1, successes);
            assertNull(session.samlLogout);
            assertNull(session.identity);
            assertNull(session.samlReference);
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static BrowserSessions.@NonNull Session authenticatedSession(@NonNull Fixture fixture) throws Exception {
        BrowserSessions.Session initial = fixture.sessions.begin();
        Response begun = fixture.resources.samlBegin(form("/saml/begin", initial, "csrf=" + initial.csrf));
        assertEquals(302, begun.getStatusCode());
        String requestId = outboundRequestId(begun.getHeaders().get("Location").get(0));
        ResponseCookie pendingCookie = begun.getCookies().get(0);
        String assertion = "<a:Assertion ID='_playground-assertion' Version='2.0' "
                + "IssueInstant='2026-10-10T00:00:00Z'>"
                + "<a:Issuer>https://idp.example.test/</a:Issuer>"
                + "<a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' "
                + "NameQualifier='https://idp.example.test/'>alice</a:NameID>"
                + "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
                + "<a:SubjectConfirmationData Recipient='https://localhost:8443/saml/acs' "
                + "InResponseTo='" + requestId + "' NotOnOrAfter='2026-10-10T00:05:00Z'/>"
                + "</a:SubjectConfirmation></a:Subject>"
                + "<a:Conditions NotBefore='2026-10-09T23:59:00Z' NotOnOrAfter='2026-10-10T00:05:00Z'>"
                + "<a:AudienceRestriction><a:Audience>https://localhost:8443/saml/metadata</a:Audience>"
                + "</a:AudienceRestriction></a:Conditions>"
                + "<a:AuthnStatement AuthnInstant='2026-10-10T00:00:00Z' SessionIndex='session-123'>"
                + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:password"
                + "</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>"
                + "</a:Assertion>";
        String responseXml = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                + "ID='_playground-response' Version='2.0' IssueInstant='2026-10-10T00:00:00Z' "
                + "Destination='https://localhost:8443/saml/acs' InResponseTo='" + requestId + "'>"
                + "<a:Issuer>https://idp.example.test/</a:Issuer>"
                + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>"
                + assertion + "</p:Response>";
        String signed = signedResponse(responseXml, idpPrivateKey());
        String formBody = "SAMLResponse=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8) + "&RelayState="
                + URLEncoder.encode(outboundRelayState(begun.getHeaders().get("Location").get(0)),
                        StandardCharsets.UTF_8);
        Request callback = Request.withPath(HttpMethod.POST, "/saml/acs")
                .headers(Map.of("Host", List.of("localhost:8443"),
                        "Origin", List.of("https://idp.example.test"),
                        "Cookie", List.of(BrowserSessions.COOKIE + "=" + initial.id + "; "
                                + pendingCookie.getName() + "=" + pendingCookie.getValue().orElseThrow()),
                        "Content-Type", List.of("application/x-www-form-urlencoded")))
                .body(formBody.getBytes(StandardCharsets.US_ASCII)).build();
        Response completed = fixture.resources.samlAcs(callback);
        assertEquals(302, completed.getStatusCode());
        ResponseCookie browserCookie = completed.getCookies().stream()
                .filter(cookie -> cookie.getName().equals(BrowserSessions.COOKIE)).findFirst().orElseThrow();
        BrowserSessions.Session loggedIn = fixture.sessions.find(Request.withPath(HttpMethod.GET, "/")
                .headers(Map.of("Cookie", List.of(BrowserSessions.COOKIE + "="
                        + browserCookie.getValue().orElseThrow()))).build()).orElseThrow();
        assertNotNull(loggedIn.identity);
        assertEquals("session-123", loggedIn.samlReference.getSessionIndex().orElseThrow());
        return loggedIn;
    }

    private static @NonNull Response beginLogout(@NonNull Fixture fixture,
            BrowserSessions.@NonNull Session session) {
        Response started = fixture.resources.samlBeginLogout(form("/saml/logout", session, "csrf=" + session.csrf));
        assertEquals(302, started.getStatusCode());
        assertNotNull(session.samlLogout);
        assertNull(session.identity);
        assertNull(session.samlReference);
        return started;
    }

    private static void assertPreserved(BrowserSessions.@NonNull Session session,
            PlaygroundSaml.@NonNull LogoutFlow flow, @NonNull Response response) {
        assertSame(flow, session.samlLogout);
        assertTrue(response.getCookies().stream().noneMatch(cookie -> cookie.getName().equals(PlaygroundSaml.LOGOUT_COOKIE)));
        assertNull(session.identity);
        assertNull(session.samlReference);
    }

    private static void assertLogoutCookieCleared(@NonNull Response response) {
        assertTrue(response.getCookies().stream().anyMatch(cookie -> cookie.getName().equals(PlaygroundSaml.LOGOUT_COOKIE)
                && cookie.getMaxAge().orElseThrow().isZero()));
    }

    private static @NonNull Request logoutCallback(BrowserSessions.@NonNull Session session,
            @NonNull String query, @Nullable String pendingCookie) {
        String cookies = BrowserSessions.COOKIE + "=" + session.id
                + (pendingCookie == null ? "" : "; " + PlaygroundSaml.LOGOUT_COOKIE + "=" + pendingCookie);
        // Browser navigations may omit Origin; a callback still has to prove its SAML and pending bindings.
        return Request.withRawUrl(HttpMethod.GET, "/saml/slo" + (query.isEmpty() ? "" : "?" + query))
                .headers(Map.of("Host", List.of("localhost:8443"), "Cookie", List.of(cookies))).build();
    }

    private static @NonNull String logoutResponseQuery(@NonNull Response started, @NonNull String responseId,
            @NonNull String destination, @NonNull String status) throws Exception {
        String redirect = started.getHeaders().get("Location").get(0);
        String xml = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='" + responseId + "' Version='2.0' "
                + "IssueInstant='2026-10-10T00:00:00Z' Destination='" + destination
                + "' InResponseTo='" + outboundRequestId(redirect) + "'>"
                + "<a:Issuer>https://idp.example.test/</a:Issuer>"
                + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:" + status
                + "'/></p:Status></p:LogoutResponse>";
        return signedRedirectQuery("SAMLResponse", xml, outboundRelayState(redirect), idpPrivateKey());
    }

    private static @NonNull String outboundRequestId(@NonNull String redirect) throws Exception {
        String query = URI.create(redirect).getRawQuery();
        String encoded = query.substring("SAMLRequest=".length(), query.indexOf('&'));
        byte[] compressed = Base64.getDecoder().decode(URLDecoder.decode(encoded, StandardCharsets.UTF_8));
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(compressed);
            byte[] output = new byte[16_384];
            int length = inflater.inflate(output);
            assertTrue(inflater.finished());
            Matcher matcher = Pattern.compile("\\bID=\"([^\"]+)\"").matcher(
                    new String(output, 0, length, StandardCharsets.UTF_8));
            assertTrue(matcher.find());
            return matcher.group(1);
        } finally { inflater.end(); }
    }

    private static @NonNull String outboundRelayState(@NonNull String redirect) {
        String query = URI.create(redirect).getRawQuery();
        String field = query.substring(query.indexOf("&RelayState=") + "&RelayState=".length());
        int end = field.indexOf('&');
        return URLDecoder.decode(end < 0 ? field : field.substring(0, end), StandardCharsets.UTF_8);
    }

    private static @NonNull PrivateKey idpPrivateKey() throws Exception {
        String pem = resource("idp-signing-rsa-2048-key.pem");
        String encoded = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(encoded)));
    }

    private static @NonNull String signedResponse(@NonNull String xml, @NonNull PrivateKey key) throws Exception {
        DocumentBuilderFactory parser = DocumentBuilderFactory.newDefaultInstance();
        parser.setNamespaceAware(true);
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document document = parser.newDocumentBuilder().parse(new ByteArrayInputStream(
                xml.getBytes(StandardCharsets.UTF_8)));
        Element root = document.getDocumentElement();
        root.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + root.getAttribute("ID"),
                factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        var signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(key, root);
        context.setDefaultNamespacePrefix("ds");
        Node afterIssuer = root.getFirstChild().getNextSibling();
        if (afterIssuer != null) context.setNextSibling(afterIssuer);
        factory.newXMLSignature(signedInfo, null).sign(context);
        Transformer writer = TransformerFactory.newDefaultInstance().newTransformer();
        writer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        writer.transform(new DOMSource(document), new StreamResult(bytes));
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static @NonNull Request signedLogoutRequest(@NonNull String id, @NonNull String sessionIndex,
            @NonNull PrivateKey key) throws Exception {
        String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='" + id + "' Version='2.0' "
                + "IssueInstant='2026-10-10T00:00:00Z' Destination='https://localhost:8443/saml/slo'>"
                + "<a:Issuer>https://idp.example.test/</a:Issuer>"
                + "<a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' "
                + "NameQualifier='https://idp.example.test/'>alice</a:NameID>"
                + "<p:SessionIndex>" + sessionIndex + "</p:SessionIndex></p:LogoutRequest>";
        return Request.withRawUrl(HttpMethod.GET, "/saml/slo?" + signedRedirectQuery("SAMLRequest", xml, null, key))
                .headers(Map.of("Host", List.of("localhost:8443"),
                        "Origin", List.of("https://idp.example.test"))).build();
    }

    private static @NonNull String signedRedirectQuery(@NonNull String field, @NonNull String xml,
            @Nullable String relay, @NonNull PrivateKey key) throws Exception {
        Deflater compressor = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] compressed = new byte[8192];
        int length;
        try {
            compressor.setInput(xml.getBytes(StandardCharsets.UTF_8));
            compressor.finish();
            length = compressor.deflate(compressed);
            assertTrue(compressor.finished());
        } finally { compressor.end(); }
        String signed = field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOf(compressed, length)), StandardCharsets.UTF_8)
                + (relay == null ? "" : "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8))
                + "&SigAlg=" + URLEncoder.encode(
                        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", StandardCharsets.UTF_8);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(signed.getBytes(StandardCharsets.US_ASCII));
        return signed + "&Signature=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(signature.sign()), StandardCharsets.UTF_8);
    }

    private @NonNull Fixture fixture() throws IOException {
        return fixture(CLOCK);
    }

    private @NonNull Fixture fixture(@NonNull Clock clock) throws IOException {
        String idpCertificate = resource("idp-signing-rsa-2048-cert.pem");
        String encoded = idpCertificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        String metadata = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
                + "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "
                + "entityID=\"https://idp.example.test/\"><md:IDPSSODescriptor "
                + "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + encoded + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "
                + "Location=\"https://idp.example.test/sso\"/>"
                + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "
                + "Location=\"https://idp.example.test/slo\"/>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
        Path metadataFile = Files.writeString(directory.resolve("idp.xml"), metadata);
        Path signingKey = Files.writeString(directory.resolve("sp.key"), resource("sp-signing-rsa-2048-key.pem"));
        Path signingCertificate = Files.writeString(directory.resolve("sp.crt"), resource("sp-signing-rsa-2048-cert.pem"));
        Map<String, String> environment = Map.of(
                "PLAYGROUND_SAML_METADATA_FILE", metadataFile.toString(),
                "PLAYGROUND_SAML_IDP_ENTITY_ID", "https://idp.example.test/",
                "PLAYGROUND_SAML_CONNECTION_ID", "example-connection",
                "PLAYGROUND_SAML_SIGNING_KEY_FILE", signingKey.toString(),
                "PLAYGROUND_SAML_SIGNING_CERT_FILE", signingCertificate.toString());
        PlaygroundConfig config = PlaygroundConfig.fromEnvironment(Map.of());
        BrowserSessions sessions = new BrowserSessions(clock, 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundSaml saml = requireNonNull(PlaygroundSaml.fromEnvironment(environment, config,
                sessions, views, clock));
        PlaygroundOidc oidc = new PlaygroundOidc(sessions, views, clock);
        PlaygroundResources resources = new PlaygroundResources(config, sessions, views, oidc,
                HttpClient.newHttpClient(), token -> { throw new AssertionError("Not part of the SAML test"); }, saml);
        return new Fixture(config, sessions, views, resources, environment, saml);
    }

    private static @NonNull Request form(@NonNull String path, BrowserSessions.@NonNull Session session,
            @NonNull String body) {
        return Request.withPath(HttpMethod.POST, path).headers(Map.of(
                "Host", List.of("localhost:8443"), "Origin", List.of("https://localhost:8443"),
                "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id),
                "Content-Type", List.of("application/x-www-form-urlencoded")))
                .body(body.getBytes(StandardCharsets.US_ASCII)).build();
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        try (var stream = PlaygroundSamlTests.class.getResourceAsStream("/saml/" + name)) {
            if (stream == null) throw new IOException("Missing SAML fixture");
            return new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    private static final class Fixture {
        final PlaygroundConfig config;
        final BrowserSessions sessions;
        final SafeViews views;
        final PlaygroundResources resources;
        final Map<String, String> environment;
        final PlaygroundSaml saml;
        Fixture(@NonNull PlaygroundConfig config, @NonNull BrowserSessions sessions, @NonNull SafeViews views,
                @NonNull PlaygroundResources resources,
                @NonNull Map<@NonNull String, @NonNull String> environment, @NonNull PlaygroundSaml saml) {
            this.config = config; this.sessions = sessions; this.views = views;
            this.resources = resources; this.environment = environment; this.saml = saml;
        }
    }

    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> now;
        private MutableClock(@NonNull Instant initial) { this.now = new AtomicReference<>(initial); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() { return now.get(); }
    }
}
