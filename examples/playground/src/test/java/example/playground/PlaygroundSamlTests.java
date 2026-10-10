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

import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import com.soklet.SokletSimulator;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NonNull;
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

    private @NonNull Fixture fixture() throws IOException {
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
        BrowserSessions sessions = new BrowserSessions(CLOCK, 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundSaml saml = requireNonNull(PlaygroundSaml.fromEnvironment(environment, config,
                sessions, views, CLOCK));
        PlaygroundOidc oidc = new PlaygroundOidc(sessions, views, CLOCK);
        PlaygroundResources resources = new PlaygroundResources(config, sessions, views, oidc,
                HttpClient.newHttpClient(), token -> { throw new AssertionError("Not part of the SAML test"); }, saml);
        return new Fixture(config, sessions, views, resources, environment);
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
        Fixture(@NonNull PlaygroundConfig config, @NonNull BrowserSessions sessions, @NonNull SafeViews views,
                @NonNull PlaygroundResources resources,
                @NonNull Map<@NonNull String, @NonNull String> environment) {
            this.config = config; this.sessions = sessions; this.views = views;
            this.resources = resources; this.environment = environment;
        }
    }
}
