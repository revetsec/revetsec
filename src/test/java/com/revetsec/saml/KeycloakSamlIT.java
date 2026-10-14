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

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real-product SAML POST response from the pinned, local Keycloak test realm. */
final class KeycloakSamlIT {
    private static final @NonNull String IMAGE =
            "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c";
    private static final @NonNull String ENTITY = "https://sp.test/KeycloakSamlIT";
    private static final @NonNull String POST_ENTITY = "https://sp.test/KeycloakSamlPostLogoutIT";
    private static final @NonNull URI ACS = URI.create("https://sp.test/acs");
    private static final @NonNull URI POST_SLO = URI.create("https://sp.test/logout/post");
    private static final @NonNull Pattern LOGIN_FORM = Pattern.compile(
            "<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", Pattern.DOTALL);
    private static final @NonNull Pattern POST_FORM = Pattern.compile(
            "<form\\b[^>]*>(.*?)</form>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final @NonNull Pattern INPUT = Pattern.compile("<input\\b[^>]*>",
            Pattern.CASE_INSENSITIVE);
    private static @NonNull GenericContainer<?> keycloak;
    private static @NonNull String issuer;

    @BeforeAll static void start() throws Exception {
        keycloak = new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withExposedPorts(8443)
                .withCreateContainerCmdModifier(command -> requireNonNull(command.getHostConfig())
                        .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"),
                                new ExposedPort(8443))))
                .withCopyFileToContainer(MountableFile.forHostPath(Path.of(
                        "src/test/resources/tls/server.pem").toAbsolutePath()),
                        "/opt/keycloak/conf/tls/cert.pem")
                .withCopyFileToContainer(MountableFile.forHostPath(Path.of(
                        "src/test/resources/tls/server-key.pem").toAbsolutePath()),
                        "/opt/keycloak/conf/tls/key.pem")
                .withCopyFileToContainer(MountableFile.forHostPath(Path.of(
                        "interop/keycloak/revetsec-test-realm.json").toAbsolutePath()),
                        "/opt/keycloak/data/import/revetsec-test-realm.json")
                .withCommand("start", "--db=dev-file", "--hostname-strict=false", "--http-enabled=false",
                        "--https-certificate-file=/opt/keycloak/conf/tls/cert.pem",
                        "--https-certificate-key-file=/opt/keycloak/conf/tls/key.pem", "--import-realm")
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        issuer = "https://localhost:" + keycloak.getMappedPort(8443) + "/realms/revetsec-test";
        HttpClient readiness = TestTls.httpClient();
        HttpResponse<String> response = readiness.send(HttpRequest.newBuilder(URI.create(issuer
                + "/protocol/saml/descriptor")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
    }

    @AfterAll static void stop() {
        if (keycloak != null) keycloak.stop();
    }

    @Test void redirectLoginProducesCheckedPostResponse() throws Exception {
        HttpClient browser = TestTls.httpClientBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        SamlIdentityProvider idp = identityProvider(browser, false);
        Clock clock = Clock.systemUTC();
        SamlCredential credential = decryptionCredential();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(URI.create("https://sp.test/logout"))
                .signingPrivateKey(credential.privateKey())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32))
                .decryptionCredentials(List.of(credential))
                .clock(clock).build();
        SamlAuthenticationRequestResult.Prepared begin = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp));
        SamlPostBindingMessage message = browserPost(browser, begin.getRedirectUri());
        assertEncryptedProfile(message);
        assertEquals(begin.getPendingAuthentication().getRelayStateHandle(),
                message.getRelayState().orElse(null));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("keycloak-saml"))
                .clock(clock).build();
        String sealed = begin.getPendingAuthentication().toSealedForm(sealer, "keycloak-saml");
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                sealed, sealer, "keycloak-saml");
        PendingSamlAuthenticationSource.Resolved resolved = assertInstanceOf(
                PendingSamlAuthenticationSource.Resolved.class,
                source.resolve(clock, message.getRelayState().orElse(null), Duration.ofSeconds(2)));
        assertEquals(idp.getEntityId(), resolved.pending().idpEntityId());
        SamlAuthenticationResult result = sp.completeAuthenticationResult(message, source, idp);
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result, result.toString());
        assertEquals("keycloak-real-product",
                success.getAuthentication().getIdentityProviderConnectionId());

        SamlLogoutRedirectResult.Prepared logout = assertInstanceOf(
                SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(idp, success.getAuthentication().getSessionReference()));
        HttpResponse<String> logoutRedirect = browser.send(HttpRequest.newBuilder(logout.getRedirectUri())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, logoutRedirect.statusCode(), logoutRedirect.body());
        URI returnUri = URI.create(logoutRedirect.headers().firstValue("Location").orElseThrow());
        assertEquals("https://sp.test/logout", returnUri.getScheme() + "://"
                + returnUri.getAuthority() + returnUri.getPath());
        SamlRedirectBindingMessage response = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(returnUri.getRawQuery())).getMessage();
        String sealedLogout = logout.getPendingLogout().toSealedForm(sealer, "keycloak-saml-logout");
        SamlLogoutResult logoutResult = sp.completeLogoutResult(response,
                PendingSamlLogoutSource.fromSealedForm(sealedLogout, sealer, "keycloak-saml-logout"), idp);
        assertInstanceOf(SamlLogoutResult.Succeeded.class, logoutResult, logoutResult.toString());
    }

    @Test void idpInitiatedLoginRequiresExplicitConnectionMode() throws Exception {
        HttpClient browser = TestTls.httpClientBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        SamlIdentityProvider idp = identityProvider(browser, true);
        Clock clock = Clock.systemUTC();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32))
                .decryptionCredentials(List.of(decryptionCredential()))
                .clock(clock).build();
        SamlPostBindingMessage message = browserPost(browser, URI.create(issuer
                + "/protocol/saml/clients/revetsec-unsolicited"));
        assertEncryptedProfile(message);
        assertTrue(message.getRelayState().isEmpty());
        SamlAuthenticationResult result = sp.completeUnsolicitedAuthenticationResult(message, idp);
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result, result.toString());
        assertTrue(success.getAuthentication().isUnsolicited());
        assertEquals("keycloak-real-product",
                success.getAuthentication().getIdentityProviderConnectionId());
        assertEquals(SamlAuthenticationResult.Reason.REPLAYED,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeUnsolicitedAuthenticationResult(message, idp)).getReason());
    }

    @Test void idpInitiatedLogoutReturnsSignedRedirectRequest() throws Exception {
        HttpClient browser = TestTls.httpClientBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        SamlIdentityProvider idp = identityProvider(browser, true);
        SamlPostBindingMessage login = browserPost(browser, URI.create(issuer
                + "/protocol/saml/clients/revetsec-unsolicited"));
        Clock clock = Clock.systemUTC();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(URI.create("https://sp.test/logout"))
                .signingPrivateKey(decryptionCredential().privateKey())
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32))
                .decryptionCredentials(List.of(decryptionCredential()))
                .clock(clock).build();
        SamlAuthentication identity = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeUnsolicitedAuthenticationResult(login, idp)).getAuthentication();
        HttpResponse<String> logout = browser.send(HttpRequest.newBuilder(URI.create(issuer
                + "/protocol/openid-connect/logout?client_id=" + encode(ENTITY))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, logout.statusCode());
        Matcher logoutForm = POST_FORM.matcher(logout.body());
        assertTrue(logoutForm.find());
        String opening = logoutForm.group().substring(0, logoutForm.group().indexOf('>') + 1);
        assertEquals("post", attribute(opening, "method").toLowerCase(Locale.ROOT));
        URI action = logout.uri().resolve(attribute(opening, "action"));
        assertEquals(URI.create(issuer).getAuthority(), action.getAuthority());
        StringBuilder body = new StringBuilder();
        Matcher fields = INPUT.matcher(logoutForm.group(1));
        while (fields.find()) {
            String element = fields.group();
            Matcher name = Pattern.compile("\\bname=[\"']([^\"']*)[\"']").matcher(element);
            if (!name.find()) continue;
            Matcher value = Pattern.compile("\\bvalue=[\"']([^\"']*)[\"']").matcher(element);
            if (!body.isEmpty()) body.append('&');
            body.append(encode(name.group(1))).append('=')
                    .append(encode(value.find() ? value.group(1) : ""));
        }
        HttpResponse<String> confirmed = browser.send(HttpRequest.newBuilder(action)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(302, confirmed.statusCode());
        URI logoutRequestUri = URI.create(confirmed.headers().firstValue("Location").orElseThrow());
        assertEquals("https://sp.test/logout", logoutRequestUri.getScheme() + "://"
                + logoutRequestUri.getAuthority() + logoutRequestUri.getPath());
        SamlRedirectBindingMessage logoutRequest = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(logoutRequestUri.getRawQuery())).getMessage();
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(logoutRequest, idp)).getRequest();
        assertEquals(identity.getSessionReference().getNameId().getValue(), accepted.getNameId().getValue());
        assertEquals(identity.getSessionIndex().orElseThrow(), accepted.getSessionIndexes().get(0));
        SamlLogoutResponseRedirectResult.Prepared answer = assertInstanceOf(
                SamlLogoutResponseRedirectResult.Prepared.class,
                sp.respondToLogoutRequestResult(accepted, idp, SamlLogoutStatus.SUCCESS));
        HttpResponse<String> finished = browser.send(HttpRequest.newBuilder(answer.getRedirectUri())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, finished.statusCode());
    }

    @Test void postLogoutExchangesSignedXmlWithRealKeycloakAndRejectsTamperingAndReplay() throws Exception {
        HttpClient browser = TestTls.httpClientBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        SamlIdentityProvider idp = identityProvider(browser, false, true);
        Clock clock = Clock.systemUTC();
        SamlCredential credential = decryptionCredential();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(POST_ENTITY).assertionConsumerServiceUrl(ACS)
                .postSingleLogoutServiceUrl(POST_SLO).signingCredential(credential)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32))
                .decryptionCredentials(List.of(credential)).clock(clock).build();
        SamlAuthenticationRequestResult.Prepared begin = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp));
        SamlPostBindingMessage login = browserPost(browser, begin.getRedirectUri());
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("keycloak-post-slo"))
                .clock(clock).build();
        SamlAuthentication identity = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(login, PendingSamlAuthenticationSource.fromSealedForm(
                        begin.getPendingAuthentication().toSealedForm(sealer, "keycloak-post-sso"),
                        sealer, "keycloak-post-sso"), idp)).getAuthentication();
        SamlLogoutPostResult.Prepared logout = assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                sp.beginPostLogoutResult(idp, identity.getSessionReference()));
        String requestXml = new String(java.util.Base64.getDecoder().decode(
                logout.getPostForm().getFields().get("SAMLRequest")), StandardCharsets.UTF_8);
        assertTrue(requestXml.contains("Signature"));
        String tamperedXml = requestXml.replace(identity.getSessionReference().getNameId().getValue(),
                "attacker-name-id");
        assertTrue(!requestXml.equals(tamperedXml));
        String badBody = "SAMLRequest=" + encode(java.util.Base64.getEncoder().encodeToString(
                tamperedXml.getBytes(StandardCharsets.UTF_8))) + "&RelayState="
                + encode(logout.getPendingLogout().getRelayStateHandle());
        HttpResponse<String> rejectedRequest = browser.send(HttpRequest.newBuilder(logout.getPostForm().getAction())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(badBody)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(400, rejectedRequest.statusCode(), rejectedRequest.body());
        HttpResponse<String> fromIdp = submitSamlPost(browser, logout.getPostForm());
        assertEquals(200, fromIdp.statusCode(), fromIdp.body());
        SamlPostBindingMessage response = logoutPostPage(fromIdp, POST_SLO);
        assertEquals(SamlPostBindingMessage.Kind.RESPONSE, response.getKind());
        String responseXml = new String(response.xml(), StandardCharsets.UTF_8);
        assertTrue(responseXml.contains("Signature"));
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                logout.getPendingLogout().toSealedForm(sealer, "keycloak-post-slo"), sealer, "keycloak-post-slo");
        String changedStatus = responseXml.replace("status:Success", "status:Responder");
        assertTrue(!changedStatus.equals(responseXml));
        SamlPostBindingMessage tamperedResponse = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(("SAMLResponse=" + encode(
                        java.util.Base64.getEncoder().encodeToString(changedStatus.getBytes(StandardCharsets.UTF_8)))
                        + "&RelayState=" + encode(response.getRelayState().orElseThrow()))
                        .getBytes(StandardCharsets.US_ASCII), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(tamperedResponse, pending, idp));
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(response, pending, idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(response, pending, idp));
    }

    @Test void idpInitiatedPostLogoutRequestAndReplyUseSignedXmlWithRealKeycloak() throws Exception {
        HttpClient browser = TestTls.httpClientBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        SamlIdentityProvider idp = identityProvider(browser, true, true);
        Clock clock = Clock.systemUTC();
        SamlCredential credential = decryptionCredential();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(POST_ENTITY).assertionConsumerServiceUrl(ACS)
                .postSingleLogoutServiceUrl(POST_SLO).signingCredential(credential)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 32))
                .decryptionCredentials(List.of(credential)).clock(clock).build();
        SamlPostBindingMessage login = browserPost(browser, URI.create(issuer
                + "/protocol/saml/clients/revetsec-post-logout-unsolicited"));
        SamlAuthentication identity = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeUnsolicitedAuthenticationResult(login, idp)).getAuthentication();
        HttpResponse<String> confirmation = browser.send(HttpRequest.newBuilder(URI.create(issuer
                + "/protocol/openid-connect/logout?client_id=" + encode(POST_ENTITY))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, confirmation.statusCode(), confirmation.body());
        HttpResponse<String> fromIdp = confirmLogout(browser, confirmation);
        assertEquals(200, fromIdp.statusCode(), fromIdp.body());
        SamlPostBindingMessage request = logoutPostPage(fromIdp, POST_SLO);
        assertEquals(SamlPostBindingMessage.Kind.REQUEST, request.getKind());
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(request, idp)).getRequest();
        assertEquals(identity.getSessionReference().getNameId().getValue(), accepted.getNameId().getValue());
        assertEquals(identity.getSessionIndex().orElseThrow(), accepted.getSessionIndexes().get(0));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class, sp.acceptLogoutRequestResult(request, idp));
        SamlLogoutResponsePostResult.Prepared answer = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                sp.respondToPostLogoutRequestResult(accepted, idp, SamlLogoutStatus.SUCCESS));
        HttpResponse<String> finished = submitSamlPost(browser, answer.getPostForm());
        assertEquals(200, finished.statusCode(), finished.body());
    }

    private static @NonNull HttpResponse<@NonNull String> confirmLogout(@NonNull HttpClient browser,
            @NonNull HttpResponse<@NonNull String> page) throws Exception {
        Matcher form = POST_FORM.matcher(page.body());
        assertTrue(form.find(), page.body());
        String opening = form.group().substring(0, form.group().indexOf('>') + 1);
        assertEquals("post", attribute(opening, "method").toLowerCase(Locale.ROOT));
        URI action = page.uri().resolve(attribute(opening, "action"));
        assertEquals(URI.create(issuer).getAuthority(), action.getAuthority());
        StringBuilder body = new StringBuilder();
        Matcher inputs = INPUT.matcher(form.group(1));
        while (inputs.find()) {
            String element = inputs.group();
            Matcher name = Pattern.compile("\\bname=[\"']([^\"']*)[\"']").matcher(element);
            if (!name.find()) continue;
            Matcher value = Pattern.compile("\\bvalue=[\"']([^\"']*)[\"']").matcher(element);
            if (!body.isEmpty()) body.append('&');
            body.append(encode(name.group(1))).append('=').append(encode(value.find() ? value.group(1) : ""));
        }
        return browser.send(HttpRequest.newBuilder(action).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static @NonNull HttpResponse<@NonNull String> submitSamlPost(@NonNull HttpClient browser,
            @NonNull SamlPostForm form) throws Exception {
        StringBuilder body = new StringBuilder();
        for (var field : form.getFields().entrySet()) {
            if (!body.isEmpty()) body.append('&');
            body.append(encode(field.getKey())).append('=').append(encode(field.getValue()));
        }
        return browser.send(HttpRequest.newBuilder(form.getAction())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static @NonNull SamlPostBindingMessage logoutPostPage(@NonNull HttpResponse<@NonNull String> page,
            @NonNull URI destination) {
        Matcher form = POST_FORM.matcher(page.body());
        assertTrue(form.find(), page.body());
        String opening = form.group().substring(0, form.group().indexOf('>') + 1);
        assertEquals("post", attribute(opening, "method").toLowerCase(Locale.ROOT));
        assertEquals(destination.toASCIIString(), attribute(opening, "action"));
        StringBuilder body = new StringBuilder();
        Matcher inputs = INPUT.matcher(form.group(1));
        while (inputs.find()) {
            String element = inputs.group();
            if (!"hidden".equalsIgnoreCase(attribute(element, "type"))) continue;
            if (!body.isEmpty()) body.append('&');
            body.append(encode(attribute(element, "name"))).append('=').append(encode(attribute(element, "value")));
        }
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(body.toString().getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull HttpClient browser,
            boolean unsolicited) throws Exception {
        return identityProvider(browser, unsolicited, false);
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull HttpClient browser,
            boolean unsolicited, boolean signedRequests) throws Exception {
        HttpResponse<String> metadataResponse = browser.send(HttpRequest.newBuilder(URI.create(
                issuer + "/protocol/saml/descriptor")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        SamlIdentityProviderMetadata metadata = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(metadataResponse.body()
                        .getBytes(StandardCharsets.UTF_8), issuer, Clock.systemUTC())).getMetadata();
        return SamlIdentityProvider.withMetadata(metadata)
                .connectionId("keycloak-real-product")
                .wantAuthnRequestsSigned(signedRequests)
                .compatibility(unsolicited ? Set.of(SamlCompatibilityMode.UNSOLICITED_RESPONSES)
                        : Set.of()).build();
    }

    private static @NonNull SamlPostBindingMessage browserPost(@NonNull HttpClient browser,
            @NonNull URI start) throws Exception {
        HttpResponse<String> loginPage = browser.send(HttpRequest.newBuilder(start)
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginPage.statusCode(), loginPage.body());
        Matcher loginForm = LOGIN_FORM.matcher(loginPage.body());
        assertTrue(loginForm.find(), loginPage.body());
        URI action = URI.create(loginForm.group(1).replace("&amp;", "&"));
        assertEquals(URI.create(issuer).getAuthority(), action.getAuthority());
        String credentials = "username=" + encode("test-user") + "&password="
                + encode("test-only-password-not-a-secret") + "&credentialId=";
        HttpResponse<String> signed = browser.send(HttpRequest.newBuilder(action)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(credentials)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, signed.statusCode(), signed.body());
        Matcher form = POST_FORM.matcher(signed.body());
        assertTrue(form.find(), signed.body());
        String opening = form.group().substring(0, form.group().indexOf('>') + 1);
        assertEquals("post", attribute(opening, "method").toLowerCase(Locale.ROOT));
        assertEquals(ACS.toASCIIString(), attribute(opening, "action"));
        StringBuilder body = new StringBuilder();
        Matcher input = INPUT.matcher(form.group(1));
        while (input.find()) {
            String element = input.group();
            if (!"hidden".equalsIgnoreCase(attribute(element, "type"))) continue;
            if (!body.isEmpty()) body.append('&');
            body.append(encode(attribute(element, "name"))).append('=')
                    .append(encode(attribute(element, "value")));
        }
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(body.toString()
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull String attribute(@NonNull String tag, @NonNull String name) {
        Matcher value = Pattern.compile("\\b" + name + "=[\"']([^\"']*)[\"']",
                Pattern.CASE_INSENSITIVE).matcher(tag);
        assertTrue(value.find(), tag);
        return value.group(1).replace("&quot;", "\"").replace("&#39;", "'")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
    }

    private static @NonNull String encode(@NonNull String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void assertEncryptedProfile(@NonNull SamlPostBindingMessage message) {
        String xml = new String(message.xml(), StandardCharsets.UTF_8);
        assertTrue(xml.contains("EncryptedAssertion"));
        assertTrue(xml.contains("http://www.w3.org/2009/xmlenc11#aes256-gcm"));
        assertTrue(xml.contains("http://www.w3.org/2009/xmlenc11#rsa-oaep"));
    }

    private static @NonNull SamlCredential decryptionCredential() throws Exception {
        String key = Files.readString(Path.of(
                "src/test/resources/fixtures/keys/sp-encryption-rsa-2048-key.pem"),
                StandardCharsets.US_ASCII);
        String certificate = Files.readString(Path.of(
                "src/test/resources/fixtures/keys/sp-encryption-rsa-2048-cert.pem"),
                StandardCharsets.US_ASCII);
        return SamlCredential.fromPem(key, certificate);
    }
}
