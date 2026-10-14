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
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.pem.Pem;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonArray;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.images.builder.Transferable;

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
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Revetsec SP against libxmlsec1's live HTTPS SSO endpoint, in both request bindings. */
final class ScriptedIdpSsoIT {
    private static final @NonNull String SP_ENTITY = "https://sp.test/ScriptedIdpSsoIT";
    private static final @NonNull URI ACS = URI.create("https://sp.test/acs");
    private static final @NonNull URI SLO = URI.create("https://sp.test/logout");
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull Pattern FIELD = Pattern.compile(
            "name=\"(SAMLResponse|RelayState)\" value=\"([^\"]+)\"");
    private static @NonNull GenericContainer<?> container;
    private static @NonNull HttpClient client;
    private static @NonNull String base;

    @BeforeAll static void start() throws Exception {
        String image = System.getProperty("scripted-idp.image", "revetsec-scripted-idp:local");
        container = new GenericContainer<>(DockerImageName.parse(image))
                .withExposedPorts(8443)
                .withEnv("SCRIPTED_IDP_TLS_CERT", "/run/tls/server.pem")
                .withEnv("SCRIPTED_IDP_TLS_KEY", "/run/tls/server-key.pem")
                .withEnv("SCRIPTED_IDP_KEYS_DIR", "/run/keys")
                .withEnv("SCRIPTED_IDP_ORACLE_DECRYPTION_KEY",
                        "/run/keys/sp-encryption-rsa-2048-key.pem")
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(2)));
        copy("src/test/resources/tls/server.pem", "/run/tls/server.pem");
        copy("src/test/resources/tls/server-key.pem", "/run/tls/server-key.pem");
        copy("src/test/resources/fixtures/keys/idp-signing-rsa-2048-key.pem",
                "/run/keys/idp-signing-rsa-2048-key.pem");
        copy("src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem",
                "/run/keys/idp-signing-rsa-2048-cert.pem");
        copy("src/test/resources/fixtures/keys/idp-signing-rsa-3072-cert.pem",
                "/run/keys/idp-signing-rsa-3072-cert.pem");
        for (String curve : List.of("p256", "p384", "p521"))
            copy("src/test/resources/fixtures/keys/idp-signing-ec-" + curve + "-cert.pem",
                    "/run/keys/idp-signing-ec-" + curve + "-cert.pem");
        copy("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-cert.pem",
                "/run/keys/sp-encryption-rsa-2048-cert.pem");
        copy("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-key.pem",
                "/run/keys/sp-encryption-rsa-2048-key.pem");
        container.start();
        client = TestTls.httpClient();
        base = "https://127.0.0.1:" + container.getMappedPort(8443);
        assertEquals(200, json("PUT", "/control/config",
                JsonObject.builder().put("base_url", base).build()).statusCode());
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlCredential decryption = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-cert.pem")));
        SamlServiceProvider metadataSp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS).singleLogoutServiceUrl(SLO)
                .postSingleLogoutServiceUrl(SLO)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8))
                .signingCredential(signing).decryptionCredentials(List.of(decryption))
                .clock(CLOCK).build();
        String spMetadata = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                SamlServiceProviderMetadata.fromServiceProviderResult(metadataSp)).getXml();
        assertEquals(200, json("PUT", "/control/sps", JsonObject.builder()
                .put("entity_id", SP_ENTITY).put("acs_url", ACS.toASCIIString())
                .put("slo_url", SLO.toASCIIString())
                .put("metadata_xml", spMetadata)
                .put("signing_certificate_pem", Files.readString(Path.of(
                        "src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")))
                .put("require_signed_requests", true).build()).statusCode());
    }

    private static void copy(@NonNull String source, @NonNull String target) throws Exception {
        container.withCopyToContainer(Transferable.of(Files.readAllBytes(Path.of(source)), 0444), target);
    }

    @AfterAll static void stop() {
        if (container != null) container.stop();
    }

    @Test void redirectAndPostAuthenticationRoundTrip() throws Exception {
        HttpResponse<String> metadataResponse = client.send(HttpRequest.newBuilder(URI.create(base
                + "/metadata?now=2026-09-01T00%3A00%3A00Z")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, metadataResponse.statusCode());
        SamlIdentityProviderMetadata metadata = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(metadataResponse.body()
                        .getBytes(StandardCharsets.UTF_8), "https://idp.scripted-idp.test/", CLOCK))
                .getMetadata();
        SamlIdentityProvider identityProvider = SamlIdentityProvider.withMetadata(metadata)
                .connectionId("scripted-live").build();
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlCredential decryption = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-cert.pem")));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(SLO)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 64))
                .signingCredential(signing).decryptionCredentials(List.of(decryption))
                .clock(CLOCK).build();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-live"))
                .clock(CLOCK).build();

        arm(false);
        SamlAuthenticationRequestResult.Prepared redirect = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(identityProvider));
        HttpResponse<String> redirectPage = client.send(HttpRequest.newBuilder(
                redirect.getRedirectUri()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, redirectPage.statusCode(), redirectPage.body());
        SamlPostBindingMessage redirectMessage = responseMessage(redirectPage.body());
        String sealed = redirect.getPendingAuthentication().toSealedForm(sealer, "saml-live");
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class, sp.completeAuthenticationResult(
                redirectMessage, PendingSamlAuthenticationSource.fromSealedForm(sealed, sealer, "saml-live"),
                identityProvider));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class, sp.completeAuthenticationResult(
                redirectMessage, PendingSamlAuthenticationSource.fromSealedForm(sealed, sealer, "saml-live"),
                identityProvider));

        arm(false);
        SamlAuthenticationRequestResult.PostPrepared post = assertInstanceOf(
                SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(identityProvider));
        StringBuilder form = new StringBuilder();
        for (var field : post.getPostForm().getFields().entrySet()) {
            if (!form.isEmpty()) form.append('&');
            form.append(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8))
                    .append('=').append(URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8));
        }
        HttpResponse<String> postPage = client.send(HttpRequest.newBuilder(post.getPostForm().getAction())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, postPage.statusCode(), postPage.body());
        SamlPostBindingMessage postMessage = responseMessage(postPage.body());
        sealed = post.getPendingAuthentication().toSealedForm(sealer, "saml-live");
        SamlAuthenticationResult.Succeeded postSuccess = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, sp.completeAuthenticationResult(
                postMessage, PendingSamlAuthenticationSource.fromSealedForm(sealed, sealer, "saml-live"),
                identityProvider));
        HttpResponse<String> received = client.send(HttpRequest.newBuilder(
                URI.create(base + "/control/received")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, received.statusCode());
        assertTrue(received.body().contains("\"binding\": \"redirect\""));
        assertTrue(received.body().contains("\"binding\": \"post\""));
        assertTrue(received.body().contains("\"signature_valid\": true"));
        assertTrue(received.body().contains("\"binding\": \"sp-metadata\""));
        assertTrue(received.body().contains("\"schema_valid\": true"));

        arm(true);
        SamlAuthenticationRequestResult.Prepared encryptedBegin = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(identityProvider));
        HttpResponse<String> encryptedPage = client.send(HttpRequest.newBuilder(
                encryptedBegin.getRedirectUri()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, encryptedPage.statusCode(), encryptedPage.body());
        String encryptedSeal = encryptedBegin.getPendingAuthentication().toSealedForm(sealer, "saml-live");
        SamlAuthenticationResult.Succeeded encryptedSuccess = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, sp.completeAuthenticationResult(
                        responseMessage(encryptedPage.body()),
                        PendingSamlAuthenticationSource.fromSealedForm(encryptedSeal, sealer, "saml-live"),
                        identityProvider));
        assertTrue(encryptedSuccess.getAuthentication().isAssertionEncrypted());

        assertEquals(200, json("PUT", "/control/armed/slo", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .build()).statusCode());
        SamlLogoutRedirectResult.Prepared beginLogout = assertInstanceOf(
                SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(identityProvider, postSuccess.getAuthentication().getSessionReference()));
        HttpResponse<String> logoutRedirect = client.send(HttpRequest.newBuilder(
                beginLogout.getRedirectUri()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, logoutRedirect.statusCode(), logoutRedirect.body());
        URI responseUri = URI.create(logoutRedirect.headers().firstValue("Location").orElseThrow());
        SamlRedirectBindingMessage logoutResponse = assertInstanceOf(
                SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(responseUri.getRawQuery())).getMessage();
        String logoutSeal = beginLogout.getPendingLogout().toSealedForm(sealer, "saml-live-logout");
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(logoutResponse,
                PendingSamlLogoutSource.fromSealedForm(logoutSeal, sealer, "saml-live-logout"),
                identityProvider));

        HttpResponse<String> initiated = json("POST", "/control/logout-requests",
                JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                        .put("sp", JsonObject.builder().put("entity_id", SP_ENTITY)
                                .put("slo_url", SLO.toASCIIString()).build())
                        .put("subject", JsonObject.builder().put("name_id", "minted-user")
                                .put("session_index", "_session-1").build()).build());
        assertEquals(200, initiated.statusCode(), initiated.body());
        JsonObject issued = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                initiated.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(64_000)));
        URI requestUri = URI.create(issued.findString("redirect_url").orElseThrow());
        SamlRedirectBindingMessage logoutRequest = assertInstanceOf(
                SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(requestUri.getRawQuery())).getMessage();
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(logoutRequest, identityProvider)).getRequest();
        assertEquals("minted-user", accepted.getNameId().getValue());
        assertEquals(List.of("_session-1"), accepted.getSessionIndexes());
        SamlLogoutResponseRedirectResult.Prepared answer = assertInstanceOf(
                SamlLogoutResponseRedirectResult.Prepared.class,
                sp.respondToLogoutRequestResult(accepted, identityProvider, SamlLogoutStatus.SUCCESS));
        HttpResponse<String> verifiedResponse = client.send(HttpRequest.newBuilder(
                answer.getRedirectUri()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, verifiedResponse.statusCode(), verifiedResponse.body());
        HttpResponse<String> logoutReceipts = client.send(HttpRequest.newBuilder(
                URI.create(base + "/control/received")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, logoutReceipts.statusCode());
        JsonObject receiptBody = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                logoutReceipts.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(64_000)));
        JsonArray entries = assertInstanceOf(JsonArray.class, receiptBody.find("received").orElseThrow());
        long schemaValidLogoutMessages = entries.getElements().stream()
                .filter(value -> value instanceof JsonObject entry
                        && "redirect-slo".equals(entry.findString("binding").orElse(null))
                        && entry.findBoolean("schema_valid").orElse(false))
                .count();
        assertTrue(schemaValidLogoutMessages >= 2, "both SP logout directions must pass the OASIS XSD");
    }

    @Test void postLogoutInBothDirectionsPassesIndependentXmlSignatureAndSchemaChecks() throws Exception {
        HttpResponse<String> metadataResponse = client.send(HttpRequest.newBuilder(URI.create(base
                + "/metadata?now=2026-09-01T00%3A00%3A00Z&variant=query-endpoints")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, metadataResponse.statusCode(), metadataResponse.body());
        SamlIdentityProviderMetadata metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(metadataResponse.body().getBytes(StandardCharsets.UTF_8),
                        "https://idp.scripted-idp.test/", CLOCK)).getMetadata();
        assertEquals(URI.create(base + "/slo?tenant=one"), metadata.getPostSingleLogoutService().orElseThrow());
        SamlIdentityProvider identityProvider = SamlIdentityProvider.withMetadata(metadata)
                .connectionId("scripted-post-slo").build();
        SamlServiceProvider sp = postLogoutServiceProvider();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("post-slo-live"))
                .clock(CLOCK).build();
        SamlSessionReference session = new SamlSessionReference(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), new SamlNameId("post-logout-user", SamlNameId.PERSISTENT,
                        identityProvider.getEntityId(), SP_ENTITY), "post-session-123", null);
        assertEquals(200, json("PUT", "/control/armed/slo", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .build()).statusCode());
        SamlLogoutPostResult.Prepared begin = assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                sp.beginPostLogoutResult(identityProvider, session));
        assertEquals(URI.create(base + "/slo?tenant=one"), begin.getPostForm().getAction());
        HttpResponse<String> fromIdp = submitPostForm(begin.getPostForm());
        assertEquals(200, fromIdp.statusCode(), fromIdp.body());
        SamlPostBindingMessage response = logoutPostPage(fromIdp.body());
        assertEquals(SamlPostBindingMessage.Kind.RESPONSE, response.getKind());
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "post-slo-cookie"), sealer, "post-slo-cookie");
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(response, pending,
                identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(response, pending,
                identityProvider));

        String relay = "post logout /+é";
        HttpResponse<String> issuedResponse = json("POST", "/control/logout-requests", JsonObject.builder()
                .put("binding", "post")
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .put("sp", JsonObject.builder().put("entity_id", SP_ENTITY).put("slo_url", SLO.toString()).build())
                .put("subject", JsonObject.builder().put("name_id", "post-logout-user")
                        .put("session_index", "post-session-123").build())
                .put("relay_state", relay).build());
        assertEquals(200, issuedResponse.statusCode(), issuedResponse.body());
        SamlPostBindingMessage request = logoutPostForm(jsonBody(issuedResponse).findString("form_body").orElseThrow());
        assertEquals(SamlPostBindingMessage.Kind.REQUEST, request.getKind());
        assertEquals(relay, request.getRelayState().orElseThrow());
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(request, identityProvider)).getRequest();
        assertEquals(session.getNameId().getValue(), accepted.getNameId().getValue());
        assertEquals(List.of("post-session-123"), accepted.getSessionIndexes());
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class, sp.acceptLogoutRequestResult(request,
                identityProvider));
        SamlLogoutResponsePostResult.Prepared answer = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                sp.respondToPostLogoutRequestResult(accepted, identityProvider, SamlLogoutStatus.SUCCESS));
        assertEquals(relay, answer.getPostForm().getFields().get("RelayState"));
        HttpResponse<String> verified = submitPostForm(answer.getPostForm());
        assertEquals(200, verified.statusCode(), verified.body());
        HttpResponse<String> receipts = client.send(HttpRequest.newBuilder(URI.create(base + "/control/received"))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        JsonArray entries = assertInstanceOf(JsonArray.class, jsonBody(receipts).find("received").orElseThrow());
        long verifiedMessages = entries.getElements().stream().filter(value -> value instanceof JsonObject entry
                && "post-slo".equals(entry.findString("binding").orElse(null))
                && entry.findBoolean("signature_valid").orElse(false)
                && entry.findBoolean("schema_valid").orElse(false)).count();
        assertTrue(verifiedMessages >= 2, "POST LogoutRequest and LogoutResponse must pass libxmlsec and OASIS XSD");
    }

    @Test void independentlySignedPostLogoutRequestsKeepStrictSemanticsAndSharedReplayProtection() throws Exception {
        SamlIdentityProvider identityProvider = postLogoutIdentityProvider();
        SamlServiceProvider sp = postLogoutServiceProvider();
        String relay = "post-hostile-relay";
        HttpResponse<String> issuedResponse = json("POST", "/control/logout-requests", JsonObject.builder()
                .put("binding", "post")
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .put("sp", JsonObject.builder().put("entity_id", SP_ENTITY).put("slo_url", SLO.toString()).build())
                .put("subject", JsonObject.builder().put("name_id", "post-hostile-user")
                        .put("session_index", "post-hostile-session").build())
                .put("ids", JsonObject.builder().put("request", "_post_slo_hostile_request").build())
                .put("relay_state", relay).build());
        assertEquals(200, issuedResponse.statusCode(), issuedResponse.body());
        JsonObject issued = jsonBody(issuedResponse);
        String xml = issued.findString("xml").orElseThrow();
        SamlPostBindingMessage original = logoutPostForm(issued.findString("form_body").orElseThrow());
        SamlPostBindingMessage tampered = logoutPostXml(xml.replace("post-hostile-user", "attacker"),
                "SAMLRequest", relay);
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(tampered, identityProvider));
        for (String altered : List.of(
                xml.replace(SLO.toASCIIString(), "https://sp.test/wrong-logout"),
                xml.replace("<a:Issuer>https://idp.scripted-idp.test/</a:Issuer>",
                        "<a:Issuer>https://attacker.test/</a:Issuer>"),
                xml.replace("2026-09-01T00:00:00Z", "2026-09-01T00:10:00Z"),
                xml.replace("NotOnOrAfter=\"2026-09-01T00:05:00Z\"", "NotOnOrAfter=\"2026-09-01T00:00:00Z\""),
                xml.replace("</p:LogoutRequest>", "<a:NameID>attacker</a:NameID></p:LogoutRequest>"))) {
            assertNotEquals(xml, altered);
            SamlPostBindingMessage signed = signPostLogoutFixture(altered, relay);
            assertTrue(oracleValid(new String(signed.xml(), StandardCharsets.UTF_8),
                    "_post_slo_hostile_request", "idp-signing-rsa-2048"));
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(signed, identityProvider));
        }
        assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(original, identityProvider));
        SamlRedirectBindingMessage crossBindingReplay = signLogoutFixture(xml, SLO, relay);
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(crossBindingReplay, identityProvider));
    }

    @Test void independentlySignedPostLogoutResponsesPreservePendingUntilValidResult() throws Exception {
        SamlIdentityProvider identityProvider = postLogoutIdentityProvider();
        SamlServiceProvider sp = postLogoutServiceProvider();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("post-slo-hostile"))
                .clock(CLOCK).build();
        SamlSessionReference session = new SamlSessionReference(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), new SamlNameId("post-hostile-user", SamlNameId.PERSISTENT,
                        identityProvider.getEntityId(), SP_ENTITY), "post-hostile-session", null);
        assertEquals(200, json("PUT", "/control/armed/slo", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .build()).statusCode());
        SamlLogoutPostResult.Prepared begin = assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                sp.beginPostLogoutResult(identityProvider, session));
        HttpResponse<String> fromIdp = submitPostForm(begin.getPostForm());
        assertEquals(200, fromIdp.statusCode(), fromIdp.body());
        SamlPostBindingMessage original = logoutPostPage(fromIdp.body());
        String xml = new String(original.xml(), StandardCharsets.UTF_8);
        String relay = begin.getPendingLogout().getRelayStateHandle();
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "post-slo-hostile-cookie"),
                sealer, "post-slo-hostile-cookie");
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(
                logoutPostXml(xml, "SAMLResponse", "attacker-relay"), pending, identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(logoutPostXml(
                xml.replace("status:Success", "status:Responder"), "SAMLResponse", relay), pending,
                identityProvider));
        for (String altered : List.of(
                xml.replace(SLO.toASCIIString(), "https://sp.test/wrong-logout"),
                xml.replace("InResponseTo=\"" + begin.getPendingLogout().getRequestId() + "\"",
                        "InResponseTo=\"_unrelated_request\""),
                xml.replace("<a:Issuer>https://idp.scripted-idp.test/</a:Issuer>",
                        "<a:Issuer>https://attacker.test/</a:Issuer>"),
                xml.replace("2026-09-01T00:00:00Z", "2026-08-31T00:00:00Z"),
                xml.replace("</p:LogoutResponse>", "<p:Status><p:StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:LogoutResponse>"))) {
            assertNotEquals(xml, altered);
            SamlPostBindingMessage signed = signPostLogoutFixture(altered, relay);
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(signed, pending, identityProvider));
        }
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(original, pending, identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(original, pending, identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(signLogoutFixture(xml, SLO, relay), pending, identityProvider));
    }

    private static @NonNull SamlServiceProvider postLogoutServiceProvider() throws Exception {
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        return SamlServiceProvider.withEntityId(SP_ENTITY).assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(SLO).postSingleLogoutServiceUrl(SLO).signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32)).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider postLogoutIdentityProvider() throws Exception {
        return SamlIdentityProvider.withEntityId("https://idp.scripted-idp.test/")
                .connectionId("scripted-post-slo-hostile")
                .redirectSingleSignOnService(URI.create(base + "/sso"))
                .redirectSingleLogoutService(URI.create(base + "/slo"))
                .postSingleLogoutService(URI.create(base + "/slo"))
                .signingKeys(List.of(Pem.parseCertificate(Files.readString(Path.of(
                        "src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem"))).getPublicKey()))
                .build();
    }

    private static @NonNull HttpResponse<@NonNull String> submitPostForm(@NonNull SamlPostForm form) throws Exception {
        StringBuilder body = new StringBuilder();
        for (var field : form.getFields().entrySet()) {
            if (!body.isEmpty()) body.append('&');
            body.append(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8));
        }
        return client.send(HttpRequest.newBuilder(form.getAction())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static @NonNull SamlPostBindingMessage signPostLogoutFixture(@NonNull String xml,
            @NonNull String relay) throws Exception {
        HttpResponse<String> signed = json("POST", "/control/logout-sign", JsonObject.builder()
                .put("binding", "post").put("xml", xml).put("destination", SLO.toASCIIString())
                .put("relay_state", relay).build());
        assertEquals(200, signed.statusCode(), signed.body());
        return logoutPostForm(jsonBody(signed).findString("form_body").orElseThrow());
    }

    private static @NonNull SamlPostBindingMessage logoutPostXml(@NonNull String xml,
            @NonNull String field, @NonNull String relay) {
        return logoutPostForm(field + "=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8));
    }

    private static @NonNull SamlPostBindingMessage logoutPostForm(@NonNull String body) {
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(body.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull SamlPostBindingMessage logoutPostPage(@NonNull String page) {
        Matcher matches = FIELD.matcher(page);
        String response = null;
        String relay = null;
        while (matches.find()) {
            if ("SAMLResponse".equals(matches.group(1))) response = matches.group(2);
            else relay = matches.group(2);
        }
        assertTrue(response != null && relay != null, page);
        return logoutPostForm("SAMLResponse=" + URLEncoder.encode(response, StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8));
    }

    @Test void queryfulMetadataEndpointsWorkAcrossRedirectPostAndLogout() throws Exception {
        HttpResponse<String> metadataResponse = client.send(HttpRequest.newBuilder(URI.create(base
                + "/metadata?now=2026-09-01T00%3A00%3A00Z&variant=query-endpoints"))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, metadataResponse.statusCode(), metadataResponse.body());
        SamlIdentityProviderMetadata metadata = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(metadataResponse.body()
                        .getBytes(StandardCharsets.UTF_8), "https://idp.scripted-idp.test/", CLOCK))
                .getMetadata();
        assertEquals(URI.create(base + "/sso?tenant=one"),
                metadata.getRedirectSingleSignOnService().orElseThrow());
        assertEquals(URI.create(base + "/sso?tenant=one"),
                metadata.getPostSingleSignOnService().orElseThrow());
        assertEquals(URI.create(base + "/slo?tenant=one"),
                metadata.getRedirectSingleLogoutService().orElseThrow());
        SamlIdentityProvider identityProvider = SamlIdentityProvider.withMetadata(metadata)
                .connectionId("scripted-query-endpoints").build();
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS).singleLogoutServiceUrl(SLO)
                .signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .clock(CLOCK).build();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-query-endpoints"))
                .clock(CLOCK).build();

        arm(false);
        SamlAuthenticationRequestResult.Prepared redirect = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(identityProvider));
        assertTrue(redirect.getRedirectUri().getRawQuery().startsWith("tenant=one&SAMLRequest="));
        HttpResponse<String> redirectPage = client.send(HttpRequest.newBuilder(redirect.getRedirectUri())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, redirectPage.statusCode(), redirectPage.body());
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(responseMessage(redirectPage.body()),
                        PendingSamlAuthenticationSource.fromSealedForm(
                                redirect.getPendingAuthentication().toSealedForm(sealer, "query-sso"),
                                sealer, "query-sso"), identityProvider));

        arm(false);
        SamlAuthenticationRequestResult.PostPrepared post = assertInstanceOf(
                SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(identityProvider));
        assertEquals(URI.create(base + "/sso?tenant=one"), post.getPostForm().getAction());
        StringBuilder form = new StringBuilder();
        for (var field : post.getPostForm().getFields().entrySet()) {
            if (!form.isEmpty()) form.append('&');
            form.append(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8))
                    .append('=').append(URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8));
        }
        HttpResponse<String> postPage = client.send(HttpRequest.newBuilder(post.getPostForm().getAction())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, postPage.statusCode(), postPage.body());
        SamlAuthenticationResult.Succeeded authenticated = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(responseMessage(postPage.body()),
                        PendingSamlAuthenticationSource.fromSealedForm(
                                post.getPendingAuthentication().toSealedForm(sealer, "query-post"),
                                sealer, "query-post"), identityProvider));

        assertEquals(200, json("PUT", "/control/armed/slo", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .build()).statusCode());
        SamlLogoutRedirectResult.Prepared logout = assertInstanceOf(
                SamlLogoutRedirectResult.Prepared.class,
                sp.beginLogoutResult(identityProvider,
                        authenticated.getAuthentication().getSessionReference()));
        assertTrue(logout.getRedirectUri().getRawQuery().startsWith("tenant=one&SAMLRequest="));
        HttpResponse<String> logoutPage = client.send(HttpRequest.newBuilder(logout.getRedirectUri())
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, logoutPage.statusCode(), logoutPage.body());
        SamlRedirectBindingMessage logoutResponse = redirectMessage(URI.create(
                logoutPage.headers().firstValue("Location").orElseThrow()).getRawQuery());
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(logoutResponse,
                PendingSamlLogoutSource.fromSealedForm(
                        logout.getPendingLogout().toSealedForm(sealer, "query-slo"),
                        sealer, "query-slo"), identityProvider));
    }

    @Test void independentRedirectLogoutRequestSignerSeparatesWireAndSemanticFailures() throws Exception {
        SamlIdentityProvider identityProvider = logoutIdentityProvider();
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS).singleLogoutServiceUrl(SLO)
                .signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .clock(CLOCK).build();
        String relay = "slo-hostile-relay";
        HttpResponse<String> issuedResponse = json("POST", "/control/logout-requests",
                JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                        .put("sp", JsonObject.builder().put("entity_id", SP_ENTITY)
                                .put("slo_url", SLO.toASCIIString()).build())
                        .put("subject", JsonObject.builder().put("name_id", "hostile-test-user")
                                .put("session_index", "session-123").build())
                        .put("ids", JsonObject.builder().put("request", "_slo_hostile_request").build())
                        .put("relay_state", relay).build());
        assertEquals(200, issuedResponse.statusCode(), issuedResponse.body());
        JsonObject issued = jsonBody(issuedResponse);
        String originalXml = issued.findString("xml").orElseThrow();
        String originalQuery = issued.findString("raw_query").orElseThrow();
        SamlRedirectBindingMessage original = redirectMessage(originalQuery);
        assertTrue(original.verify(identityProvider.signingKeys()));
        String equivalentRelayQuery = originalQuery.replace("&RelayState=" + relay,
                "&RelayState=slo%2Dhostile-relay");
        assertEquals(relay, redirectMessage(equivalentRelayQuery).relayState());
        assertFalse(redirectMessage(equivalentRelayQuery).verify(identityProvider.signingKeys()));

        for (String raw : List.of(
                originalQuery.replace("&RelayState=" + relay, "&RelayState=attacker-relay"),
                equivalentRelayQuery,
                originalQuery.replace("rsa-sha256", "rsa-sha384"),
                originalQuery + "&RelayState=duplicate",
                originalQuery.replace("Signature=", "Signature=%GG"))) {
            assertNotEquals(originalQuery, raw);
            SamlRedirectBindingParseResult parsed = SamlRedirectBindingMessage.fromRawQueryResult(raw);
            if (parsed instanceof SamlRedirectBindingParseResult.Parsed message)
                assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                        sp.acceptLogoutRequestResult(message.getMessage(), identityProvider));
            else assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class, parsed);
        }

        for (String altered : List.of(
                originalXml.replace(SLO.toASCIIString(), "https://sp.test/wrong-logout"),
                originalXml.replace("<a:Issuer>https://idp.scripted-idp.test/</a:Issuer>",
                        "<a:Issuer>https://attacker.test/</a:Issuer>"),
                originalXml.replace("2026-09-01T00:00:00Z", "2026-09-01T00:10:00Z"),
                originalXml.replace("NotOnOrAfter=\"2026-09-01T00:05:00Z\"",
                        "NotOnOrAfter=\"2026-09-01T00:00:00Z\""),
                originalXml.replace("</p:LogoutRequest>",
                        "<a:NameID>attacker</a:NameID></p:LogoutRequest>"),
                originalXml.replace("</p:LogoutRequest>",
                        "<p:Extensions/><p:SessionIndex>attacker</p:SessionIndex></p:LogoutRequest>"))) {
            assertNotEquals(originalXml, altered);
            SamlRedirectBindingMessage signed = signLogoutFixture(altered, SLO, relay);
            assertTrue(signed.verify(identityProvider.signingKeys()));
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(signed, identityProvider));
        }
        SamlLogoutRequest accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(original, identityProvider)).getRequest();
        assertEquals("hostile-test-user", accepted.getNameId().getValue());
        assertEquals(List.of("session-123"), accepted.getSessionIndexes());
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(original, identityProvider));
    }

    @Test void signedMalformedSpLogoutMessagesFailPartnerSchema() throws Exception {
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        URI destination = URI.create(base + "/slo");
        SamlSessionReference session = new SamlSessionReference("scripted-slo-schema",
                "https://idp.scripted-idp.test/", new SamlNameId("schema-user",
                        SamlNameId.PERSISTENT, "https://idp.scripted-idp.test/", null),
                "session-123", null);
        URI request = java.util.Objects.requireNonNull(SamlRedirectLogout.request(destination,
                SP_ENTITY, session, "_schema_request", "schema-relay", CLOCK.instant(),
                signing.privateKey()));
        String requestXml = new String(redirectMessage(request.getRawQuery()).xml(), StandardCharsets.UTF_8);
        String wrongRequestOrder = requestXml.replace("<a:NameID",
                "<p:SessionIndex>attacker</p:SessionIndex><a:NameID");
        assertNotEquals(requestXml, wrongRequestOrder);
        URI malformedRequest = SamlRedirectLogout.sign(destination, "SAMLRequest",
                wrongRequestOrder.getBytes(StandardCharsets.UTF_8), "schema-relay", signing.privateKey());
        HttpResponse<String> rejectedRequest = client.send(HttpRequest.newBuilder(malformedRequest).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, rejectedRequest.statusCode());
        assertTrue(rejectedRequest.body().contains("SAML logout message fails OASIS schema"));

        URI response = java.util.Objects.requireNonNull(SamlRedirectLogout.response(destination,
                SP_ENTITY, "_schema_response", "_pending", "schema-relay", CLOCK.instant(),
                SamlLogoutStatus.SUCCESS, signing.privateKey()));
        String responseXml = new String(redirectMessage(response.getRawQuery()).xml(), StandardCharsets.UTF_8);
        String wrongResponseOrder = responseXml.replace("<a:Issuer>",
                "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                        + "</p:Status><a:Issuer>");
        assertNotEquals(responseXml, wrongResponseOrder);
        URI malformedResponse = SamlRedirectLogout.sign(destination, "SAMLResponse",
                wrongResponseOrder.getBytes(StandardCharsets.UTF_8), "schema-relay", signing.privateKey());
        HttpResponse<String> rejectedResponse = client.send(HttpRequest.newBuilder(malformedResponse).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, rejectedResponse.statusCode());
        assertTrue(rejectedResponse.body().contains("SAML logout message fails OASIS schema"));
    }

    @Test void independentRedirectLogoutResponseSignerPreservesPendingUntilValidResult() throws Exception {
        SamlIdentityProvider identityProvider = logoutIdentityProvider();
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS).singleLogoutServiceUrl(SLO)
                .signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .clock(CLOCK).build();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("slo-hostile"))
                .clock(CLOCK).build();
        assertEquals(200, json("PUT", "/control/armed/slo", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .build()).statusCode());
        SamlSessionReference session = new SamlSessionReference(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), new SamlNameId("hostile-test-user",
                        SamlNameId.PERSISTENT, identityProvider.getEntityId(), null),
                "session-123", null);
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(
                SamlLogoutRedirectResult.Prepared.class, sp.beginLogoutResult(identityProvider, session));
        HttpResponse<String> fromIdp = client.send(HttpRequest.newBuilder(begin.getRedirectUri()).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(302, fromIdp.statusCode(), fromIdp.body());
        String originalQuery = URI.create(fromIdp.headers().firstValue("Location").orElseThrow()).getRawQuery();
        SamlRedirectBindingMessage original = redirectMessage(originalQuery);
        assertTrue(original.verify(identityProvider.signingKeys()));
        String originalXml = new String(original.xml(), StandardCharsets.UTF_8);
        String relay = begin.getPendingLogout().getRelayStateHandle();
        String seal = begin.getPendingLogout().toSealedForm(sealer, "slo-hostile-cookie");
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                seal, sealer, "slo-hostile-cookie");
        String equivalentRelayQuery = percentEncodeLeadingRelay(originalQuery, relay);
        assertEquals(relay, redirectMessage(equivalentRelayQuery).relayState());
        assertFalse(redirectMessage(equivalentRelayQuery).verify(identityProvider.signingKeys()));

        for (String raw : List.of(
                originalQuery.replace("&RelayState=" + relay, "&RelayState=attacker-relay"),
                equivalentRelayQuery,
                originalQuery.replace("rsa-sha256", "rsa-sha384"),
                originalQuery + "&SigAlg=duplicate")) {
            assertNotEquals(originalQuery, raw);
            SamlRedirectBindingParseResult parsed = SamlRedirectBindingMessage.fromRawQueryResult(raw);
            if (parsed instanceof SamlRedirectBindingParseResult.Parsed message)
                assertInstanceOf(SamlLogoutResult.Rejected.class,
                        sp.completeLogoutResult(message.getMessage(), pending, identityProvider));
            else assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class, parsed);
        }

        for (String altered : List.of(
                originalXml.replace(SLO.toASCIIString(), "https://sp.test/wrong-logout"),
                originalXml.replace("InResponseTo=\"" + begin.getPendingLogout().getRequestId() + "\"",
                        "InResponseTo=\"_unrelated_request\""),
                originalXml.replace("<a:Issuer>https://idp.scripted-idp.test/</a:Issuer>",
                        "<a:Issuer>https://attacker.test/</a:Issuer>"),
                originalXml.replace("2026-09-01T00:00:00Z", "2026-08-31T00:00:00Z"),
                originalXml.replace("</p:LogoutResponse>",
                        "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                                + "</p:Status></p:LogoutResponse>"),
                originalXml.replace("Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"", "Value=\"\""))) {
            assertNotEquals(originalXml, altered);
            SamlRedirectBindingMessage signed = signLogoutFixture(altered, SLO, relay);
            assertTrue(signed.verify(identityProvider.signingKeys()));
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(signed, pending, identityProvider));
        }
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                sp.completeLogoutResult(original, pending, identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(original, pending, identityProvider));
    }

    @Test void independentSignerChecksLogoutStatusMessageAndDetail() throws Exception {
        SamlIdentityProvider identityProvider = logoutIdentityProvider();
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-signing-rsa-2048-cert.pem")));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS).singleLogoutServiceUrl(SLO)
                .signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 32))
                .clock(CLOCK).build();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("slo-status-extras"))
                .clock(CLOCK).build();
        SamlSessionReference session = new SamlSessionReference(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), new SamlNameId("status-user",
                        SamlNameId.PERSISTENT, identityProvider.getEntityId(), null),
                "session-123", null);
        for (int index = 0; index < 2; index++) {
            SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(
                    SamlLogoutRedirectResult.Prepared.class, sp.beginLogoutResult(identityProvider, session));
            String relay = begin.getPendingLogout().getRelayStateHandle();
            String sealed = begin.getPendingLogout().toSealedForm(sealer, "slo-status-cookie");
            PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                    sealed, sealer, "slo-status-cookie");
            String code = index == 0 ? "Success" : "Responder";
            String status = "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:"
                    + code + "'/><p:StatusMessage>Partner detail</p:StatusMessage>"
                    + "<p:StatusDetail><x:Hint xmlns:x='urn:example:status'/></p:StatusDetail>"
                    + "</p:Status>";
            String xml = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                    + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                    + "ID='_status_extras_" + index + "' Version='2.0' "
                    + "IssueInstant='2026-09-01T00:01:00Z' Destination='" + SLO + "' "
                    + "InResponseTo='" + begin.getPendingLogout().getRequestId() + "'>"
                    + "<a:Issuer>" + identityProvider.getEntityId() + "</a:Issuer>"
                    + status + "</p:LogoutResponse>";
            SamlRedirectBindingMessage malformed = signLogoutFixture(xml.replace(
                    "</p:Status>", "<p:StatusMessage>duplicate</p:StatusMessage></p:Status>"),
                    SLO, relay);
            assertTrue(malformed.verify(identityProvider.signingKeys()));
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(malformed, pending, identityProvider));
            SamlRedirectBindingMessage valid = signLogoutFixture(xml, SLO, relay);
            assertTrue(valid.verify(identityProvider.signingKeys()));
            assertEquals(index == 0 ? SamlLogoutResult.Succeeded.INSTANCE
                            : SamlLogoutResult.StatusReceived.NON_SUCCESS,
                    sp.completeLogoutResult(valid, pending, identityProvider));
        }
    }

    @Test void independentSignerKeepsNonSuccessSsoStatusGrammarAndCoverage() throws Exception {
        SamlIdentityProvider identityProvider = logoutIdentityProvider();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16))
                .clock(CLOCK).build();
        SamlAuthenticationRequestResult.Prepared begin = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(identityProvider));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("sso-status-oracle"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource pending = PendingSamlAuthenticationSource.fromSealedForm(
                begin.getPendingAuthentication().toSealedForm(sealer, "sso-status-oracle"),
                sealer, "sso-status-oracle");
        String status = "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:Responder'/>"
                + "<p:StatusMessage>Partner detail</p:StatusMessage>"
                + "<p:StatusDetail><x:Hint xmlns:x='urn:example:status'/></p:StatusDetail>";
        for (boolean malformed : List.of(true, false)) {
            String xml = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
                    + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
                    + "ID='_independent_sso_status' Version='2.0' "
                    + "IssueInstant='2026-09-01T00:01:00Z' Destination='" + ACS + "' "
                    + "InResponseTo='" + begin.getPendingAuthentication().getRequestId() + "'>"
                    + "<a:Issuer>" + identityProvider.getEntityId() + "</a:Issuer>"
                    + status + (malformed ? "<p:StatusMessage>duplicate</p:StatusMessage>" : "")
                    + "</p:Status></p:Response>";
            HttpResponse<String> signed = json("POST", "/control/sign", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                    .put("xml", xml).put("target_id", "_independent_sso_status")
                    .put("signing", JsonObject.builder().put("algorithm", "rsa-sha256").build())
                    .build());
            assertEquals(200, signed.statusCode(), signed.body());
            String signedXml = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                    signed.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(128_000)))
                    .findString("xml").orElseThrow();
            assertTrue(oracleValid(signedXml, "_independent_sso_status", "idp-signing-rsa-2048"));
            String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                    signedXml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)
                    + "&RelayState=" + URLEncoder.encode(
                            begin.getPendingAuthentication().getRelayStateHandle(), StandardCharsets.UTF_8);
            SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                    SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                            List.of("application/x-www-form-urlencoded"), null)).getMessage();
            SamlAuthenticationResult result = sp.completeAuthenticationResult(message, pending,
                    identityProvider);
            if (malformed) {
                assertEquals(SamlAuthenticationResult.Reason.MESSAGE,
                        assertInstanceOf(SamlAuthenticationResult.Rejected.class, result).getReason());
            } else {
                SamlAuthenticationResult.StatusReceived received = assertInstanceOf(
                        SamlAuthenticationResult.StatusReceived.class, result);
                assertEquals(SamlAuthenticationResult.StatusCode.RESPONDER, received.getStatusCode());
                assertTrue(received.isAuthenticated());
            }
        }
    }

    private static @NonNull SamlIdentityProvider logoutIdentityProvider() throws Exception {
        return SamlIdentityProvider.withEntityId("https://idp.scripted-idp.test/")
                .connectionId("scripted-slo-hostile")
                .redirectSingleSignOnService(URI.create(base + "/sso"))
                .redirectSingleLogoutService(URI.create(base + "/slo"))
                .signingKeys(List.of(Pem.parseCertificate(Files.readString(Path.of(
                        "src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem")))
                        .getPublicKey())).build();
    }

    private static @NonNull SamlRedirectBindingMessage signLogoutFixture(@NonNull String xml,
            @NonNull URI destination, @NonNull String relay) throws Exception {
        HttpResponse<String> signed = json("POST", "/control/logout-sign", JsonObject.builder()
                .put("xml", xml).put("destination", destination.toASCIIString())
                .put("relay_state", relay).build());
        assertEquals(200, signed.statusCode(), signed.body());
        return redirectMessage(jsonBody(signed).findString("raw_query").orElseThrow());
    }

    private static @NonNull JsonObject jsonBody(@NonNull HttpResponse<@NonNull String> response) throws Exception {
        return assertInstanceOf(JsonObject.class, JsonCodec.parse(
                response.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(128_000)));
    }

    private static @NonNull SamlRedirectBindingMessage redirectMessage(@NonNull String rawQuery) {
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(rawQuery)).getMessage();
    }

    private static @NonNull String percentEncodeLeadingRelay(@NonNull String rawQuery,
            @NonNull String relay) {
        String encoded = "%" + Integer.toHexString(relay.charAt(0)).toUpperCase()
                + relay.substring(1);
        return rawQuery.replace("&RelayState=" + relay, "&RelayState=" + encoded);
    }

    @Test void templateSignedAmbiguousResponseIsCryptographicallyValidButRejected() throws Exception {
        JsonObject fixedClock = JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build();
        HttpResponse<String> minted = json("POST", "/control/responses", JsonObject.builder()
                .put("clock", fixedClock)
                .put("sp", JsonObject.builder().put("entity_id", SP_ENTITY)
                        .put("acs_url", ACS.toASCIIString()).build())
                .put("signing", JsonObject.builder().put("placement", "none").build())
                .put("ids", JsonObject.builder().put("response", "_template_response")
                        .put("assertion", "_template_assertion").build()).build());
        assertEquals(200, minted.statusCode(), minted.body());
        String xml = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                minted.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(64_000)))
                .findString("xml").orElseThrow();
        int start = xml.indexOf("<saml:Assertion");
        int end = xml.indexOf("</saml:Assertion>", start);
        assertTrue(start >= 0 && end > start, xml);
        String attackerAssertion = xml.substring(start, end + "</saml:Assertion>".length())
                .replace("_template_assertion", "_attacker_assertion")
                .replace("user-1", "attacker-user");
        String ambiguous = xml.replace("</samlp:Response>", attackerAssertion + "</samlp:Response>");
        HttpResponse<String> signed = json("POST", "/control/sign", JsonObject.builder()
                .put("clock", fixedClock).put("xml", ambiguous)
                .put("target_id", "_template_response")
                .put("signing", JsonObject.builder().put("algorithm", "rsa-sha256").build())
                .build());
        assertEquals(200, signed.statusCode(), signed.body());
        String signedXml = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                signed.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(128_000)))
                .findString("xml").orElseThrow();
        HttpResponse<String> oracle = json("POST", "/control/oracle/verify", JsonObject.builder()
                .put("clock", fixedClock).put("xml", signedXml)
                .put("target_id", "_template_response")
                .put("credential", "idp-signing-rsa-2048").build());
        assertEquals(200, oracle.statusCode(), oracle.body());
        assertTrue(oracle.body().contains("\"valid\": true"), oracle.body());

        SamlServiceProvider provider = SamlServiceProvider.withEntityId(SP_ENTITY)
                .assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16))
                .clock(CLOCK).build();
        SamlIdentityProvider identityProvider = SamlIdentityProvider
                .withEntityId("https://idp.scripted-idp.test/")
                .connectionId("scripted-template")
                .redirectSingleSignOnService(URI.create(base + "/sso"))
                .signingKeys(List.of(Pem.parseCertificate(Files.readString(Path.of(
                        "src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem"))).getPublicKey()))
                .compatibility(Set.of(SamlCompatibilityMode.UNSOLICITED_RESPONSES)).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                signedXml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                provider.completeUnsolicitedAuthenticationResult(message, identityProvider));
    }

    @Test void signedStructureCorpusHasIndependentSignatureProof() throws Exception {
        for (String corpus : List.of("signed-structure", "signed-assertion-structure")) {
            Path directory = Path.of("src/test/resources/fixtures/scripted-idp/" + corpus);
            List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                    .map(line -> line.substring(0, line.indexOf(' '))).toList();
            boolean assertionSigned = corpus.equals("signed-assertion-structure");
            assertEquals(assertionSigned ? 29 : 15, names.size(), corpus + " changed");
            assertEquals("clean", names.get(0));
            for (String name : names) {
                String label = corpus + ":" + name;
                String xml = Files.readString(directory.resolve(name + ".xml"));
                assertTrue(oracleValid(xml, assertionSigned ? "_mint_assertion_9" : "_mint_response_9",
                        "idp-signing-rsa-2048"), label + " libxmlsec signature");
                SamlAuthenticationResult result = checkFixture(xml, "idp-signing-rsa-2048", false);
                boolean expectedSuccess = name.equals("clean") || (assertionSigned
                        && List.of("comment-split-nameid", "cdata-nameid",
                                "advice-before-authn", "typed-attribute-statement",
                                "attribute-before-authn").contains(name));
                if (expectedSuccess) {
                    SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                            SamlAuthenticationResult.Succeeded.class, result, label);
                    assertEquals("minted-user", success.getAuthentication().getNameId()
                            .orElseThrow().getValue(), label);
                } else {
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, result, label);
                }
            }
        }
    }

    @Test void signedAttributeCorpusHasIndependentSignatureProof() throws Exception {
        Path directory = Path.of("src/test/resources/fixtures/scripted-idp/signed-attribute-values");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(12, names.size(), "signed attribute corpus changed");
        List<String> text = List.of("clean", "type-xs-string", "type-alias-string",
                "nil-false", "nil-zero");
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            assertTrue(oracleValid(xml, "_mint_assertion_9", "idp-signing-rsa-2048"),
                    name + " libxmlsec signature");
            SamlAuthentication authentication = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    checkFixture(xml, "idp-signing-rsa-2048", false, false, true), name)
                    .getAuthentication();
            assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
            if (text.contains(name)) {
                assertEquals("minted@example.test", authentication.getSubjectId().orElseThrow(), name);
                assertTrue(authentication.getSubjectKey().isPresent(), name);
            } else {
                assertTrue(authentication.getSubjectId().isEmpty(), name);
                assertTrue(authentication.getSubjectKey().isEmpty(), name);
                assertEquals(List.of(), authentication.getAttributeValues("urn:example:display-email"), name);
            }
        }
    }

    @Test void signedIdentityShapeCorpusHasIndependentSignatureProof() throws Exception {
        Path directory = Path.of("src/test/resources/fixtures/scripted-idp/signed-identity-shape");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(20, names.size(), "signed identity-shape corpus changed");
        List<String> accepted = List.of("clean", "subject-nameid-type",
                "assertion-issuer-type", "audience-type", "authn-class-ref-type",
                "subject-nameid-nil-false", "authn-locality-before-context");
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            assertTrue(oracleValid(xml, "_mint_assertion_9", "idp-signing-rsa-2048"),
                    name + " libxmlsec signature");
            SamlAuthenticationResult result = checkFixture(xml, "idp-signing-rsa-2048", false);
            if (accepted.contains(name)) {
                SamlAuthentication authentication = assertInstanceOf(
                        SamlAuthenticationResult.Succeeded.class, result, name).getAuthentication();
                assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
                assertTrue(authentication.getSubjectKey().isPresent(), name);
            } else assertInstanceOf(SamlAuthenticationResult.Rejected.class, result, name);
        }
    }

    @Test void signedBoundaryShapeCorpusHasIndependentSignatureProof() throws Exception {
        Path directory = Path.of("src/test/resources/fixtures/scripted-idp/signed-boundary-shape");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(19, names.size(), "signed boundary-shape corpus changed");
        List<String> accepted = List.of("clean", "matching-confirmation-nameid",
                "one-time-and-proxy", "typed-confirmation-data");
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            assertTrue(oracleValid(xml, "_mint_assertion_9", "idp-signing-rsa-2048"),
                    name + " libxmlsec signature");
            SamlAuthenticationResult result = checkFixture(xml, "idp-signing-rsa-2048", false);
            if (accepted.contains(name)) {
                SamlAuthentication authentication = assertInstanceOf(
                        SamlAuthenticationResult.Succeeded.class, result, name).getAuthentication();
                assertEquals("minted-user", authentication.getNameId().orElseThrow().getValue(), name);
                assertTrue(authentication.getSubjectKey().isPresent(), name);
            } else assertInstanceOf(SamlAuthenticationResult.Rejected.class, result, name);
        }
    }

    @Test void libxmlsecVerdictsAndSpPolicyStaySeparateAcrossSignedPlacements() throws Exception {
        List<String> fixtures = new ArrayList<>(List.of(
                "assertion-signxml", "assertion-ec384", "assertion-rsa-sha1"));
        for (String placement : List.of("response", "assertion", "both"))
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"))
                for (String digest : List.of("sha256", "sha384", "sha512"))
                    fixtures.add("matrix-" + placement + "-" + algorithm + "-" + digest);
        for (String fixture : fixtures) {
            String credential = signingCredential(fixture);
            String original = Files.readString(Path.of("src/test/resources/fixtures/scripted-idp/"
                    + fixture + ".xml"));
            String assertion = section(original, "<saml:Assertion ", "</saml:Assertion>");
            String responseId = id(original, "samlp:Response");
            String assertionId = id(original, "saml:Assertion");
            boolean responseOnly = fixture.startsWith("matrix-response-");
            String targetId = responseOnly ? responseId : assertionId;
            String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL)
                    .matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace(assertionId, "_attacker_assertion");
            assertTrue(oracleValid(original, targetId, credential), fixture + " baseline signature");
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    checkFixture(original, credential, fixture.endsWith("sha1")), fixture);

            List<String> names = List.of("sibling-before", "extension-before-status", "destination",
                    "duplicate-status", "polluted-response-id", "signed-name-id");
            List<String> candidates = List.of(
                    original.replace(assertion, attacker + assertion),
                    original.replace("<samlp:Status>",
                            "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>"),
                    replaceFirstLiteral(original, "https://sp.test/acs",
                            "https://attacker.example.test/acs"),
                    original.replace("<samlp:Status>",
                            "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                                    + "</samlp:Status><samlp:Status>"),
                    original.replace("<samlp:Response ",
                            "<samlp:Response samlp:ID='_attacker_response' "),
                    original.replace("minted-user", "attacker-user"));
            for (int index = 0; index < candidates.size(); index++) {
                String label = fixture + ":" + names.get(index);
                String candidate = candidates.get(index);
                assertNotEquals(original, candidate, label + " did not change XML");
                boolean expectedOracle = index < 5 && !responseOnly;
                assertEquals(expectedOracle, oracleValid(candidate, targetId, credential),
                        label + " libxmlsec");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        checkFixture(candidate, credential, fixture.endsWith("sha1")),
                        label + " Revetsec SP");
            }
            if (fixture.startsWith("matrix-both-")) {
                assertTrue(oracleValid(original, responseId, credential), fixture + " Response signature");
                assertFalse(oracleValid(candidates.get(0), responseId, credential),
                        fixture + " altered Response signature");
            }
        }
    }

    @Test void libxmlsecDecryptionMatchesRevetsecAcrossGcmAndCbcMatrix() throws Exception {
        List<EncryptedFixture> fixtures = encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        for (EncryptedFixture fixture : fixtures)
            checkEncryptedOracleFixture(fixture.name(), fixture.credential(), fixture.cbc());
    }

    private static @NonNull List<@NonNull EncryptedFixture> encryptedFixtures() {
        List<EncryptedFixture> fixtures = new ArrayList<>();
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-sha256-mgf1sha256", "rsa-oaep-mgf1p"))
                fixtures.add(new EncryptedFixture("encrypted-" + data + "-" + transport,
                        "idp-signing-rsa-2048", false));
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                    "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"))
                for (String placement : List.of("response", "assertion", "both"))
                    fixtures.add(new EncryptedFixture("oaep-" + data + "-" + transport + "-"
                            + placement, "idp-signing-rsa-2048", false));
        for (String data : List.of("aes128-cbc", "aes192-cbc", "aes256-cbc"))
            fixtures.add(new EncryptedFixture("encrypted-" + data + "-response",
                    "idp-signing-rsa-2048", true));
        fixtures.add(new EncryptedFixture("assertion-rsa512-encrypted",
                "idp-signing-rsa-3072", false));
        fixtures.add(new EncryptedFixture("assertion-ec256-encrypted-id",
                "idp-signing-ec-p256", false));
        return List.copyOf(fixtures);
    }

    private record EncryptedFixture(@NonNull String name, @NonNull String credential,
            boolean cbc) { }

    private static void checkEncryptedOracleFixture(@NonNull String name,
            @NonNull String credential, boolean cbc) throws Exception {
        String xml = Files.readString(Path.of("src/test/resources/fixtures/scripted-idp/"
                + name + ".xml"));
        JsonObject oracle = oracleDecrypt(xml);
        assertTrue(oracle.findBoolean("valid").orElseThrow(), name + " libxmlsec decryption");
        assertTrue(oracle.findString("xml").orElseThrow().contains("minted-user"),
                name + " libxmlsec plaintext identity");
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                checkFixture(xml, credential, false, cbc), name + " Revetsec");
        assertEquals("minted-user", success.getAuthentication().getNameId().orElseThrow().getValue(),
                name + " Revetsec identity");
    }

    @Test void libxmlsecSeparatesEncryptedEnvelopeMutationsFromCiphertext() throws Exception {
        String source = Files.readString(Path.of(
                "src/test/resources/fixtures/scripted-idp/assertion-signxml.xml"));
        String signedAssertion = section(source, "<saml:Assertion ", "</saml:Assertion>");
        String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                Pattern.DOTALL).matcher(signedAssertion).replaceFirst("")
                .replace("minted-user", "attacker-user")
                .replace(id(source, "saml:Assertion"), "_attacker_assertion");
        List<EncryptedFixture> fixtures = encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        for (EncryptedFixture fixture : fixtures) {
            String name = fixture.name();
            String xml = Files.readString(Path.of("src/test/resources/fixtures/scripted-idp/"
                    + name + ".xml"));
            String carrier = name.equals("assertion-ec256-encrypted-id")
                    ? section(xml, "<saml:EncryptedID>", "</saml:EncryptedID>")
                    : section(xml, "<saml:EncryptedAssertion>", "</saml:EncryptedAssertion>");
            String plaintext = oracleDecrypt(xml).findString("xml").orElseThrow();
            assertTrue(plaintext.contains("minted-user"), name + " baseline libxmlsec identity");
            boolean responseSigned = xml.indexOf("<ds:Signature") < xml.indexOf("<samlp:Status>")
                    && xml.contains("<ds:Signature");
            String responseId = id(xml, "samlp:Response");
            assertEquals(responseSigned, oracleValid(xml, responseId, fixture.credential()),
                    name + " baseline Response signature");
            if (name.equals("assertion-ec256-encrypted-id"))
                assertTrue(oracleValid(xml, id(xml, "saml:Assertion"), fixture.credential()),
                        name + " baseline Assertion signature");
            String extension = xml.replace("<samlp:Status>",
                    "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>");
            String destination = replaceFirstLiteral(xml, "https://sp.test/acs",
                    "https://attacker.example.test/acs");
            String duplicate = xml.replace(carrier, carrier + carrier);
            for (String candidate : List.of(extension, destination)) {
                String label = name + (candidate.equals(extension) ? ":extension" : ":destination");
                assertNotEquals(xml, candidate, label + " is inert");
                JsonObject decrypted = oracleDecrypt(candidate);
                assertTrue(decrypted.findBoolean("valid").orElseThrow(),
                        label + " unchanged ciphertext decrypts");
                assertEquals(plaintext, decrypted.findString("xml").orElseThrow(),
                        label + " libxmlsec plaintext remains identical");
                assertFalse(oracleValid(candidate, responseId, fixture.credential()),
                        label + " outer Response signature is absent or invalid");
                if (plaintext.contains("<saml:Assertion")
                        && plaintext.contains("<ds:Signature"))
                    assertTrue(oracleValid(plaintext, id(plaintext, "saml:Assertion"),
                            fixture.credential()), label + " decrypted Assertion signature");
                if (name.equals("assertion-ec256-encrypted-id"))
                    assertTrue(oracleValid(candidate, id(xml, "saml:Assertion"),
                            fixture.credential()), label + " untouched Assertion signature");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        checkFixture(candidate, fixture.credential(), false, fixture.cbc()),
                        label + " Revetsec SP");
            }
            assertNotEquals(xml, duplicate, name + " duplicate carrier is inert");
            HttpResponse<String> oracle = json("POST", "/control/oracle/decrypt", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                    .put("xml", duplicate).build());
            assertEquals(400, oracle.statusCode(), name + " oracle must reject two EncryptedData");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    checkFixture(duplicate, fixture.credential(), false, fixture.cbc()),
                    name + " duplicate carrier Revetsec SP");
        }
    }

    private static @NonNull JsonObject oracleDecrypt(@NonNull String xml) throws Exception {
        HttpResponse<String> response = json("POST", "/control/oracle/decrypt", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .put("xml", xml).build());
        assertEquals(200, response.statusCode(), "decryption oracle unavailable: " + response.body());
        return assertInstanceOf(JsonObject.class, JsonCodec.parse(
                response.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(64_000)));
    }

    @Test void encryptedPolicyNegativesStayRejected() throws Exception {
        for (String name : List.of("negative-rsa-1_5", "negative-mgf-under-mgf1p",
                "negative-nonempty-oaep-params", "negative-cipher-bit-flip")) {
            String xml = Files.readString(Path.of("src/test/resources/fixtures/scripted-idp/"
                    + name + ".xml"));
            JsonObject oracle = oracleDecrypt(xml);
            boolean rsa15 = name.equals("negative-rsa-1_5");
            assertEquals(rsa15, oracle.findBoolean("valid").orElseThrow(),
                    name + " libxmlsec cryptographic verdict");
            if (rsa15)
                assertTrue(oracle.findString("xml").orElseThrow().contains("minted-user"),
                        name + " libxmlsec plaintext identity");
            SamlAuthenticationResult.Rejected rejected = assertInstanceOf(
                    SamlAuthenticationResult.Rejected.class,
                    checkFixture(xml, "idp-signing-rsa-2048", false), name + " Revetsec");
            assertEquals(SamlAuthenticationResult.Reason.DECRYPTION, rejected.getReason(), name);
        }
    }

    private static @NonNull String signingCredential(@NonNull String fixture) {
        if (fixture.contains("ecdsa-sha256")) return "idp-signing-ec-p256";
        if (fixture.contains("ecdsa-sha384") || fixture.equals("assertion-ec384"))
            return "idp-signing-ec-p384";
        if (fixture.contains("ecdsa-sha512")) return "idp-signing-ec-p521";
        if (fixture.contains("rsa-sha384") || fixture.contains("rsa-sha512"))
            return "idp-signing-rsa-3072";
        return "idp-signing-rsa-2048";
    }

    private static @NonNull String section(@NonNull String xml, @NonNull String opening,
            @NonNull String closing) {
        int start = xml.indexOf(opening);
        int end = xml.indexOf(closing, start);
        assertTrue(start >= 0 && end > start, "fixture shape changed");
        return xml.substring(start, end + closing.length());
    }

    private static @NonNull String replaceFirstLiteral(@NonNull String input, @NonNull String search,
            @NonNull String replacement) {
        int start = input.indexOf(search);
        assertTrue(start >= 0, "fixture field missing: " + search);
        return input.substring(0, start) + replacement + input.substring(start + search.length());
    }

    private static @NonNull String id(@NonNull String xml, @NonNull String element) {
        Matcher match = Pattern.compile("<" + element + "\\b[^>]*\\bID=\"([^\"]+)\"")
                .matcher(xml);
        assertTrue(match.find(), "fixture ID missing: " + element);
        return match.group(1);
    }

    private static boolean oracleValid(@NonNull String xml, @NonNull String targetId,
            @NonNull String credential)
            throws Exception {
        HttpResponse<String> response = json("POST", "/control/oracle/verify", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                .put("xml", xml).put("target_id", targetId)
                .put("credential", credential).build());
        assertEquals(200, response.statusCode(), "oracle could not classify " + targetId
                + ": " + response.statusCode());
        JsonObject verdict = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                response.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(64_000)));
        boolean valid = verdict.findBoolean("valid").orElseThrow();
        if (valid) {
            assertEquals("#" + targetId, verdict.findString("reference_uri").orElseThrow());
            assertTrue(verdict.findBoolean("covers_target").orElseThrow());
        }
        return valid;
    }

    private static @NonNull SamlAuthenticationResult checkFixture(@NonNull String xml,
            @NonNull String credential, boolean sha1) throws Exception {
        return checkFixture(xml, credential, sha1, false);
    }

    private static @NonNull SamlAuthenticationResult checkFixture(@NonNull String xml,
            @NonNull String credential, boolean sha1, boolean cbc) throws Exception {
        return checkFixture(xml, credential, sha1, cbc, false);
    }

    private static @NonNull SamlAuthenticationResult checkFixture(@NonNull String xml,
            @NonNull String credential, boolean sha1, boolean cbc, boolean scoped) throws Exception {
        SamlCredential decryption = SamlCredential.fromPem(
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-key.pem")),
                Files.readString(Path.of("src/test/resources/fixtures/keys/sp-encryption-rsa-2048-cert.pem")));
        SamlServiceProvider provider = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16))
                .decryptionCredentials(List.of(decryption))
                .clock(CLOCK).build();
        EnumSet<SamlCompatibilityMode> modes = EnumSet.of(
                SamlCompatibilityMode.UNSOLICITED_RESPONSES);
        if (sha1) modes.add(SamlCompatibilityMode.SHA1_SIGNATURES);
        if (cbc) modes.add(SamlCompatibilityMode.AES_CBC_ENCRYPTION);
        SamlIdentityProvider identityProvider = SamlIdentityProvider
                .withEntityId("https://idp.scripted-idp.test/")
                .connectionId("scripted-differential")
                .redirectSingleSignOnService(URI.create(base + "/sso"))
                .signingKeys(List.of(Pem.parseCertificate(Files.readString(Path.of(
                        "src/test/resources/fixtures/keys/" + credential + "-cert.pem")))
                        .getPublicKey()))
                .authorizedIdentifierScopes(scoped ? List.of("example.test") : List.of())
                .compatibility(Set.copyOf(modes)).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return provider.completeUnsolicitedAuthenticationResult(message, identityProvider);
    }

    @Test void metadataVariantsExerciseSelectionExpiryScopesRolloverAndPinnedSignatures() throws Exception {
        String url = base + "/metadata?now=2026-09-01T00%3A00%3A00Z";
        var pinned = Pem.parseCertificate(Files.readString(Path.of(
                "src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem"))).getPublicKey();
        for (String variant : List.of("default", "rollover", "aggregate", "scopes", "no-slo",
                "signed", "aggregate-signed")) {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                    URI.create(url + "&variant=" + variant)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), variant + ": " + response.body());
            byte[] xml = response.body().getBytes(StandardCharsets.UTF_8);
            SamlIdentityProviderMetadataResult result = variant.endsWith("signed")
                    ? SamlIdentityProviderMetadata.fromXmlResult(xml,
                            "https://idp.scripted-idp.test/", CLOCK, List.of(pinned))
                    : SamlIdentityProviderMetadata.fromXmlResult(xml,
                            "https://idp.scripted-idp.test/", CLOCK);
            SamlIdentityProviderMetadata metadata = assertInstanceOf(
                    SamlIdentityProviderMetadataResult.Parsed.class, result,
                    variant + ": " + result).getMetadata();
            assertEquals("https://idp.scripted-idp.test/", metadata.getEntityId());
            assertEquals(variant.equals("rollover") ? 2 : 1,
                    metadata.getSigningCertificates().size(), variant);
            assertEquals(variant.equals("scopes") ? List.of("example.test") : List.of(),
                    metadata.getAuthorizedIdentifierScopes(), variant);
            assertEquals(!variant.equals("no-slo"),
                    metadata.getRedirectSingleLogoutService().isPresent(), variant);
        }
        HttpResponse<String> expired = client.send(HttpRequest.newBuilder(
                URI.create(url + "&variant=expired")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, expired.statusCode());
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(
                        expired.body().getBytes(StandardCharsets.UTF_8),
                        "https://idp.scripted-idp.test/", CLOCK));
    }

    private static void arm(boolean encrypted) throws Exception {
        assertEquals(200, json("PUT", "/control/armed/sso", JsonObject.builder()
                .put("entity_id", SP_ENTITY)
                .put("spec", JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", "2026-09-01T00:00:00Z").build())
                        .put("signing", JsonObject.builder().put("placement", "both")
                                .put("algorithm", "rsa-sha256").build())
                        .put("encryption", JsonObject.builder().put("assertion", encrypted)
                                .put("name_id", encrypted).build()).build()).build()).statusCode());
    }

    private static @NonNull HttpResponse<@NonNull String> json(@NonNull String method,
            @NonNull String path, @NonNull JsonObject body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body.toJson())).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static @NonNull SamlPostBindingMessage responseMessage(@NonNull String page) {
        Matcher matches = FIELD.matcher(page);
        String response = null;
        String relay = null;
        while (matches.find()) {
            if ("SAMLResponse".equals(matches.group(1))) response = matches.group(2);
            else relay = matches.group(2);
        }
        assertTrue(response != null && relay != null, page);
        String form = "SAMLResponse=" + URLEncoder.encode(response, StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(relay, StandardCharsets.UTF_8);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }
}
