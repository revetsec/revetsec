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

import com.revetsec.internal.xml.SecureXmlParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

final class SamlPostLogoutMetadataTests {
    private static final @NonNull String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final @NonNull String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private static final @NonNull String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    @Test void metadataPublishesOnlyConfiguredLogoutBindingsAtTheirExactLocations() throws Exception {
        SamlCredential credential = SamlCredential.fromPem(resource("sp-signing-rsa-2048-key.pem"),
                resource("sp-signing-rsa-2048-cert.pem"));
        for (boolean includeRedirect : List.of(false, true)) {
            SamlServiceProvider.Builder builder = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                    .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                    .postSingleLogoutServiceUrl(URI.create("https://sp.example.test/post-logout"))
                    .signingCredential(credential).replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8)).clock(CLOCK);
            if (includeRedirect) builder = builder.singleLogoutServiceUrl(URI.create("https://sp.example.test/redirect-logout"));
            SamlServiceProvider sp = builder.build();
            String xml = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                    SamlServiceProviderMetadata.fromServiceProviderResult(sp)).getXml();
            var services = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                    SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)))
                    .getDocument().getElementsByTagNameNS(MD, "SingleLogoutService");
            assertEquals(includeRedirect ? 2 : 1, services.getLength());
            boolean foundPost = false;
            boolean foundRedirect = false;
            for (int i = 0; i < services.getLength(); i++) {
                Element service = assertInstanceOf(Element.class, services.item(i));
                if (POST.equals(service.getAttribute("Binding"))) {
                    assertEquals("https://sp.example.test/post-logout", service.getAttribute("Location"));
                    foundPost = true;
                } else {
                    assertEquals(REDIRECT, service.getAttribute("Binding"));
                    assertEquals("https://sp.example.test/redirect-logout", service.getAttribute("Location"));
                    foundRedirect = true;
                }
            }
            assertTrue(foundPost);
            assertEquals(includeRedirect, foundRedirect);
        }
    }

    @Test void parsedPostLogoutEndpointSurvivesMetadataConnectionConstruction() throws Exception {
        String post = "<md:SingleLogoutService Binding='" + POST + "' Location='https://idp.example.test/post-logout'/>";
        String redirect = "<md:SingleLogoutService Binding='" + REDIRECT + "' Location='https://idp.example.test/redirect-logout'/>";
        SamlIdentityProviderMetadata metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(metadata(post + redirect).getBytes(StandardCharsets.UTF_8),
                        null, CLOCK)).getMetadata();
        assertEquals(URI.create("https://idp.example.test/post-logout"), metadata.getPostSingleLogoutService().orElseThrow());
        assertEquals(URI.create("https://idp.example.test/redirect-logout"), metadata.getRedirectSingleLogoutService().orElseThrow());
        SamlIdentityProvider idp = SamlIdentityProvider.withMetadata(metadata).connectionId("tenant-one").build();
        assertEquals(URI.create("https://idp.example.test/post-logout"), idp.postSingleLogoutService());
        assertEquals(URI.create("https://idp.example.test/redirect-logout"), idp.redirectSingleLogoutService());
        for (String invalid : List.of(post + post,
                post.replace("https://", "http://"),
                post.replace("https://idp.example.test/post-logout", "https://idp.example.test/post-logout#fragment")))
            assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                    SamlIdentityProviderMetadata.fromXmlResult(metadata(invalid).getBytes(StandardCharsets.UTF_8),
                            null, CLOCK));
    }

    private static @NonNull String metadata(@NonNull String logoutServices) throws Exception {
        String certificate = resource("idp-signing-rsa-2048-cert.pem")
                .replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
                .replaceAll("[ \\t\\r\\n]", "");
        return "<md:EntityDescriptor xmlns:md='" + MD + "' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' "
                + "entityID='https://idp.example.test/saml'><md:IDPSSODescriptor "
                + "protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + logoutServices + "<md:SingleSignOnService Binding='" + REDIRECT
                + "' Location='https://idp.example.test/sso'/></md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    private static @NonNull String resource(@NonNull String name) throws Exception {
        try (var stream = SamlPostLogoutMetadataTests.class.getResourceAsStream("/fixtures/keys/" + name)) {
            return new String(Objects.requireNonNull(stream).readAllBytes(), StandardCharsets.US_ASCII);
        }
    }
}
