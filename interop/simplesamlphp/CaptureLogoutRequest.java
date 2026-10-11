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

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

/** Test-only verifier and response generator for a live SimpleSAMLphp LogoutRequest. */
public final class CaptureLogoutRequest {
    private CaptureLogoutRequest() { }

    public static void main(@NonNull String @NonNull [] arguments) throws Exception {
        if (arguments.length != 2) throw new IllegalArgumentException("request URL and output directory required");
        Path output = Path.of(arguments[1]);
        Path keys = Path.of("src/test/resources/fixtures/keys");
        X509Certificate certificate;
        try (var input = Files.newInputStream(keys.resolve("idp-signing-rsa-2048-cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        Clock clock = Clock.systemUTC();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.test/SimpleCapture")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/slo"))
                .signingCredential(SamlCredential.fromPem(
                        Files.readString(keys.resolve("sp-signing-rsa-2048-key.pem")),
                        Files.readString(keys.resolve("sp-signing-rsa-2048-cert.pem"))))
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8))
                .clock(clock).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://ssp.example.test/idp")
                .connectionId("simplesaml-capture")
                .redirectSingleSignOnService(URI.create(
                        "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService"))
                .redirectSingleLogoutService(URI.create(
                        "https://ssp.example.test/simplesaml/module.php/saml/idp/singleLogout"))
                .signingKeys(List.of(certificate.getPublicKey())).build();
        URI requestUri = URI.create(arguments[0]);
        if (!"https://sp.example.test/slo".equals(requestUri.getScheme() + "://"
                + requestUri.getRawAuthority() + requestUri.getRawPath()))
            throw new IllegalArgumentException("Unexpected SP logout endpoint");
        SamlRedirectBindingParseResult parsed = SamlRedirectBindingMessage
                .fromRawQueryResult(requestUri.getRawQuery());
        if (!(parsed instanceof SamlRedirectBindingParseResult.Parsed accepted))
            throw new IllegalStateException("IdP LogoutRequest has an invalid Redirect binding");
        SamlLogoutRequestResult result = sp.acceptLogoutRequestResult(accepted.getMessage(), idp);
        if (!(result instanceof SamlLogoutRequestResult.Accepted logout))
            throw new IllegalStateException("Revetsec rejected real IdP LogoutRequest: " + result);
        SamlLogoutResponseRedirectResult response = sp.respondToLogoutRequestResult(
                logout.getRequest(), idp, SamlLogoutStatus.SUCCESS);
        if (!(response instanceof SamlLogoutResponseRedirectResult.Prepared prepared))
            throw new IllegalStateException("Revetsec could not sign the LogoutResponse: " + response);
        Files.write(output.resolve("logout-request.xml"), accepted.getMessage().xml());
        Files.writeString(output.resolve("logout-response-url.txt"),
                prepared.getRedirectUri().toASCIIString());
        Files.writeString(output.resolve("logout-request-session.txt"),
                logout.getRequest().getNameId().getValue() + "\n"
                        + String.join("\n", logout.getRequest().getSessionIndexes()) + "\n");
    }
}
