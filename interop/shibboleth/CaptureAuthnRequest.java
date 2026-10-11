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

/** Test-only request and metadata generator for the Shibboleth capture script. */
public final class CaptureAuthnRequest {
    private CaptureAuthnRequest() { }

    public static void main(@NonNull String @NonNull [] arguments) throws Exception {
        if (arguments.length != 2 && arguments.length != 6)
            throw new IllegalArgumentException("output, IdP certificate and optional IdP/SP identifiers required");
        Path output = Path.of(arguments[0]);
        Path keys = Path.of("src/test/resources/fixtures/keys");
        String idpEntity = arguments.length == 6 ? arguments[2]
                : "https://idp.example.org/idp/shibboleth";
        String idpSso = arguments.length == 6 ? arguments[3]
                : "https://idp.example.org/idp/profile/SAML2/Redirect/SSO";
        String spEntity = arguments.length == 6 ? arguments[4] : "https://sp.test/ShibCapture";
        String connectionId = arguments.length == 6 ? arguments[5] : "shibboleth-capture";
        X509Certificate idpCertificate;
        try (var input = Files.newInputStream(Path.of(arguments[1]))) {
            idpCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        SamlIdentityProvider idp = SamlIdentityProvider
                .withEntityId(idpEntity)
                .connectionId(connectionId)
                .redirectSingleSignOnService(URI.create(idpSso))
                .signingKeys(List.of(idpCertificate.getPublicKey()))
                .wantAuthnRequestsSigned(true).build();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(spEntity)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .signingCredential(credential(keys, "sp-signing-rsa-2048"))
                .decryptionCredentials(List.of(credential(keys, "sp-encryption-rsa-2048")))
                .replayCache(InMemorySamlReplayCache.withLimit(Clock.systemUTC(), 16))
                .clock(Clock.systemUTC()).build();
        SamlServiceProviderMetadataResult metadata = SamlServiceProviderMetadata
                .fromServiceProviderResult(sp);
        if (!(metadata instanceof SamlServiceProviderMetadataResult.Generated generated))
            throw new IllegalStateException("SP metadata generation failed");
        Files.writeString(output.resolve("sp-metadata.xml"), generated.getXml());
        SamlAuthenticationRequestResult result = sp.beginAuthenticationResult(idp);
        if (!(result instanceof SamlAuthenticationRequestResult.Prepared prepared))
            throw new IllegalStateException("AuthnRequest generation failed");
        PendingSamlAuthentication pending = prepared.getPendingAuthentication();
        Files.writeString(output.resolve("redirect-url.txt"), prepared.getRedirectUri().toASCIIString());
        Files.writeString(output.resolve("pending.txt"), pending.getRequestId() + "\n"
                + pending.getRelayStateHandle() + "\n" + pending.issuedAt() + "\n"
                + pending.getExpiresAt() + "\n");
    }

    private static @NonNull SamlCredential credential(@NonNull Path keys,
            @NonNull String name) throws Exception {
        return SamlCredential.fromPem(Files.readString(keys.resolve(name + "-key.pem")),
                Files.readString(keys.resolve(name + "-cert.pem")));
    }
}
