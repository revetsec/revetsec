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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import org.jspecify.annotations.NonNull;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/** Test-only live SP-initiated logout driver. The key seals disposable capture state only. */
public final class CaptureSpInitiatedLogout {
    private static final @NonNull String CONTEXT = "simplesaml-sp-initiated-capture";
    private static final @NonNull String SP = "https://sp.test/SimpleCapture";
    private static final @NonNull String IDP = "https://ssp.example.test/idp";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI SLO = URI.create("https://sp.example.test/slo");
    private static final @NonNull URI IDP_SLO = URI.create(
            "https://ssp.example.test/simplesaml/module.php/saml/idp/singleLogout");

    private CaptureSpInitiatedLogout() { }

    public static void main(@NonNull String @NonNull [] arguments) throws Exception {
        if (arguments.length != 3 || !("begin".equals(arguments[0]) || "complete".equals(arguments[0])))
            throw new IllegalArgumentException("begin/complete, input, output directory required");
        Path output = Path.of(arguments[2]);
        Clock clock = Clock.systemUTC();
        SamlServiceProvider sp = serviceProvider(clock);
        SamlIdentityProvider idp = identityProvider();
        StateSealer sealer = sealer(clock);
        if ("begin".equals(arguments[0])) {
            Path login = Path.of(arguments[1]);
            List<String> snapshot = Files.readAllLines(login.resolve("pending.txt"));
            if (snapshot.size() != 4) throw new IllegalStateException("SSO pending state changed");
            PendingSamlAuthentication pending = new PendingSamlAuthentication(SP, snapshot.get(0),
                    snapshot.get(1), "simplesaml-capture", IDP, ACS.toASCIIString(),
                    Instant.parse(snapshot.get(2)), Instant.parse(snapshot.get(3)));
            PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                    pending.toSealedForm(sealer, CONTEXT), sealer, CONTEXT);
            String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                    Files.readAllBytes(login.resolve("response.xml"))), StandardCharsets.UTF_8)
                    + "&RelayState=" + URLEncoder.encode(snapshot.get(1), StandardCharsets.UTF_8);
            SamlPostBindingParseResult parsed = SamlPostBindingMessage.fromFormBodyResult(
                    form.getBytes(StandardCharsets.US_ASCII),
                    List.of("application/x-www-form-urlencoded"), null);
            if (!(parsed instanceof SamlPostBindingParseResult.Parsed accepted))
                throw new IllegalStateException("Captured SSO POST could not be parsed");
            SamlAuthenticationResult result = sp.completeAuthenticationResult(
                    accepted.getMessage(), source, idp);
            if (!(result instanceof SamlAuthenticationResult.Succeeded authenticated))
                throw new IllegalStateException("Revetsec rejected live login before logout: " + result);
            SamlLogoutRedirectResult outbound = sp.beginLogoutResult(
                    idp, authenticated.getAuthentication().getSessionReference());
            if (!(outbound instanceof SamlLogoutRedirectResult.Prepared prepared))
                throw new IllegalStateException("Revetsec could not begin logout: " + outbound);
            Files.writeString(output.resolve("sp-initiated-request-url.txt"),
                    prepared.getRedirectUri().toASCIIString() + "\n");
            Files.writeString(output.resolve("sp-initiated-pending.txt"),
                    prepared.getPendingLogout().toSealedForm(sealer, CONTEXT) + "\n");
            Files.writeString(output.resolve("sp-initiated-session.txt"),
                    authenticated.getAuthentication().getSessionReference().getNameId().getValue() + "\n"
                            + authenticated.getAuthentication().getSessionReference()
                            .getSessionIndex().orElse("") + "\n");
            return;
        }
        URI reply = URI.create(Files.readString(Path.of(arguments[1])).strip());
        if (!SLO.toASCIIString().equals(reply.getScheme() + "://"
                + reply.getRawAuthority() + reply.getRawPath()))
            throw new IllegalStateException("IdP returned an unexpected SP logout endpoint");
        SamlRedirectBindingParseResult parsed = SamlRedirectBindingMessage
                .fromRawQueryResult(reply.getRawQuery());
        if (!(parsed instanceof SamlRedirectBindingParseResult.Parsed accepted))
            throw new IllegalStateException("IdP LogoutResponse has an invalid Redirect binding");
        String sealed = Files.readString(output.resolve("sp-initiated-pending.txt")).strip();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(sealed, sealer, CONTEXT);
        SamlLogoutResult result = sp.completeLogoutResult(accepted.getMessage(), source, idp);
        if (!(result instanceof SamlLogoutResult.Succeeded))
            throw new IllegalStateException("Revetsec rejected real IdP LogoutResponse: " + result);
        Files.write(output.resolve("sp-initiated-response.xml"), accepted.getMessage().xml());
    }

    private static @NonNull StateSealer sealer(@NonNull Clock clock) {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) index;
        return StateSealer.withActiveKey(SealingKey.fromBase64("capture",
                Base64.getEncoder().encodeToString(key))).clock(clock).build();
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull Clock clock) throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(SLO)
                .signingCredential(SamlCredential.fromPem(
                        Files.readString(keys.resolve("sp-signing-rsa-2048-key.pem")),
                        Files.readString(keys.resolve("sp-signing-rsa-2048-cert.pem"))))
                .decryptionCredentials(List.of(SamlCredential.fromPem(
                        Files.readString(keys.resolve("sp-encryption-rsa-2048-key.pem")),
                        Files.readString(keys.resolve("sp-encryption-rsa-2048-cert.pem")))))
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 16)).clock(clock).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider() throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        X509Certificate certificate;
        try (var input = Files.newInputStream(keys.resolve("idp-signing-rsa-2048-cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        return SamlIdentityProvider.withEntityId(IDP).connectionId("simplesaml-capture")
                .redirectSingleSignOnService(URI.create(
                        "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService"))
                .redirectSingleLogoutService(IDP_SLO)
                .signingKeys(List.of(certificate.getPublicKey()))
                .allowAesCbcEncryption(true).build();
    }
}
