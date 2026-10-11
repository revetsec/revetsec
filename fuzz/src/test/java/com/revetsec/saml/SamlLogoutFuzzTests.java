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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

/** Signed SLO acceptance and status checks against the independently minted Redirect corpus. */
public final class SamlLogoutFuzzTests {
    private static final @NonNull String SP = "https://sp.test/Selftest";
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull String SLO = "https://sp.test/logout";
    private static final @NonNull String RELAY = "AAAAAAAAAAAAAAAAAAAAAA";
    private static final @NonNull String CONNECTION = "slo-fuzz";
    private static final @NonNull String CONTEXT = "slo-fuzz-cookie";
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull Properties CORPUS = corpus();
    private static final @NonNull List<@NonNull String> CASES = CORPUS.stringPropertyNames().stream()
            .sorted().toList();
    private static final @NonNull SamlCredential SP_CREDENTIAL = credential();
    private static final @NonNull SamlIdentityProvider IDENTITY_PROVIDER = identityProvider();
    private static final @NonNull StateSealer SEALER = sealer();
    private static final @NonNull String SEALED_PENDING = pendingSeal();

    /** A valid fixture releases only its fixed session or success; every other case rejects. */
    @FuzzTest(maxDuration = "5m")
    public void signedLogoutCasesNeverReleaseWrongSessionOrSuccess(byte @NonNull [] input) {
        String name = CASES.get(octet(input, 0) % CASES.size());
        String original = Objects.requireNonNull(CORPUS.getProperty(name));
        int mutation = octet(input, 1) % 4;
        String query = switch (mutation) {
            case 0 -> original;
            case 1 -> original.replace("&RelayState=" + RELAY,
                    "&RelayState=%41" + RELAY.substring(1));
            case 2 -> original + "&SigAlg=duplicate";
            default -> changedSignedOctet(original, octet(input, 2));
        };
        if (mutation != 0) Assertions.assertNotEquals(original, query);
        SamlRedirectBindingParseResult parsed = SamlRedirectBindingMessage.fromRawQueryResult(query);
        if (parsed instanceof SamlRedirectBindingParseResult.Rejected) {
            Assertions.assertNotEquals(0, mutation, name);
            return;
        }
        SamlRedirectBindingMessage message = Assertions.assertInstanceOf(
                SamlRedirectBindingParseResult.Parsed.class, parsed).getMessage();
        SamlServiceProvider sp = serviceProvider();
        if (name.startsWith("request-")) {
            SamlLogoutRequestResult result = sp.acceptLogoutRequestResult(message, IDENTITY_PROVIDER);
            if (name.equals("request-valid") && mutation == 0) {
                SamlLogoutRequest request = Assertions.assertInstanceOf(
                        SamlLogoutRequestResult.Accepted.class, result).getRequest();
                Assertions.assertEquals(CONNECTION, request.getIdentityProviderConnectionId());
                Assertions.assertEquals("minted-user", request.getNameId().getValue());
                Assertions.assertEquals(List.of("session-123"), request.getSessionIndexes());
            } else Assertions.assertInstanceOf(SamlLogoutRequestResult.Rejected.class, result, name);
        } else {
            PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                    SEALED_PENDING, SEALER, CONTEXT);
            SamlLogoutResult result = sp.completeLogoutResult(message, source, IDENTITY_PROVIDER);
            if (name.equals("response-valid") && mutation == 0)
                Assertions.assertInstanceOf(SamlLogoutResult.Succeeded.class, result);
            else Assertions.assertInstanceOf(SamlLogoutResult.Rejected.class, result, name);
        }
    }

    private static @NonNull String changedSignedOctet(@NonNull String query, int offset) {
        int firstValue = query.indexOf('=') + 1;
        int signature = query.indexOf("&Signature=");
        if (firstValue < 1 || signature <= firstValue) throw new IllegalStateException("Invalid SLO fixture");
        int index = firstValue + offset % (signature - firstValue);
        char replacement = query.charAt(index) == 'A' ? 'B' : 'A';
        return query.substring(0, index) + replacement + query.substring(index + 1);
    }

    private static @NonNull SamlServiceProvider serviceProvider() {
        return SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .singleLogoutServiceUrl(URI.create(SLO))
                .signingCredential(SP_CREDENTIAL)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8))
                .clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider() {
        try {
            return SamlIdentityProvider.withEntityId(IDP)
                    .connectionId(CONNECTION)
                    .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                    .signingKeys(List.of(Pem.parseCertificate(resource("keys/idp-signing-rsa-2048-cert.pem"))
                            .getPublicKey())).build();
        } catch (PemException exception) {
            throw new IllegalStateException("Invalid SLO test certificate", exception);
        }
    }

    private static @NonNull SamlCredential credential() {
        return SamlCredential.fromPem(resource("keys/sp-signing-rsa-2048-key.pem"),
                resource("keys/sp-signing-rsa-2048-cert.pem"));
    }

    private static @NonNull StateSealer sealer() {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
        return StateSealer.withActiveKey(SealingKey.fromBase64(
                "slo-fuzz", Base64.getEncoder().encodeToString(key))).clock(CLOCK).build();
    }

    private static @NonNull String pendingSeal() {
        PendingSamlAuthentication fields = new PendingSamlAuthentication(SP, "_" + "00".repeat(20),
                RELAY, CONNECTION, IDP, SLO, CLOCK.instant().minusSeconds(60),
                CLOCK.instant().plusSeconds(300));
        return new PendingSamlLogout(fields).toSealedForm(SEALER, CONTEXT);
    }

    private static @NonNull Properties corpus() {
        Properties properties = new Properties();
        try (InputStream input = SamlLogoutFuzzTests.class.getResourceAsStream(
                "/fixtures/scripted-idp/slo-corpus.properties")) {
            if (input == null) throw new IllegalStateException("Missing signed SLO corpus");
            properties.load(input);
        } catch (IOException exception) { throw new IllegalStateException("Unreadable signed SLO corpus", exception); }
        if (properties.size() != 23) throw new IllegalStateException("Incomplete signed SLO corpus");
        return properties;
    }

    private static @NonNull String resource(@NonNull String name) {
        try (InputStream input = SamlLogoutFuzzTests.class.getResourceAsStream("/fixtures/" + name)) {
            if (input == null) throw new IllegalStateException("Missing SLO test credential");
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) { throw new IllegalStateException("Unreadable SLO test credential", exception); }
    }

    private static int octet(byte @NonNull [] input, int offset) {
        return offset < input.length ? input[offset] & 0xff : 0;
    }
}
