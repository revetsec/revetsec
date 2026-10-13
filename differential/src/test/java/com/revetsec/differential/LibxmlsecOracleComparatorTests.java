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
package com.revetsec.differential;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.saml.SamlAuthenticationResult;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Cryptographic comparison with libxmlsec1, which does not share the JDK XMLDSig implementation. */
final class LibxmlsecOracleComparatorTests {
    private static final @NonNull Path FIXTURES = Path.of("../src/test/resources/fixtures");
    private static final @NonNull String NOW = "2026-09-01T00:01:00Z";
    private static GenericContainer<?> container;
    private static HttpClient client;
    private static String base;

    @BeforeAll static void startOracle() throws Exception {
        String image = System.getProperty("scripted-idp.image", "revetsec-scripted-idp:local");
        GenericContainer<?> started = new GenericContainer<>(DockerImageName.parse(image))
                .withExposedPorts(8443)
                .withEnv("SCRIPTED_IDP_TLS_CERT", "/run/tls/server.pem")
                .withEnv("SCRIPTED_IDP_TLS_KEY", "/run/tls/server-key.pem")
                .withEnv("SCRIPTED_IDP_KEYS_DIR", "/run/keys")
                .withEnv("SCRIPTED_IDP_ORACLE_DECRYPTION_KEY",
                        "/run/keys/sp-encryption-rsa-2048-key.pem")
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(2)));
        copy(started, "tls/server.pem", "/run/tls/server.pem");
        copy(started, "tls/server-key.pem", "/run/tls/server-key.pem");
        for (String key : List.of("idp-signing-rsa-2048-cert.pem",
                "idp-signing-rsa-2048-key.pem",
                "idp-signing-rsa-3072-cert.pem",
                "idp-signing-ec-p256-cert.pem",
                "idp-signing-ec-p384-cert.pem",
                "idp-signing-ec-p521-cert.pem",
                "sp-encryption-rsa-2048-cert.pem",
                "sp-encryption-rsa-2048-key.pem"))
            copy(started, "fixtures/keys/" + key, "/run/keys/" + key);
        copy(started, "fixtures/shibboleth/idp-signing.crt",
                "/run/keys/shibboleth-capture-cert.pem");
        copy(started, "fixtures/keys/negative-attacker-rsa-2048-cert.pem",
                "/run/keys/negative-attacker-rsa-2048-cert.pem");
        for (String key : List.of("idp-rsa-2048.crt", "idp-ec-p256.crt",
                "idp-ec-p384.crt", "idp-ec-p521.crt")) {
            String name = key.substring(0, key.length() - 4);
            copy(started, "fixtures/saml-independent/keys/" + key,
                    "/run/keys/independent-" + name + "-cert.pem");
        }
        copy(started, "fixtures/saml-independent/keys/sp-rsa-2048.key",
                "/run/keys/independent-sp-rsa-2048-key.pem");
        started.start();
        container = started;
        base = "https://" + started.getHost() + ":" + started.getMappedPort(8443);

        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of("../src/test/resources/tls/truststore.p12"))) {
            trust.load(input, "changeit".toCharArray());
        }
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, managers.getTrustManagers(), null);
        client = HttpClient.newBuilder().sslContext(context).connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        try {
            HttpResponse<String> config = request("/control/config", JsonObject.builder()
                    .put("base_url", base).build(), "PUT");
            assertEquals(200, config.statusCode(), config.body());
        } catch (Exception exception) {
            throw new IllegalStateException("Oracle endpoint " + base + "; logs: " + started.getLogs(), exception);
        }
    }

    private static void copy(@NonNull GenericContainer<?> target, @NonNull String source,
            @NonNull String destination) throws Exception {
        target.withCopyToContainer(Transferable.of(
                Files.readAllBytes(Path.of("../src/test/resources/" + source)), 0444), destination);
    }

    @AfterAll static void stopOracle() {
        if (container != null) container.stop();
    }

    @Test void signedFixturesAndTamperingAgreeWithIndependentOracle() throws Exception {
        for (String fixture : OpenSamlSpComparatorTests.modernFixtures()) {
            String xml = OpenSamlSpComparatorTests.fixture(fixture);
            String element = fixture.startsWith("matrix-response-") ? "samlp:Response" : "saml:Assertion";
            String targetId = OpenSamlSpComparatorTests.id(xml, element);
            String credential = OpenSamlSpComparatorTests.signingCredential(fixture);
            JsonObject verified = verify(xml, targetId, credential);
            assertTrue(verified.findBoolean("valid").orElseThrow(), fixture + " oracle");
            assertTrue(verified.findBoolean("covers_target").orElseThrow(), fixture + " target");
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    OpenSamlSpComparatorTests.revetsec(xml, credential, false, false), fixture);

            String tampered = xml.replace("minted-user", "attacker-user");
            assertNotEquals(xml, tampered, fixture + " must contain the signed identity");
            assertFalse(verify(tampered, targetId, credential).findBoolean("valid").orElseThrow(),
                    fixture + " tampered oracle");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    OpenSamlSpComparatorTests.revetsec(tampered, credential, false, false),
                    fixture + " tampered Revetsec");
        }
    }

    @Test void attackerSignaturesRemainValidButCannotBorrowTheTrustedKey() throws Exception {
        for (ForgedKeyInfoCorpus.Placement placement : ForgedKeyInfoCorpus.Placement.values()) {
            for (boolean advertiseTrusted : List.of(false, true)) {
                String xml = ForgedKeyInfoCorpus.attackerSigned(placement, advertiseTrusted);
                String label = placement + ":" + (advertiseTrusted ? "trusted" : "attacker")
                        + " KeyInfo";
                if (placement != ForgedKeyInfoCorpus.Placement.ASSERTION)
                    assertAttackerSignature(xml, "samlp:Response", label + " Response");
                if (placement != ForgedKeyInfoCorpus.Placement.RESPONSE)
                    assertAttackerSignature(xml, "saml:Assertion", label + " Assertion");
            }
        }
    }

    private static void assertAttackerSignature(@NonNull String xml, @NonNull String element,
            @NonNull String label) throws Exception {
        String targetId = OpenSamlSpComparatorTests.id(xml, element);
        JsonObject attacker = verify(xml, targetId, ForgedKeyInfoCorpus.ATTACKER);
        assertTrue(attacker.findBoolean("valid").orElseThrow(), label + " attacker key");
        assertTrue(attacker.findBoolean("covers_target").orElseThrow(), label + " target");
        assertFalse(verify(xml, targetId, ForgedKeyInfoCorpus.TRUSTED)
                .findBoolean("valid").orElseThrow(), label + " configured IdP key");
    }

    @Test void fullSignedMutationMatrixSeparatesSignatureValidityFromSpPolicy() throws Exception {
        List<String> fixtures = new java.util.ArrayList<>(OpenSamlSpComparatorTests.modernFixtures());
        fixtures.addAll(List.of("assertion-rsa-sha1", "assertion-ec521",
                "both-rsa384", "response-rsa256", "digest-rsa256-sha1"));
        assertEquals(61, fixtures.size(), "signed fixture matrix changed");
        List<String> rejectedInputs = List.of("duplicate-id-before", "duplicate-id-after",
                "extension-replaces-assertion");
        List<String> stillValidAssertionSignatures = List.of("attacker-extension",
                "attacker-sibling-before", "attacker-sibling-after", "attacker-sibling-end",
                "copied-signature-extension", "duplicate-issuer", "duplicate-status",
                "qualified-response-id", "signed-assertion-in-extension",
                "signed-assertion-in-object");
        for (String name : fixtures) {
            String original = OpenSamlSpComparatorTests.fixture(name);
            String credential = OpenSamlSpComparatorTests.signingCredential(name);
            boolean outer = name.startsWith("matrix-response-") || name.startsWith("matrix-both-")
                    || name.equals("both-rsa384") || name.equals("response-rsa256")
                    || name.equals("digest-rsa256-sha1");
            String targetId = OpenSamlSpComparatorTests.id(original,
                    outer ? "samlp:Response" : "saml:Assertion");
            boolean legacySha1 = name.equals("assertion-rsa-sha1")
                    || name.equals("digest-rsa256-sha1");
            List<SignedSamlMutationMatrix.Mutation> mutations = SignedSamlMutationMatrix.from(original);
            assertEquals(19, mutations.size(), name + " mutation matrix changed");
            for (SignedSamlMutationMatrix.Mutation mutation : mutations) {
                String label = name + ":" + mutation.name();
                assertNotEquals(original, mutation.xml(), label + " is inert");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        OpenSamlSpComparatorTests.revetsec(mutation.xml(), credential,
                                legacySha1, false), label + " Revetsec");
                HttpResponse<String> response = request("/control/oracle/verify", JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", NOW).build())
                        .put("xml", mutation.xml()).put("target_id", targetId)
                        .put("credential", credential).build(), "POST");
                String verdict;
                if (response.statusCode() == 400) verdict = "rejected-input";
                else {
                    assertEquals(200, response.statusCode(), label + " oracle: " + response.body());
                    JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                            response.body().getBytes(StandardCharsets.UTF_8),
                            JsonLimits.protocolDocument(128_000)));
                    boolean valid = proof.findBoolean("valid").orElseThrow();
                    verdict = valid ? "valid" : "invalid-signature";
                    if (valid) assertTrue(proof.findBoolean("covers_target").orElseThrow(), label);
                }
                // An assertion-only signature can remain cryptographically valid after an
                // unsigned envelope edit. The SP still rejects every changed envelope.
                String expected = rejectedInputs.contains(mutation.name()) ? "rejected-input"
                        : !outer && stillValidAssertionSignatures.contains(mutation.name())
                        ? "valid" : "invalid-signature";
                assertEquals(expected, verdict, label + " libxmlsec");
            }
        }
    }

    @Test void separatelyMintedMutationsRetainOnlyTheirOriginalLibxmlsecTarget()
            throws Exception {
        List<String> fixtures = List.of("case1-response-assertion-rsa-sha256",
                "case2-assertion-rsa-sha1", "case3-assertion-ecdsa-p256",
                "case3-assertion-ecdsa-p384", "case3-assertion-ecdsa-p521",
                "case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256",
                "case5-encrypted-assertion-gcm-rsa-1_5",
                "case6-encrypted-id-gcm-rsa-oaep-sha256-mgf1sha256",
                "extra-signxml-assertion-rsa-sha256");
        int mutations = 0;
        int valid = 0;
        int invalid = 0;
        int rejectedInput = 0;
        List<String> signedInputRejections = List.of("duplicate-id-before",
                "duplicate-id-after", "extension-replaces-assertion");
        List<String> assertionSignatureSurvivors = List.of("attacker-sibling-before",
                "attacker-sibling-after", "attacker-extension",
                "signed-assertion-in-extension", "signed-assertion-in-object",
                "duplicate-issuer", "attacker-sibling-end", "duplicate-status",
                "qualified-response-id", "copied-signature-extension");
        List<String> encryptedIdSignatureBreaks = List.of("destination",
                "relative-namespace-sibling", "issuer-tamper");
        for (String name : fixtures) {
            String original = Files.readString(FIXTURES.resolve("saml-independent/" + name + ".xml"));
            String credential = "independent-idp-" + (name.contains("p256") ? "ec-p256"
                    : name.contains("p384") ? "ec-p384"
                    : name.contains("p521") ? "ec-p521" : "rsa-2048");
            boolean encryptedAssertion = name.startsWith("case4-") || name.startsWith("case5-");
            boolean encrypted = encryptedAssertion || name.startsWith("case6-");
            boolean responseSigned = name.startsWith("case1-");
            String target = encryptedAssertion ? decryptedIndependentAssertion(original)
                    : original;
            String targetId = OpenSamlSpComparatorTests.id(target,
                    responseSigned ? "samlp:Response" : "saml:Assertion");
            JsonObject baseline = verify(target, targetId, credential);
            assertTrue(baseline.findBoolean("valid").orElseThrow(), name + " baseline");
            assertTrue(baseline.findBoolean("covers_target").orElseThrow(), name + " target");
            String originalIdentity = name.startsWith("case2-") ? "user-2"
                    : name.startsWith("case3-") ? "user-3"
                    : name.startsWith("extra-") ? "user-7" : "user-1";
            List<OpenSamlSpComparatorTests.Mutation> changed = encrypted
                    ? OpenSamlSpComparatorTests.encryptedMutations(original, name)
                    : SignedSamlMutationMatrix.from(original, originalIdentity).stream()
                            .map(item -> new OpenSamlSpComparatorTests.Mutation(
                                    item.name(), item.xml())).toList();
            for (OpenSamlSpComparatorTests.Mutation mutation : changed) {
                if (mutation.xml().equals(original)) continue;
                mutations++;
                String label = name + ":" + mutation.name();
                String expected;
                if (encrypted) {
                    if (mutation.name().equals("duplicate-carrier")) expected = "rejected-input";
                    else if ((encryptedAssertion
                            && mutation.name().equals("relative-namespace-sibling"))
                            || (!encryptedAssertion
                            && encryptedIdSignatureBreaks.contains(mutation.name())))
                        expected = "invalid-signature";
                    else expected = "valid";
                } else if (signedInputRejections.contains(mutation.name())) {
                    expected = "rejected-input";
                } else if (!responseSigned && assertionSignatureSurvivors.contains(mutation.name())) {
                    expected = "valid";
                } else expected = "invalid-signature";
                String candidate = mutation.xml();
                if (encryptedAssertion) {
                    HttpResponse<String> decrypted = request("/control/oracle/decrypt",
                            JsonObject.builder()
                                    .put("clock", JsonObject.builder().put("now", NOW).build())
                                    .put("xml", candidate)
                                    .put("credential", "independent-sp-rsa-2048").build(), "POST");
                    if (decrypted.statusCode() == 400) {
                        rejectedInput++;
                        assertEquals("rejected-input", expected, label + " decrypt input");
                        continue;
                    }
                    assertEquals(200, decrypted.statusCode(), label + " decrypt");
                    JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                            decrypted.body().getBytes(StandardCharsets.UTF_8),
                            JsonLimits.protocolDocument(128_000)));
                    assertTrue(proof.findBoolean("valid").orElseThrow(), label + " ciphertext");
                    candidate = proof.findString("xml").orElseThrow();
                }
                HttpResponse<String> response = request("/control/oracle/verify",
                        JsonObject.builder().put("clock", JsonObject.builder().put("now", NOW).build())
                                .put("xml", candidate).put("target_id", targetId)
                                .put("credential", credential).build(), "POST");
                if (response.statusCode() == 400) {
                    rejectedInput++;
                    assertEquals("rejected-input", expected, label + " oracle input");
                    continue;
                }
                assertEquals(200, response.statusCode(), label + " oracle: " + response.body());
                JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                        response.body().getBytes(StandardCharsets.UTF_8),
                        JsonLimits.protocolDocument(128_000)));
                if (proof.findBoolean("valid").orElseThrow()) {
                    valid++;
                    assertEquals("valid", expected, label + " signature");
                    assertTrue(proof.findBoolean("covers_target").orElseThrow(), label);
                } else {
                    invalid++;
                    assertEquals("invalid-signature", expected, label + " signature");
                }
            }
        }
        assertEquals(171, mutations, "separately minted mutation inventory");
        assertEquals(99, valid, "unchanged signed targets in mutated envelopes");
        assertEquals(51, invalid, "mutations that break the selected signature");
        assertEquals(21, rejectedInput, "ambiguous oracle inputs");
        assertEquals(171, valid + invalid + rejectedInput, "every mutation reaches the oracle");
    }

    private static @NonNull String decryptedIndependentAssertion(@NonNull String xml)
            throws Exception {
        JsonObject result = post("/control/oracle/decrypt", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", NOW).build())
                .put("xml", xml).put("credential", "independent-sp-rsa-2048").build());
        assertTrue(result.findBoolean("valid").orElseThrow(), "independent baseline decrypt");
        return result.findString("xml").orElseThrow();
    }

    @Test void encryptedFixturesDecryptInIndependentOracleAndRevetsec() throws Exception {
        List<String> fixtures = OpenSamlSpComparatorTests.encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        for (String fixture : fixtures) {
            String xml = OpenSamlSpComparatorTests.fixture(fixture);
            JsonObject response = post("/control/oracle/decrypt", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", NOW).build())
                    .put("xml", xml).build());
            assertTrue(response.findBoolean("valid").orElseThrow(), fixture + " oracle");
            assertTrue(response.findString("xml").orElseThrow().contains("minted-user"),
                    fixture + " decrypted identity");
            boolean cbc = fixture.contains("cbc");
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    OpenSamlSpComparatorTests.revetsec(xml,
                            OpenSamlSpComparatorTests.encryptedSigningCredential(fixture), false, cbc),
                    fixture + " Revetsec");
        }
        String unsignedCbc = OpenSamlSpComparatorTests.fixture("encrypted-aes128-cbc-assertion");
        JsonObject decrypted = post("/control/oracle/decrypt", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", NOW).build())
                .put("xml", unsignedCbc).build());
        assertTrue(decrypted.findBoolean("valid").orElseThrow(), "CBC ciphertext is decryptable");
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                OpenSamlSpComparatorTests.revetsec(unsignedCbc,
                        "idp-signing-rsa-2048", false, true),
                "decryptable CBC without a signed Response must not authenticate");
    }

    @Test void encryptedWrapperMatrixKeepsOracleSignatureCoverageSeparateFromSpPolicy()
            throws Exception {
        List<String> fixtures = OpenSamlSpComparatorTests.encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        int outerInvalid = 0;
        int outerInputRejected = 0;
        int innerValid = 0;
        int innerInvalid = 0;
        int innerInputRejected = 0;
        for (String fixture : fixtures) {
            String original = OpenSamlSpComparatorTests.fixture(fixture);
            String credential = OpenSamlSpComparatorTests.encryptedSigningCredential(fixture);
            boolean encryptedId = fixture.equals("assertion-ec256-encrypted-id");
            boolean assertionOnly = fixture.endsWith("-assertion")
                    || fixture.equals("assertion-rsa512-encrypted") || encryptedId;
            String targetId = assertionOnly && !encryptedId ? "" : OpenSamlSpComparatorTests.id(
                    original, encryptedId ? "saml:Assertion" : "samlp:Response");
            if (!assertionOnly) {
                JsonObject baseline = verify(original, targetId, credential);
                assertTrue(baseline.findBoolean("valid").orElseThrow(), fixture + " outer baseline");
                assertTrue(baseline.findBoolean("covers_target").orElseThrow(), fixture + " outer target");
            } else if (encryptedId) {
                JsonObject baseline = verify(original, targetId, credential);
                assertTrue(baseline.findBoolean("valid").orElseThrow(), fixture + " assertion baseline");
            }
            List<OpenSamlSpComparatorTests.Mutation> mutations =
                    OpenSamlSpComparatorTests.encryptedMutations(original, fixture);
            assertEquals(19, mutations.size(), fixture + " mutation matrix changed");
            for (OpenSamlSpComparatorTests.Mutation mutation : mutations) {
                String label = fixture + ":" + mutation.name();
                assertNotEquals(original, mutation.xml(), label + " is inert");
                if (!assertionOnly) {
                    HttpResponse<String> response = request("/control/oracle/verify",
                            JsonObject.builder().put("clock", JsonObject.builder().put("now", NOW).build())
                                    .put("xml", mutation.xml()).put("target_id", targetId)
                                    .put("credential", credential).build(), "POST");
                    if (response.statusCode() == 400) {
                        outerInputRejected++;
                        continue;
                    }
                    assertEquals(200, response.statusCode(), label + " oracle: " + response.body());
                    JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                            response.body().getBytes(StandardCharsets.UTF_8),
                            JsonLimits.protocolDocument(128_000)));
                    assertFalse(proof.findBoolean("valid").orElseThrow(), label + " outer signature");
                    outerInvalid++;
                } else if (encryptedId) {
                    HttpResponse<String> response = request("/control/oracle/verify",
                            JsonObject.builder().put("clock", JsonObject.builder().put("now", NOW).build())
                                    .put("xml", mutation.xml()).put("target_id", targetId)
                                    .put("credential", credential).build(), "POST");
                    if (response.statusCode() == 400) {
                        assertEquals("duplicate-carrier", mutation.name(), label + " input rejection");
                        innerInputRejected++;
                        continue;
                    }
                    assertEquals(200, response.statusCode(), label + " oracle: " + response.body());
                    JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                            response.body().getBytes(StandardCharsets.UTF_8),
                            JsonLimits.protocolDocument(128_000)));
                    boolean expectedValid = !mutation.name().equals("relative-namespace-sibling")
                            && !mutation.name().equals("destination")
                            && !mutation.name().equals("issuer-tamper");
                    assertEquals(expectedValid, proof.findBoolean("valid").orElseThrow(),
                            label + " inner signature");
                    if (expectedValid)
                        assertTrue(proof.findBoolean("covers_target").orElseThrow(), label + " target");
                    if (expectedValid) innerValid++;
                    else innerInvalid++;
                } else {
                    HttpResponse<String> response = request("/control/oracle/decrypt",
                            JsonObject.builder().put("clock", JsonObject.builder().put("now", NOW).build())
                                    .put("xml", mutation.xml()).build(), "POST");
                    if (response.statusCode() == 400) {
                        assertEquals("duplicate-carrier", mutation.name(), label + " input rejection");
                        innerInputRejected++;
                        continue;
                    }
                    assertEquals(200, response.statusCode(), label + " decrypt: " + response.body());
                    JsonObject decrypted = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                            response.body().getBytes(StandardCharsets.UTF_8),
                            JsonLimits.protocolDocument(128_000)));
                    assertTrue(decrypted.findBoolean("valid").orElseThrow(), label + " ciphertext");
                    String assertion = decrypted.findString("xml").orElseThrow();
                    String assertionId = Pattern.compile("\\bID=\"([^\"]+)\"").matcher(assertion)
                            .results().findFirst().orElseThrow().group(1);
                    JsonObject proof = verify(assertion, assertionId, credential);
                    boolean expectedValid = !mutation.name().equals("relative-namespace-sibling");
                    assertEquals(expectedValid, proof.findBoolean("valid").orElseThrow(),
                            label + " inner signature");
                    if (expectedValid)
                        assertTrue(proof.findBoolean("covers_target").orElseThrow(), label + " target");
                    if (expectedValid) innerValid++;
                    else innerInvalid++;
                }
            }
        }
        assertEquals(627, outerInvalid, "signed Response mutations invalidate the outer signature");
        assertEquals(0, outerInputRejected, "all signed Response mutations reach signature verification");
        assertEquals(236, innerValid, "unsigned outer edits can preserve the inner signature");
        assertEquals(16, innerInvalid, "relative namespace and signed EncryptedID edits invalidate it");
        assertEquals(14, innerInputRejected, "duplicate carriers have ambiguous oracle input");
    }

    @Test void validAssertionSignatureCannotPromoteUnsignedExtensionIdentity() throws Exception {
        for (String fixture : OpenSamlSpComparatorTests.modernFixtures()) {
            if (!fixture.startsWith("matrix-assertion-")) continue;
            String xml = OpenSamlSpComparatorTests.fixture(fixture);
            String targetId = OpenSamlSpComparatorTests.id(xml, "saml:Assertion");
            String credential = OpenSamlSpComparatorTests.signingCredential(fixture);
            String assertion = OpenSamlSpComparatorTests.section(
                    xml, "<saml:Assertion ", "</saml:Assertion>");
            String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                    Pattern.DOTALL).matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace(targetId, "_attacker_assertion");
            String wrapped = xml.replace("<samlp:Status>",
                    "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>");
            assertNotEquals(xml, wrapped, fixture + " extension was not inserted");
            JsonObject verdict = verify(wrapped, targetId, credential);
            assertTrue(verdict.findBoolean("valid").orElseThrow(), fixture + " signed target");
            assertTrue(verdict.findBoolean("covers_target").orElseThrow(), fixture + " reference");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    OpenSamlSpComparatorTests.revetsec(wrapped, credential, false, false), fixture);
        }
    }

    @Test void structuralMutationsDistinguishOuterAndInnerSignatureCoverage() throws Exception {
        for (String fixture : OpenSamlSpComparatorTests.modernFixtures()) {
            String xml = OpenSamlSpComparatorTests.fixture(fixture);
            String credential = OpenSamlSpComparatorTests.signingCredential(fixture);
            boolean responseSigned = fixture.startsWith("matrix-response-")
                    || fixture.startsWith("matrix-both-");
            String targetId = OpenSamlSpComparatorTests.id(xml,
                    responseSigned ? "samlp:Response" : "saml:Assertion");
            String assertion = OpenSamlSpComparatorTests.section(
                    xml, "<saml:Assertion ", "</saml:Assertion>");
            String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                    Pattern.DOTALL).matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace(OpenSamlSpComparatorTests.id(xml, "saml:Assertion"),
                            "_attacker_assertion");
            List<String> mutations = List.of(
                    xml.replace(assertion, attacker + assertion),
                    xml.replace("<samlp:Status>",
                            "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>"),
                    xml.replace("Destination=\"https://sp.test/acs\"",
                            "Destination=\"https://attacker.example.test/acs\""),
                    xml.replace("<samlp:Status>",
                            "<samlp:Status><samlp:StatusCode "
                                    + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                                    + "</samlp:Status><samlp:Status>"));
            for (int index = 0; index < mutations.size(); index++) {
                String changed = mutations.get(index);
                String label = fixture + " structural mutation " + index;
                assertNotEquals(xml, changed, label + " is inert");
                JsonObject proof = verify(changed, targetId, credential);
                assertEquals(!responseSigned, proof.findBoolean("valid").orElseThrow(), label);
                if (!responseSigned)
                    assertTrue(proof.findBoolean("covers_target").orElseThrow(), label);
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        OpenSamlSpComparatorTests.revetsec(changed, credential, false, false), label);
            }
        }
    }

    @Test void realShibbolethSignaturesAndCiphertextsAgreeWithLibxmlsec() throws Exception {
        for (String mode : List.of("gcm", "cbc")) {
            String xml = Files.readString(FIXTURES.resolve("shibboleth/" + mode + "-response.xml"));
            String responseId = Pattern.compile("<saml2p:Response\\b[^>]*\\bID=\"([^\"]+)\"")
                    .matcher(xml).results().findFirst().orElseThrow().group(1);
            JsonObject verified = verify(xml, responseId, "shibboleth-capture");
            assertTrue(verified.findBoolean("valid").orElseThrow(), mode + " real IdP signature");
            assertTrue(verified.findBoolean("covers_target").orElseThrow(),
                    mode + " Response must be covered");
            JsonObject decrypted = post("/control/oracle/decrypt", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", NOW).build())
                    .put("xml", xml).build());
            assertTrue(decrypted.findBoolean("valid").orElseThrow(), mode + " real IdP encryption");
            String assertion = decrypted.findString("xml").orElseThrow();
            assertTrue(assertion.contains("AuthnStatement") && assertion.contains("Subject"),
                    mode + " decrypted assertion shape");
            String tampered = xml.replace("https://sp.example.test/acs",
                    "https://attacker.example.test/acs");
            assertNotEquals(xml, tampered, mode + " signed destination was not changed");
            assertFalse(verify(tampered, responseId, "shibboleth-capture")
                    .findBoolean("valid").orElseThrow(), mode + " tampered signature");
        }
    }

    @Test void realSimpleSamlCbcCryptographyAndSignaturePlacementAgreeWithLibxmlsec() throws Exception {
        String signed = Files.readString(FIXTURES.resolve(
                "simplesamlphp/cbc-response-signed-response.xml"));
        String responseId = OpenSamlSpComparatorTests.id(signed, "samlp:Response");
        JsonObject responseProof = verify(signed, responseId, "idp-signing-rsa-2048");
        assertTrue(responseProof.findBoolean("valid").orElseThrow());
        assertTrue(responseProof.findBoolean("covers_target").orElseThrow());
        String decryptedSigned = post("/control/oracle/decrypt", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", NOW).build())
                .put("xml", signed).build()).findString("xml").orElseThrow();
        assertTrue(decryptedSigned.contains("AuthnStatement"));
        String tampered = signed.replace("https://sp.example.test/acs",
                "https://attacker.example.test/acs");
        assertNotEquals(signed, tampered);
        assertFalse(verify(tampered, responseId, "idp-signing-rsa-2048")
                .findBoolean("valid").orElseThrow());

        String assertionSigned = Files.readString(FIXTURES.resolve(
                "simplesamlphp/cbc-assertion-signed-response.xml"));
        String decryptedAssertion = post("/control/oracle/decrypt", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", NOW).build())
                .put("xml", assertionSigned).build()).findString("xml").orElseThrow();
        var matcher = Pattern.compile("\\bID=\"([^\"]+)\"").matcher(decryptedAssertion);
        assertTrue(matcher.find());
        JsonObject assertionProof = verify(decryptedAssertion, matcher.group(1),
                "idp-signing-rsa-2048");
        assertTrue(assertionProof.findBoolean("valid").orElseThrow());
        assertTrue(assertionProof.findBoolean("covers_target").orElseThrow());
    }

    @Test void realProviderEncryptedEnvelopeAttacksInvalidateSignedResponses() throws Exception {
        for (String fixture : List.of("shibboleth/gcm-response.xml",
                "shibboleth/cbc-response.xml",
                "simplesamlphp/cbc-response-signed-response.xml")) {
            String xml = Files.readString(FIXTURES.resolve(fixture));
            boolean shibboleth = fixture.startsWith("shibboleth/");
            String protocol = shibboleth ? "saml2p" : "samlp";
            String assertion = shibboleth ? "saml2" : "saml";
            String credential = shibboleth ? "shibboleth-capture" : "idp-signing-rsa-2048";
            String responseId = OpenSamlSpComparatorTests.id(xml, protocol + ":Response");
            assertTrue(verify(xml, responseId, credential).findBoolean("valid").orElseThrow(),
                    fixture + " baseline signature");
            List<String> mutations = capturedEncryptedEnvelopeMutations(xml, protocol, assertion);
            assertEquals(19, mutations.size(), fixture + " mutation count");
            for (int index = 0; index < mutations.size(); index++) {
                String changed = mutations.get(index);
                String label = fixture + " mutation " + index;
                assertNotEquals(xml, changed, label + " is inert");
                HttpResponse<String> response = request("/control/oracle/verify", JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", NOW).build())
                        .put("xml", changed).put("target_id", responseId)
                        .put("credential", credential).build(), "POST");
                assertEquals(200, response.statusCode(), label + " oracle: " + response.body());
                JsonObject proof = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                        response.body().getBytes(StandardCharsets.UTF_8),
                        JsonLimits.protocolDocument(128_000)));
                assertFalse(proof.findBoolean("valid").orElseThrow(), label + " signature");
            }
        }
    }

    @Test void realProviderCiphertextTamperingSeparatesGcmIntegrityFromCbcSignaturePolicy()
            throws Exception {
        for (String fixture : List.of("shibboleth/gcm-response.xml",
                "shibboleth/cbc-response.xml",
                "simplesamlphp/cbc-response-signed-response.xml")) {
            String xml = Files.readString(FIXTURES.resolve(fixture));
            boolean gcm = fixture.contains("gcm");
            boolean shibboleth = fixture.startsWith("shibboleth/");
            String protocol = shibboleth ? "saml2p" : "samlp";
            String credential = shibboleth ? "shibboleth-capture" : "idp-signing-rsa-2048";
            String responseId = OpenSamlSpComparatorTests.id(xml, protocol + ":Response");
            assertTrue(verify(xml, responseId, credential).findBoolean("valid").orElseThrow(),
                    fixture + " baseline signature");
            String plaintext = post("/control/oracle/decrypt", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", NOW).build())
                    .put("xml", xml).build()).findString("xml").orElseThrow();
            for (int index = 0; index < 2; index++) {
                String changed = flipCapturedCipherValue(xml, index);
                String label = fixture + (index == 0 ? ":wrapped-key" : ":encrypted-data");
                assertNotEquals(xml, changed, label + " mutation is inert");
                assertFalse(verify(changed, responseId, credential)
                        .findBoolean("valid").orElseThrow(), label + " outer signature");
                JsonObject decrypted = post("/control/oracle/decrypt", JsonObject.builder()
                        .put("clock", JsonObject.builder().put("now", NOW).build())
                        .put("xml", changed).build());
                boolean valid = decrypted.findBoolean("valid").orElseThrow();
                if (gcm) assertFalse(valid, label + " GCM authentication");
                else if (valid) assertNotEquals(plaintext, decrypted.findString("xml").orElseThrow(),
                        label + " CBC plaintext changed without intrinsic authentication");
            }
        }
    }

    @Test void unsignedSimpleSamlEnvelopeEditsLeaveOnlyTheInnerSignatureValid() throws Exception {
        String xml = Files.readString(FIXTURES.resolve(
                "simplesamlphp/cbc-assertion-signed-response.xml"));
        List<String> mutations = capturedEncryptedEnvelopeMutations(xml, "samlp", "saml");
        assertEquals(17, mutations.size(), "unsigned captured envelope matrix");
        for (int index = 0; index < mutations.size(); index++) {
            String changed = mutations.get(index);
            assertNotEquals(xml, changed, "mutation " + index + " is inert");
            HttpResponse<String> response = request("/control/oracle/decrypt", JsonObject.builder()
                    .put("clock", JsonObject.builder().put("now", NOW).build())
                    .put("xml", changed).build(), "POST");
            if (index == 2) {
                assertEquals(400, response.statusCode(), "duplicate carrier is ambiguous");
                continue;
            }
            assertEquals(200, response.statusCode(), "mutation " + index + " decrypt response");
            JsonObject decrypted = assertInstanceOf(JsonObject.class, JsonCodec.parse(
                    response.body().getBytes(StandardCharsets.UTF_8),
                    JsonLimits.protocolDocument(128_000)));
            assertTrue(decrypted.findBoolean("valid").orElseThrow(), "mutation " + index + " decrypts");
            String assertion = decrypted.findString("xml").orElseThrow();
            String assertionId = Pattern.compile("\\bID=\"([^\"]+)\"").matcher(assertion)
                    .results().findFirst().orElseThrow().group(1);
            JsonObject proof = verify(assertion, assertionId, "idp-signing-rsa-2048");
            assertEquals(index != 14, proof.findBoolean("valid").orElseThrow(),
                    "mutation " + index + " inner signature");
            if (index != 14)
                assertTrue(proof.findBoolean("covers_target").orElseThrow(), "mutation " + index + " target");
        }
    }

    static @NonNull List<@NonNull String> capturedEncryptedEnvelopeMutations(
            @NonNull String xml, @NonNull String protocol, @NonNull String assertion) {
        String carrierStart = "<" + assertion + ":EncryptedAssertion";
        String carrierEnd = "</" + assertion + ":EncryptedAssertion>";
        int start = xml.indexOf(carrierStart);
        int end = xml.indexOf(carrierEnd);
        if (start < 0 || end < start) throw new IllegalArgumentException("EncryptedAssertion missing");
        String carrier = xml.substring(start, end + carrierEnd.length());
        String status = "<" + protocol + ":Status>";
        String attacker = "<" + assertion + ":Assertion xmlns:" + assertion
                + "='urn:oasis:names:tc:SAML:2.0:assertion' ID='_attacker'>"
                + "<" + assertion + ":Issuer>https://attacker.example.test/</" + assertion
                + ":Issuer><" + assertion + ":Subject><" + assertion
                + ":NameID>attacker-user</" + assertion + ":NameID></" + assertion
                + ":Subject></" + assertion + ":Assertion>";
        String statusEnd = "</" + protocol + ":Status>";
        String responseStart = "<" + protocol + ":Response ";
        String responseEnd = "</" + protocol + ":Response>";
        String issuerStart = "<" + assertion + ":Issuer";
        int issuerOpening = xml.indexOf(issuerStart);
        int issuerContent = xml.indexOf('>', issuerOpening) + 1;
        String issuerEnd = "</" + assertion + ":Issuer>";
        int issuerClosing = xml.indexOf(issuerEnd, issuerContent);
        if (issuerOpening < 0 || issuerContent == 0 || issuerClosing < 0)
            throw new IllegalArgumentException("Response Issuer missing");
        String issuer = xml.substring(issuerContent, issuerClosing);
        int signatureOpening = xml.indexOf("<ds:Signature");
        int signatureClosing = xml.indexOf("</ds:Signature>", signatureOpening);
        if ((signatureOpening < 0) != (signatureClosing < 0))
            throw new IllegalArgumentException("Incomplete Response Signature");
        String attackerIssuer = "<" + assertion + ":Issuer xmlns:" + assertion
                + "='urn:oasis:names:tc:SAML:2.0:assertion'>https://attacker.example.test/</"
                + assertion + ":Issuer>";
        List<String> mutations = new ArrayList<>(List.of(
                xml.replace(carrier, attacker + carrier),
                xml.replace(status, "<" + protocol + ":Extensions>" + attacker
                        + "</" + protocol + ":Extensions>" + status),
                xml.replace(carrier, carrier + carrier),
                xml.replace(status, status + "<" + protocol + ":StatusCode "
                        + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></"
                        + protocol + ":Status>" + status),
                xml.replace("https://sp.example.test/acs", "https://attacker.example.test/acs"),
                xml.replace(carrier, carrier + attacker),
                xml.replace(responseEnd, attacker + responseEnd),
                xml.replace(statusEnd, "<" + protocol + ":StatusCode Value='"
                        + "urn:oasis:names:tc:SAML:2.0:status:Success'/>" + statusEnd),
                xml.replace("urn:oasis:names:tc:SAML:2.0:status:Success",
                        "urn:oasis:names:tc:SAML:2.0:status:Responder"),
                xml.replaceFirst("(?s)<" + protocol + ":Status>.*?</" + protocol + ":Status>", ""),
                xml.replace("Destination=\"https://sp.example.test/acs\"", ""),
                xml.replace(issuer, "https://attacker.example.test/"),
                xml.replaceFirst("InResponseTo=\"[^\"]+\"", "InResponseTo=\"_attacker_request\""),
                xml.replace(responseStart, responseStart
                        + "xmlns:attacker='https://attacker.example.test/ns' "
                        + "attacker:ID='not-the-signed-ID' "),
                xml.replace(responseStart, responseStart + "xmlns:ns='1' ")
                        .replace(carrier, attacker + carrier),
                xml.replace(status, attackerIssuer + status),
                xml.replace(status, "<Status xmlns='https://attacker.example.test/ns'>")
                        .replace(statusEnd, "</Status>")));
        if (signatureOpening >= 0) {
            String signature = xml.substring(signatureOpening,
                    signatureClosing + "</ds:Signature>".length());
            String copiedSignature = "<" + protocol + ":Extensions>"
                    + "<Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                    + "<Child xml:xmlns='#other'>" + signature + "</Child></Parent></"
                    + protocol + ":Extensions>";
            mutations.add(xml.replace(status, copiedSignature + status));
            mutations.add(xml.replace(status, signature + status));
        }
        return List.copyOf(mutations);
    }

    private static @NonNull String flipCapturedCipherValue(@NonNull String xml, int ordinal) {
        String opening = "<xenc:CipherValue>";
        int start = -1;
        for (int index = 0; index <= ordinal; index++) start = xml.indexOf(opening, start + 1);
        if (start < 0) throw new IllegalArgumentException("CipherValue missing");
        int position = start + opening.length();
        int end = xml.indexOf("</xenc:CipherValue>", position);
        if (end - position < 8) throw new IllegalArgumentException("CipherValue too short");
        position += (end - position) / 2;
        char old = xml.charAt(position);
        return xml.substring(0, position) + (old == 'A' ? 'B' : 'A') + xml.substring(position + 1);
    }

    private static @NonNull JsonObject verify(@NonNull String xml, @NonNull String targetId,
            @NonNull String credential) throws Exception {
        return post("/control/oracle/verify", JsonObject.builder()
                .put("clock", JsonObject.builder().put("now", NOW).build())
                .put("xml", xml).put("target_id", targetId)
                .put("credential", credential).build());
    }

    private static @NonNull JsonObject post(@NonNull String path, @NonNull JsonObject body) throws Exception {
        HttpResponse<String> response = request(path, body, "POST");
        assertEquals(200, response.statusCode(), path + ": " + response.body());
        return assertInstanceOf(JsonObject.class, JsonCodec.parse(
                response.body().getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(128_000)));
    }

    private static @NonNull HttpResponse<@NonNull String> request(@NonNull String path,
            @NonNull JsonObject body, @NonNull String method) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path))
                        .header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(body.toJson())).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
