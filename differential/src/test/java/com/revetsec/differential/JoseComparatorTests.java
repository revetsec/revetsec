/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 */
package com.revetsec.differential;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.StaticJsonWebKeySource;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** RFC 7515/7518/7519, RFC 8037/9864 and INV-J1/J2/J5: three producers and two external verifiers. */
final class JoseComparatorTests {
    private static final String ISSUER = "https://rc1-issuer.example.test";
    private static final String AUDIENCE = "https://rc1-resource.example.test";
    private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");
    private static final String CLAIMS = "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE
            + "\",\"sub\":\"original-subject\",\"exp\":" + NOW.plusSeconds(300).getEpochSecond()
            + ",\"iat\":" + NOW.getEpochSecond() + "}";
    private static final Path KEYS = Path.of("../src/test/resources/fixtures/keys");
    private static final List<Fixture> FIXTURES = fixtures();

    // Every original fixture receives every attack below; dynamic names are retained in actual JUnit XML.
    @TestFactory Stream<DynamicTest> allAlgorithmsAndIndependentProducersHaveTheSameCheckedIdentity() {
        return FIXTURES.stream().map(f -> DynamicTest.dynamicTest(f.id(), () -> {
            Verdict verdict = compare(f, f.compact());
            assertEquals(new Verdict(true, true, !f.algorithm().equals("Ed25519")), verdict, f.id());
            Jwt checked = validator(f).validate(f.compact());
            assertEquals("original-subject", checked.getClaims().getSubject().orElseThrow());
            assertEquals(ISSUER, checked.getClaims().getIssuer().orElseThrow());
            assertEquals(List.of(AUDIENCE), checked.getClaims().getAudiences());
            assertEquals(NOW.plusSeconds(300), checked.getClaims().getExpiresAt().orElseThrow());
            assertEquals("original-subject", SignedJWT.parse(f.compact()).getJWTClaimsSet().getSubject());
            String thumbprint = JsonWebKeySet.fromJson("{\"keys\":[" + f.publicJwk() + "]}")
                    .getKeys().get(0).getThumbprintSha256();
            assertEquals(thumbprint, JWK.parse(f.publicJwk()).computeThumbprint().toString());
            assertEquals(thumbprint, org.jose4j.jwk.JsonWebKey.Factory.newJwk(f.publicJwk())
                    .calculateBase64urlEncodedThumbprint("SHA-256"));
            if (!f.algorithm().equals("Ed25519")) {
                assertEquals("original-subject", consumer(f).processToClaims(f.compact()).getSubject());
            }
        }));
    }

    @TestFactory Stream<DynamicTest> everyFixtureRejectsSignatureAndSerializationAttacks() {
        return FIXTURES.stream().flatMap(f -> List.of("signature-bit", "payload-bit", "header-bit",
                "truncated-signature", "empty-signature", "four-segments", "two-segments", "wrong-key")
                .stream().map(attack -> DynamicTest.dynamicTest(f.id() + ":" + attack, () -> {
                    String token = switch (attack) {
                        case "signature-bit" -> flip(f.compact(), 2);
                        case "payload-bit" -> flip(f.compact(), 1);
                        case "header-bit" -> flip(f.compact(), 0);
                        case "truncated-signature" -> f.compact().substring(0, f.compact().length() - 8);
                        case "empty-signature" -> f.compact().substring(0, f.compact().lastIndexOf('.') + 1);
                        case "four-segments" -> f.compact() + ".extra";
                        case "two-segments" -> f.compact().substring(0, f.compact().lastIndexOf('.'));
                        default -> f.compact();
                    };
                    Fixture trust = attack.equals("wrong-key") ? wrongTrust(f) : f;
                    assertEquals(new Verdict(false, false, false), compare(trust, token), f.id() + ":" + attack);
                })));
    }

    @TestFactory Stream<DynamicTest> everyFixtureRejectsWrongIssuerAudienceExpiryAndCriticalHeaders() {
        return FIXTURES.stream().flatMap(f -> List.of("wrong-issuer", "wrong-audience", "expired", "future-nbf",
                "missing-exp", "unknown-critical", "unsecured", "wrong-algorithm")
                .stream().map(attack -> DynamicTest.dynamicTest(f.id() + ":" + attack, () -> {
                    String claims = switch (attack) {
                        case "wrong-issuer" -> CLAIMS.replace(ISSUER, ISSUER + "/other");
                        case "wrong-audience" -> CLAIMS.replace(AUDIENCE, AUDIENCE + "/other");
                        case "expired" -> CLAIMS.replace(Long.toString(NOW.plusSeconds(300).getEpochSecond()),
                                Long.toString(NOW.minusSeconds(1).getEpochSecond()));
                        case "future-nbf" -> CLAIMS.substring(0, CLAIMS.length() - 1) + ",\"nbf\":"
                                + NOW.plusSeconds(10).getEpochSecond() + "}";
                        case "missing-exp" -> CLAIMS.replace(",\"exp\":" + NOW.plusSeconds(300).getEpochSecond(), "");
                        default -> CLAIMS;
                    };
                    String header = header(f.algorithm());
                    if (attack.equals("unknown-critical")) header = header.substring(0, header.length() - 1)
                            + ",\"crit\":[\"rc1-unknown\"],\"rc1-unknown\":true}";
                    if (attack.equals("wrong-algorithm")) header = header("HS256");
                    String token = attack.equals("unsecured") ? encode("{\"alg\":\"none\"}") + "." + encode(claims) + "."
                            : attack.equals("wrong-algorithm") ? hmacWithPublicKey(f, header, claims)
                            : jcaSign(f.algorithm(), f.privateKey(), header, claims);
                    assertEquals(new Verdict(false, false, false), compare(f, token), f.id() + ":" + attack);
                })));
    }

    @TestFactory Stream<DynamicTest> everyFixtureRejectsMalformedProtectedJsonAndClaimTypes() {
        return FIXTURES.stream().flatMap(f -> List.of("duplicate-algorithm", "duplicate-audience", "header-array",
                "claims-array", "string-expiry", "null-expiry", "numeric-issuer", "numeric-audience")
                .stream().map(attack -> DynamicTest.dynamicTest(f.id() + ":" + attack, () -> {
                    String header = switch (attack) {
                        case "duplicate-algorithm" -> header(f.algorithm()).replace("\"kid\"", "\"alg\":\"" + f.algorithm() + "\",\"kid\"");
                        case "header-array" -> "[\"" + f.algorithm() + "\"]";
                        default -> header(f.algorithm());
                    };
                    String expiry = Long.toString(NOW.plusSeconds(300).getEpochSecond());
                    String claims = switch (attack) {
                        case "duplicate-audience" -> CLAIMS.substring(0, CLAIMS.length() - 1) + ",\"aud\":\"" + AUDIENCE + "\"}";
                        case "claims-array" -> "[]";
                        case "string-expiry" -> CLAIMS.replace("\"exp\":" + expiry, "\"exp\":\"" + expiry + "\"");
                        case "null-expiry" -> CLAIMS.replace("\"exp\":" + expiry, "\"exp\":null");
                        case "numeric-issuer" -> CLAIMS.replace("\"iss\":\"" + ISSUER + "\"", "\"iss\":1");
                        case "numeric-audience" -> CLAIMS.replace("\"aud\":\"" + AUDIENCE + "\"", "\"aud\":1");
                        default -> CLAIMS;
                    };
                    // Nimbus 10.10's required-claim set checks presence: a present null exp is not timed.
                    // Revetsec and jose4j reject it. Retain this exact parser/claims-policy difference.
                    assertEquals(new Verdict(false, attack.equals("null-expiry"), false), compare(f,
                            jcaSign(f.algorithm(), f.privateKey(), header, claims)), f.id() + ":" + attack);
                })));
    }

    @TestFactory Stream<DynamicTest> documentedHeaderAndConfirmationStrictnessDifferencesAreExact() {
        // These parameters are outside Revetsec's JWT bearer profile. Fixed trusted keys mean neither oracle
        // fetches jku/x5u or promotes embedded keys. Ordinary JWT oracles do not enforce bearer cnf policy.
        return FIXTURES.stream().flatMap(f -> List.of("jku", "x5u", "embedded-jwk", "confirmation")
                .stream().map(difference -> DynamicTest.dynamicTest(f.id() + ":" + difference, () -> {
                    String header = header(f.algorithm());
                    String claims = CLAIMS;
                    if (difference.equals("confirmation")) claims = CLAIMS.substring(0, CLAIMS.length() - 1)
                            + ",\"cnf\":{\"jkt\":\"test-only-confirmation\"}}";
                    else header = header.substring(0, header.length() - 1) + switch (difference) {
                        case "embedded-jwk" -> ",\"jwk\":" + f.publicJwk() + "}";
                        case "jku" -> ",\"jku\":\"https://uncontacted.example.test/keys\"}";
                        default -> ",\"x5u\":\"https://uncontacted.example.test/cert\"}";
                    };
                    String token = jcaSign(f.algorithm(), f.privateKey(), header, claims);
                    assertEquals(new Verdict(false, true, !f.algorithm().equals("Ed25519")), compare(f, token),
                            f.id() + ":" + difference);
                })));
    }

    @Test void fullySpecifiedEd25519IsAnExplicitJose4jCapabilityDifference() throws Exception {
        // jose4j 0.9.7 registers EdDSA, not RFC 9864's Ed25519 name. Do not alias the protected header.
        assertFalse(org.jose4j.jwa.AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory()
                .isAvailable("Ed25519"));
        assertTrue(org.jose4j.jwa.AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().isAvailable("EdDSA"));
        assertEquals(3, FIXTURES.stream().filter(f -> f.algorithm().equals("EdDSA")).count());
        assertEquals(2, FIXTURES.stream().filter(f -> f.algorithm().equals("Ed25519")).count());
    }

    @Test void oracleProjectionsDetectPlantedSignatureAndIdentityDisagreements() throws Exception {
        Fixture f = FIXTURES.get(0);
        assertThrows(AssertionError.class, () -> assertEquals(new Verdict(true, true, true), compare(f, flip(f.compact(), 2))));
        String changed = jcaSign(f.algorithm(), f.privateKey(), header(f.algorithm()),
                CLAIMS.replace("original-subject", "attacker-subject"));
        assertTrue(nimbus(f, changed));
        assertNotEquals(validator(f).validate(f.compact()).getClaims().getSubject(),
                validator(f).validate(changed).getClaims().getSubject());
    }

    private static Verdict compare(Fixture f, String compact) throws Exception {
        boolean ours;
        try { validator(f).validate(compact); ours = true; }
        catch (JoseException failure) { ours = false; }
        boolean independent;
        try { consumer(f).processToClaims(compact); independent = true; }
        catch (InvalidJwtException failure) { independent = false; }
        return new Verdict(ours, nimbus(f, compact), independent);
    }

    private static boolean nimbus(Fixture f, String compact) throws Exception {
        try {
            SignedJWT jwt = SignedJWT.parse(compact);
            if (!jwt.getHeader().getAlgorithm().getName().equals(f.algorithm())) return false;
            JWSVerifier verifier = verifier(f);
            if (!jwt.verify(verifier)) return false;
            DefaultJWTClaimsVerifier<SecurityContext> claims = new DefaultJWTClaimsVerifier<>(Set.of(AUDIENCE),
                    new JWTClaimsSet.Builder().issuer(ISSUER).build(), Set.of("iss", "aud", "exp"), Set.of()) {
                @Override protected Date currentTime() { return Date.from(NOW); }
            };
            claims.setMaxClockSkew(0);
            claims.verify(jwt.getJWTClaimsSet(), null);
            return true;
        } catch (java.text.ParseException | com.nimbusds.jose.JOSEException
                 | com.nimbusds.jwt.proc.BadJWTException failure) { return false; }
    }

    private static org.jose4j.jwt.consumer.JwtConsumer consumer(Fixture f) {
        return new JwtConsumerBuilder().setExpectedIssuer(ISSUER).setExpectedAudience(AUDIENCE)
                .setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(NOW.getEpochSecond()))
                .setAllowedClockSkewInSeconds(0).setVerificationKey(f.publicKey())
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, f.algorithm()).build();
    }

    private static JwtValidator validator(Fixture f) {
        return JwtValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUDIENCE))
                .jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
                        "{\"keys\":[" + f.publicJwk() + "]}")))
                .allowedAlgorithms(Set.of(JwsAlgorithm.valueOf(f.algorithm().equals("EdDSA") ? "EDDSA" : f.algorithm().equals("Ed25519") ? "ED25519" : f.algorithm()))).clockSkew(Duration.ZERO)
                .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
    }

    private static JWSVerifier verifier(Fixture f) throws Exception {
        if (f.publicKey() instanceof RSAPublicKey rsa) return new RSASSAVerifier(rsa);
        if (f.publicKey() instanceof ECPublicKey ec) return new ECDSAVerifier(ec);
        return new Ed25519Verifier((OctetKeyPair) JWK.parse(f.publicJwk()));
    }

    private static List<Fixture> fixtures() {
        try {
            List<Fixture> result = new ArrayList<>();
            for (String algorithm : List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
                    "ES384", "ES512", "EdDSA", "Ed25519")) {
                String keyName = algorithm.startsWith("ES") ? "idp-signing-ec-" + switch (algorithm) {
                    case "ES256" -> "p256"; case "ES384" -> "p384"; default -> "p521";
                } : "idp-signing-rsa-2048";
                String keyAlgorithm = algorithm.startsWith("ES") ? "EC" : algorithm.startsWith("Ed") ? "Ed25519" : "RSA";
                Path privatePath = algorithm.startsWith("Ed") ? Path.of("../src/test/resources/fixtures/pem/ed25519-key.pem")
                        : KEYS.resolve(keyName + "-key.pem");
                PrivateKey privateKey = KeyFactory.getInstance(keyAlgorithm).generatePrivate(
                        new PKCS8EncodedKeySpec(pem(privatePath)));
                PublicKey publicKey;
                if (algorithm.startsWith("Ed")) publicKey = KeyFactory.getInstance("Ed25519").generatePublic(
                        new X509EncodedKeySpec(pem(Path.of("../src/test/resources/fixtures/pem/ed25519-public.pem"))));
                else try (var input = Files.newInputStream(KEYS.resolve(keyName + "-cert.pem"))) {
                    publicKey = CertificateFactory.getInstance("X.509").generateCertificate(input).getPublicKey();
                }
                String jwk = jwk(publicKey, algorithm);
                result.add(new Fixture(algorithm + "/jca", algorithm, privateKey, publicKey, jwk,
                        jcaSign(algorithm, privateKey, header(algorithm), CLAIMS)));
                JWSSigner signer = publicKey instanceof RSAPublicKey ? new RSASSASigner(privateKey)
                        : publicKey instanceof ECPublicKey ? new ECDSASigner((java.security.interfaces.ECPrivateKey) privateKey)
                        : new Ed25519Signer((OctetKeyPair) JWK.parse(jwk.substring(0, jwk.length() - 1)
                                + ",\"d\":\"" + encode(Arrays.copyOfRange(privateKey.getEncoded(), privateKey.getEncoded().length - 32,
                                privateKey.getEncoded().length)) + "\"}"));
                JWSObject object = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).keyID("rc1-key").build(),
                        new Payload(CLAIMS));
                object.sign(signer);
                result.add(new Fixture(algorithm + "/nimbus", algorithm, privateKey, publicKey, jwk, object.serialize()));
                if (!algorithm.equals("Ed25519")) {
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmHeaderValue(algorithm); jws.setKeyIdHeaderValue("rc1-key");
                    jws.setPayload(CLAIMS); jws.setKey(privateKey);
                    result.add(new Fixture(algorithm + "/jose4j", algorithm, privateKey, publicKey, jwk, jws.getCompactSerialization()));
                }
            }
            return List.copyOf(result);
        } catch (Exception failure) { throw new ExceptionInInitializerError(failure); }
    }

    private static Fixture wrongTrust(Fixture original) throws Exception {
        // A different key of the same family keeps an algorithm mismatch from masking signature verification.
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance(
                original.publicKey() instanceof RSAPublicKey ? "RSA" : original.publicKey() instanceof ECPublicKey ? "EC" : "Ed25519");
        if (original.publicKey() instanceof RSAPublicKey) generator.initialize(2048);
        if (original.publicKey() instanceof ECPublicKey ec) generator.initialize(ec.getParams());
        var pair = generator.generateKeyPair();
        return new Fixture(original.id(), original.algorithm(), original.privateKey(), pair.getPublic(),
                jwk(pair.getPublic(), original.algorithm()), original.compact());
    }

    private static String jwk(PublicKey publicKey, String algorithm) {
        String fields;
        if (publicKey instanceof RSAPublicKey rsa) fields = "\"kty\":\"RSA\",\"n\":\"" + unsigned(rsa.getModulus())
                + "\",\"e\":\"" + unsigned(rsa.getPublicExponent()) + "\"";
        else if (publicKey instanceof ECPublicKey ec) {
            int width = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            fields = "\"kty\":\"EC\",\"crv\":\"P-" + ec.getParams().getCurve().getField().getFieldSize()
                    + "\",\"x\":\"" + coordinate(ec.getW().getAffineX(), width) + "\",\"y\":\""
                    + coordinate(ec.getW().getAffineY(), width) + "\"";
        } else fields = "\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + encode(Arrays.copyOfRange(
                publicKey.getEncoded(), publicKey.getEncoded().length - 32, publicKey.getEncoded().length)) + "\"";
        return "{" + fields + ",\"kid\":\"rc1-key\",\"alg\":\"" + algorithm + "\",\"use\":\"sig\"}";
    }

    private static String jcaSign(String algorithm, PrivateKey key, String header, String payload) throws Exception {
        String input = encode(header) + "." + encode(payload);
        String hash = algorithm.endsWith("384") ? "384" : algorithm.endsWith("512") ? "512" : "256";
        Signature signature = Signature.getInstance(algorithm.startsWith("PS") ? "RSASSA-PSS"
                : algorithm.startsWith("RS") ? "SHA" + hash + "withRSA" : algorithm.startsWith("ES")
                ? "SHA" + hash + "withECDSAinP1363Format" : "Ed25519");
        if (algorithm.startsWith("PS")) signature.setParameter(new PSSParameterSpec("SHA-" + hash, "MGF1",
                new MGF1ParameterSpec("SHA-" + hash), Integer.parseInt(hash) / 8, 1));
        signature.initSign(key); signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + encode(signature.sign());
    }
    private static String hmacWithPublicKey(Fixture f, String header, String payload) throws Exception {
        String input = encode(header) + "." + encode(payload);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(f.publicKey().getEncoded(), "HmacSHA256"));
        return input + "." + encode(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
    }
    private static String header(String algorithm) { return "{\"alg\":\"" + algorithm + "\",\"kid\":\"rc1-key\"}"; }
    private static String flip(String compact, int index) {
        String[] parts = compact.split("\\.", -1); byte[] bytes = Base64.getUrlDecoder().decode(parts[index]);
        bytes[bytes.length - 1] ^= 1; parts[index] = encode(bytes); return String.join(".", parts);
    }
    private static String coordinate(BigInteger value, int width) {
        byte[] bytes = value.toByteArray(); byte[] exact = new byte[width];
        System.arraycopy(bytes, Math.max(0, bytes.length - width), exact, Math.max(0, width - bytes.length), Math.min(width, bytes.length));
        return encode(exact);
    }
    private static String unsigned(BigInteger value) { byte[] b = value.toByteArray(); return encode(b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b); }
    private static String encode(String value) { return encode(value.getBytes(StandardCharsets.UTF_8)); }
    private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static byte[] pem(Path path) throws Exception { return Base64.getDecoder().decode(Files.readString(path)
            .replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "")); }
    private record Fixture(String id, String algorithm, PrivateKey privateKey, PublicKey publicKey, String publicJwk, String compact) {}
    private record Verdict(boolean revetsec, boolean nimbus, boolean jose4j) {}
}
