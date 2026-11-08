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
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.XmlEncryptionDecryptor;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.Assumptions;
import org.w3c.dom.Element;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.time.*;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Shared entry/final fixture. Functional cases run in process; real-provider call counts run in one owned child. */
final class SamlDecryptionBudgetTests {
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ENC = "http://www.w3.org/2001/04/xmlenc#";
    private static final String ENC11 = "http://www.w3.org/2009/xmlenc11#";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final String SP = "https://sp.example.test/saml";
    private static final String IDP = "https://idp.example.test/saml";
    private static final TestJwk.Fixture SIGNER = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
    private static final byte[] PAYLOAD = "<a:NameID xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'>alice</a:NameID>".getBytes(StandardCharsets.UTF_8);
    @FunctionalInterface private interface Check { void run() throws Exception; }
    private record Case(@NonNull String name, @NonNull Check check) {}

    @TestFactory @NonNull Stream<@NonNull DynamicTest> functionalBudgetAndTrustBoundaries() throws Exception {
        return cases().stream().map(c -> DynamicTest.dynamicTest(c.name(), c.check()::run));
    }

    @Test void realPrivateAndContentWorkIsMeasuredInAnIsolatedJvm() throws Exception {
        ChildJvm.Result result = ChildJvm.withMainClass(WorkMain.class).timeout(Duration.ofSeconds(120)).build().run();
        assertFalse(result.isTimedOut(), result::toString);
        String output = result.getStandardOutput();
        Files.createDirectories(Path.of("target"));
        Files.writeString(Path.of("target/saml-decryption-work-probe.log"), output, StandardCharsets.UTF_8);
        boolean ignored = output.contains("PROVIDER_IGNORED");
        if (System.getProperty("java.runtime.name", "").contains("OpenJDK")) assertFalse(ignored, result::toString);
        Assumptions.assumeFalse(ignored, () -> "This runtime does not select unsigned test JCE providers: " + output);
        assertEquals(0, result.getExitCode(), result::toString);
        assertTrue(output.contains("DECRYPTION-WORK-PASS"), result::toString);
    }

    private static @NonNull List<@NonNull Case> cases() throws Exception {
        List<SamlCredential> pool = new ArrayList<>();
        for (String name : List.of("sp-encryption-rsa-2048", "sp-signing-rsa-2048", "idp-signing-rsa-2048", "negative-attacker-rsa-2048"))
            pool.add(credential(name));
        List<Case> cases = new ArrayList<>();
        for (boolean signed : List.of(false, true)) for (int candidates : List.of(1, 2, 8, 9)) for (int slots : List.of(1, 4)) {
            cases.add(new Case("direct signed=" + signed + " candidates=" + candidates + " slots=" + slots, () -> {
                String xml = encrypt(PAYLOAD, pool.get(0), candidates, false);
                List<PrivateKey> keys = pool.subList(0, slots).stream().map(SamlCredential::privateKey).toList();
                Probe.reset();
                byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), keys, signed, false, new SecureRandom());
                boolean allowed = candidates <= 8 && (signed || candidates == 1);
                try { if (allowed) assertArrayEquals(PAYLOAD, opened); else assertNull(opened); }
                finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
                Probe.expect(allowed ? candidates * slots : 0, allowed ? candidates * slots : 0);
            }));
        }
        for (int position = 0; position < 4; position++) {
            int selected = position;
            cases.add(new Case("rollover key position " + position, () -> {
                List<SamlCredential> ordered = new ArrayList<>(pool); Collections.swap(ordered, 0, selected);
                String xml = encrypt(PAYLOAD, pool.get(0), 1, false);
                WipingRandom random = new WipingRandom(); Probe.reset();
                byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), ordered.stream().map(SamlCredential::privateKey).toList(),
                        false, false, random);
                try { assertArrayEquals(PAYLOAD, opened); assertEquals(3, random.keys.size(), "do not stop after the first success"); }
                finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
                random.assertWiped(); Probe.expect(4, 4);
            }));
        }
        cases.add(new Case("one selected retrieval among eight siblings", () -> {
            String xml = referenced(encrypt(PAYLOAD, pool.get(0), 1, false), 8);
            Probe.reset(); byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), keys(pool), false, false, new SecureRandom());
            try { assertArrayEquals(PAYLOAD, opened); } finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
            Probe.expect(4, 4);
        }));
        cases.add(new Case("recipient and KeyName are not credential-selection authority", () -> {
            List<SamlCredential> ordered = new ArrayList<>(pool); Collections.swap(ordered, 0, 3);
            String xml = encrypt(PAYLOAD, pool.get(0), 1, false).replace("<xenc:EncryptedKey>",
                    "<xenc:EncryptedKey Recipient='PRIVATE-untrusted-recipient'><ds:KeyInfo><ds:KeyName>first-local-key</ds:KeyName></ds:KeyInfo>");
            Probe.reset(); byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), keys(ordered), false, false, new SecureRandom());
            try { assertArrayEquals(PAYLOAD, opened); } finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
            Probe.expect(4, 4);
        }));
        cases.add(new Case("changing carrier tag cannot authorize pre-proof fanout", () -> {
            String xml = encrypt(PAYLOAD, pool.get(0), 8, false).replace("EncryptedAssertion", "EncryptedID");
            Probe.reset(); byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), keys(pool), false, false, new SecureRandom());
            try { assertNull(opened); } finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
            Probe.expect(0, 0);
        }));
        for (boolean cbc : List.of(false, true)) cases.add(new Case("failed unwrap cannot select matching substitute plaintext cbc=" + cbc, () -> {
            byte[] cek = new byte[16]; Arrays.fill(cek, (byte) 0x5a);
            String xml = encryptWithCek(PAYLOAD, pool.get(0), 1, cbc, cek); Arrays.fill(cek, (byte) 0);
            WipingRandom random = new WipingRandom(); Probe.reset();
            byte[] opened = XmlEncryptionDecryptor.decrypt(element(xml), Collections.nCopies(4, pool.get(1).privateKey()), cbc, cbc, random);
            try { assertNull(opened, "even authenticated content under a substitute key must not escape"); }
            finally { if (opened != null) Arrays.fill(opened, (byte) 0); }
            assertEquals(4, random.keys.size()); random.assertWiped(); Probe.expect(4, 4);
        }));
        for (boolean solicited : List.of(false, true)) for (int count : List.of(1, 2, 8)) {
            cases.add(new Case("public unsigned encrypted assertion candidates=" + count + " solicited=" + solicited, () ->
                    publicCase(pool, solicited, true, count, 0, false, true, false, false, "none",
                            count == 1, count == 1 ? null : SamlAuthenticationResult.Reason.DECRYPTION, count == 1 ? 4 : 0)));
        }
        cases.add(new Case("verified outer Response permits eight candidates", () ->
                publicCase(pool, false, true, 8, 0, true, false, false, false, "none", true, null, 32)));
        cases.add(new Case("forged outer Response never authorizes decryption", () ->
                publicCase(pool, false, true, 8, 0, true, true, false, false, "outer-signature", false,
                        SamlAuthenticationResult.Reason.SIGNATURE, 0)));
        for (String fault : List.of("no-inner-signature", "inner-signature", "gcm-tag", "wrapped-key", "plaintext", "key-method")) {
            cases.add(new Case("public opaque/layered failure " + fault, () -> publicCase(pool, false, true, 1, 0, false,
                    !fault.equals("no-inner-signature"), false, false, fault, false,
                    fault.endsWith("signature") ? SamlAuthenticationResult.Reason.SIGNATURE : SamlAuthenticationResult.Reason.DECRYPTION,
                    fault.equals("key-method") ? 0 : 4)));
        }
        for (int count : List.of(1, 8)) cases.add(new Case("verified Assertion permits encrypted ID candidates=" + count, () ->
                publicCase(pool, false, false, 0, count, false, true, false, false, "none", true, null, count * 4)));
        cases.add(new Case("unsigned Assertion does no encrypted ID work", () ->
                publicCase(pool, false, false, 0, 8, false, false, false, false, "none", false,
                        SamlAuthenticationResult.Reason.SIGNATURE, 0)));
        cases.add(new Case("invalid Assertion signature does no encrypted ID work", () ->
                publicCase(pool, false, false, 0, 8, false, true, false, false, "inner-signature", false,
                        SamlAuthenticationResult.Reason.SIGNATURE, 0)));
        cases.add(new Case("assertion proof does not relax outer-signature CBC rule", () ->
                publicCase(pool, false, false, 0, 8, false, true, true, true, "none", false,
                        SamlAuthenticationResult.Reason.DECRYPTION, 0)));
        cases.add(new Case("CBC remains explicit opt-in even after outer proof", () ->
                publicCase(pool, false, false, 0, 8, true, true, true, false, "none", false,
                        SamlAuthenticationResult.Reason.DECRYPTION, 0)));
        cases.add(new Case("signed opted-in CBC retains eight-candidate ID support", () ->
                publicCase(pool, false, false, 0, 8, true, true, true, true, "none", true, null, 32)));
        cases.add(new Case("encrypted assertion establishes proof before wide encrypted ID", () ->
                publicCase(pool, false, true, 1, 8, false, true, false, false, "none", true, null, 36)));
        cases.add(new Case("verified outer Response retains bounded two-layer work", () ->
                publicCase(pool, false, true, 8, 8, true, true, false, false, "none", true, null, 64)));
        cases.add(new Case("wide outer cipher cannot bootstrap a trusted inner budget", () ->
                publicCase(pool, false, true, 8, 8, false, true, false, false, "none", false,
                        SamlAuthenticationResult.Reason.DECRYPTION, 0)));
        cases.add(new Case("CBC outer cipher requires a verified outer Response", () ->
                publicCase(pool, false, true, 1, 0, false, true, true, true, "none", false,
                        SamlAuthenticationResult.Reason.DECRYPTION, 0)));
        return cases;
    }

    private static void publicCase(@NonNull List<@NonNull SamlCredential> credentials, boolean solicited, boolean encryptedAssertion, int assertionKeys,
            int idKeys, boolean outerSigned, boolean innerSigned, boolean cbc, boolean allowCbc, @NonNull String fault,
            boolean succeeds, SamlAuthenticationResult.@Nullable Reason rejection, int work) throws Exception {
        int[] replay = {0}; List<SamlObserver.Outcome> events = new ArrayList<>();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .decryptionCredentials(credentials).clock(CLOCK).replayCache((key, end, remaining) -> { replay[0]++; return SamlReplayCache.MarkResult.MARKED; })
                .observer(new SamlObserver() {
                    @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome, @NonNull Duration elapsed) { events.add(outcome); }
                }).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("budget-connection")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(SIGNER.getPublicKey())).allowUnsolicitedResponses(true).allowAesCbcEncryption(allowCbc).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("decrypt-budget")).clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(pending.toSealedForm(sealer, "decrypt-budget"), sealer, "decrypt-budget");
        String xml = SamlResponseSemanticsTests.BASE.replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("<a:Assertion ", "<a:Assertion xmlns:a='" + A + "' xmlns:p='" + P + "' ");
        xml = solicited ? xml.replace("_request", pending.getRequestId()) : xml.replace(" InResponseTo='_request'", "");
        if (idKeys > 0) xml = xml.replace("<a:NameID>alice</a:NameID>",
                encrypt(PAYLOAD, credentials.get(0), idKeys, cbc).replace("EncryptedAssertion", "EncryptedID"));
        if (encryptedAssertion) {
            int start = xml.indexOf("<a:Assertion"); int end = xml.indexOf("</a:Assertion>") + "</a:Assertion>".length();
            // Sign the standalone assertion before encrypting it, retaining its namespace bindings.
            String content = xml.substring(start, end);
            if (innerSigned) content = SamlResponseSemanticsTests.signedXml(content, true, false,
                    fault.equals("inner-signature") ? credentials.get(1).privateKey() : SIGNER.getKeyPair().getPrivate());
            if (fault.equals("plaintext")) content = "not-an-assertion";
            String cipher = encrypt(content.getBytes(StandardCharsets.UTF_8), credentials.get(0), assertionKeys, cbc);
            if (fault.equals("gcm-tag")) cipher = damage(cipher, false);
            if (fault.equals("wrapped-key")) cipher = damage(cipher, true);
            if (fault.equals("key-method")) cipher = cipher.replace(ENC11 + "rsa-oaep", ENC + "rsa-1_5");
            xml = xml.substring(0, start) + cipher + xml.substring(end);
        } else if (innerSigned) xml = SamlResponseSemanticsTests.signedXml(xml, false, true,
                fault.equals("inner-signature") ? credentials.get(1).privateKey() : SIGNER.getKeyPair().getPrivate());
        if (outerSigned) xml = SamlResponseSemanticsTests.signedXml(xml, true, false,
                fault.equals("outer-signature") ? credentials.get(1).privateKey() : SIGNER.getKeyPair().getPrivate());
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8)).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        String form = "SAMLResponse=" + encoded + (solicited ? "&RelayState=" + pending.getRelayStateHandle() : "");
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null)).getMessage();
        events.clear(); Probe.reset();
        SamlAuthenticationResult result = solicited ? sp.completeAuthenticationResult(message, source, idp)
                : sp.completeUnsolicitedAuthenticationResult(message, idp);
        if (succeeds) {
            SamlAuthentication identity = assertInstanceOf(SamlAuthenticationResult.Succeeded.class, result).getAuthentication();
            assertEquals("alice", identity.getNameId().orElseThrow().getValue()); assertEquals(1, replay[0]);
            assertEquals(List.of(SamlObserver.Outcome.SUCCEEDED), events);
        } else {
            assertEquals(rejection, assertInstanceOf(SamlAuthenticationResult.Rejected.class, result).getReason()); assertEquals(0, replay[0]);
            assertEquals(List.of(SamlObserver.Outcome.REJECTED), events); assertFalse(result.toString().contains("PRIVATE"));
        }
        Probe.expect(work, work);
    }

    private static @NonNull List<@NonNull PrivateKey> keys(@NonNull List<@NonNull SamlCredential> credentials) { return credentials.stream().map(SamlCredential::privateKey).toList(); }
    private static @NonNull SamlCredential credential(@NonNull String stem) throws Exception {
        String key; String certificate;
        try (var input = SamlDecryptionBudgetTests.class.getResourceAsStream("/fixtures/keys/" + stem + "-key.pem")) {
            key = new String(Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        try (var input = SamlDecryptionBudgetTests.class.getResourceAsStream("/fixtures/keys/" + stem + "-cert.pem")) {
            certificate = new String(Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        return SamlCredential.fromPem(key, certificate);
    }
    private static @NonNull Element element(@NonNull String xml) {
        return assertInstanceOf(SecureXmlParser.Result.Accepted.class, SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocument().getDocumentElement();
    }
    private static @NonNull String encrypt(byte @NonNull [] plaintext, @NonNull SamlCredential recipient, int candidates, boolean cbc) throws Exception {
        byte[] cek = new byte[16]; new SecureRandom().nextBytes(cek);
        try { return encryptWithCek(plaintext, recipient, candidates, cbc, cek); } finally { Arrays.fill(cek, (byte) 0); }
    }
    private static @NonNull String encryptWithCek(byte @NonNull [] plaintext, @NonNull SamlCredential recipient, int candidates, boolean cbc, byte @NonNull [] cek) throws Exception {
        SecureRandom random = new SecureRandom(); byte[] iv = new byte[cbc ? 16 : 12]; random.nextBytes(iv);
        Cipher aes = Cipher.getInstance(cbc ? "AES/CBC/NoPadding" : "AES/GCM/NoPadding");
        byte[] input = plaintext;
        if (cbc) {
            int padding = 16 - plaintext.length % 16; input = new byte[plaintext.length + padding]; random.nextBytes(input);
            System.arraycopy(plaintext, 0, input, 0, plaintext.length); input[input.length - 1] = (byte) padding;
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new IvParameterSpec(iv));
        } else aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
        byte[] encrypted = aes.doFinal(input); if (cbc) Arrays.fill(input, (byte) 0);
        byte[] wire = new byte[iv.length + encrypted.length]; System.arraycopy(iv, 0, wire, 0, iv.length); System.arraycopy(encrypted, 0, wire, iv.length, encrypted.length);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding"); rsa.init(Cipher.ENCRYPT_MODE, recipient.getCertificate().getPublicKey(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] wrapped = rsa.doFinal(cek);
        String key = "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm='" + ENC11 + "rsa-oaep'><ds:DigestMethod Algorithm='" + ENC
                + "sha256'/><xenc11:MGF Algorithm='" + ENC11 + "mgf1sha256'/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>"
                + Base64.getEncoder().encodeToString(wrapped) + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>";
        return "<a:EncryptedAssertion xmlns:a='" + A + "' xmlns:xenc='" + ENC + "' xmlns:xenc11='" + ENC11 + "' xmlns:ds='" + DS + "'>"
                + "<xenc:EncryptedData Type='" + ENC + "Element'><xenc:EncryptionMethod Algorithm='" + (cbc ? ENC + "aes128-cbc" : ENC11 + "aes128-gcm")
                + "'/><ds:KeyInfo>" + key.repeat(candidates) + "</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>"
                + Base64.getEncoder().encodeToString(wire) + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></a:EncryptedAssertion>";
    }
    private static @NonNull String referenced(@NonNull String xml, int count) {
        int start = xml.indexOf("<xenc:EncryptedKey>"); int end = xml.indexOf("</xenc:EncryptedKey>", start) + "</xenc:EncryptedKey>".length();
        String key = xml.substring(start, end); StringBuilder siblings = new StringBuilder();
        for (int i = 0; i < count; i++) siblings.append(key.replace("<xenc:EncryptedKey>", "<xenc:EncryptedKey Id='_selected_" + i + "'>"));
        return xml.replace("<ds:KeyInfo>" + key + "</ds:KeyInfo>", "<ds:KeyInfo><ds:RetrievalMethod Type='" + ENC
                + "EncryptedKey' URI='#_selected_" + (count - 1) + "'/></ds:KeyInfo>")
                .replace("</a:EncryptedAssertion>", siblings + "</a:EncryptedAssertion>");
    }
    private static @NonNull String damage(@NonNull String xml, boolean wrapped) {
        String tag = "<xenc:CipherValue>"; int start = (wrapped ? xml.indexOf(tag) : xml.lastIndexOf(tag)) + tag.length();
        int end = xml.indexOf("</xenc:CipherValue>", start); byte[] bytes = Base64.getDecoder().decode(xml.substring(start, end)); bytes[bytes.length - 1] ^= 1;
        return xml.substring(0, start) + Base64.getEncoder().encodeToString(bytes) + xml.substring(end);
    }
    private static final class WipingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        final List<byte[]> keys = new ArrayList<>();
        @Override public void nextBytes(byte @NonNull [] bytes) { Arrays.fill(bytes, (byte) 0x5a); keys.add(bytes); }
        void assertWiped() { for (byte[] bytes : keys) assertArrayEquals(new byte[bytes.length], bytes); }
    }

    /** JCA/JCE state is changed only in this owned child JVM. Every cipher delegates to its original real provider. */
    public static final class WorkMain {
        public static void main(@NonNull String @NonNull [] args) throws Exception {
            for (String transformation : List.of("RSA/ECB/OAEPPadding", "AES/GCM/NoPadding", "AES/CBC/NoPadding"))
                Probe.original.put(transformation, Cipher.getInstance(transformation).getProvider().getName());
            Security.insertProviderAt(new WorkProvider(), 1);
            for (String transformation : Probe.original.keySet()) {
                if (!Cipher.getInstance(transformation).getProvider().getName().equals("RevetsecSamlWorkProbe")) {
                    System.out.println("PROVIDER_IGNORED " + transformation); return;
                }
            }
            Probe.active = true; int failures = 0;
            for (Case c : cases()) {
                try { c.check().run(); System.out.println("PASS " + c.name()); }
                catch (AssertionError failure) { failures++; System.out.println("FAIL " + c.name() + ": " + String.valueOf(failure.getMessage()).substring(0, Math.min(160, String.valueOf(failure.getMessage()).length()))); }
                finally { System.out.println("WORK " + c.name() + " rsa=" + Probe.rsa + " content=" + Probe.content); }
            }
            if (failures != 0) throw new AssertionError("work cases failed: " + failures);
            System.out.println("DECRYPTION-WORK-PASS");
        }
    }
    public static final class WorkProvider extends Provider {
        private static final long serialVersionUID = 1L;
        public WorkProvider() {
            super("RevetsecSamlWorkProbe", "1", "Owned real-cipher work counter");
            putService(new Service(this, "Cipher", "RSA/ECB/OAEPPadding", Rsa.class.getName(), List.of(), Map.of()));
            putService(new Service(this, "Cipher", "AES/GCM/NoPadding", Gcm.class.getName(), List.of(), Map.of()));
            putService(new Service(this, "Cipher", "AES/CBC/NoPadding", Cbc.class.getName(), List.of(), Map.of()));
        }
    }
    private static final class Probe {
        static final Map<String,String> original = new HashMap<>();
        static final List<byte[]> returned = new ArrayList<>();
        static boolean active;
        static int rsa;
        static int content;
        static void reset() { returned.clear(); rsa = 0; content = 0; }
        static void expect(int unwraps, int contents) {
            if (!active) return;
            assertEquals(unwraps, rsa, "real RSA-OAEP doFinal attempts"); assertEquals(contents, content, "real XML content doFinal attempts");
            for (byte[] bytes : returned) assertArrayEquals(new byte[bytes.length], bytes, "CEKs and plaintext arrays must be wiped after use");
        }
    }
    public static final class Rsa extends CountingCipher { public Rsa() throws GeneralSecurityException { super("RSA/ECB/OAEPPadding"); } }
    public static final class Gcm extends CountingCipher { public Gcm() throws GeneralSecurityException { super("AES/GCM/NoPadding"); } }
    public static final class Cbc extends CountingCipher { public Cbc() throws GeneralSecurityException { super("AES/CBC/NoPadding"); } }
    public abstract static class CountingCipher extends CipherSpi {
        private final Cipher delegate;
        private final boolean rsa;
        private int operation;
        private boolean aad;
        CountingCipher(@NonNull String transformation) throws GeneralSecurityException {
            rsa = transformation.startsWith("RSA/"); delegate = Cipher.getInstance(transformation, Objects.requireNonNull(Probe.original.get(transformation)));
        }
        @Override protected void engineSetMode(@NonNull String mode) { }
        @Override protected void engineSetPadding(@NonNull String padding) { }
        @Override protected int engineGetBlockSize() { return delegate.getBlockSize(); }
        @Override protected int engineGetOutputSize(int length) { return delegate.getOutputSize(length); }
        @Override protected byte @Nullable [] engineGetIV() { return delegate.getIV(); }
        @Override protected @Nullable AlgorithmParameters engineGetParameters() { return delegate.getParameters(); }
        @Override protected void engineInit(int mode, @NonNull Key key, @Nullable SecureRandom random) throws InvalidKeyException { operation = mode; aad = false; delegate.init(mode, key, random); }
        @Override protected void engineInit(int mode, @NonNull Key key, @Nullable AlgorithmParameterSpec params, @Nullable SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { operation = mode; aad = false; delegate.init(mode, key, params, random); }
        @Override protected void engineInit(int mode, @NonNull Key key, @Nullable AlgorithmParameters params, @Nullable SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { operation = mode; aad = false; delegate.init(mode, key, params, random); }
        @Override protected byte @Nullable [] engineUpdate(byte @NonNull [] input, int offset, int length) { return delegate.update(input, offset, length); }
        @Override protected int engineUpdate(byte @NonNull [] input, int offset, int length, byte @NonNull [] output, int outputOffset) throws ShortBufferException { return delegate.update(input, offset, length, output, outputOffset); }
        private boolean measured() { return operation == Cipher.DECRYPT_MODE && (rsa || !aad); }
        private void count() { if (measured()) { if (rsa) Probe.rsa++; else Probe.content++; } }
        @Override protected byte @NonNull [] engineDoFinal(byte @NonNull [] input, int offset, int length) throws IllegalBlockSizeException, BadPaddingException {
            count(); byte[] result = delegate.doFinal(input, offset, length); if (measured()) Probe.returned.add(result); return result;
        }
        @Override protected int engineDoFinal(byte @NonNull [] input, int offset, int length, byte @NonNull [] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            count(); return delegate.doFinal(input, offset, length, output, outputOffset);
        }
        @Override protected void engineUpdateAAD(byte @NonNull [] bytes, int offset, int length) { aad = true; delegate.updateAAD(bytes, offset, length); }
        @Override protected void engineUpdateAAD(@NonNull ByteBuffer bytes) { aad = true; delegate.updateAAD(bytes); }
    }
}
