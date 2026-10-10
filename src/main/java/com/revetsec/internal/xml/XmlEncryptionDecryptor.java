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
package com.revetsec.internal.xml;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Narrow XML Encryption decrypt-only boundary for SAML EncryptedAssertion and EncryptedID. Every failure is
 * opaque. The caller verifies a signed Response before permitting CBC and verifies the decrypted
 * Assertion before releasing identity.
 */
public final class XmlEncryptionDecryptor {
    private static final String ENC = "http://www.w3.org/2001/04/xmlenc#";
    private static final String ENC11 = "http://www.w3.org/2009/xmlenc11#";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SHA256 = ENC + "sha256";
    private static final String SHA1 = DS + "sha1";
    private static final String MGF_SHA256 = ENC11 + "mgf1sha256";
    private static final String MGF_SHA1 = ENC11 + "mgf1sha1";

    private XmlEncryptionDecryptor() { }

    /**
     * Returns plaintext bytes or null for every unsupported, malformed or failed decryption.
     * A returned value is still untrusted XML and must be parsed, shaped and signature checked.
     */
    public static byte @Nullable [] decrypt(@NonNull Element encryptedAssertion,
            @NonNull List<@NonNull PrivateKey> privateKeys, boolean responseSigned, boolean allowCbc,
            @NonNull SecureRandom random) {
        Objects.requireNonNull(encryptedAssertion);
        Objects.requireNonNull(privateKeys);
        Objects.requireNonNull(random);
        if (privateKeys.isEmpty() || privateKeys.size() > 4
                || !"urn:oasis:names:tc:SAML:2.0:assertion".equals(encryptedAssertion.getNamespaceURI())
                || !("EncryptedAssertion".equals(encryptedAssertion.getLocalName())
                    || "EncryptedID".equals(encryptedAssertion.getLocalName()))) return null;
        Element data = unique(encryptedAssertion, ENC, "EncryptedData");
        if (data == null || !"http://www.w3.org/2001/04/xmlenc#Element"
                .equals(data.getAttributeNS(null, "Type"))) return null;
        Element dataMethod = unique(data, ENC, "EncryptionMethod");
        Element dataCipher = cipherValue(data);
        if (dataMethod == null || dataCipher == null) return null;
        int bits = switch (dataMethod.getAttributeNS(null, "Algorithm")) {
            case ENC11 + "aes128-gcm", ENC + "aes128-cbc" -> 128;
            case ENC11 + "aes192-gcm", ENC + "aes192-cbc" -> 192;
            case ENC11 + "aes256-gcm", ENC + "aes256-cbc" -> 256;
            default -> 0;
        };
        String algorithm = dataMethod.getAttributeNS(null, "Algorithm");
        boolean gcm = algorithm.endsWith("-gcm");
        if (bits == 0 || (!gcm && (!responseSigned || !allowCbc))) return null;
        byte[] encrypted = decoded(dataCipher, 131072);
        if (encrypted == null || encrypted.length < (gcm ? 28 : 32)) return null;
        List<Element> wrappedKeys = keyCandidates(data, encryptedAssertion);
        if (wrappedKeys == null || wrappedKeys.isEmpty() || wrappedKeys.size() > 8) return null;
        byte[] accepted = null;
        for (Element wrapped : wrappedKeys) {
            KeyMethod keyMethod = keyMethod(wrapped);
            Element wrappedValue = cipherValue(wrapped);
            if (keyMethod == null || wrappedValue == null) continue;
            byte[] ciphertext = decoded(wrappedValue, 8192);
            if (ciphertext == null) continue;
            for (PrivateKey privateKey : privateKeys) {
                byte[] cek = null;
                try {
                    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsa.init(Cipher.DECRYPT_MODE, privateKey, keyMethod.parameters());
                    cek = rsa.doFinal(ciphertext);
                } catch (GeneralSecurityException | RuntimeException exception) {
                    // Follow the content-decryption path with an unpredictable substitute CEK.
                    cek = new byte[bits / 8];
                    random.nextBytes(cek);
                }
                try {
                    if (cek.length != bits / 8) continue;
                    Cipher aes = Cipher.getInstance(gcm ? "AES/GCM/NoPadding" : "AES/CBC/NoPadding");
                    int ivLength = gcm ? 12 : 16;
                    if (gcm) aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"),
                            new GCMParameterSpec(128, encrypted, 0, ivLength));
                    else aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"),
                            new IvParameterSpec(encrypted, 0, ivLength));
                    if (!gcm && (encrypted.length - ivLength) % 16 != 0) continue;
                    byte[] plaintext = aes.doFinal(encrypted, ivLength, encrypted.length - ivLength);
                    if (!gcm) {
                        // XML Encryption CBC uses random padding, with only the final octet
                        // carrying its length. It is not PKCS#5/#7 repeated-byte padding.
                        int paddingLength = plaintext[plaintext.length - 1] & 255;
                        if (paddingLength < 1 || paddingLength > 16
                                || paddingLength > plaintext.length) {
                            Arrays.fill(plaintext, (byte) 0);
                            continue;
                        }
                        byte[] unpadded = Arrays.copyOf(plaintext, plaintext.length - paddingLength);
                        Arrays.fill(plaintext, (byte) 0);
                        plaintext = unpadded;
                    }
                    if (accepted == null) accepted = plaintext;
                    else Arrays.fill(plaintext, (byte) 0);
                } catch (GeneralSecurityException | RuntimeException exception) {
                    // The public outcome is identical for unwrap and content failures.
                } finally { Arrays.fill(cek, (byte) 0); }
            }
            Arrays.fill(ciphertext, (byte) 0);
        }
        Arrays.fill(encrypted, (byte) 0);
        return accepted;
    }

    private static @Nullable KeyMethod keyMethod(@NonNull Element wrapped) {
        Element method = unique(wrapped, ENC, "EncryptionMethod");
        if (method == null) return null;
        String algorithm = method.getAttributeNS(null, "Algorithm");
        if (!algorithm.equals(ENC + "rsa-oaep-mgf1p") && !algorithm.equals(ENC11 + "rsa-oaep"))
            return null;
        Element digest = unique(method, DS, "DigestMethod");
        String hash = digest == null ? "SHA-1" : switch (digest.getAttributeNS(null, "Algorithm")) {
            case SHA1 -> "SHA-1";
            case SHA256 -> "SHA-256";
            default -> "";
        };
        if (hash.isEmpty()) return null;
        Element mgf = unique(method, ENC11, "MGF");
        String mgfHash = mgf == null ? "SHA-1" : switch (mgf.getAttributeNS(null, "Algorithm")) {
            case MGF_SHA1 -> "SHA-1";
            case MGF_SHA256 -> "SHA-256";
            default -> "";
        };
        if (mgfHash.isEmpty() || (algorithm.equals(ENC + "rsa-oaep-mgf1p") && mgf != null))
            return null;
        Element params = unique(method, ENC, "OAEPparams");
        byte[] label = params == null ? new byte[0] : decoded(params, 1024);
        if (label == null || label.length != 0) return null;
        OAEPParameterSpec spec = new OAEPParameterSpec(hash, "MGF1",
                "SHA-256".equals(mgfHash) ? MGF1ParameterSpec.SHA256 : MGF1ParameterSpec.SHA1,
                new PSource.PSpecified(label));
        return new KeyMethod(spec);
    }

    private static @Nullable List<@NonNull Element> keyCandidates(@NonNull Element data,
            @NonNull Element wrapper) {
        List<Element> inline = new ArrayList<>();
        List<Element> siblings = new ArrayList<>();
        List<String> references = new ArrayList<>();
        if (!readKeyInfo(data, inline, references) || !readKeyInfo(wrapper, inline, references))
            return null;
        for (Node child = wrapper.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element && is(element, ENC, "EncryptedKey")) siblings.add(element);
        if (inline.size() + siblings.size() > 8 || references.size() > 8) return null;
        if (references.isEmpty()) {
            inline.addAll(siblings);
            return inline;
        }
        for (String reference : references) {
            Element target = null;
            for (Element sibling : siblings)
                if (reference.equals(sibling.getAttributeNS(null, "Id"))) {
                    if (target != null) return null;
                    target = sibling;
                }
            if (target == null) return null;
            if (!inline.contains(target)) inline.add(target);
        }
        return inline;
    }

    private static boolean readKeyInfo(@NonNull Element parent,
            @NonNull List<@NonNull Element> inline, @NonNull List<@NonNull String> references) {
        Element info = unique(parent, DS, "KeyInfo");
        if (info == null) return true;
        for (Node child = info.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (is(element, ENC, "EncryptedKey")) inline.add(element);
            else if (is(element, DS, "RetrievalMethod")) {
                String uri = element.getAttributeNS(null, "URI");
                String type = element.getAttributeNS(null, "Type");
                if (!type.equals(ENC + "EncryptedKey") || uri.length() < 2 || uri.length() > 257
                        || uri.charAt(0) != '#' || element.hasChildNodes()) return false;
                references.add(uri.substring(1));
            } else return false;
        }
        return true;
    }

    private static @Nullable Element cipherValue(@NonNull Element parent) {
        Element data = unique(parent, ENC, "CipherData");
        return data == null ? null : unique(data, ENC, "CipherValue");
    }

    private static byte @Nullable [] decoded(@NonNull Element element, int maximum) {
        StringBuilder text = new StringBuilder();
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.TEXT_NODE) return null;
            text.append(child.getNodeValue());
            if (text.length() > 4 * maximum / 3 + 16) return null;
        }
        String base64 = text.toString().replaceAll("[ \\t\\r\\n]", "");
        try {
            byte[] value = Base64.getDecoder().decode(base64);
            return value.length <= maximum ? value : null;
        } catch (IllegalArgumentException exception) { return null; }
    }

    private static @Nullable Element unique(@NonNull Element parent, @NonNull String namespace,
            @NonNull String local) {
        Element match = null;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && is(element, namespace, local)) {
                if (match != null) return null;
                match = element;
            }
        }
        return match;
    }

    private static boolean is(@NonNull Element value, @NonNull String namespace, @NonNull String local) {
        return namespace.equals(value.getNamespaceURI()) && local.equals(value.getLocalName());
    }

    private record KeyMethod(@NonNull OAEPParameterSpec parameters) { }
}
