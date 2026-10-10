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

import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * An RSA private key paired with its public X.509 certificate for SAML signing or decryption.
 * The application owns key storage and rotation; Revetsec retains no mutable key provider state.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlCredential {
    private final @NonNull PrivateKey key;
    private final @NonNull X509Certificate certificate;

    private SamlCredential(@NonNull PrivateKey key, @NonNull X509Certificate certificate) {
        this.key = key;
        this.certificate = certificate;
    }

    /**
     * Pairs an RSA private key with a matching RSA certificate.
     *
     * @param key private key, at least 2048 bits
     * @param certificate certificate with the matching RSA modulus
     * @return immutable credential
     * @since 1.0.0
     */
    public static @NonNull SamlCredential fromPrivateKeyAndCertificate(@NonNull PrivateKey key,
            @NonNull X509Certificate certificate) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(certificate);
        if (!(key instanceof RSAPrivateKey privateRsa)
                || !(certificate.getPublicKey() instanceof RSAPublicKey publicRsa)
                || privateRsa.getModulus().bitLength() < 2048
                || !privateRsa.getModulus().equals(publicRsa.getModulus()))
            throw new IllegalArgumentException("Unsupported or mismatched SAML credential");
        return new SamlCredential(key, copyCertificate(certificate));
    }

    /**
     * Loads an RSA key pair from an application-owned KeyStore.
     *
     * @param store key store
     * @param alias key entry alias
     * @param password entry password
     * @return matching credential
     * @since 1.0.0
     */
    public static @NonNull SamlCredential fromKeyStore(@NonNull KeyStore store, @NonNull String alias,
            char @NonNull [] password) {
        Objects.requireNonNull(store);
        Objects.requireNonNull(alias);
        Objects.requireNonNull(password);
        try {
            Key key = store.getKey(alias, password);
            java.security.cert.Certificate certificate = store.getCertificate(alias);
            if (!(key instanceof PrivateKey privateKey) || !(certificate instanceof X509Certificate x509))
                throw new IllegalArgumentException("SAML key entry unavailable");
            return fromPrivateKeyAndCertificate(privateKey, x509);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new IllegalArgumentException("SAML key entry unavailable", exception);
        }
    }

    /**
     * Loads an unencrypted PKCS#8 or PKCS#1 RSA private key and one X.509 certificate from
     * separate PEM blocks. Invalid armor, DER, key strength or key pairing fails closed.
     *
     * @param privateKeyPem one private key PEM block
     * @param certificatePem one certificate PEM block
     * @return matching credential
     * @since 1.0.0
     */
    public static @NonNull SamlCredential fromPem(@NonNull String privateKeyPem,
            @NonNull String certificatePem) {
        Objects.requireNonNull(privateKeyPem);
        Objects.requireNonNull(certificatePem);
        try {
            return fromPrivateKeyAndCertificate(Pem.parsePrivateKey(privateKeyPem),
                    Pem.parseCertificate(certificatePem));
        } catch (PemException exception) {
            throw new IllegalArgumentException("Invalid SAML PEM credential");
        }
    }

    /**
     * Returns the certificate for SP metadata.
     *
     * @return X.509 certificate
     * @since 1.0.0
     */
    public @NonNull X509Certificate getCertificate() { return copyCertificate(certificate); }
    @NonNull PrivateKey privateKey() { return key; }

    private static @NonNull X509Certificate copyCertificate(@NonNull X509Certificate certificate) {
        try { return Pem.parseCertificateDer(certificate.getEncoded()); }
        catch (CertificateEncodingException | PemException exception) {
            throw new IllegalArgumentException("Invalid SAML certificate");
        }
    }
    /**
     * Redacts key material.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlCredential{<redacted>}"; }
}
