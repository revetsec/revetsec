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

package com.revetsec.internal.jose;

/**
 * Seeded violations: a JCA provider chosen in internal.jose (jca-provider-argument, INV-G10), by name (getInstance with
 * two and three parameters in java.security, java.security.cert, javax.crypto and XML signature; verify and getKeySpec,
 * paired with Provider overloads; SealedObject.getObject, javax.security.cert's verify and setSigProvider, which have
 * none) and as a Provider object (the last argument, a factory's middle argument, a method reference). Not
 * in controls(): getInstance without a provider or with SecureRandomParameters last, reading a JCA object's provider,
 * one-argument verify and getObject, and Strings that no same-named overload pairs with a Provider (TransformService's
 * mechanism type, a Revetsec getInstance, and a method beside a differently named one that takes a Provider).
 */
final class ProviderArgumentFixture {
	interface DigestFactory {
		java.security.MessageDigest from(String algorithm, java.security.Provider provider)
				throws java.security.GeneralSecurityException;
	}

	void seeded(java.security.Provider provider, java.security.SecureRandomParameters parameters,
			java.security.KeyStore.ProtectionParameter protection) throws java.security.GeneralSecurityException {
		java.security.Signature.getInstance("SHA256withRSA", "SunRsaSign");
		javax.crypto.Mac.getInstance("HmacSHA256", "SunJCE");
		java.security.SecureRandom.getInstance("DRBG", parameters, "SUN");
		java.security.cert.CertificateFactory.getInstance("X.509", "SUN");
		java.security.Signature.getInstance("SHA256withRSA", provider);
		java.security.KeyStore.Builder.newInstance("PKCS12", provider, protection);
		DigestFactory digests = java.security.MessageDigest::getInstance;
		javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM", "XMLDSig");
		javax.xml.crypto.dsig.TransformService.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#", "DOM", "XMLDSig");
	}

	void seededOutsideGetInstance(java.security.cert.X509Certificate certificate, java.security.cert.X509CRL crl,
			java.security.PublicKey key, javax.crypto.EncryptedPrivateKeyInfo info, javax.crypto.SealedObject sealed,
			javax.security.cert.X509Certificate legacy, java.security.cert.PKIXParameters validation) throws Exception {
		certificate.verify(key, "SunRsaSign");
		crl.verify(key, "SunRsaSign");
		info.getKeySpec(key, "SunJCE");
		sealed.getObject(key, "SunJCE");
		legacy.verify(key, "SunRsaSign");
		validation.setSigProvider("SunRsaSign");
	}

	void controls(java.security.SecureRandomParameters parameters, java.security.Signature signature,
			java.security.cert.X509Certificate certificate, java.security.PublicKey key,
			javax.crypto.SealedObject sealed, java.security.cert.PKIXParameters validation) throws Exception {
		java.security.Signature.getInstance("SHA256withRSA");
		java.security.KeyFactory.getInstance("EC");
		java.security.SecureRandom.getInstance("DRBG", parameters);
		signature.getProvider().getName();
		javax.xml.crypto.dsig.TransformService.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#", "DOM");
		getInstance("RS256", "sig");
		describe("RS256", "sig");
		certificate.verify(key);
		sealed.getObject(key);
		validation.getSigProvider();
	}

	static String getInstance(String algorithm, String use) {
		return algorithm + use;
	}

	static String describe(String algorithm, String use) {
		return algorithm + use;
	}

	static String label(String algorithm, java.security.Provider provider) {
		return algorithm + provider.getName();
	}
}
