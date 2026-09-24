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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * M0 spike cross-check for the scripted IdP.
 * <p>
 * Re-checks every selftest output with only the JDK: XMLDSig signatures through {@code javax.xml.crypto} with secure
 * validation on, and XML Encryption by hand with JCA ({@code RSA/ECB/OAEPPadding} with an explicit
 * {@link OAEPParameterSpec}, or {@code RSA/ECB/PKCS1Padding}, then {@code AES/GCM/NoPadding}). Throwaway code: it is
 * not RevetSec's verifier and shares nothing with it.
 * <p>
 * Run: {@code java spike/Crosscheck.java <selftest-output-dir>}
 */
public final class Crosscheck {
	private static final String SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
	private static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
	private static final String DS = XMLSignature.XMLNS;
	private static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
	private static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";

	private static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	private static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
	private static final String ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
	private static final String ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
	private static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	private static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	private static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
	private static final String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
	private static final String AES256_GCM = XENC11 + "aes256-gcm";
	private static final String RSA_OAEP_11 = XENC11 + "rsa-oaep";
	private static final String RSA_1_5 = XENC + "rsa-1_5";
	private static final String MGF1_SHA256 = XENC11 + "mgf1sha256";

	private final Path dir;
	private final X509Certificate idpRsa;
	private final PrivateKey spKey;

	private Crosscheck(Path dir) throws Exception {
		this.dir = dir;
		this.idpRsa = certificate("idp-rsa-2048");
		this.spKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pem(dir.resolve("keys/sp-rsa-2048.key"))));
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.err.println("usage: java spike/Crosscheck.java <selftest-output-dir>");
			System.exit(2);
		}

		Crosscheck crosscheck = new Crosscheck(Path.of(args[0]));
		Map<String, Callable<String>> cases = new LinkedHashMap<>();
		cases.put("case1", crosscheck::case1);
		cases.put("case2", crosscheck::case2);
		cases.put("case3", crosscheck::case3);
		cases.put("case4", crosscheck::case4);
		cases.put("case5", crosscheck::case5);
		cases.put("case6", crosscheck::case6);
		cases.put("signxml_smoke", crosscheck::signxmlSmoke);

		System.out.printf("JDK %s (%s)%n", System.getProperty("java.runtime.version"), System.getProperty("java.vendor"));
		int failures = 0;

		for (Map.Entry<String, Callable<String>> entry : cases.entrySet()) {
			try {
				System.out.printf("PASS %s: %s%n", entry.getKey(), entry.getValue().call());
			} catch (Exception e) {
				failures++;
				System.out.printf("FAIL %s: %s%n", entry.getKey(), e);
			}
		}

		System.exit(failures == 0 ? 0 : 1);
	}

	private String case1() throws Exception {
		Document document = document("case1-response-assertion-rsa-sha256.xml");
		Element response = document.getDocumentElement();
		verify(response, idpRsa, RSA_SHA256, SHA256, true);
		verify(child(response, SAML, "Assertion"), idpRsa, RSA_SHA256, SHA256, true);
		return "Response and Assertion signatures valid (secure validation on)";
	}

	private String case2() throws Exception {
		Element assertion = child(document("case2-assertion-rsa-sha1.xml").getDocumentElement(), SAML, "Assertion");
		String secure;

		try {
			verify(assertion, idpRsa, RSA_SHA1, SHA1, true);
			secure = "secure validation accepted RSA-SHA1";
		} catch (MarshalException | XMLSignatureException e) {
			secure = "secure validation rejected it as expected (" + e.getMessage() + ")";
		}

		verify(assertion, idpRsa, RSA_SHA1, SHA1, false);
		return "RSA-SHA1 signature valid with secure validation off; " + secure;
	}

	private String case3() throws Exception {
		List<String> details = new ArrayList<>();
		String[][] variants = {{"256", ECDSA_SHA256, SHA256}, {"384", ECDSA_SHA384, SHA384}, {"521", ECDSA_SHA512, SHA512}};

		for (String[] variant : variants) {
			int bits = Integer.parseInt(variant[0]);
			Element response = document("case3-assertion-ecdsa-p" + bits + ".xml").getDocumentElement();
			byte[] value = verify(child(response, SAML, "Assertion"), certificate("idp-ec-p" + bits), variant[1], variant[2], true);
			int expected = 2 * ((bits + 7) / 8);
			check(value.length == expected, "P-" + bits + " SignatureValue is " + value.length + " bytes, not r||s of " + expected);
			details.add("P-" + bits + " r||s " + value.length + " bytes");
		}

		return "valid (secure validation on): " + String.join(", ", details);
	}

	private String case4() throws Exception {
		return encryptedAssertion("case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256.xml", RSA_OAEP_11, "_a4")
				+ " (OAEP SHA-256/MGF1-SHA256; default SHA-1 OAEP params rejected)";
	}

	private String case5() throws Exception {
		return encryptedAssertion("case5-encrypted-assertion-gcm-rsa-1_5.xml", RSA_1_5, "_a5") + " (PKCS#1 v1.5)";
	}

	private String case6() throws Exception {
		Element assertion = child(document("case6-encrypted-id-gcm-rsa-oaep-sha256-mgf1sha256.xml").getDocumentElement(), SAML, "Assertion");
		verify(assertion, idpRsa, RSA_SHA256, SHA256, true);
		Element encryptedId = child(child(assertion, SAML, "Subject"), SAML, "EncryptedID");
		Element nameId = parse(decrypt(child(encryptedId, XENC, "EncryptedData"), RSA_OAEP_11)).getDocumentElement();
		check(SAML.equals(nameId.getNamespaceURI()) && "NameID".equals(nameId.getLocalName()), "plaintext is not a saml:NameID");
		check("user-6".equals(nameId.getTextContent()), "unexpected NameID value " + nameId.getTextContent());
		return "Assertion signature valid; EncryptedID decrypted to a standalone saml:NameID";
	}

	private String signxmlSmoke() throws Exception {
		Element response = document("extra-signxml-assertion-rsa-sha256.xml").getDocumentElement();
		verify(child(response, SAML, "Assertion"), idpRsa, RSA_SHA256, SHA256, true);
		return "signxml Assertion signature valid (secure validation on)";
	}

	private String encryptedAssertion(String file, String keyTransport, String assertionId) throws Exception {
		Element encryptedAssertion = child(document(file).getDocumentElement(), SAML, "EncryptedAssertion");
		Document plaintext = parse(decrypt(child(encryptedAssertion, XENC, "EncryptedData"), keyTransport));
		Element assertion = plaintext.getDocumentElement();
		check(SAML.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()), "plaintext is not a saml:Assertion");
		check(assertionId.equals(assertion.getAttribute("ID")), "unexpected Assertion ID " + assertion.getAttribute("ID"));
		registerIds(plaintext);
		verify(assertion, idpRsa, RSA_SHA256, SHA256, true);
		return "decrypted to a standalone saml:Assertion whose signature is valid";
	}

	/**
	 * Verifies the enveloped signature that is a direct child of {@code signed}, with a fixed trusted key.
	 */
	private static byte[] verify(Element signed, X509Certificate certificate, String signatureMethod, String digestMethod,
			boolean secureValidation) throws Exception {
		String id = signed.getAttribute("ID");
		check(signed.getOwnerDocument().getElementById(id) == signed, "ID " + id + " does not resolve to the signed element");

		DOMValidateContext context = new DOMValidateContext(KeySelector.singletonKeySelector(certificate.getPublicKey()), child(signed, DS, "Signature"));
		context.setProperty("org.jcp.xml.dsig.secureValidation", secureValidation);
		XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);

		SignedInfo signedInfo = signature.getSignedInfo();
		check(CanonicalizationMethod.EXCLUSIVE.equals(signedInfo.getCanonicalizationMethod().getAlgorithm()), "SignedInfo c14n is not exclusive");
		check(signatureMethod.equals(signedInfo.getSignatureMethod().getAlgorithm()), "unexpected SignatureMethod");
		check(signedInfo.getReferences().size() == 1, "expected exactly one Reference");
		Reference reference = signedInfo.getReferences().get(0);
		check(("#" + id).equals(reference.getURI()), "Reference URI " + reference.getURI() + " does not name the signed element");
		check(digestMethod.equals(reference.getDigestMethod().getAlgorithm()), "unexpected DigestMethod");
		List<String> transforms = new ArrayList<>();

		for (Transform transform : reference.getTransforms())
			transforms.add(transform.getAlgorithm());

		check(List.of(Transform.ENVELOPED, CanonicalizationMethod.EXCLUSIVE).equals(transforms), "unexpected transforms " + transforms);

		if (!signature.validate(context))
			throw new IllegalStateException("signature invalid (SignatureValue " + signature.getSignatureValue().validate(context)
					+ ", Reference " + reference.validate(context) + ")");

		return signature.getSignatureValue().getValue();
	}

	/**
	 * Decrypts an inline-EncryptedKey, AES-256-GCM EncryptedData by hand with JCA.
	 */
	private byte[] decrypt(Element encryptedData, String keyTransport) throws Exception {
		check(AES256_GCM.equals(child(encryptedData, XENC, "EncryptionMethod").getAttribute("Algorithm")), "data algorithm is not aes256-gcm");
		Element encryptedKey = child(child(encryptedData, DS, "KeyInfo"), XENC, "EncryptedKey");
		Element method = child(encryptedKey, XENC, "EncryptionMethod");
		check(keyTransport.equals(method.getAttribute("Algorithm")), "key transport is " + method.getAttribute("Algorithm"));
		byte[] wrappedKey = cipherValue(encryptedKey);
		Cipher rsa;

		if (RSA_OAEP_11.equals(keyTransport)) {
			check(SHA256.equals(child(method, DS, "DigestMethod").getAttribute("Algorithm")), "OAEP digest is not SHA-256");
			check(MGF1_SHA256.equals(child(method, XENC11, "MGF").getAttribute("Algorithm")), "MGF is not MGF1-SHA256");

			Cipher sha1Defaults = Cipher.getInstance("RSA/ECB/OAEPPadding");
			sha1Defaults.init(Cipher.DECRYPT_MODE, spKey, new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
			boolean unwrapsUnderSha1;

			try {
				sha1Defaults.doFinal(wrappedKey);
				unwrapsUnderSha1 = true;
			} catch (BadPaddingException expected) {
				unwrapsUnderSha1 = false;
			}

			check(!unwrapsUnderSha1, "the key also unwraps under OAEP SHA-1/MGF1-SHA1, so the parameters were ignored");
			rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
			rsa.init(Cipher.DECRYPT_MODE, spKey, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
		} else {
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, spKey);
		}

		byte[] sessionKey = rsa.doFinal(wrappedKey);
		check(sessionKey.length == 32, "session key is " + sessionKey.length + " bytes, not 32");
		byte[] data = cipherValue(encryptedData);
		Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
		aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new GCMParameterSpec(128, data, 0, 12));
		return aes.doFinal(data, 12, data.length - 12);
	}

	private Document document(String file) throws Exception {
		Document document = parse(Files.readAllBytes(dir.resolve(file)));
		registerIds(document);
		return document;
	}

	private X509Certificate certificate(String name) throws Exception {
		try (InputStream in = Files.newInputStream(dir.resolve("keys/" + name + ".crt"))) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
		}
	}

	private static Document parse(byte[] xml) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		factory.setXIncludeAware(false);
		factory.setExpandEntityReferences(false);
		return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
	}

	/**
	 * Registers {@code ID} as the ID attribute of every SAML element, which XMLDSig reference resolution needs.
	 */
	private static void registerIds(Document document) {
		NodeList elements = document.getElementsByTagNameNS("*", "*");

		for (int i = 0; i < elements.getLength(); i++) {
			Element element = (Element) elements.item(i);
			boolean saml = SAML.equals(element.getNamespaceURI()) || SAMLP.equals(element.getNamespaceURI());

			if (saml && element.hasAttributeNS(null, "ID"))
				element.setIdAttributeNS(null, "ID", true);
		}
	}

	private static Element child(Element parent, String namespace, String localName) {
		Element found = null;

		for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
			if (node instanceof Element && namespace.equals(node.getNamespaceURI()) && localName.equals(node.getLocalName())) {
				check(found == null, "more than one " + localName + " under " + parent.getLocalName());
				found = (Element) node;
			}
		}

		check(found != null, "no " + localName + " under " + parent.getLocalName());
		return found;
	}

	private static byte[] cipherValue(Element parent) {
		return Base64.getMimeDecoder().decode(child(child(parent, XENC, "CipherData"), XENC, "CipherValue").getTextContent());
	}

	private static byte[] pem(Path path) throws Exception {
		String text = Files.readString(path, StandardCharsets.US_ASCII);
		return Base64.getMimeDecoder().decode(text.replaceAll("-----[A-Z ]+-----", ""));
	}

	private static void check(boolean condition, String message) {
		if (!condition)
			throw new IllegalStateException(message);
	}
}
