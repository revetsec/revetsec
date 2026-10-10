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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Verifies a SAML Response or Assertion signature against caller-configured IdP keys. The parser and shape result
 * must refer to the same original DOM. No KeyInfo material is used as a trust anchor.
 *
 * @since 1.0.0
 */
public final class EnvelopedSignatureVerifier {
    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String EXCLUSIVE = CanonicalizationMethod.EXCLUSIVE;
    private static final String SECURE_VALIDATION = "org.jcp.xml.dsig.secureValidation";

    private EnvelopedSignatureVerifier() { }

    /**
     * The original element whose own signature is selected.
     *
     * @since 1.0.0
     */
    public enum Target { RESPONSE, ASSERTION }

    /**
     * Verify one optional direct-child signature. The result remains tied to its exact covered element. An absent
     * signature is distinct from an invalid one, so a later policy can require either Response or Assertion coverage.
     *
     * @since 1.0.0
     */
    public static @NonNull Result verify(SecureXmlParser.Result.@NonNull Accepted parsed,
            SamlResponseStructure.@NonNull Shape shape, @NonNull Target target,
            @NonNull List<@NonNull PublicKey> trustedKeys) {
        return verify(parsed, shape, target, trustedKeys, false);
    }

    /** Verifies with optional per-connection RSA-SHA1 compatibility. */
    public static @NonNull Result verify(SecureXmlParser.Result.@NonNull Accepted parsed,
            SamlResponseStructure.@NonNull Shape shape, @NonNull Target target,
            @NonNull List<@NonNull PublicKey> trustedKeys, boolean allowSha1) {
        requireNonNull(parsed);
        requireNonNull(shape);
        requireNonNull(target);
        requireNonNull(trustedKeys);
        if (trustedKeys.isEmpty() || trustedKeys.size() > 4 || trustedKeys.stream().anyMatch(key -> key == null))
            throw new IllegalArgumentException("Expected one to four trusted IdP keys");

        Element signed = target == Target.RESPONSE ? shape.getResponse() : shape.getAssertion();
        if (signed == null) return Absent.INSTANCE;
        Document document = parsed.getDocument();
        if (!signed.getOwnerDocument().isSameNode(document)
                || !shape.getResponse().getOwnerDocument().isSameNode(document))
            return new Rejected(Reason.DOCUMENT_MISMATCH);
        Element signature = target == Target.RESPONSE ? shape.getResponseSignature() : directSignature(signed);
        if (signature == null) return Absent.INSTANCE;
        if (!signature.getParentNode().isSameNode(signed) || !signatureAtSchemaPosition(signed, signature))
            return new Rejected(Reason.SIGNATURE_SHAPE);

        return verifySignedElement(document, signed, signature, trustedKeys, allowSha1);
    }

    /** Verifies a pinned-key signature on one original metadata descriptor, never its KeyInfo. */
    public static @NonNull Result verifyMetadata(SecureXmlParser.Result.@NonNull Accepted parsed,
            @NonNull Element signed, @NonNull List<@NonNull PublicKey> trustedKeys) {
        requireNonNull(parsed);
        requireNonNull(signed);
        requireNonNull(trustedKeys);
        if (trustedKeys.isEmpty() || trustedKeys.size() > 4 || trustedKeys.stream().anyMatch(key -> key == null))
            throw new IllegalArgumentException("Expected one to four pinned metadata keys");
        if (!signed.getOwnerDocument().isSameNode(parsed.getDocument()))
            return new Rejected(Reason.DOCUMENT_MISMATCH);
        Element signature = null;
        int index = 0;
        for (Node child = signed.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (is(element, DSIG, "Signature")) {
                if (signature != null || index != 0) return new Rejected(Reason.SIGNATURE_SHAPE);
                signature = element;
            }
            index++;
        }
        if (signature == null) return Absent.INSTANCE;
        return verifySignedElement(parsed.getDocument(), signed, signature, trustedKeys, false);
    }

    private static @NonNull Result verifySignedElement(@NonNull Document document,
            @NonNull Element signed, @NonNull Element signature,
            @NonNull List<@NonNull PublicKey> trustedKeys, boolean allowSha1) {
        String id = signed.getAttributeNS(null, "ID");
        if (!signed.hasAttributeNS(null, "ID") || !ncName(id)) return new Rejected(Reason.REFERENCE);
        SignatureShape prechecked = inspectSignature(signature, id, allowSha1);
        if (prechecked == null) return new Rejected(Reason.SIGNATURE_SHAPE);

        String globalSecureValidation = System.getProperty(SECURE_VALIDATION);
        if (globalSecureValidation != null && !"true".equalsIgnoreCase(globalSecureValidation))
            return Unavailable.INSTANCE;
        XMLSignatureFactory factory;
        try {
            factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        } catch (NoSuchProviderException | javax.xml.crypto.NoSuchMechanismException exception) {
            return Unavailable.INSTANCE;
        }
        URIDereferencer defaultDereferencer = factory.getURIDereferencer();
        if (defaultDereferencer == null) return Unavailable.INSTANCE;
        try {
            // The single-pass parser has already rejected every duplicate ID-like value. The document ID table,
            // unlike DOMCryptoContext's map, must resolve this exact node and no other.
            signed.setIdAttributeNS(null, "ID", true);
            if (!sameNode(document.getElementById(id), signed)) return new Rejected(Reason.REFERENCE);
            boolean compatibleKey = false;
            for (PublicKey key : trustedKeys) {
                if (!keyMatches(key, prechecked.algorithm())) continue;
                compatibleKey = true;
                DOMValidateContext context = new DOMValidateContext(key, signature);
                context.setProperty(SECURE_VALIDATION,
                        !(allowSha1 && (SignatureMethod.RSA_SHA1.equals(prechecked.algorithm())
                                || DigestMethod.SHA1.equals(prechecked.digest()))));
                context.setProperty("javax.xml.crypto.dsig.cacheReference", true);
                context.setURIDereferencer((reference, cryptoContext) -> {
                    if (!("#" + id).equals(reference.getURI()))
                        throw new URIReferenceException("Unexpected signature reference");
                    return defaultDereferencer.dereference(reference, cryptoContext);
                });
                XMLSignature xmlSignature;
                try {
                    xmlSignature = factory.unmarshalXMLSignature(context);
                    if (!postcheck(xmlSignature, id, prechecked))
                        return new Rejected(Reason.SIGNATURE_SHAPE);
                    if (!xmlSignature.validate(context)) continue;
                    Reference reference = xmlSignature.getSignedInfo().getReferences().get(0);
                    if (!digestInputStartsWith(reference.getDigestInputStream(), signed))
                        return new Rejected(Reason.REFERENCE);
                    if (!sameNode(document.getElementById(id), signed))
                        return new Rejected(Reason.REFERENCE);
                    return new Verified(signed, prechecked.algorithm());
                } catch (XMLSignatureException exception) {
                    // A candidate-key failure is checked against the remaining configured rollover keys.
                } catch (MarshalException | IOException | RuntimeException exception) {
                    return new Rejected(Reason.INVALID_SIGNATURE);
                }
            }
            return new Rejected(compatibleKey ? Reason.INVALID_SIGNATURE : Reason.NO_MATCHING_KEY);
        } catch (RuntimeException exception) {
            return new Rejected(Reason.REFERENCE);
        } finally {
            // Do not let verification of the other signature inherit an extra ID registration.
            signed.setIdAttributeNS(null, "ID", false);
        }
    }

    private static @Nullable Element directSignature(@NonNull Element element) {
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element candidate && is(candidate, DSIG, "Signature")) return candidate;
        return null;
    }

    private static boolean signatureAtSchemaPosition(@NonNull Element signed, @NonNull Element signature) {
        // Both SAML Response and Assertion allow Signature only immediately after an optional Issuer.
        Element first = null;
        Element second = null;
        for (Node child = signed.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (first == null) first = element;
            else { second = element; break; }
        }
        return sameNode(first, signature) || (first != null
                && is(first, SamlResponseStructure.ASSERTION, "Issuer") && sameNode(second, signature));
    }

    private static @Nullable SignatureShape inspectSignature(@NonNull Element signature, @NonNull String id,
            boolean allowSha1) {
        List<Element> signatureChildren = children(signature);
        if (signatureChildren.size() < 2 || signatureChildren.size() > 3
                || !is(signatureChildren.get(0), DSIG, "SignedInfo")
                || !is(signatureChildren.get(1), DSIG, "SignatureValue")
                || (signatureChildren.size() == 3 && !is(signatureChildren.get(2), DSIG, "KeyInfo"))) return null;
        if (!children(signatureChildren.get(1)).isEmpty()) return null;
        if (signatureChildren.size() == 3 && !safeKeyInfo(signatureChildren.get(2))) return null;
        List<Element> info = children(signatureChildren.get(0));
        if (info.size() != 3 || !is(info.get(0), DSIG, "CanonicalizationMethod")
                || !is(info.get(1), DSIG, "SignatureMethod") || !is(info.get(2), DSIG, "Reference")) return null;
        String canonicalization = info.get(0).getAttributeNS(null, "Algorithm");
        if (!allowedCanonicalization(canonicalization) || !safeParameters(info.get(0), canonicalization)) return null;
        String algorithm = info.get(1).getAttributeNS(null, "Algorithm");
        if (!allowedSignatureAlgorithm(algorithm, allowSha1) || !children(info.get(1)).isEmpty()) return null;
        Element reference = info.get(2);
        if (!("#" + id).equals(reference.getAttributeNS(null, "URI"))
                || reference.hasAttributeNS(null, "Type")) return null;
        List<Element> refChildren = children(reference);
        if (refChildren.size() != 3 || !is(refChildren.get(0), DSIG, "Transforms")
                || !is(refChildren.get(1), DSIG, "DigestMethod")
                || !is(refChildren.get(2), DSIG, "DigestValue")) return null;
        List<Element> transforms = children(refChildren.get(0));
        if (transforms.isEmpty() || transforms.size() > 2
                || !is(transforms.get(0), DSIG, "Transform")
                || !Transform.ENVELOPED.equals(transforms.get(0).getAttributeNS(null, "Algorithm"))
                || !children(transforms.get(0)).isEmpty()) return null;
        if (transforms.size() == 2 && (!is(transforms.get(1), DSIG, "Transform")
                || !EXCLUSIVE.equals(transforms.get(1).getAttributeNS(null, "Algorithm"))
                || !safeParameters(transforms.get(1), EXCLUSIVE))) return null;
        String digest = refChildren.get(1).getAttributeNS(null, "Algorithm");
        if ((!DigestMethod.SHA256.equals(digest) && !DigestMethod.SHA384.equals(digest)
                && !DigestMethod.SHA512.equals(digest)
                && !(allowSha1 && DigestMethod.SHA1.equals(digest)))
                || !children(refChildren.get(1)).isEmpty()
                || !children(refChildren.get(2)).isEmpty()) return null;
        return new SignatureShape(algorithm, canonicalization, digest, transforms.size());
    }

    private static boolean safeParameters(@NonNull Element method, @NonNull String algorithm) {
        List<Element> children = children(method);
        return children.isEmpty() || (EXCLUSIVE.equals(algorithm) && children.size() == 1
                && is(children.get(0), EXCLUSIVE, "InclusiveNamespaces")
                && children(children.get(0)).isEmpty());
    }

    private static boolean safeKeyInfo(@NonNull Element keyInfo) {
        for (Element child : children(keyInfo))
            if (!is(child, DSIG, "X509Data") && !is(child, DSIG, "KeyName")
                    && !is(child, DSIG, "KeyValue")) return false;
        return !containsForbiddenKeyInfoElement(keyInfo);
    }

    private static boolean containsForbiddenKeyInfoElement(@NonNull Element element) {
        for (Element child : children(element)) {
            if (is(child, DSIG, "RetrievalMethod") || is(child, DSIG, "KeyInfoReference")
                    || is(child, DSIG, "Object") || containsForbiddenKeyInfoElement(child)) return true;
        }
        return false;
    }

    private static boolean allowedCanonicalization(@NonNull String algorithm) {
        return EXCLUSIVE.equals(algorithm) || CanonicalizationMethod.INCLUSIVE.equals(algorithm)
                || CanonicalizationMethod.INCLUSIVE_11.equals(algorithm);
    }

    private static boolean allowedSignatureAlgorithm(@NonNull String algorithm, boolean allowSha1) {
        return (allowSha1 && SignatureMethod.RSA_SHA1.equals(algorithm))
                || SignatureMethod.RSA_SHA256.equals(algorithm) || SignatureMethod.RSA_SHA384.equals(algorithm)
                || SignatureMethod.RSA_SHA512.equals(algorithm) || SignatureMethod.ECDSA_SHA256.equals(algorithm)
                || SignatureMethod.ECDSA_SHA384.equals(algorithm) || SignatureMethod.ECDSA_SHA512.equals(algorithm);
    }

    private static boolean keyMatches(@NonNull PublicKey key, @NonNull String algorithm) {
        if ((algorithm.startsWith("http://www.w3.org/2001/04/xmldsig-more#rsa-")
                || SignatureMethod.RSA_SHA1.equals(algorithm))
                && key instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            return bits >= 2048 && bits <= 16384 && rsa.getPublicExponent().compareTo(java.math.BigInteger.valueOf(65537)) >= 0
                    && rsa.getPublicExponent().testBit(0);
        }
        if (algorithm.startsWith("http://www.w3.org/2001/04/xmldsig-more#ecdsa-")
                && key instanceof ECPublicKey ec) {
            ECParameterSpec actual = ec.getParams();
            return actual != null && (namedCurve(actual, "secp256r1")
                    || namedCurve(actual, "secp384r1") || namedCurve(actual, "secp521r1"));
        }
        return false;
    }

    private static boolean namedCurve(@NonNull ECParameterSpec actual, @NonNull String name) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            return expected.getCurve().equals(actual.getCurve())
                    && expected.getGenerator().equals(actual.getGenerator())
                    && expected.getOrder().equals(actual.getOrder())
                    && expected.getCofactor() == actual.getCofactor();
        } catch (java.security.NoSuchAlgorithmException | InvalidParameterSpecException exception) {
            return false;
        }
    }

    private static boolean ncName(@NonNull String value) {
        if (value.isEmpty()) return false;
        int codePoint = value.codePointAt(0);
        if (!nameStart(codePoint)) return false;
        for (int position = Character.charCount(codePoint); position < value.length(); position += Character.charCount(codePoint)) {
            codePoint = value.codePointAt(position);
            if (!nameStart(codePoint) && codePoint != '-' && codePoint != '.'
                    && !(codePoint >= '0' && codePoint <= '9') && codePoint != 0xB7
                    && !(codePoint >= 0x300 && codePoint <= 0x36F)
                    && !(codePoint >= 0x203F && codePoint <= 0x2040)) return false;
        }
        return true;
    }

    private static boolean nameStart(int codePoint) {
        return codePoint == '_' || (codePoint >= 'A' && codePoint <= 'Z')
                || (codePoint >= 'a' && codePoint <= 'z')
                || (codePoint >= 0xC0 && codePoint <= 0xD6)
                || (codePoint >= 0xD8 && codePoint <= 0xF6)
                || (codePoint >= 0xF8 && codePoint <= 0x2FF)
                || (codePoint >= 0x370 && codePoint <= 0x37D)
                || (codePoint >= 0x37F && codePoint <= 0x1FFF)
                || (codePoint >= 0x200C && codePoint <= 0x200D)
                || (codePoint >= 0x2070 && codePoint <= 0x218F)
                || (codePoint >= 0x2C00 && codePoint <= 0x2FEF)
                || (codePoint >= 0x3001 && codePoint <= 0xD7FF)
                || (codePoint >= 0xF900 && codePoint <= 0xFDCF)
                || (codePoint >= 0xFDF0 && codePoint <= 0xFFFD)
                || (codePoint >= 0x10000 && codePoint <= 0xEFFFF);
    }

    private static boolean postcheck(@NonNull XMLSignature signature, @NonNull String id,
            @NonNull SignatureShape shape) {
        if (!signature.getObjects().isEmpty()
                || !shape.algorithm().equals(signature.getSignedInfo().getSignatureMethod().getAlgorithm())
                || !shape.canonicalization().equals(signature.getSignedInfo().getCanonicalizationMethod().getAlgorithm())
                || signature.getSignedInfo().getReferences().size() != 1) return false;
        Reference reference = signature.getSignedInfo().getReferences().get(0);
        if (!("#" + id).equals(reference.getURI())
                || !shape.digest().equals(reference.getDigestMethod().getAlgorithm())
                || reference.getTransforms().size() != shape.transformCount()) return false;
        for (int i = 0; i < reference.getTransforms().size(); i++) {
            String expected = i == 0 ? Transform.ENVELOPED : EXCLUSIVE;
            if (!expected.equals(reference.getTransforms().get(i).getAlgorithm())) return false;
        }
        return true;
    }

    private static boolean digestInputStartsWith(@Nullable InputStream stream, @NonNull Element signed)
            throws IOException {
        if (stream == null) return false;
        byte[] prefix = ("<" + signed.getTagName()).getBytes(StandardCharsets.UTF_8);
        try (stream) {
            byte[] actual = stream.readNBytes(prefix.length);
            if (actual.length != prefix.length) return false;
            for (int i = 0; i < prefix.length; i++) if (actual[i] != prefix[i]) return false;
            return true;
        }
    }

    private static @NonNull List<@NonNull Element> children(@NonNull Element parent) {
        List<Element> result = new ArrayList<>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element) result.add(element);
        return result;
    }

    private static boolean is(@NonNull Element element, @NonNull String namespace, @NonNull String local) {
        return namespace.equals(element.getNamespaceURI()) && local.equals(element.getLocalName());
    }

    private static boolean sameNode(@Nullable Node left, @Nullable Node right) {
        return left != null && right != null && left.isSameNode(right);
    }

    private record SignatureShape(@NonNull String algorithm, @NonNull String canonicalization,
            @NonNull String digest, int transformCount) { }

    /**
     * A signature result bound to one selected original DOM element.
     *
     * @since 1.0.0
     */
    public sealed interface Result permits Verified, Rejected, Absent, Unavailable { }

    /**
     * This exact original element was covered by an accepted IdP signature.
     *
     * @since 1.0.0
     */
    public static final class Verified implements Result {
        private final @NonNull Element element;
        private final @NonNull String algorithm;
        private Verified(@NonNull Element element, @NonNull String algorithm) {
            this.element = element;
            this.algorithm = algorithm;
        }
        /**
         * Return the covered original node.
         *
         * @since 1.0.0
         */
        public @NonNull Element getElement() { return element; }
        /**
         * Return the XMLDSig algorithm URI.
         *
         * @since 1.0.0
         */
        public @NonNull String getAlgorithm() { return algorithm; }
        @Override public @NonNull String toString() { return "EnvelopedSignatureVerifier.Verified{<covered>}"; }
    }

    /**
     * No signature was present on the selected element.
     *
     * @since 1.0.0
     */
    public enum Absent implements Result { INSTANCE }

    /**
     * The selected signature failed a fixed local check.
     *
     * @since 1.0.0
     */
    public static final class Rejected implements Result {
        private final @NonNull Reason reason;
        private Rejected(@NonNull Reason reason) { this.reason = reason; }
        /**
         * Return a fixed classification with no hostile content.
         *
         * @since 1.0.0
         */
        public @NonNull Reason getReason() { return reason; }
    }

    /**
     * The required JDK XMLDSig validation environment is unavailable.
     *
     * @since 1.0.0
     */
    public enum Unavailable implements Result { INSTANCE }

    /**
     * A fixed classification with no hostile XML or provider message.
     *
     * @since 1.0.0
     */
    public enum Reason { DOCUMENT_MISMATCH, SIGNATURE_SHAPE, REFERENCE, NO_MATCHING_KEY, INVALID_SIGNATURE }
}
