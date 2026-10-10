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

import com.revetsec.internal.xml.EnvelopedSignatureVerifier;
import com.revetsec.internal.xml.SamlResponseStructure;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.XmlEncryptionDecryptor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Arrays;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NamedNodeMap;

/**
 * The unverified inbound SSO response boundary: raw POST form, decoded XML and response shape are checked in order,
 * with one XML parse. No result from this class is a signature verdict or may establish an application identity.
 */
final class SamlInboundResponse {
    private SamlInboundResponse() { }

    static @NonNull Result parse(byte @NonNull [] body, @NonNull List<@NonNull String> contentTypes,
            @Nullable String rawQuery) {
        SamlPostBindingDecoder.Result binding = SamlPostBindingDecoder.decode(body, contentTypes, rawQuery);
        if (binding instanceof SamlPostBindingDecoder.Rejected rejected)
            return new Rejected(Stage.BINDING, rejected.reason().name());
        SamlPostBindingDecoder.Accepted accepted = (SamlPostBindingDecoder.Accepted) binding;
        return parseXml(accepted.xml(), accepted.relayState());
    }

    static @NonNull Result parse(@NonNull SamlPostBindingMessage message) {
        return parseXml(message.xml(), message.relayState());
    }

    private static @NonNull Result parseXml(byte @NonNull [] xml, @Nullable String relayState) {
        SecureXmlParser.Result parsed = SecureXmlParser.parseResponse(xml);
        if (parsed instanceof SecureXmlParser.Result.Rejected rejected)
            return new Rejected(Stage.XML, rejected.getReason().name());
        if (parsed instanceof SecureXmlParser.Result.Unavailable) return Unavailable.INSTANCE;
        SecureXmlParser.Result.Accepted parsedXml = (SecureXmlParser.Result.Accepted) parsed;
        SamlResponseStructure.Result structured = SamlResponseStructure.inspect(parsedXml.getDocument());
        if (structured instanceof SamlResponseStructure.Rejected)
            return new Rejected(Stage.STRUCTURE, "INVALID_RESPONSE_SHAPE");
        return new Accepted(parsedXml, ((SamlResponseStructure.Accepted) structured).getShape(),
                relayState);
    }

    /** Verify every signature on an unencrypted success response. Semantic SAML checks follow. */
    static @NonNull SignatureResult verifySuccessSignatures(@NonNull Accepted inbound,
            @NonNull List<@NonNull PublicKey> trustedKeys) {
        return verifySuccessSignatures(inbound, trustedKeys, List.of(), false, false,
                new SecureRandom());
    }

    static @NonNull SignatureResult verifySuccessSignatures(@NonNull Accepted inbound,
            @NonNull List<@NonNull PublicKey> trustedKeys,
            @NonNull List<@NonNull PrivateKey> decryptionKeys, boolean allowCbc,
            @NonNull SecureRandom random) {
        return verifySuccessSignatures(inbound, trustedKeys, decryptionKeys, allowCbc, false, random);
    }

    static @NonNull SignatureResult verifySuccessSignatures(@NonNull Accepted inbound,
            @NonNull List<@NonNull PublicKey> trustedKeys,
            @NonNull List<@NonNull PrivateKey> decryptionKeys, boolean allowCbc,
            boolean allowSha1, @NonNull SecureRandom random) {
        if (inbound.shape.getAssertion() == null && inbound.shape.getEncryptedAssertion() == null)
            return new SignatureRejected("ASSERTION_NOT_AVAILABLE");
        EnvelopedSignatureVerifier.Result response = EnvelopedSignatureVerifier.verify(inbound.parsed,
                inbound.shape, EnvelopedSignatureVerifier.Target.RESPONSE, trustedKeys, allowSha1);
        if (response instanceof EnvelopedSignatureVerifier.Unavailable) return SignatureUnavailable.INSTANCE;
        if (response instanceof EnvelopedSignatureVerifier.Rejected rejected)
            return new SignatureRejected(rejected.getReason().name());
        SamlResponseStructure.Shape shape = inbound.shape;
        Element encryptedAssertion = shape.getEncryptedAssertion();
        boolean encrypted = encryptedAssertion != null;
        if (encryptedAssertion != null) {
            byte[] plaintext = XmlEncryptionDecryptor.decrypt(encryptedAssertion,
                    decryptionKeys, response instanceof EnvelopedSignatureVerifier.Verified,
                    allowCbc, random);
            if (plaintext == null) return new SignatureRejected("DECRYPTION");
            try {
                SecureXmlParser.Result parsedAssertion = SecureXmlParser.parseResponse(plaintext);
                if (!(parsedAssertion instanceof SecureXmlParser.Result.Accepted accepted))
                    return new SignatureRejected("DECRYPTION");
                Element assertion = accepted.getDocument().getDocumentElement();
                if (assertion == null || !SamlResponseStructure.ASSERTION.equals(assertion.getNamespaceURI())
                        || !"Assertion".equals(assertion.getLocalName()))
                    return new SignatureRejected("DECRYPTION");
                Node parent = shape.getResponse();
                Node replacement = inbound.parsed.getDocument().importNode(assertion, true);
                parent.replaceChild(replacement, encryptedAssertion);
                if (!uniqueIdentifiers(shape.getResponse())) return new SignatureRejected("DECRYPTION");
                SamlResponseStructure.Result rebuilt = SamlResponseStructure.inspect(inbound.parsed.getDocument());
                if (!(rebuilt instanceof SamlResponseStructure.Accepted valid))
                    return new SignatureRejected("DECRYPTION");
                shape = valid.getShape();
            } finally { Arrays.fill(plaintext, (byte) 0); }
        }
        EnvelopedSignatureVerifier.Result assertion = EnvelopedSignatureVerifier.verify(inbound.parsed,
                shape, EnvelopedSignatureVerifier.Target.ASSERTION, trustedKeys, allowSha1);
        if (assertion instanceof EnvelopedSignatureVerifier.Unavailable) return SignatureUnavailable.INSTANCE;
        if (assertion instanceof EnvelopedSignatureVerifier.Rejected rejected)
            return new SignatureRejected(rejected.getReason().name());
        if (response instanceof EnvelopedSignatureVerifier.Absent
                && assertion instanceof EnvelopedSignatureVerifier.Absent)
            return new SignatureRejected("UNSIGNED_RESPONSE");
        Element subject = directChild(shape.getAssertion(), SamlResponseStructure.ASSERTION, "Subject");
        if (subject != null) {
            Element encryptedId = null;
            int clearIds = 0;
            for (Node child = subject.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (!(child instanceof Element element)) continue;
                if (SamlResponseStructure.ASSERTION.equals(element.getNamespaceURI())
                        && "EncryptedID".equals(element.getLocalName())) {
                    if (encryptedId != null) return new SignatureRejected("DECRYPTION");
                    encryptedId = element;
                } else if (SamlResponseStructure.ASSERTION.equals(element.getNamespaceURI())
                        && "NameID".equals(element.getLocalName())) clearIds++;
            }
            if (encryptedId != null) {
                if (clearIds != 0) return new SignatureRejected("DECRYPTION");
                byte[] plaintext = XmlEncryptionDecryptor.decrypt(encryptedId, decryptionKeys,
                        response instanceof EnvelopedSignatureVerifier.Verified, allowCbc, random);
                if (plaintext == null) return new SignatureRejected("DECRYPTION");
                try {
                    SecureXmlParser.Result parsedNameId = SecureXmlParser.parseResponse(plaintext);
                    if (!(parsedNameId instanceof SecureXmlParser.Result.Accepted accepted))
                        return new SignatureRejected("DECRYPTION");
                    Element nameId = accepted.getDocument().getDocumentElement();
                    if (nameId == null || !SamlResponseStructure.ASSERTION.equals(nameId.getNamespaceURI())
                            || !"NameID".equals(nameId.getLocalName()))
                        return new SignatureRejected("DECRYPTION");
                    subject.replaceChild(inbound.parsed.getDocument().importNode(nameId, true), encryptedId);
                    if (!uniqueIdentifiers(shape.getResponse())) return new SignatureRejected("DECRYPTION");
                    SamlResponseStructure.Result rebuilt = SamlResponseStructure.inspect(inbound.parsed.getDocument());
                    if (!(rebuilt instanceof SamlResponseStructure.Accepted valid))
                        return new SignatureRejected("DECRYPTION");
                    shape = valid.getShape();
                } finally { Arrays.fill(plaintext, (byte) 0); }
            }
        }
        EnvelopedSignatureVerifier.Verified verifiedResponse = response instanceof EnvelopedSignatureVerifier.Verified covered
                ? covered : null;
        EnvelopedSignatureVerifier.Verified verifiedAssertion = assertion instanceof EnvelopedSignatureVerifier.Verified covered
                ? covered : null;
        return new SignaturesVerified(shape, inbound.relayState, verifiedResponse, verifiedAssertion,
                encrypted);
    }

    private static @Nullable Element directChild(@Nullable Element parent, @NonNull String namespace,
            @NonNull String local) {
        if (parent == null) return null;
        Element match = null;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && local.equals(element.getLocalName())) {
                if (match != null) return null;
                match = element;
            }
        }
        return match;
    }

    private static boolean uniqueIdentifiers(@NonNull Element root) {
        Set<String> identifiers = new HashSet<>();
        Deque<Element> pending = new ArrayDeque<>();
        pending.add(root);
        while (!pending.isEmpty()) {
            Element current = pending.pop();
            NamedNodeMap attributes = current.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                String local = attribute.getLocalName();
                if (("ID".equals(local) || "Id".equals(local) || "id".equals(local)
                        || "AssertionID".equals(local))
                        && !identifiers.add(attribute.getNodeValue())) return false;
            }
            for (Node child = current.getFirstChild(); child != null; child = child.getNextSibling())
                if (child instanceof Element element) pending.push(element);
        }
        return true;
    }

    /** A non-success Response can carry only a Response signature. */
    static EnvelopedSignatureVerifier.@NonNull Result verifyStatusSignature(@NonNull Accepted inbound,
            @NonNull List<@NonNull PublicKey> trustedKeys) {
        return verifyStatusSignature(inbound, trustedKeys, false);
    }

    static EnvelopedSignatureVerifier.@NonNull Result verifyStatusSignature(@NonNull Accepted inbound,
            @NonNull List<@NonNull PublicKey> trustedKeys, boolean allowSha1) {
        return EnvelopedSignatureVerifier.verify(inbound.parsed, inbound.shape,
                EnvelopedSignatureVerifier.Target.RESPONSE, trustedKeys, allowSha1);
    }

    sealed interface Result permits Accepted, Rejected, Unavailable { }

    static final class Accepted implements Result {
        private final SecureXmlParser.Result.@NonNull Accepted parsed;
        private final SamlResponseStructure.@NonNull Shape shape;
        private final @Nullable String relayState;

        private Accepted(SecureXmlParser.Result.@NonNull Accepted parsed,
                SamlResponseStructure.@NonNull Shape shape, @Nullable String relayState) {
            this.parsed = parsed;
            this.shape = shape;
            this.relayState = relayState;
        }

        SamlResponseStructure.@NonNull Shape shape() { return shape; }
        @Nullable String relayState() { return relayState; }
        @Override public @NonNull String toString() { return "SamlInboundResponse.Accepted{<unverified>}"; }
    }

    static final class Rejected implements Result {
        private final @NonNull Stage stage;
        private final @NonNull String reason;
        private Rejected(@NonNull Stage stage, @NonNull String reason) {
            this.stage = stage;
            this.reason = reason;
        }
        @NonNull Stage stage() { return stage; }
        @NonNull String reason() { return reason; }
        @Override public @NonNull String toString() { return "SamlInboundResponse.Rejected{" + stage + ", " + reason + "}"; }
    }

    enum Unavailable implements Result { INSTANCE }
    enum Stage { BINDING, XML, STRUCTURE }

    sealed interface SignatureResult permits SignaturesVerified, SignatureRejected, SignatureUnavailable { }

    /** Proof of signature coverage only; no SAML conditions, audience, replay, or identity have been checked. */
    static final class SignaturesVerified implements SignatureResult {
        private final SamlResponseStructure.@NonNull Shape shape;
        private final @Nullable String relayState;
        private final EnvelopedSignatureVerifier.@Nullable Verified response;
        private final EnvelopedSignatureVerifier.@Nullable Verified assertion;
        private final boolean encrypted;

        private SignaturesVerified(SamlResponseStructure.@NonNull Shape shape, @Nullable String relayState,
                EnvelopedSignatureVerifier.@Nullable Verified response,
                EnvelopedSignatureVerifier.@Nullable Verified assertion, boolean encrypted) {
            this.shape = shape;
            this.relayState = relayState;
            this.response = response;
            this.assertion = assertion;
            this.encrypted = encrypted;
        }

        SamlResponseStructure.@NonNull Shape shape() { return shape; }
        @Nullable String relayState() { return relayState; }
        EnvelopedSignatureVerifier.@Nullable Verified response() { return response; }
        EnvelopedSignatureVerifier.@Nullable Verified assertion() { return assertion; }
        boolean encrypted() { return encrypted; }
        @Override public @NonNull String toString() { return "SamlInboundResponse.SignaturesVerified{<semantics-unchecked>}"; }
    }

    static final class SignatureRejected implements SignatureResult {
        private final @NonNull String reason;
        private SignatureRejected(@NonNull String reason) { this.reason = reason; }
        @NonNull String reason() { return reason; }
    }

    enum SignatureUnavailable implements SignatureResult { INSTANCE }
}
