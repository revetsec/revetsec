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
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import javax.xml.XMLConstants;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Deque;

import static java.util.Objects.requireNonNull;

/**
 * Untrusted SAML Response shape. Its element references belong to the parser's original document; this class never
 * creates a second DOM or a verified identity. XML signatures and all semantic checks remain mandatory.
 */
public final class SamlResponseStructure {
    public static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String SAML1_ASSERTION = "urn:oasis:names:tc:SAML:1.0:assertion";
    private static final String SAML1_PROTOCOL = "urn:oasis:names:tc:SAML:1.0:protocol";

    private SamlResponseStructure() { }

    /** Inspect only direct children of the root for protocol fields. */
    public static @NonNull Result inspect(@NonNull Document document) {
        requireNonNull(document);
        Element root = document.getDocumentElement();
        if (root == null || !is(root, PROTOCOL, "Response") || !"2.0".equals(root.getAttribute("Version"))
                || root.getAttributeNS(null, "ID").isEmpty() || root.getAttributeNS(null, "IssueInstant").isEmpty())
            return Rejected.INSTANCE;
        Element issuer = null;
        Element responseSignature = null;
        Element status = null;
        Element assertion = null;
        Element encryptedAssertion = null;
        int position = 0;
        for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element child)) continue;
            int next;
            if (is(child, ASSERTION, "Issuer")) {
                next = 1;
                if (issuer != null) return Rejected.INSTANCE;
                issuer = child;
            } else if (is(child, DSIG, "Signature")) {
                next = 2;
                if (responseSignature != null) return Rejected.INSTANCE;
                responseSignature = child;
            } else if (is(child, PROTOCOL, "Extensions")) {
                next = 3;
            } else if (is(child, PROTOCOL, "Status")) {
                next = 4;
                if (status != null) return Rejected.INSTANCE;
                status = child;
            } else if (is(child, ASSERTION, "Assertion")) {
                next = 5;
                if (assertion != null || encryptedAssertion != null) return Rejected.INSTANCE;
                assertion = child;
            } else if (is(child, ASSERTION, "EncryptedAssertion")) {
                next = 5;
                if (assertion != null || encryptedAssertion != null) return Rejected.INSTANCE;
                encryptedAssertion = child;
            } else {
                return Rejected.INSTANCE;
            }
            if (next <= position && next != 5) return Rejected.INSTANCE;
            if (next < position || (next == 5 && status == null)) return Rejected.INSTANCE;
            position = next;
        }
        if (status == null || !allDescendantsHaveSafeShape(root, assertion, responseSignature))
            return Rejected.INSTANCE;
        @Nullable Boolean successful = successStatus(status);
        if (successful == null || successful != (assertion != null || encryptedAssertion != null))
            return Rejected.INSTANCE;
        return new Accepted(new Shape(root, issuer, responseSignature, status, assertion, encryptedAssertion));
    }

    private static boolean allDescendantsHaveSafeShape(@NonNull Element root, @Nullable Element assertion,
            @Nullable Element responseSignature) {
        Deque<Element> pending = new ArrayDeque<>();
        pending.push(root);
        int assertionCount = 0;
        int encryptedCount = 0;
        int assertionSignatures = 0;
        while (!pending.isEmpty()) {
            Element element = pending.pop();
            String namespace = element.getNamespaceURI();
            if (SAML1_ASSERTION.equals(namespace) || SAML1_PROTOCOL.equals(namespace)) return false;
            if (is(element, ASSERTION, "Assertion")) {
                assertionCount++;
                if (!sameNode(element, assertion) || assertionCount > 1) return false;
            }
            if (is(element, ASSERTION, "EncryptedAssertion")) {
                encryptedCount++;
                if (!sameNode(element.getParentNode(), root) || encryptedCount > 1) return false;
            }
            if (is(element, DSIG, "Signature")) {
                Node parent = element.getParentNode();
                if (!sameNode(parent, root) && !sameNode(parent, assertion)) return false;
                if (sameNode(parent, root) && !sameNode(element, responseSignature)) return false;
                if (sameNode(parent, assertion) && ++assertionSignatures > 1) return false;
            }
            NamedNodeMap attributes = element.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Attr attribute = (Attr) attributes.item(i);
                String attributeNamespace = attribute.getNamespaceURI();
                if (XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attributeNamespace)) {
                    String value = attribute.getValue();
                    if (!value.isEmpty() && !isAbsoluteUri(value)) return false;
                }
                if ("ID".equals(attribute.getLocalName())
                        && (PROTOCOL.equals(attributeNamespace) || ASSERTION.equals(attributeNamespace)))
                    return false;
            }
            for (Node child = element.getLastChild(); child != null; child = child.getPreviousSibling())
                if (child instanceof Element childElement) pending.push(childElement);
        }
        return assertionCount + encryptedCount <= 1;
    }

    private static boolean isAbsoluteUri(@NonNull String text) {
        try { return URI.create(text).isAbsolute(); }
        catch (IllegalArgumentException exception) { return false; }
    }

    private static boolean sameNode(@Nullable Node left, @Nullable Node right) {
        return left != null && right != null && left.isSameNode(right);
    }

    private static @Nullable Boolean successStatus(@NonNull Element status) {
        Element statusCode = null;
        for (Node child = status.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (is(element, PROTOCOL, "StatusCode")) {
                if (statusCode != null) return null;
                statusCode = element;
            }
        }
        if (statusCode == null || !statusCode.hasAttributeNS(null, "Value")) return null;
        return SUCCESS.equals(statusCode.getAttributeNS(null, "Value"));
    }

    private static boolean is(@NonNull Element element, @NonNull String namespace,
            @NonNull String localName) {
        return namespace.equals(element.getNamespaceURI()) && localName.equals(element.getLocalName());
    }

    /** Still unverified: merely a bounded original-DOM shape. */
    public sealed interface Result permits Accepted, Rejected { }

    /** Contains no checked SAML identity. */
    public static final class Accepted implements Result {
        private final @NonNull Shape shape;
        private Accepted(@NonNull Shape shape) { this.shape = shape; }
        public @NonNull Shape getShape() { return shape; }
        @Override public @NonNull String toString() { return "SamlResponseStructure.Accepted{<unverified>}"; }
    }

    /** A fixed rejection that retains no document contents. */
    public enum Rejected implements Result { INSTANCE }

    /** References to the original document only; downstream verification must authenticate their coverage. */
    public static final class Shape {
        private final @NonNull Element response;
        private final @Nullable Element issuer;
        private final @Nullable Element responseSignature;
        private final @NonNull Element status;
        private final @Nullable Element assertion;
        private final @Nullable Element encryptedAssertion;

        private Shape(@NonNull Element response, @Nullable Element issuer, @Nullable Element responseSignature,
                @NonNull Element status, @Nullable Element assertion, @Nullable Element encryptedAssertion) {
            this.response = response;
            this.issuer = issuer;
            this.responseSignature = responseSignature;
            this.status = status;
            this.assertion = assertion;
            this.encryptedAssertion = encryptedAssertion;
        }

        public @NonNull Element getResponse() { return response; }
        public @Nullable Element getIssuer() { return issuer; }
        public @Nullable Element getResponseSignature() { return responseSignature; }
        public @NonNull Element getStatus() { return status; }
        public @Nullable Element getAssertion() { return assertion; }
        public @Nullable Element getEncryptedAssertion() { return encryptedAssertion; }
        @Override public @NonNull String toString() { return "SamlResponseStructure.Shape{<unverified>}"; }
    }
}
