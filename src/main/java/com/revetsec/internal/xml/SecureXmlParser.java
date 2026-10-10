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

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.ext.DefaultHandler2;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Single-pass XML parsing boundary for SAML. The SAX reader counts structure before adding a node to the DOM;
 * neither an external entity nor an XML processing instruction is interpreted. A returned document is untrusted:
 * it is not a signature verdict or a SAML identity and must be consumed only by the later shape/verification layer.
 */
public final class SecureXmlParser {
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
    private static final String NAMESPACE_PREFIXES = "http://xml.org/sax/features/namespace-prefixes";
    private static final String LEXICAL_HANDLER = "http://xml.org/sax/properties/lexical-handler";

    private SecureXmlParser() { }

    /** Parse a decoded SAML response using the default size and structural limits. */
    public static @NonNull Result parseResponse(byte @NonNull [] input) {
        return parse(input, Limits.SAML_RESPONSE_DECODED_SIZE.getDefaultIntValue(),
                Limits.XML_DEPTH.getDefaultIntValue(), Limits.XML_ELEMENTS.getDefaultIntValue(),
                Limits.XML_ATTRIBUTES_PER_ELEMENT.getDefaultIntValue(),
                Limits.XML_NAME_LENGTH.getDefaultIntValue());
    }

    /** Parse metadata using its separate input-size limit and the same structural limits. */
    public static @NonNull Result parseMetadata(byte @NonNull [] input) {
        return parse(input, Limits.SAML_METADATA_SIZE.getDefaultIntValue(),
                Limits.XML_DEPTH.getDefaultIntValue(), Limits.XML_ELEMENTS.getDefaultIntValue(),
                Limits.XML_ATTRIBUTES_PER_ELEMENT.getDefaultIntValue(),
                Limits.XML_NAME_LENGTH.getDefaultIntValue());
    }

    static @NonNull Result parse(byte @NonNull [] input, int maximumInputBytes,
            int maximumDepth, int maximumElements, int maximumAttributes, int maximumNameLength) {
        requireNonNull(input);
        if (maximumInputBytes < 1 || maximumInputBytes > Limits.SAML_METADATA_SIZE.getCap()
                || maximumDepth < 1 || maximumDepth > Limits.XML_DEPTH.getCap()
                || maximumElements < 1 || maximumElements > Limits.XML_ELEMENTS.getCap()
                || maximumAttributes < 0 || maximumAttributes > Limits.XML_ATTRIBUTES_PER_ELEMENT.getCap()
                || maximumNameLength < 1 || maximumNameLength > Limits.XML_NAME_LENGTH.getCap())
            throw new IllegalArgumentException("Invalid XML parser limit");
        if (input.length < 1 || input.length > maximumInputBytes)
            return new Result.Rejected(Reason.INPUT_SIZE);

        XMLReader reader;
        Document document;
        try {
            SAXParserFactory sax = SAXParserFactory.newDefaultNSInstance();
            sax.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            sax.setFeature(DISALLOW_DOCTYPE, true);
            sax.setFeature(EXTERNAL_GENERAL, false);
            sax.setFeature(EXTERNAL_PARAMETER, false);
            sax.setFeature(LOAD_EXTERNAL_DTD, false);
            sax.setXIncludeAware(false);
            reader = sax.newSAXParser().getXMLReader();
            reader.setFeature(NAMESPACE_PREFIXES, true);
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            DocumentBuilderFactory dom = DocumentBuilderFactory.newDefaultNSInstance();
            document = dom.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException | SAXException | IllegalArgumentException exception) {
            return Result.Unavailable.INSTANCE;
        }

        DomBuilder builder = new DomBuilder(document, maximumDepth, maximumElements,
                maximumAttributes, maximumNameLength);
        try {
            reader.setContentHandler(builder);
            reader.setErrorHandler(builder);
            reader.setEntityResolver(builder);
            reader.setProperty(LEXICAL_HANDLER, builder);
            reader.parse(new InputSource(new ByteArrayInputStream(input)));
            if (document.getDocumentElement() == null) return new Result.Rejected(Reason.MALFORMED);
            return new Result.Accepted(document);
        } catch (LimitExceeded exception) {
            return new Result.Rejected(Reason.STRUCTURE_LIMIT);
        } catch (SAXException | DOMException exception) {
            return new Result.Rejected(Reason.MALFORMED);
        } catch (IOException exception) {
            // The reader has only an in-memory byte array and external resolution is disabled.
            // Xerces also reports attacker-selected unsupported XML encodings as IOException.
            return new Result.Rejected(Reason.MALFORMED);
        }
    }

    /** This result carries no SAML verification authority. */
    public sealed interface Result permits Result.Accepted, Result.Rejected, Result.Unavailable {
        /** A structurally bounded but unverified XML document; callers must not mutate it before verification. */
        final class Accepted implements Result {
            private final @NonNull Document document;

            private Accepted(@NonNull Document document) { this.document = document; }

            public @NonNull Document getDocument() { return document; }

            @Override public @NonNull String toString() { return "SecureXmlParser.Accepted{<unverified>}"; }
        }

        /** Fixed, input-free rejection. */
        final class Rejected implements Result {
            private final @NonNull Reason reason;

            private Rejected(@NonNull Reason reason) { this.reason = reason; }

            public @NonNull Reason getReason() { return reason; }

            @Override public @NonNull String toString() { return "SecureXmlParser.Rejected{" + reason + "}"; }
        }

        /** The required parser configuration could not be established. */
        enum Unavailable implements Result { INSTANCE }
    }

    /** A classification only; no hostile XML or parser message is retained. */
    public enum Reason { INPUT_SIZE, STRUCTURE_LIMIT, MALFORMED }

    private static final class LimitExceeded extends SAXException {
        private static final long serialVersionUID = 1L;
    }

    private static final class DomBuilder extends DefaultHandler2 {
        private final @NonNull Document document;
        private final int maximumDepth;
        private final int maximumElements;
        private final int maximumAttributes;
        private final int maximumNameLength;
        private final @NonNull Set<@NonNull String> identifiers = new HashSet<>();
        private final @NonNull StringBuilder pendingText = new StringBuilder();
        private @NonNull Node parent;
        private int depth;
        private int elements;

        private DomBuilder(@NonNull Document document, int maximumDepth, int maximumElements,
                int maximumAttributes, int maximumNameLength) {
            this.document = document;
            this.parent = document;
            this.maximumDepth = maximumDepth;
            this.maximumElements = maximumElements;
            this.maximumAttributes = maximumAttributes;
            this.maximumNameLength = maximumNameLength;
        }

        @Override public void startElement(@NonNull String uri, @NonNull String localName,
                @NonNull String qName, @NonNull Attributes attributes) throws SAXException {
            if (++depth > maximumDepth || ++elements > maximumElements
                    || qName.isEmpty() || qName.length() > maximumNameLength
                    || localName.length() > maximumNameLength || attributes.getLength() > maximumAttributes)
                throw new LimitExceeded();
            flushText();
            Element element = document.createElementNS(uri.isEmpty() ? null : uri, qName);
            for (int i = 0; i < attributes.getLength(); i++) {
                String name = attributes.getQName(i);
                String local = attributes.getLocalName(i);
                if (name.isEmpty() || name.length() > maximumNameLength || local.length() > maximumNameLength)
                    throw new LimitExceeded();
                String namespace = attributes.getURI(i);
                if (name.equals("xmlns") || name.startsWith("xmlns:"))
                    namespace = XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
                String value = attributes.getValue(i);
                if (local.equals("ID") || local.equals("Id") || local.equals("id")
                        || local.equals("AssertionID")) {
                    if (value.isEmpty() || !identifiers.add(value)) throw new SAXException();
                }
                element.setAttributeNS(namespace.isEmpty() ? null : namespace, name, value);
            }
            parent.appendChild(element);
            parent = element;
        }

        @Override public void endElement(@NonNull String uri, @NonNull String localName,
                @NonNull String qName) {
            flushText();
            parent = requireNonNull(parent.getParentNode());
            depth--;
        }

        @Override public void characters(char @NonNull [] characters, int start, int length) throws SAXException {
            if (length == 0) return;
            if (parent.isSameNode(document)) {
                for (int i = start; i < start + length; i++)
                    if (!Character.isWhitespace(characters[i])) throw new SAXException();
                return;
            }
            pendingText.append(characters, start, length);
        }

        private void flushText() {
            if (pendingText.length() == 0) return;
            parent.appendChild(document.createTextNode(pendingText.toString()));
            pendingText.setLength(0);
        }

        @Override public void processingInstruction(@NonNull String target, @NonNull String data)
                throws SAXException { throw new SAXException(); }

        @Override public void skippedEntity(@NonNull String name) throws SAXException { throw new SAXException(); }

        @Override public void startDTD(@NonNull String name, @Nullable String publicId,
                @Nullable String systemId) throws SAXException { throw new SAXException(); }

        @Override public @NonNull InputSource resolveEntity(@Nullable String publicId,
                @Nullable String systemId) throws SAXException { throw new SAXException(); }

        @Override public @NonNull InputSource resolveEntity(@Nullable String name,
                @Nullable String publicId, @Nullable String baseUri, @Nullable String systemId)
                throws SAXException { throw new SAXException(); }

        @Override public void warning(@NonNull SAXParseException exception) throws SAXException { throw exception; }

        @Override public void error(@NonNull SAXParseException exception) throws SAXException { throw exception; }

        @Override public void fatalError(@NonNull SAXParseException exception) throws SAXException { throw exception; }
    }
}
