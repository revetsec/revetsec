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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Objects;

/**
 * Local SP metadata publication. It advertises only capabilities that the SP can actually use.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlServiceProviderMetadata {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    private SamlServiceProviderMetadata() { }

    /**
     * Produces one EntityDescriptor. A signing certificate is required, and encryption is never
     * advertised until the configured engine can complete the corresponding profile.
     *
     * @param serviceProvider immutable SP configuration
     * @return generated metadata or a fixed failure
     * @since 1.0.0
     */
    public static @NonNull SamlServiceProviderMetadataResult fromServiceProviderResult(
            @NonNull SamlServiceProvider serviceProvider) {
        Objects.requireNonNull(serviceProvider);
        SamlCredential signing = serviceProvider.signingCredential();
        if (signing == null)
            return SamlServiceProviderMetadataResult.Rejected.CONFIGURATION;
        byte[] certificate;
        try { certificate = signing.getCertificate().getEncoded(); }
        catch (CertificateEncodingException exception) {
            return SamlServiceProviderMetadataResult.Unavailable.INSTANCE;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            XMLStreamWriter xml = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(bytes, "UTF-8");
            try {
                xml.writeStartDocument("UTF-8", "1.0");
                xml.writeStartElement("md", "EntityDescriptor", MD);
                xml.writeNamespace("md", MD);
                xml.writeNamespace("ds", DS);
                xml.writeAttribute("entityID", serviceProvider.entityId());
                xml.writeStartElement("md", "SPSSODescriptor", MD);
                xml.writeAttribute("protocolSupportEnumeration", PROTOCOL);
                xml.writeAttribute("AuthnRequestsSigned", "true");
                xml.writeAttribute("WantAssertionsSigned", "false");
                xml.writeStartElement("md", "KeyDescriptor", MD);
                xml.writeAttribute("use", "signing");
                xml.writeStartElement("ds", "KeyInfo", DS);
                xml.writeStartElement("ds", "X509Data", DS);
                xml.writeStartElement("ds", "X509Certificate", DS);
                xml.writeCharacters(Base64.getEncoder().encodeToString(certificate));
                xml.writeEndElement();
                xml.writeEndElement();
                xml.writeEndElement();
                xml.writeEndElement();
                for (SamlCredential decryption : serviceProvider.decryptionCredentials()) {
                    xml.writeStartElement("md", "KeyDescriptor", MD);
                    xml.writeAttribute("use", "encryption");
                    xml.writeStartElement("ds", "KeyInfo", DS);
                    xml.writeStartElement("ds", "X509Data", DS);
                    xml.writeStartElement("ds", "X509Certificate", DS);
                    xml.writeCharacters(Base64.getEncoder().encodeToString(
                            decryption.getCertificate().getEncoded()));
                    xml.writeEndElement();
                    xml.writeEndElement();
                    xml.writeEndElement();
                    xml.writeEmptyElement("md", "EncryptionMethod", MD);
                    xml.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#aes128-gcm");
                    xml.writeEmptyElement("md", "EncryptionMethod", MD);
                    xml.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#aes192-gcm");
                    xml.writeEmptyElement("md", "EncryptionMethod", MD);
                    xml.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-gcm");
                    xml.writeEmptyElement("md", "EncryptionMethod", MD);
                    xml.writeAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#rsa-oaep");
                    xml.writeEndElement();
                }
                URI logoutUrl = serviceProvider.singleLogoutServiceUrl();
                if (logoutUrl != null) {
                    xml.writeEmptyElement("md", "SingleLogoutService", MD);
                    xml.writeAttribute("Binding",
                            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
                    xml.writeAttribute("Location", logoutUrl.toASCIIString());
                }
                xml.writeEmptyElement("md", "AssertionConsumerService", MD);
                xml.writeAttribute("Binding", POST);
                xml.writeAttribute("Location", serviceProvider.assertionConsumerServiceUrl().toASCIIString());
                xml.writeAttribute("index", "0");
                xml.writeAttribute("isDefault", "true");
                xml.writeEndElement();
                xml.writeEndElement();
                xml.writeEndDocument();
                xml.flush();
            } finally { xml.close(); }
            return new SamlServiceProviderMetadataResult.Generated(bytes.toString(StandardCharsets.UTF_8));
        } catch (XMLStreamException | CertificateEncodingException | RuntimeException exception) {
            return SamlServiceProviderMetadataResult.Unavailable.INSTANCE;
        }
    }
}
