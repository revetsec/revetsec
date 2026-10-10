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

import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.SamlXmlWriter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.zip.Deflater;

import static java.util.Objects.requireNonNull;

/** Internal HTTP-Redirect AuthnRequest writer. It keeps the exact signed query octets. */
final class SamlRedirectAuthnRequest {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private static final String SIGALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String HEX = "0123456789ABCDEF";
    private static final int MAXIMUM_XML_BYTES = 16_384;
    private static final int MAXIMUM_COMPRESSED_BYTES = 16_384;

    private SamlRedirectAuthnRequest() { }

    static @NonNull Result prepare(@NonNull String spEntityId, @NonNull URI acs,
            @NonNull URI identityProviderEndpoint, @Nullable PrivateKey signingKey,
            boolean signingRequired, @NonNull SecureRandom random, @NonNull Clock clock,
            @NonNull Duration lifetime) {
        return prepare(spEntityId, acs, identityProviderEndpoint, signingKey,
                signingRequired, random, clock, lifetime, SamlAuthenticationRequestOptions.builder().build());
    }

    static @NonNull Result prepare(@NonNull String spEntityId, @NonNull URI acs,
            @NonNull URI identityProviderEndpoint, @Nullable PrivateKey signingKey,
            boolean signingRequired, @NonNull SecureRandom random, @NonNull Clock clock,
            @NonNull Duration lifetime, @NonNull SamlAuthenticationRequestOptions options) {
        requireNonNull(spEntityId);
        requireNonNull(acs);
        requireNonNull(identityProviderEndpoint);
        requireNonNull(random);
        requireNonNull(clock);
        requireNonNull(lifetime);
        requireNonNull(options);
        if (spEntityId.isEmpty() || spEntityId.length() > 2048 || !https(acs)
                || !https(identityProviderEndpoint) || identityProviderEndpoint.getRawFragment() != null
                || !safeEndpointQuery(identityProviderEndpoint.getRawQuery())
                || lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(Duration.ofMinutes(15)) > 0
                || (signingKey == null && signingRequired)
                || (signingKey != null && (!(signingKey instanceof RSAPrivateKey rsa)
                    || rsa.getModulus().bitLength() < 2048)))
            return new Rejected(Reason.CONFIGURATION);
        Instant now;
        Instant expiresAt;
        try {
            now = clock.instant();
            expiresAt = now.plus(lifetime);
        } catch (RuntimeException exception) { return Unavailable.INSTANCE; }
        byte[] idBytes = new byte[20];
        byte[] relayBytes = new byte[16];
        try {
            random.nextBytes(idBytes);
            random.nextBytes(relayBytes);
        } catch (RuntimeException exception) { return Unavailable.INSTANCE; }
        StringBuilder id = new StringBuilder(41).append('_');
        for (byte value : idBytes) {
            id.append(HEX.charAt((value >>> 4) & 15));
            id.append(HEX.charAt(value & 15));
        }
        String relay = Base64.getUrlEncoder().withoutPadding().encodeToString(relayBytes);
        try {
            byte[] xml = xml(id.toString(), spEntityId, acs.toASCIIString(),
                    identityProviderEndpoint.toASCIIString(), now, options);
            if (xml.length > MAXIMUM_XML_BYTES) return new Rejected(Reason.CONFIGURATION);
            byte[] compressed = deflate(xml);
            if (compressed == null) return new Rejected(Reason.CONFIGURATION);
            String signedQuery = "SAMLRequest=" + percentEncode(Base64.getEncoder().encodeToString(compressed))
                    + "&RelayState=" + percentEncode(relay);
            if (signingKey != null) signedQuery += "&SigAlg=" + percentEncode(SIGALG);
            String query = signedQuery;
            if (signingKey != null) {
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(signingKey);
                signer.update(signedQuery.getBytes(StandardCharsets.US_ASCII));
                query += "&Signature=" + percentEncode(Base64.getEncoder().encodeToString(signer.sign()));
            }
            URI redirect = URI.create(identityProviderEndpoint.toASCIIString()
                    + (identityProviderEndpoint.getRawQuery() == null ? "?" : "&") + query);
            return new Prepared(redirect, id.toString(), relay, now, expiresAt, signingKey != null);
        } catch (GeneralSecurityException | XMLStreamException | IllegalArgumentException exception) {
            return Unavailable.INSTANCE;
        }
    }

    static @NonNull Result preparePost(@NonNull String spEntityId, @NonNull URI acs,
            @NonNull URI identityProviderEndpoint, @Nullable PrivateKey signingKey,
            boolean signingRequired, @NonNull SecureRandom random, @NonNull Clock clock,
            @NonNull Duration lifetime) {
        return preparePost(spEntityId, acs, identityProviderEndpoint, signingKey,
                signingRequired, random, clock, lifetime, SamlAuthenticationRequestOptions.builder().build());
    }

    static @NonNull Result preparePost(@NonNull String spEntityId, @NonNull URI acs,
            @NonNull URI identityProviderEndpoint, @Nullable PrivateKey signingKey,
            boolean signingRequired, @NonNull SecureRandom random, @NonNull Clock clock,
            @NonNull Duration lifetime, @NonNull SamlAuthenticationRequestOptions options) {
        requireNonNull(spEntityId);
        requireNonNull(acs);
        requireNonNull(identityProviderEndpoint);
        requireNonNull(random);
        requireNonNull(clock);
        requireNonNull(lifetime);
        requireNonNull(options);
        if (spEntityId.isEmpty() || spEntityId.length() > 2048 || !https(acs)
                || !https(identityProviderEndpoint) || identityProviderEndpoint.getRawFragment() != null
                || lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(Duration.ofMinutes(15)) > 0
                || (signingKey == null && signingRequired)
                || (signingKey != null && (!(signingKey instanceof RSAPrivateKey rsa)
                    || rsa.getModulus().bitLength() < 2048)))
            return new Rejected(Reason.CONFIGURATION);
        Instant now;
        Instant expiresAt;
        try { now = clock.instant(); expiresAt = now.plus(lifetime); }
        catch (RuntimeException exception) { return Unavailable.INSTANCE; }
        byte[] idBytes = new byte[20];
        byte[] relayBytes = new byte[16];
        try { random.nextBytes(idBytes); random.nextBytes(relayBytes); }
        catch (RuntimeException exception) { return Unavailable.INSTANCE; }
        StringBuilder id = new StringBuilder(41).append('_');
        for (byte value : idBytes) {
            id.append(HEX.charAt((value >>> 4) & 15));
            id.append(HEX.charAt(value & 15));
        }
        String relay = Base64.getUrlEncoder().withoutPadding().encodeToString(relayBytes);
        try {
            byte[] unsigned = xml(id.toString(), spEntityId, acs.toASCIIString(),
                    identityProviderEndpoint.toASCIIString(), now, options);
            byte[] output = signingKey == null ? unsigned : signPostXml(unsigned, id.toString(), signingKey);
            if (output == null || output.length > MAXIMUM_XML_BYTES)
                return new Rejected(Reason.CONFIGURATION);
            return new PostPrepared(new SamlPostForm(identityProviderEndpoint,
                    Base64.getEncoder().encodeToString(output), relay),
                    id.toString(), relay, now, expiresAt);
        } catch (XMLStreamException | GeneralSecurityException | javax.xml.crypto.MarshalException
                | javax.xml.crypto.dsig.XMLSignatureException
                | javax.xml.transform.TransformerException exception) {
            return Unavailable.INSTANCE;
        }
    }

    private static byte @Nullable [] signPostXml(byte @NonNull [] unsigned, @NonNull String id,
            @NonNull PrivateKey signingKey) throws GeneralSecurityException,
            javax.xml.crypto.MarshalException, javax.xml.crypto.dsig.XMLSignatureException,
            javax.xml.transform.TransformerException {
        SecureXmlParser.Result parsed = SecureXmlParser.parseMetadata(unsigned);
        if (!(parsed instanceof SecureXmlParser.Result.Accepted accepted)) return null;
        Document document = accepted.getDocument();
        Element root = document.getDocumentElement();
        root.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + id,
                factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        var signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(signingKey, root);
        context.setDefaultNamespacePrefix("ds");
        Node next = root.getFirstChild().getNextSibling();
        if (next != null) context.setNextSibling(next);
        factory.newXMLSignature(signedInfo, null).sign(context);
        return SamlXmlWriter.serialize(document);
    }

    private static byte @NonNull [] xml(@NonNull String id, @NonNull String entityId, @NonNull String acs,
            @NonNull String destination, @NonNull Instant issuedAt,
            @NonNull SamlAuthenticationRequestOptions options) throws XMLStreamException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        XMLStreamWriter writer = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(bytes, "UTF-8");
        try {
            writer.writeStartDocument("UTF-8", "1.0");
            writer.writeStartElement("samlp", "AuthnRequest", PROTOCOL);
            writer.writeNamespace("samlp", PROTOCOL);
            writer.writeNamespace("saml", ASSERTION);
            writer.writeAttribute("ID", id);
            writer.writeAttribute("Version", "2.0");
            writer.writeAttribute("IssueInstant", issuedAt.toString());
            writer.writeAttribute("Destination", destination);
            writer.writeAttribute("AssertionConsumerServiceURL", acs);
            writer.writeAttribute("ProtocolBinding", POST);
            if (options.isForceAuthn()) writer.writeAttribute("ForceAuthn", "true");
            if (options.isPassive()) writer.writeAttribute("IsPassive", "true");
            writer.writeStartElement("saml", "Issuer", ASSERTION);
            writer.writeCharacters(entityId);
            writer.writeEndElement();
            writer.writeEmptyElement("samlp", "NameIDPolicy", PROTOCOL);
            writer.writeAttribute("AllowCreate", "true");
            if (!options.getRequestedAuthnContextClassRefs().isEmpty()) {
                writer.writeStartElement("samlp", "RequestedAuthnContext", PROTOCOL);
                writer.writeAttribute("Comparison", "exact");
                for (String classRef : options.getRequestedAuthnContextClassRefs()) {
                    writer.writeStartElement("saml", "AuthnContextClassRef", ASSERTION);
                    writer.writeCharacters(classRef);
                    writer.writeEndElement();
                }
                writer.writeEndElement();
            }
            writer.writeEndElement();
            writer.writeEndDocument();
            writer.flush();
        } finally {
            writer.close();
        }
        return bytes.toByteArray();
    }

    private static byte @Nullable [] deflate(byte @NonNull [] xml) {
        Deflater compressor = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            compressor.setInput(xml);
            compressor.finish();
            byte[] output = new byte[MAXIMUM_COMPRESSED_BYTES];
            int used = 0;
            while (!compressor.finished()) {
                if (used == output.length) return null;
                int read = compressor.deflate(output, used, output.length - used);
                if (read <= 0) return null;
                used += read;
            }
            byte[] exact = new byte[used];
            System.arraycopy(output, 0, exact, 0, used);
            return exact;
        } finally {
            compressor.end();
        }
    }

    private static @NonNull String percentEncode(@NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder result = new StringBuilder(bytes.length * 3);
        for (byte valueByte : bytes) {
            int octet = valueByte & 0xff;
            if ((octet >= 'A' && octet <= 'Z') || (octet >= 'a' && octet <= 'z')
                    || (octet >= '0' && octet <= '9') || octet == '-' || octet == '.'
                    || octet == '_' || octet == '~') result.append((char) octet);
            else result.append('%').append(HEX.charAt(octet >>> 4)).append(HEX.charAt(octet & 15));
        }
        return result.toString();
    }

    private static boolean https(@NonNull URI uri) {
        return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                && uri.getRawUserInfo() == null;
    }

    private static boolean safeEndpointQuery(@Nullable String rawQuery) {
        if (rawQuery == null) return true;
        if (rawQuery.length() > 2048) return false;
        for (String field : rawQuery.split("&", -1)) {
            int equals = field.indexOf('=');
            String rawName = equals < 0 ? field : field.substring(0, equals);
            String name;
            try { name = URLDecoder.decode(rawName, StandardCharsets.UTF_8); }
            catch (IllegalArgumentException exception) { return false; }
            if (name.equals("SAMLRequest") || name.equals("SAMLResponse") || name.equals("RelayState")
                    || name.equals("SigAlg") || name.equals("Signature")) return false;
        }
        return true;
    }

    sealed interface Result permits Prepared, PostPrepared, Rejected, Unavailable { }

    static final class Prepared implements Result {
        private final @NonNull URI redirect;
        private final @NonNull String requestId;
        private final @NonNull String relayState;
        private final @NonNull Instant issuedAt;
        private final @NonNull Instant expiresAt;
        private final boolean signed;

        private Prepared(@NonNull URI redirect, @NonNull String requestId, @NonNull String relayState,
                @NonNull Instant issuedAt, @NonNull Instant expiresAt, boolean signed) {
            this.redirect = redirect;
            this.requestId = requestId;
            this.relayState = relayState;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.signed = signed;
        }
        @NonNull URI redirect() { return redirect; }
        @NonNull String requestId() { return requestId; }
        @NonNull String relayState() { return relayState; }
        @NonNull Instant issuedAt() { return issuedAt; }
        @NonNull Instant expiresAt() { return expiresAt; }
        boolean signed() { return signed; }
        @Override public @NonNull String toString() { return "SamlRedirectAuthnRequest.Prepared{<redacted>}"; }
    }

    static final class PostPrepared implements Result {
        private final @NonNull SamlPostForm form;
        private final @NonNull String requestId;
        private final @NonNull String relayState;
        private final @NonNull Instant issuedAt;
        private final @NonNull Instant expiresAt;

        private PostPrepared(@NonNull SamlPostForm form, @NonNull String requestId,
                @NonNull String relayState, @NonNull Instant issuedAt, @NonNull Instant expiresAt) {
            this.form = form;
            this.requestId = requestId;
            this.relayState = relayState;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }
        @NonNull SamlPostForm form() { return form; }
        @NonNull String requestId() { return requestId; }
        @NonNull String relayState() { return relayState; }
        @NonNull Instant issuedAt() { return issuedAt; }
        @NonNull Instant expiresAt() { return expiresAt; }
    }

    static final class Rejected implements Result {
        private final @NonNull Reason reason;
        private Rejected(@NonNull Reason reason) { this.reason = reason; }
        @NonNull Reason reason() { return reason; }
    }

    enum Unavailable implements Result { INSTANCE }
    enum Reason { CONFIGURATION }
}
