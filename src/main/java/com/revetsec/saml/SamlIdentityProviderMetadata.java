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
import com.revetsec.internal.xml.EnvelopedSignatureVerifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.annotation.concurrent.Immutable;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One bounded, application-supplied SAML IdP metadata descriptor. No network fetch occurs and
 * parsing does not approve the entity as an application connection.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlIdentityProviderMetadata {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SHIBMD = "urn:mace:shibboleth:metadata:1.0";
    private static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    private final @NonNull String entityId;
    private final @Nullable URI redirectSso;
    private final @Nullable URI postSso;
    private final @Nullable URI redirectSlo;
    private final @NonNull List<@NonNull X509Certificate> signingCertificates;
    private final boolean wantAuthnRequestsSigned;
    private final @Nullable Instant validUntil;
    private final @NonNull List<@NonNull String> authorizedScopes;

    private SamlIdentityProviderMetadata(@NonNull String entityId, @Nullable URI redirectSso,
            @Nullable URI postSso, @Nullable URI redirectSlo,
            @NonNull List<@NonNull X509Certificate> signingCertificates,
            boolean wantAuthnRequestsSigned, @Nullable Instant validUntil,
            @NonNull List<@NonNull String> authorizedScopes) {
        this.entityId = entityId;
        this.redirectSso = redirectSso;
        this.postSso = postSso;
        this.redirectSlo = redirectSlo;
        this.signingCertificates = List.copyOf(signingCertificates);
        this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
        this.validUntil = validUntil;
        this.authorizedScopes = List.copyOf(authorizedScopes);
    }

    /**
     * Parses a single EntityDescriptor using the system UTC clock.
     *
     * @param xml application-supplied metadata bytes
     * @return parsed metadata or a fixed failure
     * @since 1.0.0
     */
    public static @NonNull SamlIdentityProviderMetadataResult fromXmlResult(byte @NonNull [] xml) {
        return fromXmlResult(xml, null, Clock.systemUTC());
    }

    /**
     * Selects one entity from a single or aggregate descriptor using the system UTC clock.
     *
     * @param xml application-supplied metadata bytes
     * @param expectedEntityId exact entity ID to select
     * @return parsed metadata or a fixed failure
     * @since 1.0.0
     */
    public static @NonNull SamlIdentityProviderMetadataResult fromXmlResult(byte @NonNull [] xml,
            @NonNull String expectedEntityId) {
        return fromXmlResult(xml, Objects.requireNonNull(expectedEntityId), Clock.systemUTC());
    }

    /**
     * Parses metadata with an explicit validation clock.
     *
     * @param xml application-supplied metadata bytes
     * @param expectedEntityId exact entity ID for aggregate selection, or null for a single descriptor
     * @param clock validation clock
     * @return parsed metadata or a fixed failure
     * @since 1.0.0
     */
    public static @NonNull SamlIdentityProviderMetadataResult fromXmlResult(byte @NonNull [] xml,
            @Nullable String expectedEntityId, @NonNull Clock clock) {
        return parse(xml, expectedEntityId, clock, null);
    }

    /**
     * Parses metadata only when a pinned trusted key verifies a signature covering the selected
     * entity or its containing aggregate. Embedded KeyInfo is never a trust anchor.
     *
     * @param xml application-supplied metadata bytes
     * @param expectedEntityId exact entity ID for aggregate selection, or null for a single descriptor
     * @param clock validation clock
     * @param trustedMetadataKeys one to four application-pinned verification keys
     * @return parsed metadata or a fixed failure
     * @since 1.0.0
     */
    public static @NonNull SamlIdentityProviderMetadataResult fromXmlResult(byte @NonNull [] xml,
            @Nullable String expectedEntityId, @NonNull Clock clock,
            @NonNull List<@NonNull PublicKey> trustedMetadataKeys) {
        Objects.requireNonNull(trustedMetadataKeys);
        if (trustedMetadataKeys.isEmpty() || trustedMetadataKeys.size() > 4
                || trustedMetadataKeys.stream().anyMatch(key -> key == null))
            throw new IllegalArgumentException("Expected one to four pinned metadata keys");
        return parse(xml, expectedEntityId, clock, trustedMetadataKeys);
    }

    private static @NonNull SamlIdentityProviderMetadataResult parse(byte @NonNull [] xml,
            @Nullable String expectedEntityId, @NonNull Clock clock,
            @Nullable List<@NonNull PublicKey> trustedMetadataKeys) {
        Objects.requireNonNull(xml);
        Objects.requireNonNull(clock);
        SecureXmlParser.Result parsed = SecureXmlParser.parseMetadata(xml);
        if (parsed instanceof SecureXmlParser.Result.Rejected)
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        if (parsed instanceof SecureXmlParser.Result.Unavailable)
            return SamlIdentityProviderMetadataResult.Unavailable.INSTANCE;
        Instant now;
        try { now = clock.instant(); }
        catch (RuntimeException exception) { return SamlIdentityProviderMetadataResult.Unavailable.INSTANCE; }
        Element root = ((SecureXmlParser.Result.Accepted) parsed).getDocument().getDocumentElement();
        if (root == null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        Element entity = root;
        Instant aggregateLimit = null;
        if (is(root, MD, "EntitiesDescriptor")) {
            if (expectedEntityId == null || expectedEntityId.isEmpty())
                return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
            aggregateLimit = validity(root, now);
            if (root.hasAttributeNS(null, "validUntil") && aggregateLimit == null)
                return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
            entity = null;
            boolean aggregateSignature = false;
            boolean sawEntity = false;
            for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (!(child instanceof Element candidate)) continue;
                if (is(candidate, DS, "Signature")) {
                    if (aggregateSignature || sawEntity)
                        return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    aggregateSignature = true;
                    continue;
                }
                if (!is(candidate, MD, "EntityDescriptor"))
                    return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                sawEntity = true;
                if (expectedEntityId.equals(candidate.getAttributeNS(null, "entityID"))) {
                    if (entity != null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    entity = candidate;
                }
            }
        }
        if (entity == null || !is(entity, MD, "EntityDescriptor"))
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        String entityId = entity.getAttributeNS(null, "entityID");
        if (entityId.isEmpty() || entityId.length() > 2048
                || (expectedEntityId != null && !expectedEntityId.equals(entityId)))
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        if (trustedMetadataKeys != null) {
            Element signed = !root.isSameNode(entity) && directSignature(root) ? root : entity;
            EnvelopedSignatureVerifier.Result proof = EnvelopedSignatureVerifier.verifyMetadata(
                    (SecureXmlParser.Result.Accepted) parsed, signed, trustedMetadataKeys);
            if (proof instanceof EnvelopedSignatureVerifier.Unavailable)
                return SamlIdentityProviderMetadataResult.Unavailable.INSTANCE;
            if (!(proof instanceof EnvelopedSignatureVerifier.Verified))
                return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        }
        Instant entityLimit = validity(entity, now);
        if (entity.hasAttributeNS(null, "validUntil") && entityLimit == null)
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        Instant validUntil = entityLimit == null ? aggregateLimit
                : aggregateLimit == null || entityLimit.isBefore(aggregateLimit) ? entityLimit : aggregateLimit;
        Element descriptor = null;
        for (Node child = entity.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element candidate)) continue;
            if (is(candidate, MD, "IDPSSODescriptor")) {
                if (descriptor != null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                descriptor = candidate;
            }
        }
        if (descriptor == null || !descriptor.getAttributeNS(null, "protocolSupportEnumeration")
                .matches("(?:^|.*\\s)urn:oasis:names:tc:SAML:2\\.0:protocol(?:\\s.*|$)"))
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        URI redirect = null;
        URI post = null;
        URI logout = null;
        List<X509Certificate> certificates = new ArrayList<>();
        List<String> scopes = new ArrayList<>();
        for (Node child = descriptor.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (is(element, MD, "SingleSignOnService")) {
                String binding = element.getAttributeNS(null, "Binding");
                if (!REDIRECT.equals(binding) && !POST.equals(binding)) continue;
                URI location = endpoint(element.getAttributeNS(null, "Location"));
                if (location == null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                if (REDIRECT.equals(binding)) {
                    if (redirect != null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    redirect = location;
                } else if (POST.equals(binding)) {
                    if (post != null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    post = location;
                }
            } else if (is(element, MD, "SingleLogoutService")
                    && REDIRECT.equals(element.getAttributeNS(null, "Binding"))) {
                if (logout != null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                logout = endpoint(element.getAttributeNS(null, "Location"));
                if (logout == null) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
            } else if (is(element, MD, "KeyDescriptor")) {
                String use = element.getAttributeNS(null, "use");
                if (!use.isEmpty() && !"signing".equals(use) && !"encryption".equals(use))
                    return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                if (!"encryption".equals(use)) {
                    X509Certificate certificate = certificate(element);
                    if (certificate == null || certificates.size() >= 8)
                        return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    certificates.add(certificate);
                }
            } else if (is(element, MD, "Extensions")) {
                for (Node extension = element.getFirstChild(); extension != null;
                        extension = extension.getNextSibling()) {
                    if (!(extension instanceof Element scope) || !is(scope, SHIBMD, "Scope")) continue;
                    if ("true".equals(scope.getAttributeNS(null, "regexp"))) continue;
                    String literal = textOnly(scope);
                    if (literal == null || literal.isEmpty() || literal.length() > 255
                            || literal.contains("@") || literal.contains("*") || literal.contains(" ")
                            || scopes.size() >= 32) return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
                    scopes.add(literal);
                }
            }
        }
        if ((redirect == null && post == null) || certificates.isEmpty())
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        String wants = descriptor.getAttributeNS(null, "WantAuthnRequestsSigned");
        if (!wants.isEmpty() && !wants.equals("true") && !wants.equals("false")
                && !wants.equals("1") && !wants.equals("0"))
            return SamlIdentityProviderMetadataResult.Rejected.INSTANCE;
        return new SamlIdentityProviderMetadataResult.Parsed(new SamlIdentityProviderMetadata(entityId,
                redirect, post, logout, certificates, wants.equals("true") || wants.equals("1"),
                validUntil, scopes));
    }

    private static @Nullable Instant validity(@NonNull Element element, @NonNull Instant now) {
        if (!element.hasAttributeNS(null, "validUntil")) return null;
        Instant until = SamlDateTime.parse(element.getAttributeNS(null, "validUntil"));
        return until != null && now.isBefore(until) ? until : null;
    }

    private static boolean directSignature(@NonNull Element element) {
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element candidate && is(candidate, DS, "Signature")) return true;
        return false;
    }

    private static @Nullable URI endpoint(@NonNull String text) {
        try {
            URI value = URI.create(text);
            return "https".equalsIgnoreCase(value.getScheme()) && value.getHost() != null
                    && value.getRawUserInfo() == null && value.getRawFragment() == null ? value : null;
        } catch (IllegalArgumentException exception) { return null; }
    }

    private static @Nullable X509Certificate certificate(@NonNull Element descriptor) {
        Element keyInfo = onlyChild(descriptor, DS, "KeyInfo");
        Element data = keyInfo == null ? null : onlyChild(keyInfo, DS, "X509Data");
        Element encoded = null;
        if (data != null) for (Node child = data.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element certificate && is(certificate, DS, "X509Certificate")) {
                encoded = certificate;
                break;
            }
        }
        if (encoded == null) return null;
        String value = encoded.getTextContent().replaceAll("[ \\t\\r\\n]", "");
        if (value.isEmpty() || value.length() > 32768) return null;
        try {
            byte[] der = Base64.getDecoder().decode(value);
            if (der.length > 24576) return null;
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (IllegalArgumentException | CertificateException exception) { return null; }
    }

    private static @Nullable Element onlyChild(@NonNull Element parent, @NonNull String namespace,
            @NonNull String local) {
        Element match = null;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element candidate)) continue;
            if (is(candidate, namespace, local)) {
                if (match != null) return null;
                match = candidate;
            }
        }
        return match;
    }

    private static boolean is(@NonNull Element element, @NonNull String namespace, @NonNull String local) {
        return namespace.equals(element.getNamespaceURI()) && local.equals(element.getLocalName());
    }

    private static @Nullable String textOnly(@NonNull Element element) {
        StringBuilder value = new StringBuilder();
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.TEXT_NODE) return null;
            value.append(child.getNodeValue());
        }
        return value.toString();
    }

    /**
     * Returns the selected IdP entity ID.
     *
     * @return entity ID
     * @since 1.0.0
     */
    public @NonNull String getEntityId() { return entityId; }
    /**
     * Returns the Redirect SSO endpoint when advertised.
     *
     * @return optional endpoint
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getRedirectSingleSignOnService() {
        return Optional.ofNullable(redirectSso);
    }
    /**
     * Returns the POST SSO endpoint when advertised.
     *
     * @return optional endpoint
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getPostSingleSignOnService() { return Optional.ofNullable(postSso); }
    /**
     * Returns the HTTP-Redirect SLO endpoint when advertised.
     *
     * @return optional endpoint
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getRedirectSingleLogoutService() {
        return Optional.ofNullable(redirectSlo);
    }
    /**
     * Returns signing certificates from this metadata, including rollover certificates.
     *
     * @return immutable certificate list
     * @since 1.0.0
     */
    public @NonNull List<@NonNull X509Certificate> getSigningCertificates() {
        return signingCertificates;
    }
    /**
     * Reports whether the IdP requests signed AuthnRequests.
     *
     * @return true if requested
     * @since 1.0.0
     */
    public @NonNull Boolean wantsAuthnRequestsSigned() { return wantAuthnRequestsSigned; }
    /**
     * Returns the earliest metadata expiry when present.
     *
     * @return optional expiry
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Instant> getValidUntil() { return Optional.ofNullable(validUntil); }
    /**
     * Returns literal identifier scopes advertised by this metadata. The application still
     * approves the scopes before building a connection.
     *
     * @return immutable literal scopes
     * @since 1.0.0
     */
    public @NonNull List<@NonNull String> getAuthorizedIdentifierScopes() { return authorizedScopes; }
    /**
     * Redacts certificate and endpoint data.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlIdentityProviderMetadata{<redacted>}"; }
}
