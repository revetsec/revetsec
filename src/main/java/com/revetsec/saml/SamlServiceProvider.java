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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.List;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * An immutable SAML 2.0 service provider for SP-initiated HTTP-Redirect login and HTTP-POST
 * assertion response completion. The application owns browser cookies or pending storage,
 * account linking and application sessions. The replay cache is supplied explicitly and must
 * be shared across nodes for a distributed deployment.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class SamlServiceProvider {
    private final @NonNull String entityId;
    private final @NonNull URI assertionConsumerServiceUrl;
    private final @Nullable URI singleLogoutServiceUrl;
    private final @NonNull SamlReplayCache replayCache;
    private final @Nullable PrivateKey signingKey;
    private final @Nullable SamlCredential signingCredential;
    private final @NonNull List<@NonNull SamlCredential> decryptionCredentials;
    private final @NonNull Clock clock;
    private final @NonNull SecureRandom random;
    private final @NonNull Duration clockSkew;
    private final @NonNull Duration maximumResponseAge;
    private final @NonNull Duration pendingLifetime;
    private final @NonNull Duration replayBudget;

    private SamlServiceProvider(@NonNull Builder builder) {
        this.entityId = builder.entityId;
        this.assertionConsumerServiceUrl = Objects.requireNonNull(builder.assertionConsumerServiceUrl);
        this.singleLogoutServiceUrl = builder.singleLogoutServiceUrl;
        this.replayCache = Objects.requireNonNull(builder.replayCache);
        this.signingKey = builder.signingKey;
        this.signingCredential = builder.signingCredential;
        this.decryptionCredentials = List.copyOf(builder.decryptionCredentials);
        this.clock = builder.clock;
        this.random = builder.random;
        this.clockSkew = builder.clockSkew;
        this.maximumResponseAge = builder.maximumResponseAge;
        this.pendingLifetime = builder.pendingLifetime;
        this.replayBudget = builder.replayBudget;
    }

    /**
     * Begins SP configuration with its exact entity ID.
     *
     * @param entityId SP entity ID
     * @return a builder
     * @since 1.0.0
     */
    public static @NonNull Builder withEntityId(@NonNull String entityId) {
        if (Objects.requireNonNull(entityId).isEmpty() || entityId.length() > 2048)
            throw new IllegalArgumentException("Invalid SP entity ID");
        return new Builder(entityId);
    }

    /**
     * Creates one outbound Redirect AuthnRequest with a fresh request ID and RelayState handle.
     * Persist its pending state in the initiating browser before sending the redirect.
     *
     * @param identityProvider approved IdP connection
     * @return a prepared redirect and pending state, rejection, or unavailability
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationRequestResult beginAuthenticationResult(
            @NonNull SamlIdentityProvider identityProvider) {
        return beginAuthenticationResult(identityProvider, SamlAuthenticationRequestOptions.builder().build());
    }

    /**
     * Begins a Redirect AuthnRequest with explicit freshness, context and application state.
     * @param identityProvider approved IdP connection
     * @param options request policy sealed into pending state
     * @return prepared request and pending state, rejection or unavailability
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationRequestResult beginAuthenticationResult(
            @NonNull SamlIdentityProvider identityProvider,
            @NonNull SamlAuthenticationRequestOptions options) {
        Objects.requireNonNull(identityProvider);
        Objects.requireNonNull(options);
        URI endpoint = identityProvider.redirectSingleSignOnService();
        if (endpoint == null) return SamlAuthenticationRequestResult.Rejected.CONFIGURATION;
        SamlRedirectAuthnRequest.Result prepared = SamlRedirectAuthnRequest.prepare(entityId,
                assertionConsumerServiceUrl, endpoint, signingKey,
                identityProvider.wantAuthnRequestsSigned(), random, clock, pendingLifetime, options);
        if (prepared instanceof SamlRedirectAuthnRequest.Rejected)
            return SamlAuthenticationRequestResult.Rejected.CONFIGURATION;
        if (prepared instanceof SamlRedirectAuthnRequest.Unavailable)
            return SamlAuthenticationRequestResult.Unavailable.INSTANCE;
        SamlRedirectAuthnRequest.Prepared request = (SamlRedirectAuthnRequest.Prepared) prepared;
        PendingSamlAuthentication pending = new PendingSamlAuthentication(entityId, request.requestId(),
                request.relayState(), identityProvider.getConnectionId(), identityProvider.getEntityId(),
                assertionConsumerServiceUrl.toASCIIString(), request.issuedAt(), request.expiresAt(), options);
        return new SamlAuthenticationRequestResult.Prepared(request.redirect(), pending);
    }

    /**
     * Begins a POST-binding AuthnRequest. The returned form contains a signed XML request when
     * this SP has a signing key. Persist pending state before delivering the form page.
     *
     * @param identityProvider approved IdP connection with a POST endpoint
     * @return prepared form and pending state, rejection or unavailability
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationRequestResult beginPostAuthenticationResult(
            @NonNull SamlIdentityProvider identityProvider) {
        return beginPostAuthenticationResult(identityProvider, SamlAuthenticationRequestOptions.builder().build());
    }

    /**
     * Begins a POST AuthnRequest with explicit freshness, context and application state.
     * @param identityProvider approved IdP connection with a POST endpoint
     * @param options request policy sealed into pending state
     * @return prepared form and pending state, rejection or unavailability
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationRequestResult beginPostAuthenticationResult(
            @NonNull SamlIdentityProvider identityProvider,
            @NonNull SamlAuthenticationRequestOptions options) {
        Objects.requireNonNull(identityProvider);
        Objects.requireNonNull(options);
        URI endpoint = identityProvider.postSingleSignOnService();
        if (endpoint == null) return SamlAuthenticationRequestResult.Rejected.CONFIGURATION;
        SamlRedirectAuthnRequest.Result prepared = SamlRedirectAuthnRequest.preparePost(entityId,
                assertionConsumerServiceUrl, endpoint, signingKey,
                identityProvider.wantAuthnRequestsSigned(), random, clock, pendingLifetime, options);
        if (prepared instanceof SamlRedirectAuthnRequest.Rejected)
            return SamlAuthenticationRequestResult.Rejected.CONFIGURATION;
        if (prepared instanceof SamlRedirectAuthnRequest.Unavailable)
            return SamlAuthenticationRequestResult.Unavailable.INSTANCE;
        SamlRedirectAuthnRequest.PostPrepared request = (SamlRedirectAuthnRequest.PostPrepared) prepared;
        PendingSamlAuthentication pending = new PendingSamlAuthentication(entityId, request.requestId(),
                request.relayState(), identityProvider.getConnectionId(), identityProvider.getEntityId(),
                assertionConsumerServiceUrl.toASCIIString(), request.issuedAt(), request.expiresAt(), options);
        return new SamlAuthenticationRequestResult.PostPrepared(request.form(), pending);
    }

    /**
     * Completes an SP-initiated login. It authenticates the browser's pending record and RelayState
     * before parsing XML. Identity is returned only after a successful atomic replay insertion.
     * The application clears the pending cookie on every terminal outcome.
     *
     * @param message opaque POST-binding message
     * @param pendingSource pending state received from the initiating browser
     * @param identityProvider approved IdP connection
     * @return a result with identity only on success
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationResult completeAuthenticationResult(@NonNull SamlPostBindingMessage message,
            @NonNull PendingSamlAuthenticationSource pendingSource,
            @NonNull SamlIdentityProvider identityProvider) {
        Objects.requireNonNull(message);
        Objects.requireNonNull(pendingSource);
        Objects.requireNonNull(identityProvider);
        PendingSamlAuthenticationSource.Resolution resolution = pendingSource.resolve(clock,
                message.relayState(), replayBudget);
        if (resolution instanceof PendingSamlAuthenticationSource.Rejected)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.PENDING);
        if (resolution instanceof PendingSamlAuthenticationSource.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        if (resolution instanceof PendingSamlAuthenticationSource.Indeterminate)
            return SamlAuthenticationResult.Indeterminate.INSTANCE;
        PendingSamlAuthentication pending = ((PendingSamlAuthenticationSource.Resolved) resolution).pending();
        Instant now;
        try { now = clock.instant(); }
        catch (RuntimeException exception) { return SamlAuthenticationResult.Unavailable.INSTANCE; }
        if (!entityId.equals(pending.spEntityId()) || !identityProvider.getConnectionId().equals(pending.connectionId())
                || !identityProvider.getEntityId().equals(pending.idpEntityId())
                || !assertionConsumerServiceUrl.toASCIIString().equals(pending.acs())
                || !pending.issuedAt().isBefore(pending.expiresAt()) || !now.isBefore(pending.expiresAt())
                || !sameHandle(pending.relayState(), message.relayState()))
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.PENDING);
        SamlInboundResponse.Result inbound = SamlInboundResponse.parse(message);
        if (inbound instanceof SamlInboundResponse.Rejected)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.MESSAGE);
        if (inbound instanceof SamlInboundResponse.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        SamlInboundResponse.Accepted parsed = (SamlInboundResponse.Accepted) inbound;
        if (parsed.shape().getAssertion() == null && parsed.shape().getEncryptedAssertion() == null)
            return statusResult(parsed, pending, identityProvider, now);
        SamlInboundResponse.SignatureResult signatures = SamlInboundResponse.verifySuccessSignatures(
                parsed, identityProvider.signingKeys(), decryptionKeys(),
                identityProvider.allowAesCbcEncryption(), identityProvider.allowSha1Signatures(), random);
        if (signatures instanceof SamlInboundResponse.SignatureRejected rejected)
            return new SamlAuthenticationResult.Rejected("DECRYPTION".equals(rejected.reason())
                    ? SamlAuthenticationResult.Reason.DECRYPTION : SamlAuthenticationResult.Reason.SIGNATURE);
        if (signatures instanceof SamlInboundResponse.SignatureUnavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        SamlResponseSemantics.Expectation expected = new SamlResponseSemantics.Expectation(entityId,
                identityProvider.getConnectionId(), identityProvider.getEntityId(),
                assertionConsumerServiceUrl.toASCIIString(), pending.requestId(), pending.relayState(),
                pending.expiresAt(), clock, clockSkew, maximumResponseAge,
                identityProvider.requireSignedAssertions(), identityProvider.authorizedIdentifierScopes(),
                replayCache, replayBudget);
        SamlResponseSemantics.Result checked = SamlResponseSemantics.validate(
                (SamlInboundResponse.SignaturesVerified) signatures, expected,
                pending.issuedAt(), pending.options());
        if (checked instanceof SamlResponseSemantics.Rejected rejected)
            return new SamlAuthenticationResult.Rejected(map(rejected.reason()));
        if (checked instanceof SamlResponseSemantics.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        if (checked instanceof SamlResponseSemantics.Indeterminate)
            return SamlAuthenticationResult.Indeterminate.INSTANCE;
        return new SamlAuthenticationResult.Succeeded(new SamlAuthentication(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), (SamlResponseSemantics.Accepted) checked, false),
                pending.getApplicationData().orElse(null));
    }

    /**
     * Completes an IdP-initiated login only for a connection that explicitly enables it.
     * RelayState is rejected and never treated as an application return destination. The
     * assertion age is limited to two minutes before skew.
     *
     * @param message POST-binding message
     * @param identityProvider approved IdP connection
     * @return validated identity or a fixed non-success outcome
     * @since 1.0.0
     */
    public @NonNull SamlAuthenticationResult completeUnsolicitedAuthenticationResult(
            @NonNull SamlPostBindingMessage message, @NonNull SamlIdentityProvider identityProvider) {
        Objects.requireNonNull(message);
        Objects.requireNonNull(identityProvider);
        if (!identityProvider.allowUnsolicitedResponses() || message.relayState() != null)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.REQUEST_BINDING);
        SamlInboundResponse.Result inbound = SamlInboundResponse.parse(message);
        if (inbound instanceof SamlInboundResponse.Rejected)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.MESSAGE);
        if (inbound instanceof SamlInboundResponse.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        SamlInboundResponse.Accepted parsed = (SamlInboundResponse.Accepted) inbound;
        if (parsed.shape().getAssertion() == null && parsed.shape().getEncryptedAssertion() == null)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.STATUS);
        SamlInboundResponse.SignatureResult signatures = SamlInboundResponse.verifySuccessSignatures(parsed,
                identityProvider.signingKeys(), decryptionKeys(), identityProvider.allowAesCbcEncryption(),
                identityProvider.allowSha1Signatures(), random);
        if (signatures instanceof SamlInboundResponse.SignatureRejected rejected)
            return new SamlAuthenticationResult.Rejected("DECRYPTION".equals(rejected.reason())
                    ? SamlAuthenticationResult.Reason.DECRYPTION : SamlAuthenticationResult.Reason.SIGNATURE);
        if (signatures instanceof SamlInboundResponse.SignatureUnavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        Duration age = maximumResponseAge.compareTo(Duration.ofMinutes(2)) < 0
                ? maximumResponseAge : Duration.ofMinutes(2);
        SamlResponseSemantics.Expectation expected = new SamlResponseSemantics.Expectation(entityId,
                identityProvider.getConnectionId(), identityProvider.getEntityId(),
                assertionConsumerServiceUrl.toASCIIString(), null, null, null, clock, clockSkew, age,
                identityProvider.requireSignedAssertions(), identityProvider.authorizedIdentifierScopes(),
                replayCache, replayBudget);
        SamlResponseSemantics.Result checked = SamlResponseSemantics.validate(
                (SamlInboundResponse.SignaturesVerified) signatures, expected);
        if (checked instanceof SamlResponseSemantics.Rejected rejected)
            return new SamlAuthenticationResult.Rejected(map(rejected.reason()));
        if (checked instanceof SamlResponseSemantics.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        if (checked instanceof SamlResponseSemantics.Indeterminate)
            return SamlAuthenticationResult.Indeterminate.INSTANCE;
        return new SamlAuthenticationResult.Succeeded(new SamlAuthentication(identityProvider.getConnectionId(),
                identityProvider.getEntityId(), (SamlResponseSemantics.Accepted) checked, true));
    }

    /**
     * Validates a signed IdP-initiated HTTP-Redirect LogoutRequest. A successful result only
     * identifies sessions; the application remains responsible for ending them.
     *
     * @param message parsed raw-query Redirect message
     * @param identityProvider approved IdP connection
     * @return checked logout request or a fixed failure
     * @since 1.0.0
     */
    public @NonNull SamlLogoutRequestResult acceptLogoutRequestResult(
            @NonNull SamlRedirectBindingMessage message,
            @NonNull SamlIdentityProvider identityProvider) {
        Objects.requireNonNull(message);
        Objects.requireNonNull(identityProvider);
        URI logoutEndpoint = singleLogoutServiceUrl;
        if (logoutEndpoint == null || message.getKind() != SamlRedirectBindingMessage.Kind.REQUEST
                || !message.verify(identityProvider.signingKeys(), identityProvider.allowSha1Signatures()))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        SecureXmlParser.Result parsed = SecureXmlParser.parseResponse(message.xml());
        if (parsed instanceof SecureXmlParser.Result.Unavailable)
            return SamlLogoutRequestResult.Unavailable.INSTANCE;
        if (!(parsed instanceof SecureXmlParser.Result.Accepted accepted))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        Element root = accepted.getDocument().getDocumentElement();
        if (root == null || !SamlResponseStructure.PROTOCOL.equals(root.getNamespaceURI())
                || !"LogoutRequest".equals(root.getLocalName())
                || !"2.0".equals(root.getAttributeNS(null, "Version"))
                || !logoutEndpoint.toASCIIString().equals(root.getAttributeNS(null, "Destination")))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        String id = root.getAttributeNS(null, "ID");
        if (id.isEmpty() || id.length() > 256) return SamlLogoutRequestResult.Rejected.INSTANCE;
        Instant now;
        try { now = clock.instant(); }
        catch (RuntimeException exception) { return SamlLogoutRequestResult.Unavailable.INSTANCE; }
        Instant issued = SamlDateTime.parse(root.getAttributeNS(null, "IssueInstant"));
        if (issued == null || issued.isAfter(now.plus(clockSkew))
                || now.isAfter(issued.plus(maximumResponseAge).plus(clockSkew)))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        if (root.hasAttributeNS(null, "NotOnOrAfter")) {
            Instant expires = SamlDateTime.parse(root.getAttributeNS(null, "NotOnOrAfter"));
            if (expires == null || !now.isBefore(expires)) return SamlLogoutRequestResult.Rejected.INSTANCE;
        }
        Element issuer = null;
        Element nameId = null;
        List<String> sessionIndexes = new ArrayList<>();
        for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (SamlResponseStructure.ASSERTION.equals(element.getNamespaceURI())
                    && "Issuer".equals(element.getLocalName())) {
                if (issuer != null) return SamlLogoutRequestResult.Rejected.INSTANCE;
                issuer = element;
            } else if (SamlResponseStructure.ASSERTION.equals(element.getNamespaceURI())
                    && "NameID".equals(element.getLocalName())) {
                if (nameId != null) return SamlLogoutRequestResult.Rejected.INSTANCE;
                nameId = element;
            } else if (SamlResponseStructure.PROTOCOL.equals(element.getNamespaceURI())
                    && "SessionIndex".equals(element.getLocalName())) {
                String value = textOnly(element);
                if (value == null || value.isEmpty() || value.length() > 2048
                        || sessionIndexes.size() >= 32) return SamlLogoutRequestResult.Rejected.INSTANCE;
                sessionIndexes.add(value);
            } else return SamlLogoutRequestResult.Rejected.INSTANCE;
        }
        if (issuer == null || nameId == null || !identityProvider.getEntityId().equals(textOnly(issuer)))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        String format = issuer.getAttributeNS(null, "Format");
        if (!format.isEmpty() && !"urn:oasis:names:tc:SAML:2.0:nameid-format:entity".equals(format))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        String name = textOnly(nameId);
        if (name == null || name.isEmpty() || name.length() > 4096)
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        String nameFormat = optionalNameIdField(nameId, "Format");
        String nameQualifier = optionalNameIdField(nameId, "NameQualifier");
        String spQualifier = optionalNameIdField(nameId, "SPNameQualifier");
        if (longField(nameFormat) || longField(nameQualifier) || longField(spQualifier))
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        String replayKey;
        try { replayKey = logoutReplayKey(identityProvider, id); }
        catch (NoSuchAlgorithmException exception) { return SamlLogoutRequestResult.Unavailable.INSTANCE; }
        Instant replayExpiry = issued.plus(maximumResponseAge).plus(clockSkew);
        SamlReplayCache.MarkResult mark;
        try { mark = replayCache.markIfAbsent(replayKey, replayExpiry, replayBudget); }
        catch (RuntimeException exception) { return SamlLogoutRequestResult.Indeterminate.INSTANCE; }
        if (mark == null || mark == SamlReplayCache.MarkResult.INDETERMINATE)
            return SamlLogoutRequestResult.Indeterminate.INSTANCE;
        if (mark == SamlReplayCache.MarkResult.ALREADY_PRESENT)
            return SamlLogoutRequestResult.Rejected.INSTANCE;
        if (mark != SamlReplayCache.MarkResult.MARKED)
            return SamlLogoutRequestResult.Unavailable.INSTANCE;
        return new SamlLogoutRequestResult.Accepted(new SamlLogoutRequest(identityProvider.getConnectionId(),
                entityId, identityProvider.getEntityId(), id, message.relayState(),
                new SamlNameId(name, nameFormat, nameQualifier, spQualifier), sessionIndexes));
    }

    /**
     * Begins signed SP-initiated front-channel logout for a stored session reference.
     * The application saves the returned pending state in the initiating browser.
     *
     * @param identityProvider approved IdP connection
     * @param session checked reference retained with the application session
     * @return signed Redirect and pending state, or a fixed failure
     * @since 1.0.0
     */
    public @NonNull SamlLogoutRedirectResult beginLogoutResult(@NonNull SamlIdentityProvider identityProvider,
            @NonNull SamlSessionReference session) {
        Objects.requireNonNull(identityProvider);
        Objects.requireNonNull(session);
        URI destination = identityProvider.redirectSingleLogoutService();
        if (singleLogoutServiceUrl == null || destination == null || signingKey == null
                || !identityProvider.getConnectionId().equals(session.getIdentityProviderConnectionId())
                || !identityProvider.getEntityId().equals(session.getIdentityProviderEntityId()))
            return SamlLogoutRedirectResult.Rejected.CONFIGURATION;
        try {
            Instant now = clock.instant();
            Instant expiry = now.plus(pendingLifetime);
            String id = SamlRedirectLogout.id(random);
            String relay = SamlRedirectLogout.relay(random);
            URI redirect = SamlRedirectLogout.request(destination, entityId, session, id, relay,
                    now, signingKey);
            if (redirect == null) return SamlLogoutRedirectResult.Unavailable.INSTANCE;
            PendingSamlAuthentication fields = new PendingSamlAuthentication(entityId, id, relay,
                    identityProvider.getConnectionId(), identityProvider.getEntityId(),
                    singleLogoutServiceUrl.toASCIIString(), now, expiry);
            return new SamlLogoutRedirectResult.Prepared(redirect, new PendingSamlLogout(fields));
        } catch (RuntimeException exception) { return SamlLogoutRedirectResult.Unavailable.INSTANCE; }
    }

    /**
     * Completes SP-initiated logout after authenticating browser pending state and the signed
     * IdP Redirect response. The application still owns its local session lifecycle.
     *
     * @param message parsed raw-query Redirect message
     * @param pendingSource source bound to the initiating browser
     * @param identityProvider approved IdP connection
     * @return verified IdP status or a fixed failure
     * @since 1.0.0
     */
    public @NonNull SamlLogoutResult completeLogoutResult(@NonNull SamlRedirectBindingMessage message,
            @NonNull PendingSamlLogoutSource pendingSource,
            @NonNull SamlIdentityProvider identityProvider) {
        Objects.requireNonNull(message);
        Objects.requireNonNull(pendingSource);
        Objects.requireNonNull(identityProvider);
        PendingSamlLogoutSource.Resolution resolved = pendingSource.resolve(clock, message.relayState(), replayBudget);
        if (resolved instanceof PendingSamlLogoutSource.Rejected) return SamlLogoutResult.Rejected.INSTANCE;
        if (resolved instanceof PendingSamlLogoutSource.Unavailable) return SamlLogoutResult.Unavailable.INSTANCE;
        if (resolved instanceof PendingSamlLogoutSource.Indeterminate)
            return SamlLogoutResult.Indeterminate.INSTANCE;
        PendingSamlAuthentication pending = ((PendingSamlLogoutSource.Resolved) resolved).pending();
        Instant now;
        try { now = clock.instant(); }
        catch (RuntimeException exception) { return SamlLogoutResult.Unavailable.INSTANCE; }
        if (message.getKind() != SamlRedirectBindingMessage.Kind.RESPONSE
                || singleLogoutServiceUrl == null || !entityId.equals(pending.spEntityId())
                || !singleLogoutServiceUrl.toASCIIString().equals(pending.acs())
                || !identityProvider.getConnectionId().equals(pending.connectionId())
                || !identityProvider.getEntityId().equals(pending.idpEntityId())
                || !now.isBefore(pending.expiresAt())
                || !sameHandle(pending.relayState(), message.relayState()))
            return SamlLogoutResult.Rejected.INSTANCE;
        if (!message.verify(identityProvider.signingKeys(), identityProvider.allowSha1Signatures()))
            return SamlLogoutResult.Rejected.INSTANCE;
        SecureXmlParser.Result parsed = SecureXmlParser.parseResponse(message.xml());
        if (parsed instanceof SecureXmlParser.Result.Unavailable) return SamlLogoutResult.Unavailable.INSTANCE;
        if (!(parsed instanceof SecureXmlParser.Result.Accepted accepted)) return SamlLogoutResult.Rejected.INSTANCE;
        Element root = accepted.getDocument().getDocumentElement();
        if (root == null || !SamlResponseStructure.PROTOCOL.equals(root.getNamespaceURI())
                || !"LogoutResponse".equals(root.getLocalName())
                || !"2.0".equals(root.getAttributeNS(null, "Version"))
                || !singleLogoutServiceUrl.toASCIIString().equals(root.getAttributeNS(null, "Destination"))
                || !pending.requestId().equals(root.getAttributeNS(null, "InResponseTo")))
            return SamlLogoutResult.Rejected.INSTANCE;
        String responseId = root.getAttributeNS(null, "ID");
        if (responseId.isEmpty() || responseId.length() > 256) return SamlLogoutResult.Rejected.INSTANCE;
        Instant issued = SamlDateTime.parse(root.getAttributeNS(null, "IssueInstant"));
        if (issued == null || issued.isAfter(now.plus(clockSkew))
                || now.isAfter(issued.plus(maximumResponseAge).plus(clockSkew)))
            return SamlLogoutResult.Rejected.INSTANCE;
        Element issuer = null;
        Element status = null;
        for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (SamlResponseStructure.ASSERTION.equals(element.getNamespaceURI())
                    && "Issuer".equals(element.getLocalName())) {
                if (issuer != null) return SamlLogoutResult.Rejected.INSTANCE;
                issuer = element;
            } else if (SamlResponseStructure.PROTOCOL.equals(element.getNamespaceURI())
                    && "Status".equals(element.getLocalName())) {
                if (status != null) return SamlLogoutResult.Rejected.INSTANCE;
                status = element;
            } else return SamlLogoutResult.Rejected.INSTANCE;
        }
        if (issuer == null || status == null || !identityProvider.getEntityId().equals(textOnly(issuer)))
            return SamlLogoutResult.Rejected.INSTANCE;
        Element code = null;
        for (Node child = status.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element)) continue;
            if (code != null || !SamlResponseStructure.PROTOCOL.equals(element.getNamespaceURI())
                    || !"StatusCode".equals(element.getLocalName())) return SamlLogoutResult.Rejected.INSTANCE;
            code = element;
        }
        if (code == null || code.getAttributeNS(null, "Value").isEmpty())
            return SamlLogoutResult.Rejected.INSTANCE;
        String replayKey;
        try { replayKey = logoutReplayKey(identityProvider, "response:" + responseId); }
        catch (NoSuchAlgorithmException exception) { return SamlLogoutResult.Unavailable.INSTANCE; }
        SamlReplayCache.MarkResult mark;
        try { mark = replayCache.markIfAbsent(replayKey,
                issued.plus(maximumResponseAge).plus(clockSkew), replayBudget); }
        catch (RuntimeException exception) { return SamlLogoutResult.Indeterminate.INSTANCE; }
        if (mark == null || mark == SamlReplayCache.MarkResult.INDETERMINATE)
            return SamlLogoutResult.Indeterminate.INSTANCE;
        if (mark == SamlReplayCache.MarkResult.ALREADY_PRESENT) return SamlLogoutResult.Rejected.INSTANCE;
        if (mark != SamlReplayCache.MarkResult.MARKED) return SamlLogoutResult.Unavailable.INSTANCE;
        return SamlLogoutStatus.SUCCESS.uri().equals(code.getAttributeNS(null, "Value"))
                ? SamlLogoutResult.Succeeded.INSTANCE : SamlLogoutResult.StatusReceived.NON_SUCCESS;
    }

    /**
     * Prepares a signed response after the application has handled a verified IdP-initiated
     * logout request. The application chooses the status based on its session termination result.
     *
     * @param request checked request returned by this SP
     * @param identityProvider approved IdP connection
     * @param status application-selected outcome
     * @return signed Redirect or fixed failure
     * @since 1.0.0
     */
    public @NonNull SamlLogoutResponseRedirectResult respondToLogoutRequestResult(
            @NonNull SamlLogoutRequest request, @NonNull SamlIdentityProvider identityProvider,
            @NonNull SamlLogoutStatus status) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(identityProvider);
        Objects.requireNonNull(status);
        URI destination = identityProvider.redirectSingleLogoutService();
        if (singleLogoutServiceUrl == null || signingKey == null || destination == null
                || !entityId.equals(request.spEntityId())
                || !identityProvider.getConnectionId().equals(request.getIdentityProviderConnectionId())
                || !identityProvider.getEntityId().equals(request.idpEntityId()))
            return SamlLogoutResponseRedirectResult.Rejected.INSTANCE;
        try {
            URI redirect = SamlRedirectLogout.response(destination, entityId,
                    SamlRedirectLogout.id(random), request.getRequestId(), request.relayState(),
                    clock.instant(), status, signingKey);
            return redirect == null ? SamlLogoutResponseRedirectResult.Unavailable.INSTANCE
                    : new SamlLogoutResponseRedirectResult.Prepared(redirect);
        } catch (RuntimeException exception) { return SamlLogoutResponseRedirectResult.Unavailable.INSTANCE; }
    }

    private @NonNull String logoutReplayKey(@NonNull SamlIdentityProvider idp, @NonNull String requestId)
            throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (String value : List.of("saml-logout-request", entityId, idp.getConnectionId(),
                idp.getEntityId(), requestId)) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
            digest.update(bytes);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    }

    private static @Nullable String optionalNameIdField(@NonNull Element nameId, @NonNull String field) {
        String value = nameId.getAttributeNS(null, field);
        return value.isEmpty() ? null : value;
    }

    private static boolean longField(@Nullable String value) {
        return value != null && value.length() > 2048;
    }

    private @NonNull SamlAuthenticationResult statusResult(SamlInboundResponse.@NonNull Accepted inbound,
            @NonNull PendingSamlAuthentication pending, @NonNull SamlIdentityProvider idp,
            @NonNull Instant now) {
        SamlResponseStructure.Shape shape = inbound.shape();
        if (shape.getEncryptedAssertion() != null)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.MESSAGE);
        Element response = shape.getResponse();
        if (!pending.requestId().equals(response.getAttributeNS(null, "InResponseTo")))
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.REQUEST_BINDING);
        Element issuer = shape.getIssuer();
        if (issuer == null || !idp.getEntityId().equals(textOnly(issuer)))
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.ISSUER);
        String destination = response.getAttributeNS(null, "Destination");
        if (!destination.isEmpty() && !assertionConsumerServiceUrl.toASCIIString().equals(destination))
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.DESTINATION);
        EnvelopedSignatureVerifier.Result proof = SamlInboundResponse.verifyStatusSignature(inbound,
                idp.signingKeys(), idp.allowSha1Signatures());
        if (proof instanceof EnvelopedSignatureVerifier.Unavailable)
            return SamlAuthenticationResult.Unavailable.INSTANCE;
        if (proof instanceof EnvelopedSignatureVerifier.Rejected)
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.SIGNATURE);
        boolean authenticated = proof instanceof EnvelopedSignatureVerifier.Verified;
        if (authenticated && destination.isEmpty())
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.DESTINATION);
        Instant issued = SamlDateTime.parse(response.getAttributeNS(null, "IssueInstant"));
        if (issued == null || issued.isAfter(now.plus(clockSkew))
                || now.isAfter(issued.plus(maximumResponseAge).plus(clockSkew)))
            return new SamlAuthenticationResult.Rejected(SamlAuthenticationResult.Reason.RESPONSE_AGE);
        String code = shape.getStatus().getElementsByTagNameNS(SamlResponseStructure.PROTOCOL,
                "StatusCode").item(0) instanceof Element element
                ? element.getAttributeNS(null, "Value") : "";
        SamlAuthenticationResult.StatusCode classification = switch (code) {
            case "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" ->
                    SamlAuthenticationResult.StatusCode.AUTHN_FAILED;
            case "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" ->
                    SamlAuthenticationResult.StatusCode.NO_AUTHN_CONTEXT;
            case "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" ->
                    SamlAuthenticationResult.StatusCode.REQUEST_DENIED;
            case "urn:oasis:names:tc:SAML:2.0:status:Requester" ->
                    SamlAuthenticationResult.StatusCode.REQUESTER;
            case "urn:oasis:names:tc:SAML:2.0:status:Responder" ->
                    SamlAuthenticationResult.StatusCode.RESPONDER;
            case "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" ->
                    SamlAuthenticationResult.StatusCode.VERSION_MISMATCH;
            default -> SamlAuthenticationResult.StatusCode.OTHER;
        };
        return new SamlAuthenticationResult.StatusReceived(classification, authenticated);
    }

    private static @Nullable String textOnly(@NonNull Element element) {
        StringBuilder text = new StringBuilder();
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.TEXT_NODE) return null;
            text.append(child.getNodeValue());
        }
        return text.toString();
    }

    private static SamlAuthenticationResult.@NonNull Reason map(SamlResponseSemantics.@NonNull Reason reason) {
        return switch (reason) {
            case PENDING -> SamlAuthenticationResult.Reason.PENDING;
            case COVERAGE -> SamlAuthenticationResult.Reason.SIGNATURE;
            case ISSUER -> SamlAuthenticationResult.Reason.ISSUER;
            case DESTINATION -> SamlAuthenticationResult.Reason.DESTINATION;
            case REQUEST_BINDING -> SamlAuthenticationResult.Reason.REQUEST_BINDING;
            case STATUS -> SamlAuthenticationResult.Reason.STATUS;
            case SUBJECT -> SamlAuthenticationResult.Reason.SUBJECT;
            case CONFIRMATION -> SamlAuthenticationResult.Reason.CONFIRMATION;
            case CONDITIONS -> SamlAuthenticationResult.Reason.CONDITIONS;
            case AUTHN_STATEMENT -> SamlAuthenticationResult.Reason.AUTHN_STATEMENT;
            case RESPONSE_AGE -> SamlAuthenticationResult.Reason.RESPONSE_AGE;
            case REPLAYED -> SamlAuthenticationResult.Reason.REPLAYED;
            case ASSERTION_SHAPE -> SamlAuthenticationResult.Reason.ASSERTION_SHAPE;
        };
    }

    private static boolean sameHandle(@NonNull String expected, @Nullable String actual) {
        return actual != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    @Nullable SamlCredential signingCredential() { return signingCredential; }
    @NonNull List<@NonNull SamlCredential> decryptionCredentials() { return decryptionCredentials; }
    private @NonNull List<@NonNull PrivateKey> decryptionKeys() {
        List<PrivateKey> keys = new ArrayList<>();
        for (SamlCredential credential : decryptionCredentials) keys.add(credential.privateKey());
        return List.copyOf(keys);
    }
    @NonNull String entityId() { return entityId; }
    @NonNull URI assertionConsumerServiceUrl() { return assertionConsumerServiceUrl; }
    @Nullable URI singleLogoutServiceUrl() { return singleLogoutServiceUrl; }

    /**
     * Redacts configuration and keys.
     *
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlServiceProvider{<redacted>}"; }

    /**
     * Mutable configuration before creating an immutable SP.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String entityId;
        private @Nullable URI assertionConsumerServiceUrl;
        private @Nullable URI singleLogoutServiceUrl;
        private @Nullable SamlReplayCache replayCache;
        private @Nullable PrivateKey signingKey;
        private @Nullable SamlCredential signingCredential;
        private @NonNull List<@NonNull SamlCredential> decryptionCredentials = List.of();
        private @NonNull Clock clock = Clock.systemUTC();
        private @NonNull SecureRandom random = new SecureRandom();
        private @NonNull Duration clockSkew = Duration.ofMinutes(3);
        private @NonNull Duration maximumResponseAge = Duration.ofMinutes(5);
        private @NonNull Duration pendingLifetime = Duration.ofMinutes(5);
        private @NonNull Duration replayBudget = Duration.ofSeconds(5);

        private Builder(@NonNull String entityId) { this.entityId = entityId; }

        /**
         * Configures this option.
         *
         * @param value HTTPS ACS URL
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder assertionConsumerServiceUrl(@Nullable URI value) {
            this.assertionConsumerServiceUrl = value;
            return this;
        }
        /**
         * Configures the public SP HTTP-Redirect logout receiver.
         *
         * @param value HTTPS logout URI, or null to disable SLO
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder singleLogoutServiceUrl(@Nullable URI value) {
            this.singleLogoutServiceUrl = value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value explicitly selected replay cache
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder replayCache(@Nullable SamlReplayCache value) {
            this.replayCache = value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value optional RSA signing key for Redirect AuthnRequests
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder signingPrivateKey(@Nullable PrivateKey value) {
            this.signingKey = value;
            this.signingCredential = null;
            return this;
        }
        /**
         * Configures a signing key and certificate for requests and metadata.
         *
         * @param value signing credential, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder signingCredential(@Nullable SamlCredential value) {
            this.signingCredential = value;
            this.signingKey = value == null ? null : value.privateKey();
            return this;
        }
        /**
         * Configures decryption credentials, including rollover keys.
         *
         * @param value credentials, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder decryptionCredentials(
                @Nullable List<@NonNull SamlCredential> value) {
            this.decryptionCredentials = value == null ? List.of() : List.copyOf(value);
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value validation clock, or null to reset to system UTC
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder clock(@Nullable Clock value) {
            this.clock = value == null ? Clock.systemUTC() : value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value cryptographic random source, or null for a new default
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder random(@Nullable SecureRandom value) {
            this.random = value == null ? new SecureRandom() : value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value skew from zero to five minutes, or null for three minutes
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder clockSkew(@Nullable Duration value) {
            this.clockSkew = value == null ? Duration.ofMinutes(3) : value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value assertion age from one second to fifteen minutes, or null for five minutes
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder maximumResponseAge(@Nullable Duration value) {
            this.maximumResponseAge = value == null ? Duration.ofMinutes(5) : value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value pending lifetime from one second to fifteen minutes, or null for five minutes
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder pendingAuthenticationLifetime(@Nullable Duration value) {
            this.pendingLifetime = value == null ? Duration.ofMinutes(5) : value;
            return this;
        }
        /**
         * Configures this option.
         *
         * @param value replay operation budget from one millisecond to thirty seconds
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder replayBudget(@Nullable Duration value) {
            this.replayBudget = value == null ? Duration.ofSeconds(5) : value;
            return this;
        }

        /**
         * Returns this value.
         *
         * @return immutable SP configuration
         * @since 1.0.0
         */
        public @NonNull SamlServiceProvider build() {
            URI acs = assertionConsumerServiceUrl;
            if (acs == null || !"https".equalsIgnoreCase(acs.getScheme()) || acs.getHost() == null
                    || acs.getRawUserInfo() != null || acs.getRawFragment() != null)
                throw new IllegalStateException("HTTPS ACS URL is required");
            if (singleLogoutServiceUrl != null
                    && (!"https".equalsIgnoreCase(singleLogoutServiceUrl.getScheme())
                        || singleLogoutServiceUrl.getHost() == null
                        || singleLogoutServiceUrl.getRawUserInfo() != null
                        || singleLogoutServiceUrl.getRawFragment() != null))
                throw new IllegalStateException("Invalid HTTPS SAML logout URL");
            if (singleLogoutServiceUrl != null && signingKey == null)
                throw new IllegalStateException("SAML logout requires a signing key");
            if (replayCache == null) throw new IllegalStateException("SAML replay cache is required");
            if (decryptionCredentials.size() > 4)
                throw new IllegalStateException("Too many SAML decryption credentials");
            if (signingKey != null && (!(signingKey instanceof RSAPrivateKey rsa)
                    || rsa.getModulus().bitLength() < 2048))
                throw new IllegalStateException("Unsupported or weak SAML signing key");
            if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(5)) > 0
                    || maximumResponseAge.compareTo(Duration.ofSeconds(1)) < 0
                    || maximumResponseAge.compareTo(Duration.ofMinutes(15)) > 0
                    || pendingLifetime.compareTo(Duration.ofSeconds(1)) < 0
                    || pendingLifetime.compareTo(Duration.ofMinutes(15)) > 0
                    || replayBudget.compareTo(Duration.ofMillis(1)) < 0
                    || replayBudget.compareTo(Duration.ofSeconds(30)) > 0)
                throw new IllegalStateException("Invalid SAML time policy");
            return new SamlServiceProvider(this);
        }
    }
}
