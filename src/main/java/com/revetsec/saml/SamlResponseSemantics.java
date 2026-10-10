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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Internal signed SSO semantic boundary. It accepts only the original nodes checked by the signature stage, and
 * writes the replay key after every other validation. Public SP configuration, metadata, encryption and SLO remain
 * separate work; callers must authenticate pending state before constructing an expectation.
 */
final class SamlResponseSemantics {
    private static final String ASSERTION = SamlResponseStructure.ASSERTION;
    private static final String PROTOCOL = SamlResponseStructure.PROTOCOL;
    private static final String BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    private static final String ENTITY_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String XSI = "http://www.w3.org/2001/XMLSchema-instance";
    private static final String XSD = "http://www.w3.org/2001/XMLSchema";

    private SamlResponseSemantics() { }

    /** A trusted pending and IdP context, to be constructed only after pending-state authentication. */
    record Expectation(@NonNull String spEntityId, @NonNull String connectionId,
            @NonNull String idpEntityId, @NonNull String assertionConsumerServiceUrl,
            @Nullable String requestId, @Nullable String relayState, @Nullable Instant pendingExpiresAt,
            @NonNull Clock clock, @NonNull Duration skew, @NonNull Duration maximumResponseAge,
            boolean requireSignedAssertion, @NonNull List<@NonNull String> authorizedIdentifierScopes,
            @NonNull SamlReplayCache replayCache,
            @NonNull Duration replayBudget) {
        Expectation {
            requireNonNull(spEntityId);
            requireNonNull(connectionId);
            requireNonNull(idpEntityId);
            requireNonNull(assertionConsumerServiceUrl);
            requireNonNull(clock);
            requireNonNull(skew);
            requireNonNull(maximumResponseAge);
            requireNonNull(replayCache);
            authorizedIdentifierScopes = List.copyOf(authorizedIdentifierScopes);
            requireNonNull(replayBudget);
            if (spEntityId.isEmpty() || connectionId.isEmpty() || idpEntityId.isEmpty()
                    || assertionConsumerServiceUrl.isEmpty() || skew.isNegative()
                    || maximumResponseAge.isZero() || maximumResponseAge.isNegative()
                    || replayBudget.isZero() || replayBudget.isNegative()
                    || (requestId == null) != (relayState == null)
                    || (requestId == null) != (pendingExpiresAt == null))
                throw new IllegalArgumentException("Invalid trusted SAML expectation");
        }
    }

    sealed interface Result permits Accepted, Rejected, Unavailable, Indeterminate { }

    /** Checked identity fields from the single covered assertion. No raw XML escapes this internal result. */
    static final class Accepted implements Result {
        private final @NonNull String assertionId;
        private final @NonNull SamlNameId nameId;
        private final @NonNull Instant authnInstant;
        private final @Nullable String sessionIndex;
        private final @Nullable Instant sessionNotOnOrAfter;
        private final @Nullable String authnContextClassRef;
        private final @NonNull List<@NonNull SamlAttribute> attributes;
        private final @Nullable String subjectId;
        private final @Nullable String pairwiseId;
        private final @NonNull Instant expiresAt;
        private final boolean responseSigned;
        private final boolean assertionSigned;
        private final boolean encrypted;

        private Accepted(@NonNull String assertionId, @NonNull SamlNameId nameId,
                @NonNull AuthenticationCheck authentication, @NonNull List<@NonNull SamlAttribute> attributes,
                @Nullable String subjectId, @Nullable String pairwiseId,
                @NonNull Instant expiresAt,
                boolean responseSigned, boolean assertionSigned, boolean encrypted) {
            this.assertionId = assertionId;
            this.nameId = nameId;
            this.authnInstant = authentication.instant();
            this.sessionIndex = authentication.sessionIndex();
            this.sessionNotOnOrAfter = authentication.sessionNotOnOrAfter();
            this.authnContextClassRef = authentication.contextClassRef();
            this.attributes = List.copyOf(attributes);
            this.subjectId = subjectId;
            this.pairwiseId = pairwiseId;
            this.expiresAt = expiresAt;
            this.responseSigned = responseSigned;
            this.assertionSigned = assertionSigned;
            this.encrypted = encrypted;
        }

        @NonNull String assertionId() { return assertionId; }
        @NonNull SamlNameId nameId() { return nameId; }
        @NonNull Instant authnInstant() { return authnInstant; }
        @Nullable String sessionIndex() { return sessionIndex; }
        @Nullable Instant sessionNotOnOrAfter() { return sessionNotOnOrAfter; }
        @Nullable String authnContextClassRef() { return authnContextClassRef; }
        @NonNull List<@NonNull SamlAttribute> attributes() { return attributes; }
        @Nullable String subjectId() { return subjectId; }
        @Nullable String pairwiseId() { return pairwiseId; }
        @NonNull Instant expiresAt() { return expiresAt; }
        boolean responseSigned() { return responseSigned; }
        boolean assertionSigned() { return assertionSigned; }
        boolean encrypted() { return encrypted; }
        @Override public @NonNull String toString() { return "SamlResponseSemantics.Accepted{<checked>}"; }
    }

    static final class Rejected implements Result {
        private final @NonNull Reason reason;
        private Rejected(@NonNull Reason reason) { this.reason = reason; }
        @NonNull Reason reason() { return reason; }
        @Override public @NonNull String toString() { return "SamlResponseSemantics.Rejected{" + reason + "}"; }
    }

    enum Unavailable implements Result { INSTANCE }
    enum Indeterminate implements Result { INSTANCE }

    enum Reason { PENDING, COVERAGE, ISSUER, DESTINATION, REQUEST_BINDING, STATUS, SUBJECT,
        CONFIRMATION, CONDITIONS, AUTHN_STATEMENT, RESPONSE_AGE, REPLAYED, ASSERTION_SHAPE }

    static @NonNull Result validate(SamlInboundResponse.@NonNull SignaturesVerified signed,
            @NonNull Expectation expected) {
        return validate(signed, expected, null, SamlAuthenticationRequestOptions.builder().build());
    }

    static @NonNull Result validate(SamlInboundResponse.@NonNull SignaturesVerified signed,
            @NonNull Expectation expected, @Nullable Instant requestIssuedAt,
            @NonNull SamlAuthenticationRequestOptions options) {
        requireNonNull(signed);
        requireNonNull(expected);
        requireNonNull(options);
        Instant now;
        try { now = expected.clock().instant(); }
        catch (RuntimeException exception) { return Unavailable.INSTANCE; }
        if (expected.requestId() != null) {
            if (!now.isBefore(requireNonNull(expected.pendingExpiresAt()))
                    || !constantTimeEqual(requireNonNull(expected.relayState()), signed.relayState()))
                return new Rejected(Reason.PENDING);
        }

        SamlResponseStructure.Shape shape = signed.shape();
        Element response = shape.getResponse();
        Element assertion = shape.getAssertion();
        if (assertion == null || !sameNode(assertion.getParentNode(), response))
            return new Rejected(Reason.ASSERTION_SHAPE);
        EnvelopedSignatureVerifier.Verified responseProof = signed.response();
        EnvelopedSignatureVerifier.Verified assertionProof = signed.assertion();
        boolean responseSigned = responseProof != null;
        boolean assertionSigned = assertionProof != null;
        if ((!responseSigned && !assertionSigned) || (expected.requireSignedAssertion() && !assertionSigned)
                || (responseProof != null && !sameNode(responseProof.getElement(), response))
                || (assertionProof != null && !sameNode(assertionProof.getElement(), assertion)))
            return new Rejected(Reason.COVERAGE);
        if (!"2.0".equals(assertion.getAttributeNS(null, "Version")))
            return new Rejected(Reason.ASSERTION_SHAPE);

        if (!validIssuer(shape.getIssuer(), expected.idpEntityId(), true)
                || !validIssuer(unique(assertion, ASSERTION, "Issuer"), expected.idpEntityId(), true))
            return new Rejected(Reason.ISSUER);
        String destination = response.getAttributeNS(null, "Destination");
        if ((responseSigned && destination.isEmpty())
                || (!destination.isEmpty() && !destination.equals(expected.assertionConsumerServiceUrl())))
            return new Rejected(Reason.DESTINATION);
        String inResponseTo = response.getAttributeNS(null, "InResponseTo");
        if (expected.requestId() == null ? !inResponseTo.isEmpty()
                : ((responseSigned && inResponseTo.isEmpty())
                        || (!inResponseTo.isEmpty() && !inResponseTo.equals(expected.requestId()))))
            return new Rejected(Reason.REQUEST_BINDING);
        if (!successStatus(shape.getStatus())) return new Rejected(Reason.STATUS);

        Instant assertionIssued = SamlDateTime.parse(assertion.getAttributeNS(null, "IssueInstant"));
        Instant responseIssued = SamlDateTime.parse(response.getAttributeNS(null, "IssueInstant"));
        if (assertionIssued == null || responseIssued == null) return new Rejected(Reason.RESPONSE_AGE);
        Instant assertionAgeEnd = plus(assertionIssued, expected.maximumResponseAge());
        if (assertionAgeEnd == null || !validIssueInstant(assertionIssued, assertionAgeEnd, now, expected.skew()))
            return new Rejected(Reason.RESPONSE_AGE);
        if (responseSigned) {
            Instant responseAgeEnd = plus(responseIssued, expected.maximumResponseAge());
            if (responseAgeEnd == null || !validIssueInstant(responseIssued, responseAgeEnd, now, expected.skew()))
                return new Rejected(Reason.RESPONSE_AGE);
        }

        String assertionId = assertion.getAttributeNS(null, "ID");
        if (assertionId.isEmpty() || assertionId.length() > 256) return new Rejected(Reason.ASSERTION_SHAPE);
        SubjectCheck subject = inspectSubject(assertion);
        if (subject == null) return new Rejected(Reason.SUBJECT);
        Instant bearerEnd = validBearerEnd(subject.confirmations(), subject.nameId(), expected, now);
        if (bearerEnd == null) return new Rejected(Reason.CONFIRMATION);
        ConditionsCheck conditions = inspectConditions(assertion, expected, now);
        if (conditions == null) return new Rejected(Reason.CONDITIONS);
        AuthenticationCheck authentication = inspectAuthentication(assertion, now, expected.skew());
        if (authentication == null) return new Rejected(Reason.AUTHN_STATEMENT);
        if (options.isForceAuthn()) {
            Instant earliest = requestIssuedAt == null ? null : minus(requestIssuedAt, expected.skew());
            if (earliest == null || authentication.instant().isBefore(earliest))
                return new Rejected(Reason.AUTHN_STATEMENT);
        }
        if (!options.getRequestedAuthnContextClassRefs().isEmpty()
                && !options.getRequestedAuthnContextClassRefs().contains(authentication.contextClassRef()))
            return new Rejected(Reason.AUTHN_STATEMENT);
        if (!safeRemainingAssertionContent(assertion)) return new Rejected(Reason.ASSERTION_SHAPE);
        List<SamlAttribute> attributes = inspectAttributes(assertion);
        if (attributes == null) return new Rejected(Reason.ASSERTION_SHAPE);
        String subjectId = scopedIdentifier(attributes,
                "urn:oasis:names:tc:SAML:attribute:subject-id", expected.authorizedIdentifierScopes());
        String pairwiseId = scopedIdentifier(attributes,
                "urn:oasis:names:tc:SAML:attribute:pairwise-id", expected.authorizedIdentifierScopes());

        Instant cutoff = earlier(assertionAgeEnd, bearerEnd);
        Instant conditionEnd = conditions.notOnOrAfter();
        if (conditionEnd != null) cutoff = earlier(cutoff, conditionEnd);
        Instant expiresAt = plus(cutoff, expected.skew());
        if (expiresAt == null || !now.isBefore(expiresAt)) return new Rejected(Reason.CONDITIONS);
        String replayKey;
        try { replayKey = replayKey(expected, assertionId); }
        catch (NoSuchAlgorithmException exception) { return Unavailable.INSTANCE; }
        SamlReplayCache.MarkResult mark;
        try { mark = expected.replayCache().markIfAbsent(replayKey, expiresAt, expected.replayBudget()); }
        catch (RuntimeException exception) { return Indeterminate.INSTANCE; }
        if (mark == null || mark == SamlReplayCache.MarkResult.INDETERMINATE) return Indeterminate.INSTANCE;
        if (mark == SamlReplayCache.MarkResult.UNAVAILABLE
                || mark == SamlReplayCache.MarkResult.CAPACITY_REFUSED) return Unavailable.INSTANCE;
        if (mark == SamlReplayCache.MarkResult.ALREADY_PRESENT) return new Rejected(Reason.REPLAYED);
        return new Accepted(assertionId, subject.nameId(), authentication,
                releasedAttributes(attributes, subjectId, pairwiseId),
                subjectId, pairwiseId, expiresAt,
                responseSigned, assertionSigned, signed.encrypted());
    }

    private static boolean validIssuer(@Nullable Element issuer, @NonNull String expected, boolean required) {
        if (issuer == null) return !required;
        String format = issuer.getAttributeNS(null, "Format");
        String value = leaf(issuer);
        return scalarDeclarationAllowed(issuer, ASSERTION, "NameIDType")
                && (format.isEmpty() || ENTITY_FORMAT.equals(format)) && expected.equals(value);
    }

    private static boolean successStatus(@NonNull Element status) {
        Element code = unique(status, PROTOCOL, "StatusCode");
        return code != null && children(code).isEmpty()
                && SUCCESS.equals(code.getAttributeNS(null, "Value"));
    }

    private static boolean validIssueInstant(@NonNull Instant issued, @NonNull Instant ageEnd,
            @NonNull Instant now, @NonNull Duration skew) {
        Instant latest = plus(now, skew);
        Instant end = plus(ageEnd, skew);
        return latest != null && end != null && !issued.isAfter(latest) && !now.isAfter(end);
    }

    private static @Nullable SubjectCheck inspectSubject(@NonNull Element assertion) {
        Element subject = unique(assertion, ASSERTION, "Subject");
        if (subject == null || !scalarDeclarationAllowed(subject, ASSERTION, "SubjectType")) return null;
        Element nameId = null;
        List<Element> confirmations = new ArrayList<>();
        for (Element child : children(subject)) {
            if (is(child, ASSERTION, "NameID")) {
                if (nameId != null || !confirmations.isEmpty()) return null;
                nameId = child;
            } else if (is(child, ASSERTION, "SubjectConfirmation")) confirmations.add(child);
            else return null;
        }
        if (nameId == null) return null;
        SamlNameId parsed = parseNameId(nameId);
        return parsed == null ? null : new SubjectCheck(parsed, List.copyOf(confirmations));
    }

    private static @Nullable SamlNameId parseNameId(@NonNull Element nameId) {
        if (!scalarDeclarationAllowed(nameId, ASSERTION, "NameIDType")) return null;
        String value = leaf(nameId);
        if (value == null || value.isEmpty() || value.length() > 4096) return null;
        String format = optionalAttribute(nameId, "Format");
        String nameQualifier = optionalAttribute(nameId, "NameQualifier");
        String spNameQualifier = optionalAttribute(nameId, "SPNameQualifier");
        if (tooLong(format) || tooLong(nameQualifier) || tooLong(spNameQualifier)) return null;
        return new SamlNameId(value, format, nameQualifier, spNameQualifier);
    }

    private static @Nullable String optionalAttribute(@NonNull Element element, @NonNull String name) {
        String value = element.getAttributeNS(null, name);
        return value.isEmpty() ? null : value;
    }

    private static boolean tooLong(@Nullable String value) { return value != null && value.length() > 2048; }

    private static @Nullable Instant validBearerEnd(@NonNull List<@NonNull Element> confirmations,
            @NonNull SamlNameId subjectNameId, @NonNull Expectation expected, @NonNull Instant now) {
        Instant maximumEnd = null;
        boolean valid = false;
        for (Element confirmation : confirmations) {
            if (!BEARER.equals(confirmation.getAttributeNS(null, "Method"))) continue;
            Element data = bearerData(confirmation, subjectNameId);
            if (data == null || !scalarDeclarationAllowed(data, ASSERTION, "SubjectConfirmationDataType")
                    || !children(data).isEmpty() || hasNonWhitespaceDirectText(data)
                    || !expected.assertionConsumerServiceUrl().equals(data.getAttributeNS(null, "Recipient"))) continue;
            String boundRequest = data.getAttributeNS(null, "InResponseTo");
            String requestId = expected.requestId();
            if (requestId == null ? !boundRequest.isEmpty() : !requestId.equals(boundRequest)) continue;
            Instant end = SamlDateTime.parse(data.getAttributeNS(null, "NotOnOrAfter"));
            if (end == null) continue;
            Instant adjustedEnd = plus(end, expected.skew());
            Instant notBefore = data.hasAttributeNS(null, "NotBefore")
                    ? SamlDateTime.parse(data.getAttributeNS(null, "NotBefore")) : null;
            if (data.hasAttributeNS(null, "NotBefore")
                    && (notBefore == null || !notBefore.isBefore(end))) continue;
            Instant adjustedStart = notBefore == null ? null : minus(notBefore, expected.skew());
            if (adjustedEnd != null && now.isBefore(adjustedEnd)
                    && (notBefore == null || (adjustedStart != null && !now.isBefore(adjustedStart)))) {
                valid = true;
                if (maximumEnd == null || end.isAfter(maximumEnd)) maximumEnd = end;
            }
        }
        return valid ? maximumEnd : null;
    }

    private static @Nullable Element bearerData(@NonNull Element confirmation,
            @NonNull SamlNameId subjectNameId) {
        if (!scalarDeclarationAllowed(confirmation, ASSERTION, "SubjectConfirmationType")
                || hasNonWhitespaceDirectText(confirmation)) return null;
        Element data = null;
        boolean nameSeen = false;
        for (Element child : children(confirmation)) {
            if (is(child, ASSERTION, "NameID")) {
                if (nameSeen || data != null) return null;
                SamlNameId confirmed = parseNameId(child);
                if (confirmed == null || !sameNameId(subjectNameId, confirmed)) return null;
                nameSeen = true;
            } else if (is(child, ASSERTION, "SubjectConfirmationData")) {
                if (data != null) return null;
                data = child;
            } else return null;
        }
        return data;
    }

    private static boolean sameNameId(@NonNull SamlNameId left, @NonNull SamlNameId right) {
        return left.getValue().equals(right.getValue())
                && java.util.Objects.equals(left.rawFormat(), right.rawFormat())
                && java.util.Objects.equals(left.rawNameQualifier(), right.rawNameQualifier())
                && java.util.Objects.equals(left.rawSpNameQualifier(), right.rawSpNameQualifier());
    }

    private static @Nullable ConditionsCheck inspectConditions(@NonNull Element assertion,
            @NonNull Expectation expected, @NonNull Instant now) {
        Element conditions = unique(assertion, ASSERTION, "Conditions");
        if (conditions == null || !scalarDeclarationAllowed(conditions, ASSERTION, "ConditionsType")
                || hasNonWhitespaceDirectText(conditions)) return null;
        Instant start = conditions.hasAttributeNS(null, "NotBefore")
                ? SamlDateTime.parse(conditions.getAttributeNS(null, "NotBefore")) : null;
        Instant end = conditions.hasAttributeNS(null, "NotOnOrAfter")
                ? SamlDateTime.parse(conditions.getAttributeNS(null, "NotOnOrAfter")) : null;
        if ((conditions.hasAttributeNS(null, "NotBefore") && start == null)
                || (conditions.hasAttributeNS(null, "NotOnOrAfter") && end == null)
                || (start != null && end != null && !start.isBefore(end))) return null;
        Instant adjustedStart = start == null ? null : minus(start, expected.skew());
        Instant adjustedEnd = end == null ? null : plus(end, expected.skew());
        if ((start != null && (adjustedStart == null || now.isBefore(adjustedStart)))
                || (end != null && (adjustedEnd == null || !now.isBefore(adjustedEnd)))) return null;
        int restrictions = 0;
        boolean oneTimeUse = false;
        boolean proxyRestriction = false;
        for (Element child : children(conditions)) {
            if (is(child, ASSERTION, "AudienceRestriction")) {
                if (!scalarDeclarationAllowed(child, ASSERTION, "AudienceRestrictionType")
                        || hasNonWhitespaceDirectText(child)) return null;
                restrictions++;
                boolean matched = false;
                for (Element audience : children(child)) {
                    if (!is(audience, ASSERTION, "Audience")) return null;
                    if (!scalarDeclarationAllowed(audience, XSD, "anyURI")) return null;
                    String text = leaf(audience);
                    if (expected.spEntityId().equals(text)) matched = true;
                }
                if (!matched) return null;
            } else if (is(child, ASSERTION, "OneTimeUse")) {
                if (oneTimeUse || !scalarDeclarationAllowed(child, ASSERTION, "OneTimeUseType")
                        || !children(child).isEmpty() || hasNonWhitespaceDirectText(child)) return null;
                oneTimeUse = true;
            } else if (is(child, ASSERTION, "ProxyRestriction")) {
                if (proxyRestriction || !scalarDeclarationAllowed(child, ASSERTION, "ProxyRestrictionType")
                        || hasNonWhitespaceDirectText(child)
                        || (child.hasAttributeNS(null, "Count")
                                && !nonNegativeInteger(child.getAttributeNS(null, "Count")))) return null;
                for (Element audience : children(child)) {
                    if (!is(audience, ASSERTION, "Audience")
                            || !scalarDeclarationAllowed(audience, XSD, "anyURI")) return null;
                    String value = leaf(audience);
                    if (value == null || value.isEmpty()) return null;
                }
                proxyRestriction = true;
            } else return null;
        }
        return restrictions == 0 ? null : new ConditionsCheck(end);
    }

    private static boolean nonNegativeInteger(@NonNull String value) {
        String digits = value.trim();
        int start = digits.startsWith("+") ? 1 : 0;
        if (start == digits.length()) return false;
        for (int i = start; i < digits.length(); i++)
            if (digits.charAt(i) < '0' || digits.charAt(i) > '9') return false;
        return true;
    }

    private static @Nullable AuthenticationCheck inspectAuthentication(@NonNull Element assertion,
            @NonNull Instant now, @NonNull Duration skew) {
        AuthenticationCheck checked = null;
        for (Element child : children(assertion)) {
            if (!is(child, ASSERTION, "AuthnStatement")) continue;
            if (checked != null) return null;
            Instant instant = SamlDateTime.parse(child.getAttributeNS(null, "AuthnInstant"));
            Instant latestPermitted = plus(now, skew);
            if (instant == null || latestPermitted == null || instant.isAfter(latestPermitted)) return null;
            Instant sessionEnd = null;
            if (child.hasAttributeNS(null, "SessionNotOnOrAfter")) {
                sessionEnd = SamlDateTime.parse(child.getAttributeNS(null, "SessionNotOnOrAfter"));
                Instant adjustedEnd = sessionEnd == null ? null : plus(sessionEnd, skew);
                if (adjustedEnd == null || !now.isBefore(adjustedEnd)) return null;
            }
            String sessionIndex = optionalAttribute(child, "SessionIndex");
            if (tooLong(sessionIndex)) return null;
            Element context = null;
            boolean localitySeen = false;
            for (Element statementChild : children(child)) {
                if (is(statementChild, ASSERTION, "SubjectLocality")) {
                    if (localitySeen || context != null || !children(statementChild).isEmpty()) return null;
                    localitySeen = true;
                } else if (is(statementChild, ASSERTION, "AuthnContext")) {
                    if (context != null) return null;
                    context = statementChild;
                } else return null;
            }
            String contextClassRef = null;
            if (context != null) {
                // The SAML 2.0 assertion schema permits ClassRef followed by one
                // Decl/DeclRef, or a Decl/DeclRef alone, then authorities.
                int contextPosition = 0;
                for (Element contextChild : children(context)) {
                    if (is(contextChild, ASSERTION, "AuthnContextClassRef")) {
                        if (contextPosition != 0) return null;
                        if (!scalarDeclarationAllowed(contextChild, XSD, "anyURI")) return null;
                        contextClassRef = leaf(contextChild);
                        if (contextClassRef == null || contextClassRef.isEmpty()
                                || contextClassRef.length() > 2048) return null;
                        contextPosition = 1;
                    } else if (is(contextChild, ASSERTION, "AuthnContextDecl")
                            || is(contextChild, ASSERTION, "AuthnContextDeclRef")) {
                        if (contextPosition > 1) return null;
                        if (is(contextChild, ASSERTION, "AuthnContextDeclRef")) {
                            if (!scalarDeclarationAllowed(contextChild, XSD, "anyURI")) return null;
                            String value = leaf(contextChild);
                            if (value == null || value.isEmpty() || value.length() > 2048)
                                return null;
                        }
                        contextPosition = 2;
                    } else if (is(contextChild, ASSERTION, "AuthenticatingAuthority")) {
                        if (contextPosition == 0) return null;
                        if (!scalarDeclarationAllowed(contextChild, XSD, "anyURI")) return null;
                        String value = leaf(contextChild);
                        if (value == null || value.isEmpty() || value.length() > 2048)
                            return null;
                        contextPosition = 3;
                    } else {
                        return null;
                    }
                }
                if (contextPosition == 0) return null;
            }
            checked = new AuthenticationCheck(instant, sessionIndex, sessionEnd, contextClassRef);
        }
        return checked;
    }

    private static boolean safeRemainingAssertionContent(@NonNull Element assertion) {
        if (!scalarDeclarationAllowed(assertion, ASSERTION, "AssertionType")
                || hasNonWhitespaceDirectText(assertion)) return false;
        // AssertionType has a fixed prefix followed by zero or more statements.
        // A verified signature authenticates these bytes; it does not make an
        // out-of-order or nilled tree a SAML Assertion with one interpretation.
        int position = 0;
        for (Element child : children(assertion)) {
            if (is(child, ASSERTION, "Issuer")) {
                if (position != 0) return false;
                position = 1;
                continue;
            }
            if ("http://www.w3.org/2000/09/xmldsig#".equals(child.getNamespaceURI())
                    && "Signature".equals(child.getLocalName())) {
                if (position != 1) return false;
                position = 2;
                continue;
            }
            if (is(child, ASSERTION, "Subject")) {
                if (position < 1 || position > 2) return false;
                position = 3;
                continue;
            }
            if (is(child, ASSERTION, "Conditions")) {
                if (position < 1 || position > 3) return false;
                position = 4;
                continue;
            }
            if (is(child, ASSERTION, "Advice")) {
                if (position < 1 || position > 4
                        || !scalarDeclarationAllowed(child, ASSERTION, "AdviceType")
                        || hasNonWhitespaceDirectText(child)) return false;
                position = 5;
                continue;
            }
            if (position < 1) return false;
            position = 6;
            if (is(child, ASSERTION, "AuthnStatement")) {
                if (!scalarDeclarationAllowed(child, ASSERTION, "AuthnStatementType")) return false;
                continue;
            }
            if (is(child, ASSERTION, "AuthzDecisionStatement")) {
                if (!scalarDeclarationAllowed(child, ASSERTION, "AuthzDecisionStatementType")) return false;
                continue;
            }
            if (is(child, ASSERTION, "AttributeStatement")) {
                if (!validAttributeStatement(child)) return false;
                continue;
            }
            return false;
        }
        return position >= 1;
    }

    private static boolean validAttributeStatement(@NonNull Element statement) {
        if (!scalarDeclarationAllowed(statement, ASSERTION, "AttributeStatementType")
                || hasNonWhitespaceDirectText(statement)) return false;
        for (Element attribute : children(statement)) {
            if (!is(attribute, ASSERTION, "Attribute")
                    || !scalarDeclarationAllowed(attribute, ASSERTION, "AttributeType")
                    || hasNonWhitespaceDirectText(attribute)
                    || attribute.getAttributeNS(null, "Name").isEmpty()) return false;
            for (Element value : children(attribute))
                if (!is(value, ASSERTION, "AttributeValue")) return false;
        }
        return true;
    }

    private static @Nullable List<@NonNull SamlAttribute> inspectAttributes(@NonNull Element assertion) {
        List<SamlAttribute> attributes = new ArrayList<>();
        int values = 0;
        for (Element statement : children(assertion)) {
            if (!is(statement, ASSERTION, "AttributeStatement")) continue;
            for (Element attribute : children(statement)) {
                if (attributes.size() >= 128) return null;
                String name = attribute.getAttributeNS(null, "Name");
                String format = optionalAttribute(attribute, "NameFormat");
                String friendlyName = optionalAttribute(attribute, "FriendlyName");
                if (name.isEmpty() || name.length() > 2048 || tooLong(format) || tooLong(friendlyName))
                    return null;
                List<SamlAttributeValue> typed = new ArrayList<>();
                for (Element value : children(attribute)) {
                    if (++values > 256) return null;
                    List<Element> nested = children(value);
                    if (!scalarValueAllowed(value) || (value.hasAttributeNS(XSI, "type")
                            && !nested.isEmpty())) {
                        typed.add(SamlAttributeValue.complex());
                    } else if (nested.isEmpty()) {
                        String text = leaf(value);
                        if (text == null || text.length() > 4096) return null;
                        typed.add(SamlAttributeValue.text(text));
                    } else if (nested.size() == 1 && is(nested.get(0), ASSERTION, "NameID")
                            && !hasNonWhitespaceDirectText(value)) {
                        SamlNameId nameId = parseNameId(nested.get(0));
                        typed.add(nameId == null ? SamlAttributeValue.complex()
                                : SamlAttributeValue.nameId(nameId));
                    } else typed.add(SamlAttributeValue.complex());
                }
                attributes.add(new SamlAttribute(name, format, friendlyName, typed));
            }
        }
        return List.copyOf(attributes);
    }

    private static boolean scalarValueAllowed(@NonNull Element value) {
        return scalarDeclarationAllowed(value, XSD, "string");
    }

    private static boolean scalarDeclarationAllowed(@NonNull Element element,
            @NonNull String typeNamespace, @NonNull String typeLocalName) {
        if (element.hasAttributeNS(XSI, "nil")) {
            String nil = element.getAttributeNS(XSI, "nil");
            if (!"false".equals(nil) && !"0".equals(nil)) return false;
        }
        if (!element.hasAttributeNS(XSI, "type")) return true;
        String type = element.getAttributeNS(XSI, "type");
        int separator = type.indexOf(':');
        return separator > 0 && separator == type.lastIndexOf(':')
                && typeLocalName.equals(type.substring(separator + 1))
                && typeNamespace.equals(element.lookupNamespaceURI(type.substring(0, separator)));
    }

    private static @Nullable String scopedIdentifier(@NonNull List<@NonNull SamlAttribute> attributes,
            @NonNull String name, @NonNull List<@NonNull String> scopes) {
        String candidate = null;
        for (SamlAttribute attribute : attributes) {
            if (!name.equals(attribute.getName())) continue;
            if (candidate != null || attribute.getTypedValues().size() != 1
                    || attribute.getTypedValues().get(0).getKind() != SamlAttributeValue.Kind.TEXT) return null;
            candidate = attribute.getValues().get(0);
        }
        if (candidate == null || candidate.length() > 512) return null;
        int separator = candidate.lastIndexOf('@');
        if (separator <= 0 || separator == candidate.length() - 1) return null;
        String scope = candidate.substring(separator + 1);
        if (!scopes.contains(scope)) return null;
        for (int i = 0; i < candidate.length(); i++) {
            char value = candidate.charAt(i);
            if (value <= ' ' || value == 127) return null;
        }
        return candidate;
    }

    private static @NonNull List<@NonNull SamlAttribute> releasedAttributes(
            @NonNull List<@NonNull SamlAttribute> attributes, @Nullable String subjectId,
            @Nullable String pairwiseId) {
        List<SamlAttribute> released = new ArrayList<>();
        for (SamlAttribute attribute : attributes) {
            if ("urn:oasis:names:tc:SAML:attribute:subject-id".equals(attribute.getName())) {
                if (subjectId != null && attribute.getTypedValues().size() == 1
                        && attribute.getValues().equals(List.of(subjectId)))
                    released.add(attribute);
            } else if ("urn:oasis:names:tc:SAML:attribute:pairwise-id".equals(attribute.getName())) {
                if (pairwiseId != null && attribute.getTypedValues().size() == 1
                        && attribute.getValues().equals(List.of(pairwiseId)))
                    released.add(attribute);
            } else released.add(attribute);
        }
        return List.copyOf(released);
    }

    private static @NonNull String replayKey(@NonNull Expectation expected, @NonNull String assertionId)
            throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        addPart(digest, expected.spEntityId());
        addPart(digest, expected.connectionId());
        addPart(digest, expected.idpEntityId());
        addPart(digest, assertionId);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    }

    private static void addPart(@NonNull MessageDigest digest, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static boolean constantTimeEqual(@NonNull String expected, @Nullable String actual) {
        return actual != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static @Nullable Element unique(@NonNull Element parent, @NonNull String namespace,
            @NonNull String localName) {
        Element found = null;
        for (Element child : children(parent)) {
            if (!is(child, namespace, localName)) continue;
            if (found != null) return null;
            found = child;
        }
        return found;
    }

    private static @Nullable String leaf(@NonNull Element element) {
        if (!children(element).isEmpty()) return null;
        return element.getTextContent();
    }

    private static boolean hasNonWhitespaceDirectText(@NonNull Element element) {
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if ((node.getNodeType() == Node.TEXT_NODE || node.getNodeType() == Node.CDATA_SECTION_NODE)
                    && !node.getNodeValue().isBlank()) return true;
        }
        return false;
    }

    private static @NonNull List<@NonNull Element> children(@NonNull Element parent) {
        List<Element> elements = new ArrayList<>();
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element) elements.add(element);
        return elements;
    }

    private static boolean is(@NonNull Element element, @NonNull String namespace, @NonNull String localName) {
        return namespace.equals(element.getNamespaceURI()) && localName.equals(element.getLocalName());
    }

    private static boolean sameNode(@Nullable Node left, @Nullable Node right) {
        return left != null && right != null && left.isSameNode(right);
    }

    private static @NonNull Instant earlier(@NonNull Instant left, @NonNull Instant right) {
        return left.isBefore(right) ? left : right;
    }

    private static @Nullable Instant plus(@NonNull Instant instant, @NonNull Duration duration) {
        try { return instant.plus(duration); }
        catch (DateTimeException | ArithmeticException exception) { return null; }
    }

    private static @Nullable Instant minus(@NonNull Instant instant, @NonNull Duration duration) {
        try { return instant.minus(duration); }
        catch (DateTimeException | ArithmeticException exception) { return null; }
    }

    private record SubjectCheck(@NonNull SamlNameId nameId, @NonNull List<@NonNull Element> confirmations) { }
    private record ConditionsCheck(@Nullable Instant notOnOrAfter) { }
    private record AuthenticationCheck(@NonNull Instant instant, @Nullable String sessionIndex,
            @Nullable Instant sessionNotOnOrAfter, @Nullable String contextClassRef) { }
}
