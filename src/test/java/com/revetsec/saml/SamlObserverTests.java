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

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlObserverTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"),
            ZoneOffset.UTC);
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";

    @Test void recordsOneRedactedPairForEachPreparationResult() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-secret")
                .postSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();

        assertInstanceOf(SamlAuthenticationRequestResult.Rejected.class, sp.beginAuthenticationResult(idp));
        assertInstanceOf(SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(idp));
        assertEquals(List.of("will:BEGIN_AUTHENTICATION", "did:BEGIN_AUTHENTICATION:REJECTED",
                "will:BEGIN_POST_AUTHENTICATION", "did:BEGIN_POST_AUTHENTICATION:SUCCEEDED"), observer.events);
        assertTrue(observer.elapsed.stream().allMatch(value -> !value.isNegative()));
        assertTrue(observer.events.stream().noneMatch(value -> value.contains("tenant-secret")));
    }

    @Test void completionReportsIndeterminateStoreWithoutCallingItARejection() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        SamlIdentityProvider idp = idp(key);
        SamlPostBindingMessage message = message("<untrusted/>", "relay");
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-observer"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationStore uncertainStore = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull String sealedRecord,
                    @NonNull Instant expiresAt, @NonNull Duration remainingBudget) {
                throw new IllegalStateException("secret backend text");
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Duration remainingBudget) {
                throw new IllegalStateException("secret backend text");
            }
        };
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromStore(uncertainStore,
                "browser-secret", sealer, "observer-context");
        assertInstanceOf(SamlAuthenticationResult.Indeterminate.class,
                sp.completeAuthenticationResult(message, source, idp));
        assertEquals(List.of("will:COMPLETE_AUTHENTICATION", "did:COMPLETE_AUTHENTICATION:INDETERMINATE"),
                observer.events);
        assertTrue(observer.events.stream().noneMatch(value -> value.contains("secret")));
    }

    @Test void throwingHooksCannotChangeResultOrEscapeAsCredentialText() throws Exception {
        KeyPair key = rsa();
        SamlObserver broken = new SamlObserver() {
            @Override public void willHandleOperation(@NonNull Operation operation) {
                throw new IllegalStateException("secret from start hook");
            }
            @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                    @NonNull Duration elapsed) {
                throw new IllegalStateException("secret from terminal hook");
            }
        };
        SamlServiceProvider sp = serviceProvider(broken);
        SamlIdentityProvider idp = idp(key);
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));

        SamlServiceProvider reset = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.fromLimit(CLOCK, 4))
                .clock(CLOCK).observer(broken).observer(null).build();
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, reset.beginAuthenticationResult(idp));
    }

    @Test void everyLogoutAndNonSuccessLoginResultHasItsExactObserverOutcome() {
        SamlObserver.Outcome success = SamlObserver.Outcome.SUCCEEDED;
        SamlObserver.Outcome rejected = SamlObserver.Outcome.REJECTED;
        SamlObserver.Outcome unavailable = SamlObserver.Outcome.UNAVAILABLE;
        SamlObserver.Outcome indeterminate = SamlObserver.Outcome.INDETERMINATE;
        SamlObserver.Outcome status = SamlObserver.Outcome.STATUS_RECEIVED;

        assertEquals(status, SamlServiceProvider.outcome(new SamlAuthenticationResult.StatusReceived(
                SamlAuthenticationResult.StatusCode.AUTHN_FAILED, true)));
        assertEquals(rejected, SamlServiceProvider.outcome(new SamlAuthenticationResult.Rejected(
                SamlAuthenticationResult.Reason.SIGNATURE)));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlAuthenticationResult.Unavailable.INSTANCE));
        assertEquals(indeterminate, SamlServiceProvider.outcome(SamlAuthenticationResult.Indeterminate.INSTANCE));

        SamlLogoutRequest request = new SamlLogoutRequest("tenant-secret", SP, IDP, "_request", null,
                new SamlNameId("checked-user", null, null, null), List.of("_session"));
        assertEquals(success, SamlServiceProvider.outcome(new SamlLogoutRequestResult.Accepted(request)));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutRequestResult.Rejected.INSTANCE));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutRequestResult.Unavailable.INSTANCE));
        assertEquals(indeterminate, SamlServiceProvider.outcome(SamlLogoutRequestResult.Indeterminate.INSTANCE));

        PendingSamlAuthentication pending = new PendingSamlAuthentication(SP, "_request", "relay",
                "tenant-secret", IDP, "https://sp.example.test/acs", CLOCK.instant(),
                CLOCK.instant().plusSeconds(300));
        assertEquals(success, SamlServiceProvider.outcome(new SamlLogoutRedirectResult.Prepared(
                URI.create("https://idp.example.test/slo"), new PendingSamlLogout(pending))));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutRedirectResult.Rejected.CONFIGURATION));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutRedirectResult.Unavailable.INSTANCE));

        assertEquals(success, SamlServiceProvider.outcome(SamlLogoutResult.Succeeded.INSTANCE));
        assertEquals(status, SamlServiceProvider.outcome(SamlLogoutResult.StatusReceived.NON_SUCCESS));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutResult.Rejected.INSTANCE));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutResult.Unavailable.INSTANCE));
        assertEquals(indeterminate, SamlServiceProvider.outcome(SamlLogoutResult.Indeterminate.INSTANCE));

        assertEquals(success, SamlServiceProvider.outcome(new SamlLogoutResponseRedirectResult.Prepared(
                URI.create("https://idp.example.test/slo?SAMLResponse=redacted"))));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutResponseRedirectResult.Rejected.INSTANCE));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutResponseRedirectResult.Unavailable.INSTANCE));

        SamlPostForm form = new SamlPostForm(URI.create("https://idp.example.test/slo"),
                "SAMLRequest", "redacted", null);
        assertEquals(success, SamlServiceProvider.outcome(new SamlLogoutPostResult.Prepared(
                form, new PendingSamlLogout(pending))));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutPostResult.Rejected.CONFIGURATION));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutPostResult.Unavailable.INSTANCE));
        assertEquals(success, SamlServiceProvider.outcome(new SamlLogoutResponsePostResult.Prepared(form)));
        assertEquals(rejected, SamlServiceProvider.outcome(SamlLogoutResponsePostResult.Rejected.INSTANCE));
        assertEquals(unavailable, SamlServiceProvider.outcome(SamlLogoutResponsePostResult.Unavailable.INSTANCE));
    }

    @Test void privateDomAndReasonClassifiersCoverEveryClosedInputKind() throws Exception {
        Method ignorable = SamlServiceProvider.class.getDeclaredMethod("ignorableStructuralNode", Node.class);
        ignorable.setAccessible(true);
        var document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        assertEquals(true, ignorable.invoke(null, document.createComment("comment")));
        assertEquals(true, ignorable.invoke(null, document.createProcessingInstruction("target", "data")));
        assertEquals(false, ignorable.invoke(null, document.createElement("element")));
        assertEquals(true, ignorable.invoke(null, document.createTextNode("")));
        assertEquals(true, ignorable.invoke(null, document.createTextNode(" \t\r\n")));
        for (String value : List.of("x", "\tx", "\rx", "\nx"))
            assertEquals(false, ignorable.invoke(null, document.createTextNode(value)));
        Node nullText = (Node) Proxy.newProxyInstance(Node.class.getClassLoader(), new Class<?>[]{Node.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getNodeType" -> Node.TEXT_NODE;
                    case "getNodeValue" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        assertEquals(false, ignorable.invoke(null, nullText));
		Method textOnly = SamlServiceProvider.class.getDeclaredMethod("textOnly", org.w3c.dom.Element.class);
		textOnly.setAccessible(true);
		var mixed = document.createElement("mixed");
		mixed.appendChild(document.createComment("not scalar text"));
		assertEquals(null, textOnly.invoke(null, mixed));

        Method map = SamlServiceProvider.class.getDeclaredMethod("map", SamlResponseSemantics.Reason.class);
        map.setAccessible(true);
        Map<SamlResponseSemantics.Reason, SamlAuthenticationResult.Reason> expected = Map.ofEntries(
                Map.entry(SamlResponseSemantics.Reason.PENDING, SamlAuthenticationResult.Reason.PENDING),
                Map.entry(SamlResponseSemantics.Reason.COVERAGE, SamlAuthenticationResult.Reason.SIGNATURE),
                Map.entry(SamlResponseSemantics.Reason.ISSUER, SamlAuthenticationResult.Reason.ISSUER),
                Map.entry(SamlResponseSemantics.Reason.DESTINATION, SamlAuthenticationResult.Reason.DESTINATION),
                Map.entry(SamlResponseSemantics.Reason.REQUEST_BINDING, SamlAuthenticationResult.Reason.REQUEST_BINDING),
                Map.entry(SamlResponseSemantics.Reason.STATUS, SamlAuthenticationResult.Reason.STATUS),
                Map.entry(SamlResponseSemantics.Reason.SUBJECT, SamlAuthenticationResult.Reason.SUBJECT),
                Map.entry(SamlResponseSemantics.Reason.CONFIRMATION, SamlAuthenticationResult.Reason.CONFIRMATION),
                Map.entry(SamlResponseSemantics.Reason.CONDITIONS, SamlAuthenticationResult.Reason.CONDITIONS),
                Map.entry(SamlResponseSemantics.Reason.AUTHN_STATEMENT, SamlAuthenticationResult.Reason.AUTHN_STATEMENT),
                Map.entry(SamlResponseSemantics.Reason.RESPONSE_AGE, SamlAuthenticationResult.Reason.RESPONSE_AGE),
                Map.entry(SamlResponseSemantics.Reason.REPLAYED, SamlAuthenticationResult.Reason.REPLAYED),
                Map.entry(SamlResponseSemantics.Reason.ASSERTION_SHAPE, SamlAuthenticationResult.Reason.ASSERTION_SHAPE));
        for (var entry : expected.entrySet()) assertEquals(entry.getValue(), map.invoke(null, entry.getKey()));

        Method requestOutcome = SamlServiceProvider.class.getDeclaredMethod("outcome",
                SamlAuthenticationRequestResult.class);
        requestOutcome.setAccessible(true);
        assertEquals(SamlObserver.Outcome.UNAVAILABLE,
                requestOutcome.invoke(null, SamlAuthenticationRequestResult.Unavailable.INSTANCE));
    }

    @Test @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    void unexpectedRuntimeFailureIsObservedThenRethrownWithoutItsMessage() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        NullPointerException failure = assertThrows(NullPointerException.class,
                () -> sp.beginAuthenticationResult(null));
        assertEquals(List.of("will:BEGIN_AUTHENTICATION", "did:BEGIN_AUTHENTICATION:FAILED"), observer.events);
        assertTrue(failure.getMessage() == null || !failure.getMessage().contains("tenant-secret"));
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp(key)));
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull SamlObserver observer) {
        return SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.fromLimit(CLOCK, 4))
                .clock(CLOCK).observer(observer).build();
    }

    private static @NonNull SamlIdentityProvider idp(@NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-secret")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String xml, @NonNull String relay) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded + "&RelayState=" + relay)
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static final class RecordingObserver implements SamlObserver {
        private final @NonNull List<@NonNull String> events = new ArrayList<>();
        private final @NonNull List<@NonNull Duration> elapsed = new ArrayList<>();
        @Override public void willHandleOperation(@NonNull Operation operation) {
            events.add("will:" + operation);
        }
        @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                @NonNull Duration duration) {
            events.add("did:" + operation + ":" + outcome);
            elapsed.add(duration);
        }
    }
}
