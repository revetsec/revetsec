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
package example.playground;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.*;
import com.revetsec.oidc.*;
import com.revetsec.soklet.SokletOAuth;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** The app owns browser binding, cookies, sessions, and its bounded opt-in replay journal. */
final class PlaygroundOidc {
    private final BrowserSessions sessions;
    private final SafeViews views;
    private final StateSealer sealer;
    private final InMemoryPendingAuthorizationStore pending;
    private final Clock clock;

    PlaygroundOidc(@NonNull BrowserSessions sessions, @NonNull SafeViews views, @NonNull Clock clock) {
        this.sessions = sessions; this.views = views; this.clock = clock;
        sealer = StateSealer.withActiveKey(SealingKey.fromBase64("playground-run",
                Base64.getEncoder().encodeToString(LocalSecrets.randomBytes()))).clock(clock).build();
        pending = InMemoryPendingAuthorizationStore.builder().clock(clock).maximumLiveEntries(256)
                .maximumChargedBytes(1_048_576L).maximumOpaqueRecordBytes(8192).build();
    }

    @NonNull Response begin(@NonNull PlaygroundConfig config, @NonNull OidcClient client,
            BrowserSessions.@NonNull Session session, boolean sealed, boolean formPost, boolean capture) {
        synchronized (session) {
            if (session.flow != null || session.journal != null)
                return PlaygroundResources.fixed(409, "One pending or journaled demonstration per session.");
            AuthorizationRedirect redirect = client.beginAuthentication(OidcAuthenticationOptions.builder()
                    .responseMode(formPost ? AuthorizationRequestOptions.ResponseMode.FORM_POST
                            : AuthorizationRequestOptions.ResponseMode.QUERY).build());
            String context = "playground-oidc:" + session.binding;
            String sealedForm = sealed ? redirect.getPendingAuthorization().toSealedForm(sealer, context) : "store";
            if (sealedForm.length() > 3800) throw new IllegalStateException("Pending cookie exceeds local cap.");
            if (!sealed) redirect.getPendingAuthorization().saveTo(pending, session.binding);
            session.flow = new Flow(client, config.callbackUri(), redirect.getPerFlowCookieName(),
                    context, redirect.getPendingAuthorization().getExpiresAt(), sealed,
                    capture && config.replayEnabled, sealedForm);
            ResponseCookie flowCookie = ResponseCookie.with(redirect.getPerFlowCookieName(), sealedForm)
                    .path("/").secure(true).httpOnly(true).sameSite(ResponseCookie.SameSite.NONE)
                    .maxAge(java.time.Duration.between(clock.instant(), session.flow.expires)).build();
            return SokletOAuth.redirect(redirect.getAuthorizationUri(), Set.of(flowCookie));
        }
    }

    @NonNull Response callback(@NonNull PlaygroundConfig config, @NonNull Request request) {
        BrowserSessions.Session session = sessions.find(request).orElse(null);
        if (session == null) return PlaygroundResources.fixed(400, "Browser binding is required.");
        synchronized (session) {
            Flow flow = session.flow;
            session.flow = null;
            if (flow == null) return PlaygroundResources.fixed(400, "Pending authorization is unavailable.");
            ResponseCookie clear = clearCookie(flow.cookieName);
            try {
                if (!clock.instant().isBefore(flow.expires))
                    return PlaygroundResources.fixed(400, "Pending authorization expired.").copy().cookies(Set.of(clear)).finish();
                AuthorizationResponse response = SokletOAuth.authorizationResponseFor(request);
                // The selected cookie is still required even in store mode; no state-only source is accepted.
                String browserCookie = BrowserSessions.cookieValue(request, flow.cookieName).orElse("");
                if (!response.getPerFlowCookieName().equals(flow.cookieName) || !browserCookie.equals(flow.cookieValue))
                    return PlaygroundResources.fixed(400, "Browser binding is required.").copy().cookies(Set.of(clear)).finish();
                PendingAuthorizationSource source = flow.sealed
                        ? PendingAuthorizationSource.fromSealedForm(browserCookie, sealer, flow.context)
                        : PendingAuthorizationSource.fromStore(pending, session.binding);
                int callbackBytes = 0;
                for (var entry : response.getParameters().entrySet()) {
                    callbackBytes += entry.getKey().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                    for (String value : entry.getValue()) callbackBytes += value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                }
                if (callbackBytes > 24_576) throw new IllegalArgumentException("Callback journal exceeds cap.");
                if (flow.capture) session.journal = new Journal(response, source, flow.client, flow.callback,
                        flow.expires, flow.sealed);
                OidcAuthenticationResult result = flow.client.completeAuthenticationResult(response, source, flow.callback);
                if (!(result instanceof OidcAuthenticationResult.Succeeded authenticated))
                    return PlaygroundResources.fixed(400, "Authentication rejected.").copy().cookies(Set.of(clear)).finish();
                OidcAuthentication authentication = authenticated.getAuthentication();
                JsonObject identity = JsonObject.builder().put("issuer", authentication.getIssuer())
                        .put("subject", views.partition(authentication.getIssuer(), authentication.getSubject(), "local"))
                        .put("validation", "Completed OIDC authentication profile").build();
                BrowserSessions.Session rotated = sessions.rotate(session, identity);
                return SokletOAuth.redirect(config.origin.resolve("/"), Set.of(clear, BrowserSessions.cookie(rotated)));
            } catch (com.revetsec.RevetsecException failure) {
                if (failure instanceof OAuthResponseException responseFailure
                        && responseFailure.getReason() == OAuthException.Reason.CALLBACK_MALFORMED)
                    return PlaygroundResources.fixed(400, "Callback rejected.").copy().cookies(Set.of(clear)).finish();
                return PlaygroundResources.fixed(503, "Authentication service unavailable.")
                        .copy().cookies(Set.of(clear)).finish();
            } catch (IllegalArgumentException failure) {
                return PlaygroundResources.fixed(400, "Callback rejected.").copy().cookies(Set.of(clear)).finish();
            }
        }
    }

    @NonNull JsonObject replay(BrowserSessions.@NonNull Session session) {
        synchronized (session) {
            Journal journal = session.journal;
            session.journal = null; // One attempt; do not create a reusable callback exporter.
            if (journal == null || !clock.instant().isBefore(journal.expires))
                return JsonObject.builder().put("outcome", "Journal unavailable or expired").build();
            String boundary = journal.sealed ? "Sealed cookie: AS single-use code boundary; concurrent replay can race"
                    : "Atomic store: local consume boundary before another code POST";
            try {
                OidcAuthenticationResult result = journal.client.completeAuthenticationResult(journal.response,
                        journal.source, journal.callback);
                return JsonObject.builder().put("boundary", boundary).put("outcome",
                        result instanceof OidcAuthenticationResult.Succeeded
                                ? "Completed by provider; this mode has no local at-most-once guarantee"
                                : "Rejected by normal callback validation").build();
            } catch (OAuthErrorResponseException failure) {
                return JsonObject.builder().put("boundary", boundary)
                        .put("outcome", failure.getErrorCode().filter("invalid_grant"::equals).isPresent()
                                ? "AS rejected single-use authorization code" : "AS rejected replay").build();
            } catch (com.revetsec.RevetsecException failure) {
                return JsonObject.builder().put("boundary", boundary).put("outcome", "Provider unavailable").build();
            }
        }
    }

    private static @NonNull ResponseCookie clearCookie(@NonNull String name) {
        return ResponseCookie.with(name, "").path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.NONE).maxAge(java.time.Duration.ZERO).build();
    }

    static final class Flow {
        final OidcClient client;
        final URI callback;
        final String cookieName;
        final String context;
        final Instant expires;
        final boolean sealed;
        final boolean capture;
        final String cookieValue;
        Flow(@NonNull OidcClient client, @NonNull URI callback, @NonNull String cookieName,
                @NonNull String context, @NonNull Instant expires, boolean sealed, boolean capture,
                @NonNull String cookieValue) {
            this.client = client; this.callback = callback; this.cookieName = cookieName;
            this.context = context; this.expires = expires; this.sealed = sealed;
            this.capture = capture; this.cookieValue = cookieValue;
        }
        @Override public @NonNull String toString() { return "OidcFlow{data=<redacted>}"; }
    }

    static final class Journal {
        final AuthorizationResponse response;
        final PendingAuthorizationSource source;
        final OidcClient client;
        final URI callback;
        final Instant expires;
        final boolean sealed;
        Journal(@NonNull AuthorizationResponse response, @NonNull PendingAuthorizationSource source,
                @NonNull OidcClient client, @NonNull URI callback, @NonNull Instant expires, boolean sealed) {
            this.response = response; this.source = source; this.client = client;
            this.callback = callback; this.expires = expires; this.sealed = sealed;
        }
        @Override public @NonNull String toString() { return "ReplayJournal{data=<redacted>}"; }
    }
}
