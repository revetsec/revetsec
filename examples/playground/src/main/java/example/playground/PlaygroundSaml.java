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
import com.revetsec.saml.*;
import com.revetsec.soklet.SokletOAuth;
import com.revetsec.soklet.SokletSaml;
import com.revetsec.soklet.SokletRequestResult;
import com.soklet.Request;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** One trusted, local SAML connection; the app owns accounts, sessions, and browser state. */
final class PlaygroundSaml {
    static final String LOGIN_COOKIE = "__Host-RevetsecSamlPending";
    static final String LOGOUT_COOKIE = "__Host-RevetsecSamlLogout";
    private final BrowserSessions sessions;
    private final SafeViews views;
    private final SamlServiceProvider sp;
    private final SamlIdentityProvider idp;
    private final StateSealer sealer;
    private final URI origin;
    private final URI idpOrigin;
    private final Clock clock;
    private final String metadataXml;
    private final boolean postLogout;
    private final @Nullable URI postLogoutOrigin;
    private final Map<@NonNull String, @NonNull String> accounts = new LinkedHashMap<>();

    private PlaygroundSaml(@NonNull BrowserSessions sessions, @NonNull SafeViews views,
            @NonNull SamlServiceProvider sp, @NonNull SamlIdentityProvider idp,
            @NonNull StateSealer sealer, @NonNull URI origin, @NonNull URI idpOrigin,
            @NonNull Clock clock, @NonNull String metadataXml, boolean postLogout, @Nullable URI postLogoutOrigin) {
        this.sessions = sessions; this.views = views; this.sp = sp; this.idp = idp;
        this.sealer = sealer; this.origin = origin; this.idpOrigin = idpOrigin;
        this.clock = clock; this.metadataXml = metadataXml; this.postLogout = postLogout; this.postLogoutOrigin = postLogoutOrigin;
    }

    static @Nullable PlaygroundSaml fromEnvironment(@NonNull Map<@NonNull String, @NonNull String> env,
            @NonNull PlaygroundConfig config, @NonNull BrowserSessions sessions,
            @NonNull SafeViews views, @NonNull Clock clock) {
        String metadataPath = env.get("PLAYGROUND_SAML_METADATA_FILE");
        if (metadataPath == null) return null;
        String entityId = required(env, "PLAYGROUND_SAML_IDP_ENTITY_ID");
        String connectionId = required(env, "PLAYGROUND_SAML_CONNECTION_ID");
        byte[] metadataBytes = readFile(metadataPath, 262_144);
        SamlIdentityProviderMetadataResult metadataResult = SamlIdentityProviderMetadata.fromXmlResult(
                metadataBytes, entityId, clock);
        if (!(metadataResult instanceof SamlIdentityProviderMetadataResult.Parsed parsed))
            throw new IllegalArgumentException("SAML metadata was rejected or unavailable.");
        SamlIdentityProviderMetadata metadata = parsed.getMetadata();
        SamlIdentityProvider idp = SamlIdentityProvider.withMetadata(metadata)
                .connectionId(connectionId).build();
        URI sso = metadata.getRedirectSingleSignOnService().orElseThrow(
                () -> new IllegalArgumentException("SAML IdP Redirect SSO is required."));
        metadata.getRedirectSingleLogoutService().orElseThrow(
                () -> new IllegalArgumentException("SAML IdP Redirect logout is required."));
        URI idpOrigin = URI.create(sso.getScheme() + "://" + sso.getRawAuthority());
        String logoutBinding = env.getOrDefault("PLAYGROUND_SAML_LOGOUT_BINDING", "redirect");
        if (!Set.of("redirect", "post").contains(logoutBinding))
            throw new IllegalArgumentException("SAML logout binding must be redirect or post.");
        boolean postLogout = logoutBinding.equals("post");
        URI postSlo = postLogout ? metadata.getPostSingleLogoutService().orElseThrow(
                () -> new IllegalArgumentException("SAML IdP POST logout is required.")) : null;
        URI postOrigin = postSlo == null ? null : URI.create(postSlo.getScheme() + "://" + postSlo.getRawAuthority());

        SamlCredential signing = credential(env, "PLAYGROUND_SAML_SIGNING_KEY_FILE",
                "PLAYGROUND_SAML_SIGNING_CERT_FILE");
        String decryptionKey = env.get("PLAYGROUND_SAML_DECRYPTION_KEY_FILE");
        String decryptionCertificate = env.get("PLAYGROUND_SAML_DECRYPTION_CERT_FILE");
        if ((decryptionKey == null) != (decryptionCertificate == null))
            throw new IllegalArgumentException("SAML decryption key and certificate must be paired.");
        List<SamlCredential> decryption = decryptionKey == null ? List.of() : List.of(SamlCredential.fromPem(
                new String(readFile(decryptionKey, 8192), StandardCharsets.UTF_8),
                new String(readFile(decryptionCertificate, 8192), StandardCharsets.UTF_8)));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId(config.origin.resolve("/saml/metadata").toString())
                .assertionConsumerServiceUrl(config.origin.resolve("/saml/acs"))
                .singleLogoutServiceUrl(config.origin.resolve("/saml/slo"))
                .postSingleLogoutServiceUrl(postLogout ? config.origin.resolve("/saml/slo") : null)
                .signingCredential(signing).decryptionCredentials(decryption)
                .replayCache(InMemorySamlReplayCache.fromLimit(clock, 1024)).clock(clock).build();
        SamlServiceProviderMetadataResult generated = SamlServiceProviderMetadata.fromServiceProviderResult(sp);
        if (!(generated instanceof SamlServiceProviderMetadataResult.Generated ready))
            throw new IllegalArgumentException("SAML SP metadata is unavailable.");
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("playground-saml-run",
                Base64.getEncoder().encodeToString(LocalSecrets.randomBytes()))).clock(clock).build();
        return new PlaygroundSaml(sessions, views, sp, idp, sealer, config.origin, idpOrigin,
                clock, ready.getXml(), postLogout, postOrigin);
    }

    private static @NonNull String required(@NonNull Map<@NonNull String, @NonNull String> env,
            @NonNull String name) {
        String value = env.get(name);
        if (value == null || value.isBlank() || value.length() > 512)
            throw new IllegalArgumentException("SAML configuration is incomplete.");
        return value;
    }

    private static byte @NonNull [] readFile(@NonNull String name, int maximum) {
        try {
            Path path = Path.of(name);
            if (!path.isAbsolute() || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(path) > maximum) throw new IllegalArgumentException("SAML file is invalid.");
            try (var stream = Files.newInputStream(path)) {
                byte[] bytes = stream.readNBytes(maximum + 1);
                if (bytes.length == 0 || bytes.length > maximum)
                    throw new IllegalArgumentException("SAML file is invalid.");
                return bytes;
            }
        } catch (IOException failure) { throw new IllegalArgumentException("SAML file is unavailable."); }
    }

    private static @NonNull SamlCredential credential(@NonNull Map<@NonNull String, @NonNull String> env,
            @NonNull String keyName, @NonNull String certificateName) {
        return SamlCredential.fromPem(
                new String(readFile(required(env, keyName), 8192), StandardCharsets.UTF_8),
                new String(readFile(required(env, certificateName), 8192), StandardCharsets.UTF_8));
    }

    @NonNull String connectionId() { return idp.getConnectionId(); }
    @NonNull URI identityProviderOrigin() { return idpOrigin; }

    @NonNull Response metadata(@NonNull Request request) {
        if (!trustedHost(request)) return PlaygroundResources.fixed(403, "Request denied.");
        return Response.withStatusCode(200).body(metadataXml).headers(Map.of(
                "Content-Type", List.of("application/samlmetadata+xml; charset=UTF-8"),
                "Cache-Control", List.of("no-store"), "Referrer-Policy", List.of("no-referrer"),
                "X-Content-Type-Options", List.of("nosniff"))).build();
    }

    @NonNull Response begin(BrowserSessions.@NonNull Session session) {
        synchronized (session) {
            if (session.samlFlow != null || session.samlLogout != null)
                return PlaygroundResources.fixed(409, "One SAML flow per browser session.");
            SamlAuthenticationRequestResult result = sp.beginAuthenticationResult(idp);
            if (result instanceof SamlAuthenticationRequestResult.Unavailable)
                return PlaygroundResources.fixed(503, "SAML login unavailable.");
            if (!(result instanceof SamlAuthenticationRequestResult.Prepared prepared))
                return PlaygroundResources.fixed(400, "SAML login configuration rejected.");
            String context = context(session, "login");
            String sealed = prepared.getPendingAuthentication().toSealedForm(sealer, context);
            if (sealed.length() > 3800) return PlaygroundResources.fixed(503, "SAML pending state unavailable.");
            Instant expires = prepared.getPendingAuthentication().getExpiresAt();
            session.samlFlow = new Flow(sealed, context, expires);
            return SokletSaml.authenticationRedirect(prepared, Set.of(cookie(LOGIN_COOKIE, sealed, expires)));
        }
    }

    @NonNull Response callback(@NonNull Request request) {
        if (!trustedCallback(request, true)) return PlaygroundResources.fixed(403, "Request denied.");
        BrowserSessions.Session session = sessions.find(request).orElse(null);
        if (session == null) return failed(400, "Browser binding is required.", clear(LOGIN_COOKIE));
        synchronized (session) {
            Flow flow = session.samlFlow;
            if (flow == null) return failed(400, "SAML pending state is unavailable.", clear(LOGIN_COOKIE));
            long generation;
            try { generation = sessions.claimSamlFlow(session, flow); }
            catch (IllegalStateException cancelled) { return failed(400, "SAML pending state is unavailable.", clear(LOGIN_COOKIE)); }
            ResponseCookie clear = clear(LOGIN_COOKIE);
            if (!clock.instant().isBefore(flow.expires)
                    || !sameCookie(request, LOGIN_COOKIE, flow.sealed))
                return failed(400, "SAML browser binding rejected.", clear);
            var read = SokletSaml.postBindingResultFor(request);
            if (!(read instanceof SokletRequestResult.Completed<SamlPostBindingParseResult> completed))
                return failed(413, "SAML request body exceeds the limit.", clear);
            SamlPostBindingParseResult parsed = completed.getResult();
            if (!(parsed instanceof SamlPostBindingParseResult.Parsed post))
                return failed(400, "SAML POST rejected.", clear);
            SamlAuthenticationResult result = sp.completeAuthenticationResult(post.getMessage(),
                    PendingSamlAuthenticationSource.fromSealedForm(flow.sealed, sealer, flow.context), idp);
            if (result instanceof SamlAuthenticationResult.Unavailable
                    || result instanceof SamlAuthenticationResult.Indeterminate)
                return failed(503, "SAML login unavailable.", clear);
            if (!(result instanceof SamlAuthenticationResult.Succeeded success))
                return failed(400, "SAML authentication rejected.", clear);
            SamlAuthentication authentication = success.getAuthentication();
            SamlSubjectKey subject = authentication.getSubjectKey().orElse(null);
            if (subject == null) return failed(400, "Stable SAML subject required.", clear);
            String account = account(idp.getConnectionId(), subject);
            if (account == null) return failed(503, "Local account directory is full.", clear);
            JsonObject identity = JsonObject.builder().put("method", "SAML")
                    .put("connection", idp.getConnectionId())
                    .put("account", views.partition(idp.getConnectionId(), account, "local"))
                    .put("validation", "Checked SAML authentication").build();
            try {
                BrowserSessions.Session rotated = sessions.rotateSaml(session, generation, identity, authentication.getSessionReference());
                return SokletOAuth.redirect(origin.resolve("/"), Set.of(clear, BrowserSessions.cookie(rotated)));
            } catch (IllegalStateException expired) {
                return failed(400, "Browser session expired.", clear);
            }
        }
    }

    @NonNull Response beginLogout(BrowserSessions.@NonNull Session session) {
        // Claim currentness and close authority before waiting on a callback's session monitor.
        BrowserSessions.SamlClosure closed = sessions.closeSamlAuthority(session).orElse(null);
        if (closed == null) return PlaygroundResources.fixed(400, "No SAML session is active.");
        synchronized (session) {
            SamlSessionReference reference = closed.reference();
            Set<ResponseCookie> cookies = new LinkedHashSet<>();
            if (closed.hadLogin()) cookies.add(clear(LOGIN_COOKIE));
            if (closed.oidcCookie() != null) cookies.add(clear(closed.oidcCookie()));
            PendingSamlLogout pending; SamlPostForm postForm = null; URI redirect = null;
            if (postLogout) {
                SamlLogoutPostResult result = sp.beginPostLogoutResult(idp, reference);
                if (!(result instanceof SamlLogoutPostResult.Prepared prepared))
                    return localCloseFailure(result instanceof SamlLogoutPostResult.Unavailable ? 503 : 400, cookies);
                pending = prepared.getPendingLogout(); postForm = prepared.getPostForm();
            } else {
                SamlLogoutRedirectResult result = sp.beginLogoutResult(idp, reference);
                if (!(result instanceof SamlLogoutRedirectResult.Prepared prepared))
                    return localCloseFailure(result instanceof SamlLogoutRedirectResult.Unavailable ? 503 : 400, cookies);
                pending = prepared.getPendingLogout(); redirect = prepared.getRedirectUri();
            }
            String context = context(session, postLogout ? "logout-post" : "logout");
            String sealed = pending.toSealedForm(sealer, context);
            if (sealed.length() > 3800) return localCloseFailure(503, cookies);
            Instant expires = pending.getExpiresAt();
            if (!clock.instant().isBefore(expires)) return localCloseFailure(503, cookies);
            cookies.add(cookie(LOGOUT_COOKIE, sealed, expires));
            Response response = postForm != null ? postForm(postForm, cookies)
                    : SokletOAuth.redirect(java.util.Objects.requireNonNull(redirect), cookies);
            if (!clock.instant().isBefore(expires)) return localCloseFailure(503, cookies);
            if (!sessions.saveSamlLogout(session, closed.generation(), new LogoutFlow(sealed, context, expires, postLogout)))
                return localCloseFailure(503, cookies);
            return response;
        }
    }

    private static @NonNull Response localCloseFailure(int status, @NonNull Set<@NonNull ResponseCookie> cookies) {
        Set<ResponseCookie> cleared = new LinkedHashSet<>();
        for (ResponseCookie cookie : cookies) if (!cookie.getName().equals(LOGOUT_COOKIE)) cleared.add(cookie);
        cleared.add(clear(LOGOUT_COOKIE));
        return PlaygroundResources.fixed(status, "SAML logout unavailable.").copy().cookies(List.copyOf(cleared)).finish();
    }

    private static @NonNull Response postForm(@NonNull SamlPostForm form, @NonNull Set<@NonNull ResponseCookie> cookies) {
        String nonce = LocalSecrets.randomId();
        MarshaledResponse rendered = SokletSaml.postFormResponse(form, nonce);
        Map<String, List<String>> headers = new LinkedHashMap<>(rendered.getHeaders());
        URI action = form.getAction();
        String origin = action.getScheme() + "://" + action.getRawAuthority();
        headers.put("Content-Security-Policy", List.of("default-src 'none'; script-src 'nonce-" + nonce
                + "'; form-action " + origin + "; base-uri 'none'; frame-ancestors 'none'"));
        return Response.withStatusCode(rendered.getStatusCode()).headers(headers).cookies(List.copyOf(cookies))
                .body(((MarshaledResponseBody.Bytes) rendered.getBody().orElseThrow()).getBytes()).build();
    }

    @NonNull Response logoutCallback(@NonNull Request request) {
        boolean post = request.getHttpMethod() == HttpMethod.POST;
        if (post && !postLogout) return PlaygroundResources.fixed(405, "SAML POST logout is not configured.")
                .copy().headers(headers -> headers.put("Allow", List.of("GET"))).finish();
        if (!trustedCallback(request, post)) return PlaygroundResources.fixed(403, "Request denied.");
        if (post) {
            var read = SokletSaml.postLogoutBindingResultFor(request);
            if (read instanceof SokletRequestResult.TooLarge<?>) return PlaygroundResources.fixed(413, "SAML logout input is too large.");
            if (!(read instanceof SokletRequestResult.Completed<SamlPostBindingParseResult> completed)) return PlaygroundResources.fixed(503, "SAML logout input unavailable.");
            SamlPostBindingParseResult parsedPost = completed.getResult();
            if (!(parsedPost instanceof SamlPostBindingParseResult.Parsed parsed)) return malformedLogout(request);
            SamlPostBindingMessage message = parsed.getMessage();
            if (message.getKind() == SamlPostBindingMessage.Kind.REQUEST) {
                SamlLogoutRequestResult result = sp.acceptLogoutRequestResult(message, idp);
                if (result instanceof SamlLogoutRequestResult.Unavailable || result instanceof SamlLogoutRequestResult.Indeterminate)
                    return PlaygroundResources.fixed(503, "SAML logout unavailable.");
                if (!(result instanceof SamlLogoutRequestResult.Accepted accepted)) return PlaygroundResources.fixed(400, "SAML logout request rejected.");
                sessions.endMatchingSamlSessions(accepted.getRequest());
                SamlLogoutResponsePostResult response = sp.respondToPostLogoutRequestResult(accepted.getRequest(), idp, SamlLogoutStatus.SUCCESS);
                return response instanceof SamlLogoutResponsePostResult.Prepared prepared ? postForm(prepared.getPostForm(), Set.of())
                        : PlaygroundResources.fixed(503, "SAML logout response unavailable.");
            }
            return completeLogout(request, null, message);
        }
        SamlRedirectBindingParseResult parsed = SokletSaml.redirectBindingResultFor(request);
        if (!(parsed instanceof SamlRedirectBindingParseResult.Parsed redirect)) return malformedLogout(request);
        SamlRedirectBindingMessage message = redirect.getMessage();
        if (message.getKind() == SamlRedirectBindingMessage.Kind.REQUEST) {
            SamlLogoutRequestResult result = sp.acceptLogoutRequestResult(message, idp);
            if (result instanceof SamlLogoutRequestResult.Unavailable
                    || result instanceof SamlLogoutRequestResult.Indeterminate)
                return PlaygroundResources.fixed(503, "SAML logout unavailable.");
            if (!(result instanceof SamlLogoutRequestResult.Accepted accepted))
                return PlaygroundResources.fixed(400, "SAML logout request rejected.");
            sessions.endMatchingSamlSessions(accepted.getRequest());
            SamlLogoutResponseRedirectResult response = sp.respondToLogoutRequestResult(
                    accepted.getRequest(), idp, SamlLogoutStatus.SUCCESS);
            if (response instanceof SamlLogoutResponseRedirectResult.Prepared prepared)
                return SokletSaml.logoutResponseRedirect(prepared, Set.of());
            return PlaygroundResources.fixed(503, "SAML logout response unavailable.");
        }
        return completeLogout(request, message, null);
    }

    private @NonNull Response malformedLogout(@NonNull Request request) {
        BrowserSessions.Session session = sessions.findForSamlLogout(request).orElse(null);
        if (session != null) {
            synchronized (session) {
                if (session.samlLogout == null && BrowserSessions.cookieValue(request, LOGOUT_COOKIE).isPresent())
                    return failed(400, "SAML logout binding rejected.", clear(LOGOUT_COOKIE));
            }
        }
        return PlaygroundResources.fixed(400, "SAML logout binding rejected.");
    }

    private @NonNull Response completeLogout(@NonNull Request request, @Nullable SamlRedirectBindingMessage redirect,
            @Nullable SamlPostBindingMessage post) {
        BrowserSessions.Session session = sessions.findForSamlLogout(request).orElse(null);
        if (session == null) return PlaygroundResources.fixed(400, "Browser binding is required.");
        synchronized (session) {
            LogoutFlow flow = session.samlLogout;
            if (flow == null) return failed(400, "SAML logout pending state unavailable.", clear(LOGOUT_COOKIE));
            if (!clock.instant().isBefore(flow.expires)) {
                session.samlLogout = null;
                return failed(400, "SAML logout pending state expired.", clear(LOGOUT_COOKIE));
            }
            if (flow.post != (post != null)) return PlaygroundResources.fixed(400, "SAML logout binding rejected.");
            if (!sameCookie(request, LOGOUT_COOKIE, flow.sealed))
                return PlaygroundResources.fixed(400, "SAML logout browser binding rejected.");
            PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(flow.sealed, sealer, flow.context);
            SamlLogoutResult result = post != null ? sp.completeLogoutResult(post, source, idp)
                    : sp.completeLogoutResult(java.util.Objects.requireNonNull(redirect), source, idp);
            if (!clock.instant().isBefore(flow.expires)) {
                session.samlLogout = null;
                return failed(400, "SAML logout pending state expired.", clear(LOGOUT_COOKIE));
            }
            if (result instanceof SamlLogoutResult.Succeeded) {
                session.samlLogout = null;
                return SokletOAuth.redirect(origin.resolve("/"), Set.of(clear(LOGOUT_COOKIE)));
            }
            if (result instanceof SamlLogoutResult.StatusReceived) {
                session.samlLogout = null;
                return failed(400, "SAML provider reported an unsuccessful logout.", clear(LOGOUT_COOKIE));
            }
            if (result instanceof SamlLogoutResult.Unavailable || result instanceof SamlLogoutResult.Indeterminate)
                return PlaygroundResources.fixed(503, "SAML logout unavailable.");
            return PlaygroundResources.fixed(400, "SAML logout rejected.");
        }
    }

    private synchronized @Nullable String account(@NonNull String connectionId, @NonNull SamlSubjectKey subject) {
        String key = connectionId + '\0' + subject.toStableString();
        String existing = accounts.get(key);
        if (existing != null) return existing;
        if (accounts.size() >= 128) return null;
        String selected = LocalSecrets.randomId();
        accounts.put(key, selected);
        return selected;
    }

    private boolean trustedHost(@NonNull Request request) {
        List<String> hosts = PlaygroundAdmission.headerValues(request, "Host");
        return hosts.size() == 1 && hosts.get(0).equals(origin.getRawAuthority());
    }

    private boolean trustedCallback(@NonNull Request request, boolean opaquePostOrigin) {
        if (!trustedHost(request)) return false;
        List<String> origins = PlaygroundAdmission.headerValues(request, "Origin");
        // Opaque Origin is auxiliary only for ACS or enabled POST-SLO. It grants no IdP trust:
        // signed SAML and saved browser pending state (returns) or full session matching remain mandatory.
        return origins.isEmpty() || origins.size() == 1 && (origins.get(0).equals(idpOrigin.toString())
                || origins.get(0).equals(origin.toString())
                || (opaquePostOrigin && postLogoutOrigin != null && origins.get(0).equals(postLogoutOrigin.toString()))
                || (opaquePostOrigin && origins.get(0).equals("null")));
    }

    private static @NonNull String context(BrowserSessions.@NonNull Session session, @NonNull String kind) {
        return "playground-saml:" + kind + ':' + session.binding.toSecretString();
    }

    private boolean sameCookie(@NonNull Request request, @NonNull String name, @NonNull String expected) {
        String actual = BrowserSessions.cookieValue(request, name).orElse("");
        return actual.length() == expected.length() && MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.US_ASCII), expected.getBytes(StandardCharsets.US_ASCII));
    }

    private @NonNull ResponseCookie cookie(@NonNull String name, @NonNull String value,
            @NonNull Instant expires) {
        Duration age = Duration.between(clock.instant(), expires);
        return ResponseCookie.with(name, value).path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.NONE).maxAge(age.isNegative() ? Duration.ZERO : age).build();
    }

    private static @NonNull ResponseCookie clear(@NonNull String name) {
        return ResponseCookie.with(name, "").path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.NONE).maxAge(Duration.ZERO).build();
    }

    private static @NonNull Response failed(int status, @NonNull String message,
            @NonNull ResponseCookie clear) {
        return PlaygroundResources.fixed(status, message).copy().cookies(List.of(clear)).finish();
    }

    static final class Flow {
        final String sealed;
        final String context;
        final Instant expires;
        Flow(@NonNull String sealed, @NonNull String context, @NonNull Instant expires) {
            this.sealed = sealed; this.context = context; this.expires = expires;
        }
        @Override public @NonNull String toString() { return "SamlFlow{data=<redacted>}"; }
    }

    static final class LogoutFlow {
        final String sealed;
        final String context;
        final Instant expires;
        final boolean post;
        LogoutFlow(@NonNull String sealed, @NonNull String context, @NonNull Instant expires, boolean post) {
            this.sealed = sealed; this.context = context; this.expires = expires; this.post = post;
        }
        @Override public @NonNull String toString() { return "SamlLogoutFlow{data=<redacted>}"; }
    }
}
