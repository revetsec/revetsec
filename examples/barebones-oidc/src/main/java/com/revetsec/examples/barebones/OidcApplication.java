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
package com.revetsec.examples.barebones;

import com.revetsec.RevetsecException;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.OAuthResponseException;
import com.revetsec.oidc.OidcAuthenticationResult;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.oidc.OidcClient;
import com.revetsec.soklet.SokletOAuth;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import static java.util.Objects.requireNonNull;

/** A bounded, single-process application example. Identity comes only from successful OIDC validation.
 * @since 1.0.0
 */
@ThreadSafe
public final class OidcApplication {
    static final @NonNull String SESSION_COOKIE = "__Host-revetsec-session";
    static final @NonNull String PENDING_COOKIE = "__Host-revetsec-pending";
    private static final @NonNull Duration SESSION_AGE = Duration.ofMinutes(30);
    private final @NonNull OidcClient client;
    private final @NonNull URI origin;
    private final @NonNull URI callback;
    private final @NonNull String issuerOrigin;
    private final @NonNull Clock clock;
    private final @NonNull PendingStore pending;
    private final @NonNull SecureRandom random = new SecureRandom();
    private final byte @NonNull [] identityKey = new byte[32];
    private final @NonNull Map<@NonNull String, @NonNull Session> sessions = new HashMap<>();
    private long sessionBytes;
    private final int maximumSessions;
    private final AuthorizationRequestOptions.@NonNull ResponseMode responseMode;

    OidcApplication(@NonNull OidcClient client, @NonNull URI origin, @NonNull URI issuer, @NonNull Clock clock,
                    int maximumSessions, @NonNull PendingStore pending,
                    AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
        this.client = requireNonNull(client);
        this.origin = checkedOrigin(origin);
        this.callback = origin.resolve("/callback");
        this.issuerOrigin = requireNonNull(issuer).getScheme() + "://" + issuer.getRawAuthority();
        this.clock = requireNonNull(clock);
        if (maximumSessions < 1 || maximumSessions > 1024) throw new IllegalArgumentException("Invalid session limit");
        this.maximumSessions = maximumSessions;
        this.pending = requireNonNull(pending);
        this.responseMode = requireNonNull(responseMode);
        this.random.nextBytes(this.identityKey);
    }

    static @NonNull URI checkedOrigin(@NonNull URI origin) {
        requireNonNull(origin);
        if (!"https".equals(origin.getScheme()) || !Set.of("localhost", "127.0.0.1").contains(origin.getHost())
                || origin.getRawUserInfo() != null || origin.getRawQuery() != null || origin.getRawFragment() != null
                || !(origin.getRawPath().isEmpty() || origin.getRawPath().equals("/"))
                || origin.getPort() < -1 || origin.getPort() == 0 || origin.getPort() > 65535)
            throw new IllegalArgumentException("App origin requires an HTTPS loopback origin");
        return URI.create("https://" + origin.getRawAuthority());
    }

    @NonNull SokletConfig configuration(int port) {
        if (port < 1024 || port > 65535) throw new IllegalArgumentException("Invalid loopback listener port");
        OidcApplication application = this;
        return SokletConfig.withHttpServer(HttpServer.withPort(port).host("127.0.0.1")
                .maximumRequestSizeInBytes(65_536).maximumHeadersSizeInBytes(8192).maximumHeaderCount(32)
                .maximumRequestTargetLengthInBytes(8192).concurrentConnectionLimit(64)
                .requestHandlerConcurrency(8).requestHandlerQueueCapacity(16).build())
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(OidcApplication.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        if (type == OidcApplication.class) return type.cast(application);
                        throw new IllegalArgumentException("Unknown application component");
                    }
                }).requestInterceptor(new RequestInterceptor() {
                    @Override public void interceptRequest(@NonNull ServerType type, @NonNull Request request,
                            @Nullable ResourceMethod method,
                            @NonNull Function<@NonNull Request, @NonNull MarshaledResponse> handler,
                            @NonNull Consumer<@NonNull MarshaledResponse> writer) {
                        application.cleanup();
                        writer.accept(application.hostAllowed(request) ? handler.apply(request)
                                : MarshaledResponse.withStatusCode(400).headers(headers("text/plain; charset=UTF-8"))
                                        .body("Invalid request".getBytes(StandardCharsets.UTF_8)).build());
                    }
                }).lifecycleObserver(new LifecycleObserver() {
                    @Override public void didReceiveLogEvent(@NonNull LogEvent event) {
                        // The example deliberately has no request, credential or exception logging.
                    }
                }).build();
    }

    /** Shows only a per-process pseudonym and checked issuer; tokens never enter the view.
     * @param request untrusted request
     * @return fixed application response
     * @since 1.0.0
     */
    @GET("/")
    public @NonNull Response home(@NonNull Request request) {
        if (!hostAllowed(request) || !headerAbsentOr(request, "Origin", this.origin.toString()))
            return failure(400, "Invalid request");
        Session session = sessionFor(request);
        List<ResponseCookie> cookies = List.of();
        if (session == null) {
            session = addSession(null);
            if (session == null) return failure(503, "Please try again later");
            cookies = List.of(cookie(SESSION_COOKIE, session.id, SESSION_AGE));
        }
        String identity = session.identity == null ? "Signed out" : "Signed in as " + escape(session.identity);
        String action = session.identity == null ? "login" : "logout";
        String html = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Revetsec OIDC</title>"
                + "<h1>Revetsec OIDC example</h1><p>" + identity + "</p>"
                + "<form method=\"post\" action=\"/" + action + "\"><input type=\"hidden\" name=\"csrf\" value=\""
                + session.csrf + "\"><button>" + (action.equals("login") ? "Sign in" : "Sign out")
                + "</button></form><p>This example uses process-local storage.</p></html>";
        Map<String, List<String>> htmlHeaders = new HashMap<>(headers("text/html; charset=UTF-8"));
        // Browsers need the same-origin document referrer to send a non-null Origin on navigation POST forms.
        htmlHeaders.put("Referrer-Policy", List.of("same-origin"));
        // Some browsers apply form-action to redirect destinations. Only the configured provider origin is added.
        htmlHeaders.put("Content-Security-Policy", List.of("default-src 'none'; form-action 'self' "
                + this.issuerOrigin + "; frame-ancestors 'none'; base-uri 'none'"));
        return Response.withStatusCode(200).headers(htmlHeaders).cookies(cookies).body(html).build();
    }

    /** Starts a single browser-bound flow after the application's origin and CSRF checks.
     * @param request untrusted request
     * @return redirect or fixed error
     * @since 1.0.0
     */
    @POST("/login")
    public @NonNull Response login(@NonNull Request request) {
        Session session = sessionFor(request);
        if (!mutationAllowed(request, session)) return failure(403, "Invalid request");
        String binding = token();
        synchronized (this.sessions) {
            if (this.sessions.get(session.id) != session || session.binding != null || session.identity != null)
                return failure(409, "Sign in already started");
            session.binding = binding;
            session.pendingUntil = this.clock.instant().plus(Duration.ofMinutes(5));
        }
        try {
            AuthorizationRedirect redirect = this.client.beginAuthentication(OidcAuthenticationOptions.builder()
                    .responseMode(this.responseMode).build());
            redirect.getPendingAuthorization().saveTo(this.pending, binding);
            return SokletOAuth.redirect(redirect.getAuthorizationUri(), Set.of(cookie(PENDING_COOKIE, binding, Duration.ofMinutes(5))));
        } catch (RevetsecException | PendingStore.CapacityException exception) {
            clearPending(session, binding);
            return failure(503, "Please try again later");
        }
    }

    /** Completes query-mode callbacks through the raw adapter and normal OIDC validator.
     * @param request untrusted request
     * @return rotating app-session redirect or fixed error
     * @since 1.0.0
     */
    @GET("/callback")
    public @NonNull Response queryCallback(@NonNull Request request) { return complete(request); }

    /** Completes form-post callbacks through the raw adapter and normal OIDC validator.
     * @param request untrusted request
     * @return rotating app-session redirect or fixed error
     * @since 1.0.0
     */
    @POST("/callback")
    public @NonNull Response formCallback(@NonNull Request request) { return complete(request); }

    private @NonNull Response complete(@NonNull Request request) {
        List<ResponseCookie> deletion = List.of(cookie(PENDING_COOKIE, "", Duration.ZERO));
        Session session = sessionFor(request);
        String binding = cookieValue(request, PENDING_COOKIE);
        if (!hostAllowed(request) || session == null || binding == null
                || !headerAbsentOr(request, "Origin", this.issuerOrigin))
            return failure(400, "Sign in failed", deletion);
        synchronized (this.sessions) {
            if (this.sessions.get(session.id) != session || session.binding == null
                    || !same(session.binding, binding)) return failure(400, "Sign in failed", deletion);
            session.binding = null; // Reserve before network I/O; competing callbacks cannot start a token POST.
            session.pendingUntil = null;
        }
        try {
            AuthorizationResponse response = SokletOAuth.authorizationResponseFor(request);
            OidcAuthenticationResult result = this.client.completeAuthenticationResult(response,
                    PendingAuthorizationSource.fromStore(this.pending, binding), this.callback);
            if (!(result instanceof OidcAuthenticationResult.Succeeded success))
                return failure(400, "Sign in failed", deletion);
            String identity = pseudonym(success.getAuthentication().getIssuer(), success.getAuthentication().getSubject());
            Session authenticated;
            synchronized (this.sessions) {
                if (this.sessions.get(session.id) != session) return failure(400, "Sign in failed", deletion);
                this.sessions.remove(session.id);
                this.sessionBytes -= session.chargedBytes;
                authenticated = addSession(identity);
            }
            if (authenticated == null) return failure(503, "Please try again later", deletion);
            return SokletOAuth.redirect(this.origin.resolve("/"), Set.of(
                    cookie(SESSION_COOKIE, authenticated.id, SESSION_AGE), cookie(PENDING_COOKIE, "", Duration.ZERO)));
        } catch (OAuthResponseException exception) {
            return failure(400, "Sign in failed", deletion);
        } catch (RevetsecException exception) {
            return failure(503, "Please try again later", deletion);
        } catch (IllegalArgumentException exception) {
            return failure(400, "Sign in failed", deletion);
        } finally {
            this.pending.discardBinding(binding);
        }
    }

    /** Removes only this application's session; this does not log out the identity provider.
     * @param request untrusted request
     * @return fixed local redirect or error
     * @since 1.0.0
     */
    @POST("/logout")
    public @NonNull Response logout(@NonNull Request request) {
        Session session = sessionFor(request);
        if (!mutationAllowed(request, session)) return failure(403, "Invalid request");
        synchronized (this.sessions) {
            if (this.sessions.remove(session.id, session)) this.sessionBytes -= session.chargedBytes;
            if (session.binding != null) this.pending.discardBinding(session.binding);
        }
        return SokletOAuth.redirect(this.origin.resolve("/"), Set.of(cookie(SESSION_COOKIE, "", Duration.ZERO),
                cookie(PENDING_COOKIE, "", Duration.ZERO)));
    }

    private boolean mutationAllowed(@NonNull Request request, @Nullable Session session) {
        if (session == null || !hostAllowed(request) || !singleHeader(request, "Origin", this.origin.toString())
                || !singleHeader(request, "Content-Type", "application/x-www-form-urlencoded")
                || request.getRawQuery().isPresent()) return false;
        byte[] expected = ("csrf=" + session.csrf).getBytes(StandardCharsets.US_ASCII);
        byte[] body = request.getBody().orElseGet(() -> new byte[0]);
        return body.length == expected.length && MessageDigest.isEqual(expected, body);
    }

    private @Nullable Session sessionFor(@NonNull Request request) {
        cleanup();
        String id = cookieValue(request, SESSION_COOKIE);
        synchronized (this.sessions) { return id == null ? null : this.sessions.get(id); }
    }

    private @Nullable Session addSession(@Nullable String identity) {
        synchronized (this.sessions) {
            cleanup();
            if (identity != null && identity.length() > 4096) return null;
            long charged = 512L + (identity == null ? 0 : identity.getBytes(StandardCharsets.UTF_8).length);
            if (this.sessions.size() >= this.maximumSessions || charged > 262_144 - this.sessionBytes) return null;
            Session session = new Session(token(), token(), this.clock.instant(), identity, charged);
            this.sessions.put(session.id, session);
            this.sessionBytes += charged;
            return session;
        }
    }

    private void clearPending(@NonNull Session session, @NonNull String binding) {
        synchronized (this.sessions) {
            if (binding.equals(session.binding)) { session.binding = null; session.pendingUntil = null; }
        }
        this.pending.discardBinding(binding);
    }

    private void cleanup() {
        synchronized (this.sessions) {
            Instant now = this.clock.instant();
            Iterator<Session> iterator = this.sessions.values().iterator();
            while (iterator.hasNext()) {
                Session session = iterator.next();
                if (now.isBefore(session.createdAt) || !now.isBefore(session.createdAt.plus(SESSION_AGE))) {
                    if (session.binding != null) this.pending.discardBinding(session.binding);
                    this.sessionBytes -= session.chargedBytes;
                    iterator.remove();
                } else if (session.pendingUntil != null && !now.isBefore(session.pendingUntil)) {
                    if (session.binding != null) this.pending.discardBinding(session.binding);
                    session.binding = null; session.pendingUntil = null;
                }
            }
        }
        this.pending.prune();
    }

    private boolean hostAllowed(@NonNull Request request) {
        return singleHeader(request, "Host", this.origin.getRawAuthority());
    }

    private static @NonNull List<@NonNull String> values(@NonNull Request request, @NonNull String name) {
        List<String> result = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet())
            if (name.equalsIgnoreCase(entry.getKey())) result.addAll(entry.getValue());
        return result;
    }

    private static boolean singleHeader(@NonNull Request request, @NonNull String name, @NonNull String expected) {
        return values(request, name).equals(List.of(expected));
    }

    private static boolean headerAbsentOr(@NonNull Request request, @NonNull String name, @NonNull String expected) {
        List<String> values = values(request, name);
        return values.isEmpty() || values.equals(List.of(expected));
    }

    private static @Nullable String cookieValue(@NonNull Request request, @NonNull String name) {
        // Parse raw fields ourselves so duplicate cookie pairs cannot be normalized away.
        List<String> values = values(request, "Cookie");
        if (values.size() != 1 || values.get(0).length() > 2048) return null;
        String found = null;
        for (String pair : values.get(0).split(";", -1)) {
            String trimmed = pair.strip();
            int equals = trimmed.indexOf('=');
            if (equals > 0 && trimmed.substring(0, equals).equals(name)) {
                if (found != null) return null;
                found = trimmed.substring(equals + 1);
                if (!found.matches("[A-Za-z0-9_-]{43}")) return null;
            }
        }
        return found;
    }

    private static @NonNull ResponseCookie cookie(@NonNull String name, @NonNull String value, @NonNull Duration age) {
        // NONE supports form_post delivery. All application mutations additionally require Origin + CSRF.
        return ResponseCookie.with(name, value).path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.NONE).maxAge(age).build();
    }

    private @NonNull String token() {
        byte[] bytes = new byte[32]; this.random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private @NonNull String pseudonym(@NonNull String issuer, @NonNull String subject) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.identityKey, "HmacSHA256"));
            mac.update(issuer.getBytes(StandardCharsets.UTF_8)); mac.update((byte) 0);
            return "user-" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(subject.getBytes(StandardCharsets.UTF_8))).substring(0, 16)
                    + " (issuer " + issuer + ")";
        } catch (GeneralSecurityException exception) { throw new IllegalStateException("Identity view unavailable"); }
    }

    private static boolean same(@NonNull String left, @NonNull String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII), right.getBytes(StandardCharsets.US_ASCII));
    }

    private static @NonNull String escape(@NonNull String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers(@NonNull String contentType) {
        return Map.of("Content-Type", List.of(contentType), "Cache-Control", List.of("no-store"),
                "Referrer-Policy", List.of("no-referrer"), "X-Content-Type-Options", List.of("nosniff"),
                "Content-Security-Policy", List.of("default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    }

    private static @NonNull Response failure(int status, @NonNull String text) { return failure(status, text, List.of()); }
    private static @NonNull Response failure(int status, @NonNull String text, @NonNull List<@NonNull ResponseCookie> cookies) {
        return Response.withStatusCode(status).headers(headers("text/plain; charset=UTF-8")).cookies(cookies).body(text).build();
    }

    private static final class Session {
        final @NonNull String id;
        final @NonNull String csrf;
        final @NonNull Instant createdAt;
        final @Nullable String identity;
        final long chargedBytes;
        @Nullable String binding;
        @Nullable Instant pendingUntil;
        Session(@NonNull String id, @NonNull String csrf, @NonNull Instant createdAt, @Nullable String identity, long chargedBytes) {
            this.id = id; this.csrf = csrf; this.createdAt = createdAt; this.identity = identity;
            this.chargedBytes = chargedBytes;
        }
    }
}
