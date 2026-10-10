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
import com.soklet.Request;
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
    private final Map<@NonNull String, @NonNull String> accounts = new LinkedHashMap<>();

    private PlaygroundSaml(@NonNull BrowserSessions sessions, @NonNull SafeViews views,
            @NonNull SamlServiceProvider sp, @NonNull SamlIdentityProvider idp,
            @NonNull StateSealer sealer, @NonNull URI origin, @NonNull URI idpOrigin,
            @NonNull Clock clock, @NonNull String metadataXml) {
        this.sessions = sessions; this.views = views; this.sp = sp; this.idp = idp;
        this.sealer = sealer; this.origin = origin; this.idpOrigin = idpOrigin;
        this.clock = clock; this.metadataXml = metadataXml;
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
                .signingCredential(signing).decryptionCredentials(decryption)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 1024)).clock(clock).build();
        SamlServiceProviderMetadataResult generated = SamlServiceProviderMetadata.fromServiceProviderResult(sp);
        if (!(generated instanceof SamlServiceProviderMetadataResult.Generated ready))
            throw new IllegalArgumentException("SAML SP metadata is unavailable.");
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("playground-saml-run",
                Base64.getEncoder().encodeToString(LocalSecrets.randomBytes()))).clock(clock).build();
        return new PlaygroundSaml(sessions, views, sp, idp, sealer, config.origin, idpOrigin,
                clock, ready.getXml());
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
            session.samlFlow = null;
            if (flow == null) return failed(400, "SAML pending state is unavailable.", clear(LOGIN_COOKIE));
            ResponseCookie clear = clear(LOGIN_COOKIE);
            if (!clock.instant().isBefore(flow.expires)
                    || !sameCookie(request, LOGIN_COOKIE, flow.sealed))
                return failed(400, "SAML browser binding rejected.", clear);
            SamlPostBindingParseResult parsed = SokletSaml.postBindingResultFor(request);
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
                BrowserSessions.Session rotated = sessions.rotate(session, identity);
                rotated.samlReference = authentication.getSessionReference();
                return SokletOAuth.redirect(origin.resolve("/"), Set.of(clear, BrowserSessions.cookie(rotated)));
            } catch (IllegalStateException expired) {
                return failed(400, "Browser session expired.", clear);
            }
        }
    }

    @NonNull Response beginLogout(BrowserSessions.@NonNull Session session) {
        synchronized (session) {
            SamlSessionReference reference = session.samlReference;
            if (reference == null) return PlaygroundResources.fixed(400, "No SAML session is active.");
            if (session.samlFlow != null || session.samlLogout != null)
                return PlaygroundResources.fixed(409, "One SAML flow per browser session.");
            SamlLogoutRedirectResult result = sp.beginLogoutResult(idp, reference);
            if (result instanceof SamlLogoutRedirectResult.Unavailable)
                return PlaygroundResources.fixed(503, "SAML logout unavailable.");
            if (!(result instanceof SamlLogoutRedirectResult.Prepared prepared))
                return PlaygroundResources.fixed(400, "SAML logout configuration rejected.");
            String context = context(session, "logout");
            String sealed = prepared.getPendingLogout().toSealedForm(sealer, context);
            if (sealed.length() > 3800) return PlaygroundResources.fixed(503, "SAML logout state unavailable.");
            Instant expires = prepared.getPendingLogout().getExpiresAt();
            session.samlLogout = new LogoutFlow(sealed, context, expires);
            // Local access ends now, even if the front-channel return never arrives.
            session.identity = null;
            session.samlReference = null;
            return SokletSaml.logoutRedirect(prepared, Set.of(cookie(LOGOUT_COOKIE, sealed, expires)));
        }
    }

    @NonNull Response logoutCallback(@NonNull Request request) {
        if (!trustedCallback(request, false)) return PlaygroundResources.fixed(403, "Request denied.");
        SamlRedirectBindingParseResult parsed = SokletSaml.redirectBindingResultFor(request);
        if (!(parsed instanceof SamlRedirectBindingParseResult.Parsed redirect)) {
            BrowserSessions.Session session = sessions.find(request).orElse(null);
            if (session != null) {
                synchronized (session) {
                    if (session.samlLogout != null) {
                        session.samlLogout = null;
                        return failed(400, "SAML logout binding rejected.", clear(LOGOUT_COOKIE));
                    }
                }
            }
            return PlaygroundResources.fixed(400, "SAML logout binding rejected.");
        }
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
        BrowserSessions.Session session = sessions.find(request).orElse(null);
        if (session == null) return failed(400, "Browser binding is required.", clear(LOGOUT_COOKIE));
        synchronized (session) {
            LogoutFlow flow = session.samlLogout;
            session.samlLogout = null;
            if (flow == null) return failed(400, "SAML logout pending state unavailable.", clear(LOGOUT_COOKIE));
            ResponseCookie clear = clear(LOGOUT_COOKIE);
            if (!clock.instant().isBefore(flow.expires)
                    || !sameCookie(request, LOGOUT_COOKIE, flow.sealed))
                return failed(400, "SAML logout browser binding rejected.", clear);
            SamlLogoutResult result = sp.completeLogoutResult(message,
                    PendingSamlLogoutSource.fromSealedForm(flow.sealed, sealer, flow.context), idp);
            if (result instanceof SamlLogoutResult.Succeeded)
                return SokletOAuth.redirect(origin.resolve("/"), Set.of(clear));
            if (result instanceof SamlLogoutResult.Unavailable || result instanceof SamlLogoutResult.Indeterminate)
                return failed(503, "SAML logout unavailable.", clear);
            return failed(400, "SAML logout rejected.", clear);
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

    private boolean trustedCallback(@NonNull Request request, boolean postAcs) {
        if (!trustedHost(request)) return false;
        List<String> origins = PlaygroundAdmission.headerValues(request, "Origin");
        // A redirected IdP form POST can carry the opaque Origin "null". Only the ACS accepts it;
        // the browser-bound pending state and verified SAML response remain mandatory.
        return origins.isEmpty() || origins.size() == 1 && (origins.get(0).equals(idpOrigin.toString())
                || origins.get(0).equals(origin.toString())
                || (postAcs && origins.get(0).equals("null")));
    }

    private static @NonNull String context(BrowserSessions.@NonNull Session session, @NonNull String kind) {
        return "playground-saml:" + kind + ':' + session.binding;
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
        LogoutFlow(@NonNull String sealed, @NonNull String context, @NonNull Instant expires) {
            this.sealed = sealed; this.context = context; this.expires = expires;
        }
        @Override public @NonNull String toString() { return "SamlLogoutFlow{data=<redacted>}"; }
    }
}
