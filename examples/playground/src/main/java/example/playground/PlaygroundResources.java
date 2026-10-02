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

import com.revetsec.RevetsecException;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.*;
import com.revetsec.oidc.OidcClient;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Fixed HTTP routes. No generic file server, callback exporter, or browser credential store. */
public final class PlaygroundResources {
    private final BrowserSessions sessions;
    private final SafeViews views;
    private final PlaygroundOidc oidc;
    private final HttpClient http;
    private final ArrayDeque<@NonNull AppEvent> events = new ArrayDeque<>();
    private volatile PlaygroundAdmission.RuntimeProfile profile;

    PlaygroundResources(@NonNull PlaygroundConfig config, @NonNull BrowserSessions sessions,
            @NonNull SafeViews views, @NonNull PlaygroundOidc oidc, @NonNull HttpClient http) {
        this(config, sessions, views, oidc, http, config.validator(http));
    }

    PlaygroundResources(@NonNull PlaygroundConfig config, @NonNull BrowserSessions sessions,
            @NonNull SafeViews views, @NonNull PlaygroundOidc oidc, @NonNull HttpClient http,
            PlaygroundAdmission.@NonNull TokenValidator validator) {
        this.sessions = sessions; this.views = views; this.oidc = oidc; this.http = http;
        profile = new PlaygroundAdmission.RuntimeProfile(config, validator);
    }

    PlaygroundAdmission.@NonNull RuntimeProfile profile() { sessions.cleanup(); cleanupEvents(); return profile; }

    @GET("/") public @NonNull Response index(@NonNull Request request) { return asset(request, "index.html", "text/html; charset=UTF-8"); }
    @GET("/app.js") public @NonNull Response script(@NonNull Request request) { return asset(request, "app.js", "text/javascript; charset=UTF-8"); }
    @GET("/style.css") public @NonNull Response style(@NonNull Request request) { return asset(request, "style.css", "text/css; charset=UTF-8"); }

    @GET("/api/session") public @NonNull Response session(@NonNull Request request) {
        if (!PlaygroundAdmission.trusted(request, profile.config, false)) return fixed(403, "Request denied.");
        try {
            BrowserSessions.Session session = sessions.find(request).orElseGet(sessions::begin);
            synchronized (session) {
                JsonObject.Builder view = JsonObject.builder().put("csrf", session.csrf).put("authenticated", session.identity != null)
                        .put("issuer", profile.config.issuer).put("clientId", profile.config.clientId)
                        .put("strategy", profile.config.strategy).put("resource", profile.config.resourceUri().toString())
                        .put("secretReference", profile.config.secretReference)
                        .put("probeClientId", profile.config.probeClientId)
                        .put("probeSecretReference", profile.config.probeSecretReference)
                        .put("loopbackHttp", profile.config.loopbackHttp).put("replayEnabled", profile.config.replayEnabled)
                        .put("journalAvailable", session.journal != null)
                        .put("events", SafeViews.scopes(eventSnapshot()));
                if (session.identity != null) view.put("identity", session.identity);
                return json(200, view.build()).copy().cookies(Set.of(BrowserSessions.cookie(session))).finish();
            }
        } catch (IllegalStateException full) { return fixed(503, "Local session store is full."); }
    }

    @GET("/.well-known/oauth-protected-resource/mcp")
    public @NonNull Response metadata(@NonNull Request request) {
        PlaygroundConfig config = profile.config;
        if (!PlaygroundAdmission.trusted(request, config, false)) return fixed(403, "Request denied.");
        ProtectedResourceMetadata metadata = ProtectedResourceMetadata.withResource(config.resourceUri())
                .authorizationServers(List.of(config.issuer)).scopesSupported(PlaygroundConfig.SCOPES.stream().sorted().toList())
                .allowInsecureLoopback(config.loopbackHttp).build();
        return response(200, metadata.toJson(), "application/json; charset=UTF-8");
    }

    @POST("/api/config") public @NonNull Response configure(@NonNull Request request) {
        if (controlSession(request) == null) return fixed(403, "Request denied.");
        try {
            Map<String, String> form = form(request);
            if (!Set.of("issuer", "clientId", "secretReference", "probeClientId", "probeSecretReference", "strategy")
                    .containsAll(form.keySet())) return fixed(400, "Configuration rejected.");
            PlaygroundConfig selected = profile.config.withForm(form);
            PlaygroundAdmission.TokenValidator validator = selected.validator(http);
            // Constructing the OIDC client checks secret/config references; no discovery runs here.
            selected.oidcClient(http);
            profile = new PlaygroundAdmission.RuntimeProfile(selected, validator);
            event("Provider configuration selected");
            return json(200, JsonObject.builder().put("outcome", "Configuration selected").build());
        } catch (IllegalArgumentException | IllegalStateException failure) { return fixed(400, "Configuration rejected."); }
    }

    @POST("/oidc/begin") public @NonNull Response begin(@NonNull Request request) {
        BrowserSessions.Session session = controlSession(request);
        if (session == null) return fixed(403, "Request denied.");
        try {
            Map<String, String> form = form(request);
            PlaygroundConfig config = profile.config;
            OidcClient client = config.oidcClient(http);
            return oidc.begin(config, client, session, form.getOrDefault("mode", "atomic").equals("sealed"),
                    form.getOrDefault("responseMode", "query").equals("form_post"),
                    form.getOrDefault("capture", "false").equals("true"));
        } catch (RevetsecException failure) { return fixed(503, "Authentication service unavailable."); }
        catch (IllegalArgumentException failure) { return fixed(400, "Authentication request rejected."); }
    }

    @GET("/oidc/callback") @POST("/oidc/callback")
    public @NonNull Response callback(@NonNull Request request) {
        if (!PlaygroundAdmission.trusted(request, profile.config, true)) return fixed(403, "Request denied.");
        event("OIDC callback received");
        return oidc.callback(profile.config, request);
    }

    @POST("/api/replay") public @NonNull Response replay(@NonNull Request request) {
        BrowserSessions.Session session = controlSession(request);
        if (session == null) return fixed(403, "Request denied.");
        if (!profile.config.replayEnabled) return fixed(403, "Replay journal is disabled.");
        event("One replay demonstration attempted");
        return json(200, oidc.replay(session));
    }

    @POST("/api/inspect") public @NonNull Response inspect(@NonNull Request request) {
        if (controlSession(request) == null) return fixed(403, "Request denied.");
        String credential;
        try {
            List<String> types = PlaygroundAdmission.headerValues(request, "Content-Type");
            if (types.size() != 1 || !types.get(0).equalsIgnoreCase("text/plain; charset=UTF-8"))
                return fixed(400, "Inspection input rejected.");
            byte[] bytes = request.getBody().orElseGet(() -> new byte[0]);
            if (bytes.length == 0 || bytes.length > 8192) return fixed(400, "Inspection input rejected.");
            credential = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            BearerToken token = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + credential), 8192).orElseThrow();
            AccessTokenValidationResult result = profile.validator.validate(token);
            event("Transient token inspection completed");
            if (result instanceof AccessTokenValidationResult.Succeeded success)
                return json(200, views.checked(success.getAccessToken()));
            JsonObject.Builder view = JsonObject.builder().put("validation", "Rejected; no checked identity released")
                    .put("headerLabels", unverifiedLabels(credential));
            if (result instanceof AccessTokenValidationResult.Rejected rejected) view.put("reason", rejected.getReason().name());
            return json(400, view.build());
        } catch (AccessTokenValidationException | CharacterCodingException failure) {
            return fixed(400, "Inspection input rejected.");
        } catch (RevetsecException failure) { return fixed(503, "Validation service unavailable."); }
    }

    @POST("/api/probe") public @NonNull Response probe(@NonNull Request request) {
        if (controlSession(request) == null) return fixed(403, "Request denied.");
        PlaygroundConfig config = profile.config;
        try {
            ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(config.oauthClient(http, true))
                    .scopes(PlaygroundConfig.SCOPES).resources(List.of(config.resourceUri())).build();
            AccessToken token = source.getAccessToken();
            int status = probeCall(config, token);
            boolean retried = false;
            if (status == 401) {
                source.invalidate(token); // app-selected single retry, only after the RS's credential rejection
                status = probeCall(config, source.getAccessToken());
                retried = true;
            }
            event("Client credentials MCP probe completed");
            return json(status == 200 ? 200 : 400, JsonObject.builder().put("httpStatus", (long) status)
                    .put("retriedOnce", retried).put("outcome", status == 200 ? "MCP request completed" : "MCP request denied").build());
        } catch (RevetsecException | IOException failure) { return fixed(503, "Probe service unavailable."); }
        catch (InterruptedException failure) { Thread.currentThread().interrupt(); return fixed(503, "Probe service unavailable."); }
        catch (IllegalArgumentException failure) { return fixed(400, "Probe configuration rejected."); }
    }

    private int probeCall(@NonNull PlaygroundConfig config, @NonNull AccessToken token) throws IOException, InterruptedException {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":\"probe\",\"method\":\"tools/call\",\"params\":{\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},"
                + "\"name\":\"whoami\",\"arguments\":{\"tenant\":\"local\",\"object\":\"self\"}}}";
        HttpRequest call = HttpRequest.newBuilder(config.resourceUri()).timeout(Duration.ofSeconds(5))
                .header("Authorization", token.getAuthorizationHeaderValue()).header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream").header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call").header("Mcp-Name", "whoami")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
        // Only the status is used. Return after headers and cancel the unread body immediately: on older
        // JDKs the request timeout does not bound a response body that starts and then stalls.
        HttpResponse<java.io.InputStream> response = http.send(call, HttpResponse.BodyHandlers.ofInputStream());
        response.body().close();
        return response.statusCode();
    }

    private BrowserSessions.@Nullable Session controlSession(@NonNull Request request) {
        sessions.cleanup();
        if (!PlaygroundAdmission.trusted(request, profile.config, false)) return null;
        List<String> origins = PlaygroundAdmission.headerValues(request, "Origin");
        if (origins.size() != 1 || !origins.get(0).equals(profile.config.origin.toString())) return null;
        BrowserSessions.Session session = sessions.find(request).orElse(null);
        if (session == null) return null;
        List<String> headers = PlaygroundAdmission.headerValues(request, "X-CSRF-Token");
        String candidate = headers.size() == 1 ? headers.get(0) : null;
        if (request.getResourcePath().getPath().equals("/oidc/begin") && headers.isEmpty()) {
            try { candidate = formValues(request).get("csrf"); } catch (RuntimeException bad) { return null; }
        }
        return BrowserSessions.csrfMatches(session, candidate) ? session : null;
    }

    private static @NonNull Map<@NonNull String, @NonNull String> form(@NonNull Request request) {
        Map<String, String> values = new LinkedHashMap<>(formValues(request));
        values.remove("csrf");
        return Map.copyOf(values);
    }

    private static @NonNull Map<@NonNull String, @NonNull String> formValues(@NonNull Request request) {
        if (request.getBody().map(b -> b.length).orElse(0) > 4096 || request.isContentTooLarge())
            throw new IllegalArgumentException("Control input exceeds cap.");
        List<String> types = PlaygroundAdmission.headerValues(request, "Content-Type");
        if (types.size() != 1 || !types.get(0).equalsIgnoreCase("application/x-www-form-urlencoded"))
            throw new IllegalArgumentException("Control media type is invalid.");
        Map<String, String> values = new LinkedHashMap<>();
        String body;
        try {
            body = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(request.getBody().orElseGet(() -> new byte[0]))).toString();
        } catch (CharacterCodingException bad) { throw new IllegalArgumentException("Control encoding is invalid."); }
        for (String pair : body.split("&", -1)) {
            int equals = pair.indexOf('=');
            if (equals < 1) throw new IllegalArgumentException("Control field is invalid.");
            String key = formComponent(pair.substring(0, equals));
            String value = formComponent(pair.substring(equals + 1));
            if (key.isEmpty() || key.length() > 64 || values.containsKey(key))
                throw new IllegalArgumentException("Control field is invalid.");
            if (value.length() > 512) throw new IllegalArgumentException("Control field is invalid.");
            values.put(key, value);
        }
        if (values.size() - (values.containsKey("csrf") ? 1 : 0) > 10)
            throw new IllegalArgumentException("Control fields exceed cap.");
        return Map.copyOf(values);
    }

    private static @NonNull String formComponent(@NonNull String encoded) {
        byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream decoded = new java.io.ByteArrayOutputStream(bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 255;
            if (value == '%') {
                if (i + 2 >= bytes.length) throw new IllegalArgumentException("Control encoding is invalid.");
                int high = Character.digit((char) bytes[++i], 16);
                int low = Character.digit((char) bytes[++i], 16);
                if (high < 0 || low < 0) throw new IllegalArgumentException("Control encoding is invalid.");
                decoded.write(high * 16 + low);
            } else decoded.write(value == '+' ? ' ' : value);
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(decoded.toByteArray())).toString();
        } catch (CharacterCodingException bad) { throw new IllegalArgumentException("Control encoding is invalid."); }
    }

    /** Diagnostic-only candidates, never an authentication parse: values come from a fixed safe vocabulary. */
    static @NonNull JsonObject unverifiedLabels(@NonNull String credential) {
        JsonObject.Builder labels = JsonObject.builder().put("trust", "UNVERIFIED header labels; no claims or permission");
        int end = credential.indexOf('.');
        if (end < 1 || end > 2048) return labels.build();
        try {
            String header = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Base64.getUrlDecoder().decode(credential.substring(0, end)))).toString();
            for (String key : List.of("alg", "typ")) {
                var matches = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([A-Za-z0-9/+._-]{1,32})\"").matcher(header);
                if (matches.find()) {
                    String candidate = matches.group(1);
                    if (!matches.find() && Set.of("RS256", "RS384", "RS512", "ES256", "EdDSA", "none", "HS256",
                            "JWT", "at+jwt", "application/at+jwt").contains(candidate)) labels.put(key, candidate);
                }
            }
        } catch (IllegalArgumentException | CharacterCodingException malformed) { /* no unverified output */ }
        return labels.build();
    }

    private @NonNull Response asset(@NonNull Request request, @NonNull String name, @NonNull String type) {
        sessions.cleanup();
        cleanupEvents();
        if (!PlaygroundAdmission.trusted(request, profile.config, false)) return fixed(403, "Request denied.");
        try (var input = PlaygroundResources.class.getResourceAsStream("/web/" + name)) {
            if (input == null) throw new IllegalStateException("Packaged static resource missing.");
            byte[] bytes = input.readNBytes(65_537);
            if (bytes.length > 65_536) throw new IllegalStateException("Packaged static resource exceeds cap.");
            Response response = response(200, new String(bytes, StandardCharsets.UTF_8), type);
            if (name.equals("index.html")) {
                java.net.URI provider = java.net.URI.create(profile.config.issuer);
                String action = provider.getScheme() + "://" + provider.getRawAuthority();
                return response.copy().headers(headers -> {
                    headers.put("Referrer-Policy", Set.of("same-origin"));
                    headers.put("Content-Security-Policy", Set.of(
                            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self' "
                                    + action + "; base-uri 'none'; frame-ancestors 'none'"));
                }).finish();
            }
            return response;
        } catch (IOException failure) { return fixed(503, "Static resource unavailable."); }
    }

    private synchronized void event(@NonNull String fixedEvent) {
        if (events.size() == 32) events.removeFirst();
        events.addLast(new AppEvent(fixedEvent, java.time.Instant.now())); // fixed vocabulary; at most 2 KiB
    }
    private synchronized @NonNull List<@NonNull String> eventSnapshot() {
        cleanupEvents();
        return events.stream().map(event -> event.name).toList();
    }
    private synchronized void cleanupEvents() {
        java.time.Instant cutoff = java.time.Instant.now().minus(Duration.ofMinutes(10));
        events.removeIf(event -> !event.at.isAfter(cutoff));
    }

    private static final class AppEvent {
        final String name;
        final java.time.Instant at;
        AppEvent(@NonNull String name, java.time.@NonNull Instant at) { this.name = name; this.at = at; }
    }

    static @NonNull Response json(int status, @NonNull JsonObject body) { return response(status, body.toJson(), "application/json; charset=UTF-8"); }
    static @NonNull Response fixed(int status, @NonNull String message) { return json(status, JsonObject.builder().put("outcome", message).build()); }
    private static @NonNull Response response(int status, @NonNull String body, @NonNull String type) {
        return Response.withStatusCode(status).body(body).headers(Map.of("Content-Type", Set.of(type),
                "Cache-Control", Set.of("no-store"), "Referrer-Policy", Set.of("no-referrer"),
                "X-Content-Type-Options", Set.of("nosniff"), "Content-Security-Policy", Set.of(
                    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"))).build();
    }
}
