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

import com.revetsec.BrowserBinding;
import com.revetsec.json.JsonObject;
import com.revetsec.saml.SamlLogoutRequest;
import com.revetsec.saml.SamlNameId;
import com.revetsec.saml.SamlSessionReference;
import com.soklet.Request;
import com.soklet.ResponseCookie;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Application sessions expire without a background worker; a finite cap rejects new entries. */
final class BrowserSessions {
    static final String COOKIE = "__Host-RevetsecPlayground";
    static final Duration LIFETIME = Duration.ofMinutes(10);
    // Reserve before allocating a session. Covers identity (2 KiB UTF-8), the bounded original callback
    // (24 KiB UTF-8), sealed cookie (3,800 ASCII chars), bindings and fixed per-entry bookkeeping.
    // This is a charged content budget, not a claim about exact JVM object allocation.
    static final long SESSION_CHARGE_BYTES = 65_536L;
    private final Map<@NonNull String, @NonNull Session> entries = new LinkedHashMap<>();
    private final Clock clock;
    private final int capacity;
    private final long maximumChargedBytes;

    BrowserSessions(@NonNull Clock clock, int capacity) {
        this(clock, capacity, 8_388_608L);
    }

    BrowserSessions(@NonNull Clock clock, int capacity, long maximumChargedBytes) {
        if (capacity < 1 || capacity > 256) throw new IllegalArgumentException("Session capacity is invalid.");
        if (maximumChargedBytes < SESSION_CHARGE_BYTES || maximumChargedBytes > 16_777_216L)
            throw new IllegalArgumentException("Session byte budget is invalid.");
        this.clock = clock; this.capacity = capacity; this.maximumChargedBytes = maximumChargedBytes;
    }

    synchronized @NonNull Session begin() {
        cleanup();
        if (entries.size() >= capacity || (entries.size() + 1L) * SESSION_CHARGE_BYTES > maximumChargedBytes)
            throw new IllegalStateException("Local session store is full.");
        Session session = new Session(LocalSecrets.randomId(), LocalSecrets.randomId(),
                BrowserBinding.fresh(), clock.instant().plus(LIFETIME));
        entries.put(session.id, session);
        return session;
    }

    synchronized @NonNull Optional<@NonNull Session> find(@NonNull Request request) {
        cleanup();
        String id = cookieValue(request, COOKIE).orElse("");
        Session found = entries.get(id);
        return found == null || found.authenticationClosed ? Optional.empty() : Optional.of(found);
    }

    /** A closed browser marker can correlate a logout return but grants no authentication authority. */
    synchronized @NonNull Optional<@NonNull Session> findForSamlLogout(@NonNull Request request) {
        cleanup();
        return Optional.ofNullable(entries.get(cookieValue(request, COOKIE).orElse("")));
    }

    synchronized long claimSamlFlow(@NonNull Session session, PlaygroundSaml.@NonNull Flow flow) {
        cleanup();
        if (entries.get(session.id) != session || session.authenticationClosed || session.samlFlow != flow)
            throw new IllegalStateException("Browser session or SAML attempt is no longer current.");
        session.samlFlow = null;
        return session.authenticationGeneration;
    }

    synchronized @NonNull Optional<@NonNull SamlClosure> closeSamlAuthority(@NonNull Session session) {
        cleanup();
        if (entries.get(session.id) != session || session.authenticationClosed || session.samlReference == null)
            return Optional.empty();
        SamlSessionReference reference = session.samlReference;
        boolean hadLogin = session.samlFlow != null;
        String oidcCookie = session.flow == null ? null : session.flow.cookieName;
        if (cancelAuthentication(session)) entries.remove(session.id);
        return Optional.of(new SamlClosure(reference, hadLogin, oidcCookie, session.authenticationGeneration));
    }

    synchronized boolean saveSamlLogout(@NonNull Session session, long generation, PlaygroundSaml.@NonNull LogoutFlow flow) {
        cleanup();
        if (entries.get(session.id) != session || !session.authenticationClosed
                || session.authenticationGeneration != generation || !clock.instant().isBefore(flow.expires)) return false;
        session.samlLogout = flow;
        return true;
    }

    synchronized @NonNull Session rotateSaml(@NonNull Session old, long generation, @NonNull JsonObject identity,
            @NonNull SamlSessionReference reference) {
        if (old.authenticationGeneration != generation) throw new IllegalStateException("Browser session changed.");
        // Retain the store monitor through both identity and reference publication; IdP logout sees both.
        Session rotated = rotate(old, identity);
        rotated.samlReference = reference;
        return rotated;
    }

    private static boolean cancelAuthentication(@NonNull Session session) {
        boolean retire = session.authenticationGeneration == Long.MAX_VALUE;
        if (!retire) session.authenticationGeneration++;
        session.authenticationClosed = true;
        session.identity = null; session.flow = null; session.journal = null;
        session.samlReference = null; session.samlFlow = null; session.samlLogout = null;
        return retire;
    }

    record SamlClosure(@NonNull SamlSessionReference reference, boolean hadLogin, @Nullable String oidcCookie,
            long generation) {
        @Override public @NonNull String toString() { return "SamlClosure{data=<redacted>}"; }
    }

    synchronized @NonNull Session rotate(@NonNull Session old, @NonNull JsonObject identity) {
        cleanup();
        if (identity.toJson().getBytes(StandardCharsets.UTF_8).length > 2048)
            throw new IllegalArgumentException("Redacted browser identity exceeds cap.");
        if (entries.get(old.id) != old || old.authenticationClosed || old.authenticationGeneration == Long.MAX_VALUE)
            throw new IllegalStateException("Browser session expired or closed.");
        entries.remove(old.id);
        Session rotated = new Session(LocalSecrets.randomId(), LocalSecrets.randomId(), old.binding,
                clock.instant().plus(LIFETIME));
        rotated.identity = identity;
        rotated.journal = old.journal;
        old.flow = null; old.journal = null; old.samlReference = null;
        entries.put(rotated.id, rotated);
        return rotated;
    }

    synchronized void cleanup() {
        Instant now = clock.instant();
        entries.values().removeIf(s -> !now.isBefore(s.expires));
        // Do not acquire a session monitor while holding the store monitor: completion rotates under the session.
        for (Session session : entries.values()) {
            PlaygroundOidc.Flow flow = session.flow;
            PlaygroundOidc.Journal journal = session.journal;
            if (flow != null && !now.isBefore(flow.expires)) session.flow = null;
            if (journal != null && !now.isBefore(journal.expires)) session.journal = null;
            PlaygroundSaml.Flow samlFlow = session.samlFlow;
            PlaygroundSaml.LogoutFlow samlLogout = session.samlLogout;
            if (samlFlow != null && !now.isBefore(samlFlow.expires)) session.samlFlow = null;
            if (samlLogout != null && !now.isBefore(samlLogout.expires)) session.samlLogout = null;
        }
    }

    synchronized int endMatchingSamlSessions(@NonNull SamlLogoutRequest request) {
        cleanup();
        int ended = 0;
        var iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Session session = iterator.next();
            SamlSessionReference reference = session.samlReference;
            if (reference == null || !reference.getIdentityProviderConnectionId()
                    .equals(request.getIdentityProviderConnectionId())
                    || !sameNameId(reference.getNameId(), request.getNameId())) continue;
            if (!request.getSessionIndexes().isEmpty()
                    && reference.getSessionIndex().filter(request.getSessionIndexes()::contains).isEmpty()) continue;
            if (cancelAuthentication(session)) iterator.remove();
            ended++;
        }
        return ended;
    }

    private static boolean sameNameId(@NonNull SamlNameId left, @NonNull SamlNameId right) {
        return left.getValue().equals(right.getValue()) && left.getFormat().equals(right.getFormat())
                && left.getNameQualifier().equals(right.getNameQualifier())
                && left.getSpNameQualifier().equals(right.getSpNameQualifier())
                && left.getSpProvidedId().equals(right.getSpProvidedId());
    }

    synchronized int size() { cleanup(); return entries.size(); }
    synchronized long chargedBytes() { cleanup(); return entries.size() * SESSION_CHARGE_BYTES; }

    /** Parse the raw field once, before a cookie-pair convenience map loses duplicate names. */
    static @NonNull Optional<@NonNull String> cookieValue(@NonNull Request request, @NonNull String selectedName) {
        java.util.List<String> fields = PlaygroundAdmission.headerValues(request, "Cookie");
        if (fields.size() != 1 || fields.get(0).length() > 8192) return Optional.empty();
        String raw = fields.get(0);
        if (raw.endsWith(";") || raw.chars().anyMatch(c -> c < 32 || c > 126)) return Optional.empty();
        java.util.Set<String> names = new HashSet<>();
        String selected = null;
        int start = 0;
        while (start < raw.length()) {
            if (names.size() == 32) return Optional.empty();
            int end = raw.indexOf(';', start);
            if (end < 0) end = raw.length();
            String pair = raw.substring(start, end).strip();
            int equals = pair.indexOf('=');
            if (equals < 1) return Optional.empty();
            String name = pair.substring(0, equals);
            String value = pair.substring(equals + 1);
            if (name.length() > 128 || !name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+") || !names.add(name)
                    || value.length() > 4096 || value.chars().anyMatch(c -> c < 33 || c > 126 || c == '"' || c == ',' || c == '\\'))
                return Optional.empty();
            if (name.equals(selectedName)) selected = value;
            start = end + 1;
        }
        return Optional.ofNullable(selected);
    }

    static @NonNull ResponseCookie cookie(@NonNull Session session) {
        // SameSite=None is deliberate: the synthetic provider's cross-site form_post needs the binding.
        return ResponseCookie.with(COOKIE, session.id).path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.NONE).maxAge(LIFETIME).build();
    }

    static boolean csrfMatches(@NonNull Session session, @Nullable String candidate) {
        return candidate != null && candidate.length() == session.csrf.length()
                && MessageDigest.isEqual(session.csrf.getBytes(StandardCharsets.US_ASCII),
                        candidate.getBytes(StandardCharsets.US_ASCII));
    }

    static final class Session {
        final String id;
        final String csrf;
        final BrowserBinding binding;
        final Instant expires;
        volatile @Nullable JsonObject identity;
        volatile long authenticationGeneration;
        volatile boolean authenticationClosed;
        volatile PlaygroundOidc.@Nullable Flow flow;
        volatile PlaygroundOidc.@Nullable Journal journal;
        volatile PlaygroundSaml.@Nullable Flow samlFlow;
        volatile PlaygroundSaml.@Nullable LogoutFlow samlLogout;
        volatile @Nullable SamlSessionReference samlReference;
        Session(@NonNull String id, @NonNull String csrf, @NonNull BrowserBinding binding, @NonNull Instant expires) {
            this.id = id; this.csrf = csrf; this.binding = binding; this.expires = expires;
        }
        @Override public @NonNull String toString() { return "BrowserSession{data=<redacted>}"; }
    }
}
