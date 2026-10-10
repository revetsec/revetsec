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
package example.passkeys;

import com.soklet.Request;
import com.soklet.ResponseCookie;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Application-owned volatile browser sessions, separate from WebAuthn ceremony storage. */
final class PasskeySessions {
    static final String COOKIE = "__Host-RevetsecPasskeyDemo";
    private static final Duration LIFETIME = Duration.ofMinutes(10);
    private static final Duration STEP_UP_LIFETIME = Duration.ofMinutes(1);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final @NonNull Map<@NonNull String, @NonNull Session> entries = new LinkedHashMap<>();
    private final @NonNull Clock clock;
    private final int maximumSessions;

    PasskeySessions(@NonNull Clock clock, int maximumSessions) {
        if (maximumSessions < 1 || maximumSessions > 128) throw new IllegalArgumentException("Invalid session limit");
        this.clock = java.util.Objects.requireNonNull(clock);
        this.maximumSessions = maximumSessions;
    }

    synchronized @NonNull Session begin() {
        cleanup();
        if (this.entries.size() >= this.maximumSessions) throw new IllegalStateException("Session capacity reached");
        Session session = fresh(false);
        this.entries.put(session.id, session);
        return session;
    }

    synchronized @NonNull Optional<@NonNull Session> find(@NonNull Request request) {
        cleanup();
        return Optional.ofNullable(this.entries.get(cookieValue(request)));
    }

    synchronized boolean current(@NonNull Session session) {
        cleanup();
        return this.entries.get(session.id) == session;
    }

    synchronized @NonNull Session rotate(@NonNull Session previous, boolean authenticated) {
        cleanup();
        if (this.entries.get(previous.id) != previous) throw new IllegalStateException("Session expired");
        Session replacement = fresh(authenticated);
        this.entries.remove(previous.id);
        this.entries.put(replacement.id, replacement);
        return replacement;
    }

    synchronized boolean grantStepUp(@NonNull Session session) {
        cleanup();
        if (this.entries.get(session.id) != session || !session.authenticated) return false;
        session.stepUpUntil = this.clock.instant().plus(STEP_UP_LIFETIME);
        return true;
    }

    synchronized boolean consumeStepUp(@NonNull Session session) {
        cleanup();
        if (this.entries.get(session.id) != session || !session.authenticated) return false;
        Instant deadline = session.stepUpUntil;
        session.stepUpUntil = null;
        return deadline != null && this.clock.instant().isBefore(deadline);
    }

    @NonNull ResponseCookie cookie(@NonNull Session session) {
        return ResponseCookie.with(COOKIE, session.id).path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.STRICT).maxAge(LIFETIME).build();
    }

    private @NonNull Session fresh(boolean authenticated) {
        return new Session(randomId(), randomId(), randomId(),
                this.clock.instant().plus(LIFETIME), authenticated);
    }

    private void cleanup() {
        Instant now = this.clock.instant();
        this.entries.values().removeIf(session -> !now.isBefore(session.expiresAt));
    }

    static @NonNull String randomId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static @Nullable String cookieValue(@NonNull Request request) {
        List<String> fields = PasskeyApp.headers(request, "Cookie");
        if (fields.size() != 1 || fields.get(0).length() > 4096) return null;
        String raw = fields.get(0);
        if (raw.isEmpty() || raw.endsWith(";") || raw.chars().anyMatch(c -> c < 32 || c > 126)) return null;
        Set<String> names = new HashSet<>();
        String selected = null;
        for (String part : raw.split(";", -1)) {
            if (names.size() >= 16) return null;
            String item = part.strip();
            int equals = item.indexOf('=');
            if (equals < 1) return null;
            String name = item.substring(0, equals);
            String value = item.substring(equals + 1);
            if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}") || !names.add(name)
                    || value.length() > 512 || value.chars().anyMatch(c -> c < 33 || c > 126
                    || c == '"' || c == ',' || c == '\\')) return null;
            if (name.equals(COOKIE)) selected = value;
        }
        return selected;
    }

    static final class Session {
        final @NonNull String id;
        final @NonNull String csrf;
        final @NonNull String binding;
        final @NonNull Instant expiresAt;
        final boolean authenticated;
        @Nullable Instant stepUpUntil;

        private Session(@NonNull String id, @NonNull String csrf, @NonNull String binding,
                @NonNull Instant expiresAt, boolean authenticated) {
            this.id = id;
            this.csrf = csrf;
            this.binding = binding;
            this.expiresAt = expiresAt;
            this.authenticated = authenticated;
        }

        @Override public @NonNull String toString() { return "PasskeySession{<redacted>}"; }
    }
}
