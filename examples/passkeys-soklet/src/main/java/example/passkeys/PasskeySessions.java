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

import com.revetsec.OperationBinding;
import com.soklet.Request;
import com.revetsec.webauthn.WebAuthnReauthentication;
import com.revetsec.webauthn.WebAuthnStoreKey;
import java.security.MessageDigest;
import java.util.Arrays;
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
    private final byte @NonNull [] accountHandle;
    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;

    PasskeySessions(@NonNull Clock clock, int maximumSessions,
            byte @NonNull [] accountHandle, @NonNull String namespace, @NonNull String relyingPartyId) {
        if (maximumSessions < 1 || maximumSessions > 128) throw new IllegalArgumentException("Invalid session limit");
        this.clock = java.util.Objects.requireNonNull(clock);
        WebAuthnStoreKey.forAccountFence(namespace, relyingPartyId, accountHandle);
        this.accountHandle = accountHandle.clone();
        this.namespace = namespace;
        this.relyingPartyId = relyingPartyId;
        this.maximumSessions = maximumSessions;
    }

    synchronized @NonNull Session begin() {
        cleanup();
        if (this.entries.size() >= this.maximumSessions) {
            String oldestAnonymous = this.entries.values().stream()
                    .filter(session -> !session.authenticated).map(session -> session.id).findFirst().orElse(null);
            if (oldestAnonymous == null) throw new IllegalStateException("Session capacity reached");
            this.entries.remove(oldestAnonymous);
        }
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

    enum Action {
        SENSITIVE("demo-sensitive-action"), SELF_REMOVAL("demo-remove-passkey");
        final @NonNull String purpose;
        Action(@NonNull String purpose) { this.purpose = purpose; }
    }

    synchronized @NonNull Optional<@NonNull PendingAction> pendingAction(
            @NonNull Session session, @NonNull Action action, @NonNull String ceremonyId) {
        cleanup();
        PendingAction pending = session.pending;
        return currentAuthenticated(session) && pending != null && pending.owner == session
                && pending.action == action && pending.ceremonyId.equals(ceremonyId)
                ? Optional.of(pending) : Optional.empty();
    }

    synchronized boolean rememberAction(@NonNull Session session, @NonNull Action action,
            byte @NonNull [] target, @NonNull String ceremonyId) {
        cleanup();
        if (!currentAuthenticated(session)) return false;
        if (!ceremonyId.matches("[A-Za-z0-9_-]{43}") || target.length > 1023
                || (action == Action.SENSITIVE ? target.length != 0 : target.length == 0))
            throw new IllegalArgumentException("Invalid app action context");
        session.pending = new PendingAction(session, action, target, ceremonyId,
                this.accountHandle, this.namespace, this.relyingPartyId);
        session.grant = null;
        return true;
    }

    synchronized @NonNull Optional<@NonNull AuthorizedAction> completeAction(
            @NonNull Session session, @NonNull PendingAction pending,
            @NonNull WebAuthnReauthentication proof, @NonNull Object publicationId) {
        cleanup();
        if (!currentAuthenticated(session) || session.pending != pending || pending.owner != session
                || !this.namespace.equals(proof.getCredentialNamespace())
                || !this.relyingPartyId.equals(proof.getRelyingPartyId())
                || !pending.namespace.equals(proof.getCredentialNamespace())
                || !pending.relyingPartyId.equals(proof.getRelyingPartyId())
                || !pending.action.purpose.equals(proof.getActionPurpose())
                || !pending.ceremonyId.equals(proof.getCeremonyId())) return Optional.empty();
        byte[] handle = proof.getUserHandle();
        try {
            if (!MessageDigest.isEqual(this.accountHandle, handle)
                    || !MessageDigest.isEqual(pending.accountHandle, handle)) return Optional.empty();
        } finally { Arrays.fill(handle, (byte) 0); }
        Instant deadline = this.clock.instant().plus(STEP_UP_LIFETIME);
        if (session.expiresAt.isBefore(deadline)) deadline = session.expiresAt;
        AuthorizedAction grant = new AuthorizedAction(pending, deadline, publicationId);
        session.pending = null;
        session.grant = grant;
        return Optional.of(grant);
    }

    synchronized boolean consumeAction(@NonNull Session session, @NonNull Action action,
            byte @NonNull [] target) {
        AuthorizedAction grant = session.grant;
        session.grant = null;
        cleanup();
        if (!currentAuthenticated(session) || grant == null) return false;
        PendingAction context = grant.context;
        return context.owner == session && context.action == action
                && this.namespace.equals(context.namespace) && this.relyingPartyId.equals(context.relyingPartyId)
                && MessageDigest.isEqual(this.accountHandle, context.accountHandle)
                && MessageDigest.isEqual(target, context.target)
                && this.clock.instant().isBefore(grant.expiresAt);
    }

    synchronized boolean publishable(@NonNull Session owner, @NonNull AuthorizedAction exactGrant) {
        cleanup();
        return currentAuthenticated(owner) && owner.grant == exactGrant
                && this.clock.instant().isBefore(exactGrant.expiresAt);
    }

    synchronized void discardApproval(@NonNull Session owner, @NonNull AuthorizedAction exactGrant) {
        if (owner.grant == exactGrant) owner.grant = null;
        if (owner.pending == exactGrant.context) owner.pending = null;
    }

    synchronized void discardUnwrittenApproval(@NonNull Object publicationId) {
        for (Session session : this.entries.values()) {
            AuthorizedAction selected = session.grant;
            if (selected != null && selected.publicationId.equals(publicationId))
                discardApproval(session, selected);
        }
    }

    private boolean currentAuthenticated(@NonNull Session session) {
        return this.entries.get(session.id) == session && session.authenticated
                && MessageDigest.isEqual(this.accountHandle, session.accountHandle);
    }

    static final class PendingAction {
        final @NonNull Session owner;
        final @NonNull Action action;
        private final byte @NonNull [] target;
        final @NonNull String ceremonyId;
        private final byte @NonNull [] accountHandle;
        private final @NonNull String namespace;
        private final @NonNull String relyingPartyId;
        private PendingAction(@NonNull Session owner, @NonNull Action action, byte @NonNull [] target,
                @NonNull String ceremonyId, byte @NonNull [] accountHandle,
                @NonNull String namespace, @NonNull String relyingPartyId) {
            this.owner = owner; this.action = action; this.target = target.clone();
            this.ceremonyId = ceremonyId; this.accountHandle = accountHandle.clone();
            this.namespace = namespace; this.relyingPartyId = relyingPartyId;
        }
        @Override public @NonNull String toString() { return "PendingPasskeyAction{<redacted>}"; }
    }

    static final class AuthorizedAction {
        private final @NonNull PendingAction context;
        private final @NonNull Instant expiresAt;
        private final @NonNull Object publicationId;
        private AuthorizedAction(@NonNull PendingAction context, @NonNull Instant expiresAt,
                @NonNull Object publicationId) {
            this.context = context; this.expiresAt = expiresAt; this.publicationId = publicationId;
        }
        @Override public @NonNull String toString() { return "AuthorizedPasskeyAction{<redacted>}"; }
    }

    @NonNull ResponseCookie cookie(@NonNull Session session) {
        return ResponseCookie.with(COOKIE, session.id).path("/").secure(true).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.STRICT).maxAge(LIFETIME).build();
    }

    private @NonNull Session fresh(boolean authenticated) {
        return new Session(randomId(), randomId(), OperationBinding.fresh(),
                this.clock.instant().plus(LIFETIME), authenticated, this.accountHandle);
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
        final @NonNull OperationBinding binding;
        final @NonNull Instant expiresAt;
        final boolean authenticated;
        private final byte @NonNull [] accountHandle;
        private @Nullable PendingAction pending;
        private @Nullable AuthorizedAction grant;

        private Session(@NonNull String id, @NonNull String csrf, @NonNull OperationBinding binding,
                @NonNull Instant expiresAt, boolean authenticated, byte @NonNull [] accountHandle) {
            this.id = id;
            this.csrf = csrf;
            this.binding = binding;
            this.expiresAt = expiresAt;
            this.authenticated = authenticated;
            this.accountHandle = accountHandle.clone();
        }

        @Override public @NonNull String toString() { return "PasskeySession{<redacted>}"; }
    }
}
