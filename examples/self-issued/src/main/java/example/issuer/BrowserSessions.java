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
package example.issuer;

import com.soklet.Request;
import com.soklet.ResponseCookie;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Bounded app sessions; login rotates the cookie/CSRF while retaining the independent browser binding. */
final class BrowserSessions implements BrowserSessionStore {
    private static final Duration LIFETIME=Duration.ofMinutes(10);
    private final Map<String,Session> entries=new LinkedHashMap<>();
    private final Clock clock;
    private final int capacity;
    private final boolean secure;
    private final String cookieName;
    BrowserSessions(@NonNull Clock clock,int capacity,boolean secure) {
        if(capacity<1 || capacity>128) throw new IllegalArgumentException("Session cap rejected.");
        this.clock=clock;this.capacity=capacity;this.secure=secure;
        this.cookieName=secure?"__Host-RevetsecIssuer":"RevetsecIssuerDev";
    }
    @Override public synchronized @NonNull Session begin() {
        cleanup();if(entries.size()>=capacity) throw new IllegalStateException("Session store full.");
        Session s=new Session(LocalInputs.randomId(),LocalInputs.randomId(),LocalInputs.randomId(),clock.instant().plus(LIFETIME));
        entries.put(s.id,s);return s;
    }
    @Override public synchronized @NonNull Optional<@NonNull Session> find(@NonNull Request request) {
        cleanup();return Optional.ofNullable(entries.get(LocalInputs.cookie(request,cookieName)));
    }
    @Override public synchronized void replacePending(@NonNull Session session,@NonNull Pending pending) {
        cleanup();if(entries.get(session.id)!=session) throw new IllegalStateException("Session expired.");
        session.pending.set(pending);
    }
    @Override public synchronized @NonNull Session login(@NonNull Session previous,@NonNull Pending selected) {
        cleanup();if(entries.get(previous.id)!=previous || previous.pending.get()!=selected)
            throw new IllegalStateException("Session expired.");
        entries.remove(previous.id);
        Session s=new Session(LocalInputs.randomId(),LocalInputs.randomId(),previous.binding,clock.instant().plus(LIFETIME));
        s.pending.set(selected);s.authenticated=true;previous.pending.set(null);entries.put(s.id,s);return s;
    }
    @Override public synchronized boolean claimPending(@NonNull Session session,@NonNull Pending selected) {
        cleanup();return entries.get(session.id)==session && session.pending.compareAndSet(selected,null);
    }
    @Override public synchronized void remove(@NonNull Session session) {entries.remove(session.id);session.authenticated=false;session.pending.set(null);}
    private void cleanup() {entries.values().removeIf(s -> !clock.instant().isBefore(s.expires));}
    @Override public @NonNull ResponseCookie cookie(@NonNull Session s) {
        return ResponseCookie.with(cookieName,s.id).path("/").secure(secure).httpOnly(true)
                .sameSite(ResponseCookie.SameSite.LAX).maxAge(LIFETIME).build();
    }
    static final class Pending {
        final String handle,nonce;
        Pending(@NonNull String handle) {this.handle=handle;this.nonce=LocalInputs.randomId();}
        Pending(@NonNull String handle,@NonNull String nonce) {this.handle=handle;this.nonce=nonce;}
        @Override public @NonNull String toString() {return "IssuerPending{<redacted>}";}
    }
    static final class Session {
        final String id,csrf,binding;
        final Instant expires;
        volatile boolean authenticated;
        final AtomicReference<@Nullable Pending> pending=new AtomicReference<>();
        Session(@NonNull String id,@NonNull String csrf,@NonNull String binding,@NonNull Instant expires) {
            this.id=id;this.csrf=csrf;this.binding=binding;this.expires=expires;
        }
        @Override public @NonNull String toString() {return "IssuerSession{<redacted>}";}
    }
}
