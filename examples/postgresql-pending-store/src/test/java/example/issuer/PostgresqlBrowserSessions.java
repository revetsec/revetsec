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

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import com.revetsec.StateSealer;
import com.soklet.Request;
import com.soklet.ResponseCookie;
import example.pending.PostgresqlPyranidDataSource;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Test application backend: one authoritative PostgreSQL primary and confirmed session transitions. */
public final class PostgresqlBrowserSessions implements BrowserSessionStore {
    private static final @NonNull Duration LIFETIME=Duration.ofMinutes(10);
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
    private final @NonNull String namespace;
    private final PostgresqlPyranidDataSource.@NonNull ConnectionSource source;
    private final @NonNull Clock clock;
    private final @NonNull StateSealer sealer;
    private final int capacity;
    private final @NonNull String cookieName;

    public record ClockRow(long observedSeconds,int observedNanos) { }
    public record SessionRow(@NonNull String sealedForm,long expiresSeconds,int expiresNanos) {
        @Override public @NonNull String toString() {return "BrowserSessionRow{<redacted>}";}
    }
    private static final class Completion {private @Nullable TransactionResult result;}
    private static final class Holder<@NonNull T> {private @Nullable T value;}
    @FunctionalInterface private interface Operation<@NonNull T> {
        @NonNull T apply(@NonNull Database database,@NonNull Instant now,long deadline) throws SQLException;
    }

    PostgresqlBrowserSessions(@NonNull String namespace,PostgresqlPyranidDataSource.@NonNull ConnectionSource source,
            @NonNull Clock clock,@NonNull StateSealer sealer,int capacity,boolean secure) {
        this.namespace=requireNonNull(namespace);this.source=requireNonNull(source);
        this.clock=requireNonNull(clock);this.sealer=requireNonNull(sealer);
        if(!namespace.matches("[A-Za-z0-9_-]{1,128}") || capacity<1 || capacity>10_000)
            throw new IllegalArgumentException("Browser-session configuration rejected.");
        this.capacity=capacity;this.cookieName=secure?"__Host-RevetsecIssuer":"RevetsecIssuerDev";
    }

    @Override public BrowserSessions.@NonNull Session begin() {
        return transaction((database,now,deadline) -> {
            prune(database,now,deadline);
            bound(database,deadline);
            long count=database.query("SELECT count(*) FROM issuer_browser_session WHERE namespace=:namespace")
                    .bind("namespace",namespace).fetchObject(Long.class).orElseThrow();
            if(count>=capacity) throw unavailable();
            BrowserSessions.Session session=new BrowserSessions.Session(LocalInputs.randomId(),LocalInputs.randomId(),
                    LocalInputs.randomId(),now.plus(LIFETIME));
            insert(database,session,deadline);return session;
        });
    }

    @Override public @NonNull Optional<BrowserSessions.@NonNull Session> find(@NonNull Request request) {
        String id=LocalInputs.cookie(request,cookieName);
        if(id==null || !id.matches("[A-Za-z0-9_-]{43}")) return Optional.empty();
        return transaction((database,now,deadline) -> current(database,id,now,deadline));
    }

    @Override public void replacePending(BrowserSessions.@NonNull Session session,BrowserSessions.@NonNull Pending pending) {
        requireNonNull(session);requireNonNull(pending);
        transaction((database,now,deadline) -> {
            BrowserSessions.Session current=current(database,session.id,now,deadline)
                    .orElseThrow(PostgresqlBrowserSessions::unavailable);
            if(!sameSession(current,session)) throw unavailable();
            current.pending.set(pending);update(database,current,deadline);return Boolean.TRUE;
        });
        session.pending.set(pending);
    }

    @Override public BrowserSessions.@NonNull Session login(BrowserSessions.@NonNull Session previous,
            BrowserSessions.@NonNull Pending selected) {
        requireNonNull(previous);requireNonNull(selected);
        return transaction((database,now,deadline) -> {
            BrowserSessions.Session current=current(database,previous.id,now,deadline)
                    .orElseThrow(PostgresqlBrowserSessions::unavailable);
            if(!sameSession(current,previous) || !samePending(current.pending.get(),selected))
                throw unavailable();
            BrowserSessions.Session next=new BrowserSessions.Session(LocalInputs.randomId(),LocalInputs.randomId(),
                    current.binding,now.plus(LIFETIME));
            next.authenticated=true;next.pending.set(selected);
            bound(database,deadline);
            if(database.query("DELETE FROM issuer_browser_session WHERE namespace=:namespace AND session_key=:key")
                    .bind("namespace",namespace).bind("key",key(previous.id)).execute()!=1) throw unavailable();
            insert(database,next,deadline);return next;
        });
    }

    @Override public boolean claimPending(BrowserSessions.@NonNull Session session,
            BrowserSessions.@NonNull Pending selected) {
        requireNonNull(session);requireNonNull(selected);
        boolean claimed=transaction((database,now,deadline) -> {
            Optional<BrowserSessions.Session> found=current(database,session.id,now,deadline);
            if(found.isEmpty()) return Boolean.FALSE;
            BrowserSessions.Session current=found.orElseThrow();
            if(!sameSession(current,session) || !current.authenticated
                    || !samePending(current.pending.get(),selected)) return Boolean.FALSE;
            current.pending.set(null);update(database,current,deadline);return Boolean.TRUE;
        });
        if(claimed) session.pending.compareAndSet(selected,null);
        return claimed;
    }

    @Override public void remove(BrowserSessions.@NonNull Session session) {
        requireNonNull(session);
        transaction((database,now,deadline) -> {
            Optional<BrowserSessions.Session> found=current(database,session.id,now,deadline);
            if(found.isPresent() && sameSession(found.orElseThrow(),session)) {
                bound(database,deadline);
                if(database.query("DELETE FROM issuer_browser_session WHERE namespace=:namespace AND session_key=:key")
                        .bind("namespace",namespace).bind("key",key(session.id)).execute()!=1) throw unavailable();
            }
            return Boolean.TRUE;
        });
        session.authenticated=false;session.pending.set(null);
    }

    @Override public @NonNull ResponseCookie cookie(BrowserSessions.@NonNull Session session) {
        return ResponseCookie.with(cookieName,requireNonNull(session).id).path("/")
                .secure(cookieName.startsWith("__Host-"))
                .httpOnly(true).sameSite(ResponseCookie.SameSite.LAX).maxAge(LIFETIME).build();
    }

    private @NonNull Optional<BrowserSessions.@NonNull Session> current(@NonNull Database database,
            @NonNull String id,@NonNull Instant now,long deadline) throws SQLException {
        byte[] key=key(id);
        bound(database,deadline);
        Optional<SessionRow> row=database.query("SELECT sealed_form,expires_seconds,expires_nanos "
                +"FROM issuer_browser_session WHERE namespace=:namespace AND session_key=:key")
                .bind("namespace",namespace).bind("key",key).fetchObject(SessionRow.class);
        if(row.isEmpty()) return Optional.empty();
        Instant expiry=Instant.ofEpochSecond(row.orElseThrow().expiresSeconds(),row.orElseThrow().expiresNanos());
        if(!now.isBefore(expiry)) return Optional.empty();
        return Optional.of(open(id,key,row.orElseThrow(),expiry));
    }

    private BrowserSessions.@NonNull Session open(@NonNull String id,byte @NonNull [] key,
            @NonNull SessionRow row,@NonNull Instant expiry) {
        String raw=sealer.unseal(row.sealedForm(),context(key));
        String[] parts=raw.split("\\.",-1);
        if(parts.length!=8 || !parts[0].equals("1") || !parts[6].equals(Long.toString(expiry.getEpochSecond()))
                || !parts[7].equals(Integer.toString(expiry.getNano()))) throw unavailable();
        String csrf=decode(parts[1]),binding=decode(parts[2]);
        if(!csrf.matches("[A-Za-z0-9_-]{43}") || !binding.matches("[A-Za-z0-9_-]{43}")
                || !(parts[3].equals("0") || parts[3].equals("1"))) throw unavailable();
        String handle=decode(parts[4]),nonce=decode(parts[5]);
        if((handle.isEmpty() != nonce.isEmpty()) || handle.length()>1024
                || (!nonce.isEmpty() && !nonce.matches("[A-Za-z0-9_-]{43}"))) throw unavailable();
        BrowserSessions.Session session=new BrowserSessions.Session(id,csrf,binding,expiry);
        session.authenticated=parts[3].equals("1");
        if(!handle.isEmpty()) session.pending.set(new BrowserSessions.Pending(handle,nonce));
        return session;
    }

    private void insert(@NonNull Database database,BrowserSessions.@NonNull Session session,long deadline)
            throws SQLException {
        byte[] key=key(session.id);
        bound(database,deadline);
        if(database.query("INSERT INTO issuer_browser_session(namespace,session_key,sealed_form,expires_seconds,expires_nanos) "
                +"VALUES (:namespace,:key,:sealed,:seconds,:nanos)")
                .bind("namespace",namespace).bind("key",key).bind("sealed",seal(session,key))
                .bind("seconds",session.expires.getEpochSecond()).bind("nanos",session.expires.getNano())
                .execute()!=1) throw unavailable();
    }

    private void update(@NonNull Database database,BrowserSessions.@NonNull Session session,long deadline)
            throws SQLException {
        byte[] key=key(session.id);
        bound(database,deadline);
        if(database.query("UPDATE issuer_browser_session SET sealed_form=:sealed "
                +"WHERE namespace=:namespace AND session_key=:key")
                .bind("sealed",seal(session,key)).bind("namespace",namespace).bind("key",key)
                .execute()!=1) throw unavailable();
    }

    private @NonNull String seal(BrowserSessions.@NonNull Session session,byte @NonNull [] key) {
        BrowserSessions.Pending pending=session.pending.get();
        String raw=String.join(".","1",encode(session.csrf),encode(session.binding),
                session.authenticated?"1":"0",encode(pending==null?"":pending.handle),
                encode(pending==null?"":pending.nonce),Long.toString(session.expires.getEpochSecond()),
                Integer.toString(session.expires.getNano()));
        return sealer.seal(raw,context(key),LIFETIME);
    }

    private void prune(@NonNull Database database,@NonNull Instant now,long deadline) throws SQLException {
        bound(database,deadline);
        database.query("DELETE FROM issuer_browser_session WHERE namespace=:namespace "
                +"AND (expires_seconds<:seconds OR (expires_seconds=:seconds AND expires_nanos<=:nanos))")
                .bind("namespace",namespace).bind("seconds",now.getEpochSecond())
                .bind("nanos",now.getNano()).execute();
    }

    private <@NonNull T> @NonNull T transaction(@NonNull Operation<@NonNull T> operation) {
        long deadline=System.nanoTime()+BUDGET.toNanos();
        Database database=Database.withDataSource(new PostgresqlPyranidDataSource(source,deadline))
                .databaseType(DatabaseType.POSTGRESQL).build();
        Completion completion=new Completion();Holder<T> candidate=new Holder<>();
        try {
            Optional<T> result=database.transaction(
                    TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(),() -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result=value);
                bound(database,deadline);
                database.query("SELECT set_config('synchronous_commit','on',true)")
                        .fetchObject(String.class).orElseThrow();
                bound(database,deadline);
                Boolean safe=database.query("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' "
                        +"AND current_setting('full_page_writes')='on'").fetchObject(Boolean.class).orElseThrow();
                if(!safe) throw unavailable();
                bound(database,deadline);
                ClockRow fence=database.query("SELECT observed_seconds,observed_nanos FROM issuer_browser_namespace "
                        +"WHERE namespace=:namespace FOR UPDATE")
                        .bind("namespace",namespace).fetchObject(ClockRow.class).orElseThrow();
                Instant observed=Instant.ofEpochSecond(fence.observedSeconds(),fence.observedNanos());
                Instant now=clock.instant();
                if(now.isBefore(observed)) throw unavailable();
                bound(database,deadline);
                if(database.query("UPDATE issuer_browser_namespace SET observed_seconds=:seconds,observed_nanos=:nanos "
                        +"WHERE namespace=:namespace").bind("seconds",now.getEpochSecond())
                        .bind("nanos",now.getNano()).bind("namespace",namespace).execute()!=1) throw unavailable();
                T value=operation.apply(database,now,deadline);candidate.value=value;
                bound(database,deadline);return Optional.of(value);
            });
            if(completion.result==TransactionResult.COMMITTED && !expired(deadline))
                return result.orElseThrow(PostgresqlBrowserSessions::unavailable);
            throw unavailable();
        } catch(RuntimeException failure) {
            if(completion.result==TransactionResult.COMMITTED && candidate.value!=null && !expired(deadline))
                return candidate.value;
            throw unavailable();
        }
    }

    private static void bound(@NonNull Database database,long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database,deadline);
    }
    private static boolean expired(long deadline) {
        return deadline-System.nanoTime()<=0 || Thread.currentThread().isInterrupted();
    }
    private static @NonNull BrowserSessionUnavailableException unavailable() {
        return new BrowserSessionUnavailableException();
    }
    private @NonNull String context(byte @NonNull [] key) {
        return "issuer-browser:"+namespace+":"+Base64.getUrlEncoder().withoutPadding().encodeToString(key);
    }
    private static byte @NonNull [] key(@NonNull String id) {
        try {return MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.US_ASCII));}
        catch(NoSuchAlgorithmException impossible) {throw new IllegalStateException("SHA-256 unavailable.");}
    }
    private static @NonNull String encode(@NonNull String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
    private static @NonNull String decode(@NonNull String value) {
        try {
            byte[] bytes=Base64.getUrlDecoder().decode(value);
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch(Exception malformed) {throw unavailable();}
    }
    private static boolean sameSession(BrowserSessions.@NonNull Session left,BrowserSessions.@NonNull Session right) {
        return left.id.equals(right.id) && left.csrf.equals(right.csrf) && left.binding.equals(right.binding);
    }
    private static boolean samePending(BrowserSessions.@Nullable Pending left,BrowserSessions.@NonNull Pending right) {
        return left!=null && left.handle.equals(right.handle) && left.nonce.equals(right.nonce);
    }
    @Override public @NonNull String toString() {return "PostgresqlBrowserSessions{<redacted>}";}
}
