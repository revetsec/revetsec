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

import com.revetsec.oauth.server.*;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.NonNull;

/** App-owned finite single-process store. It provides atomicity, never durability or restore protection. */
final class VolatileStore implements OAuthAuthorizationServerStore {
    private final ReentrantLock lock=new ReentrantLock();
    private final Map<OAuthStoreKey,OAuthStoreEntry> entries=new LinkedHashMap<>();
    private final Clock clock;
    private final int capacity;
    private final long maximumBytes;
    VolatileStore(@NonNull Clock clock,int capacity,long maximumBytes) {
        if(capacity<2 || capacity>4096 || maximumBytes<1024 || maximumBytes>16_777_216) throw unavailable();
        this.clock=clock;this.capacity=capacity;this.maximumBytes=maximumBytes;
    }
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {
        acquire(budget);try {cleanup();return Optional.ofNullable(entries.get(key));} finally {lock.unlock();}
    }
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget) {
        acquire(budget);
        try {
            cleanup();
            for(OAuthStoreTransaction.Condition condition:transaction.getConditions()) {
                OAuthStoreEntry current=entries.get(condition.getKey());
                if(!condition.getExpectedVersion().equals(current==null?Optional.empty():Optional.of(current.getVersion()))) return OAuthStoreCommitStatus.CONFLICT;
            }
            // Reserve the complete resulting content before touching the authoritative map.
            Map<OAuthStoreKey,OAuthStoreEntry> next=new LinkedHashMap<>(entries);
            for(OAuthStoreTransaction.Mutation mutation:transaction.getMutations()) {
                if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE) next.remove(mutation.getKey());
                else next.put(mutation.getKey(),mutation.getEntry().orElseThrow());
            }
            if(next.size()>capacity || charged(next)>maximumBytes) throw unavailable();
            entries.clear();entries.putAll(next);return OAuthStoreCommitStatus.COMMITTED;
        } finally {lock.unlock();}
    }
    private void acquire(@NonNull Duration budget) {
        if(budget.isNegative() || budget.isZero() || Thread.currentThread().isInterrupted()) throw unavailable();
        try {if(!lock.tryLock(budget.toNanos(),TimeUnit.NANOSECONDS)) throw unavailable();}
        catch(InterruptedException interrupted) {Thread.currentThread().interrupt();throw unavailable();}
    }
    private void cleanup() {
        // Permanent issuer/subject kinds never receive TTL deletion, including under capacity pressure.
        entries.values().removeIf(e -> e.getKey().getKind()!=OAuthStoreKey.Kind.ISSUER_STATE
                && e.getKey().getKind()!=OAuthStoreKey.Kind.SUBJECT_STATE && !clock.instant().isBefore(e.getRetainUntil()));
    }
    private static long charged(@NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> map) {
        long used=0;for(OAuthStoreEntry entry:map.values()) used+=entry.getKey().getStorageKey().length()+entry.getVersion().length()+entry.toSealedForm().length()+128L;
        return used;
    }
    private static @NonNull IllegalStateException unavailable() {return new IllegalStateException("Local issuer store unavailable.");}
}
