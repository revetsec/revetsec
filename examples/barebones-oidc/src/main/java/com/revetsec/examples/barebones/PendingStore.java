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

import com.revetsec.oauth.PendingAuthorizationStore;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Single-process application storage; no worker, live eviction or cross-node replay guarantee. */
@ThreadSafe
final class PendingStore implements PendingAuthorizationStore {
    private final @NonNull Clock clock;
    private final int maximumEntries;
    private final long maximumBytes;
    private final @NonNull Map<@NonNull Key, @NonNull Entry> entries = new HashMap<>();
    private long bytes;

    PendingStore(@NonNull Clock clock, int maximumEntries, long maximumBytes) {
        this.clock = requireNonNull(clock);
        if (maximumEntries < 1 || maximumEntries > 1024 || maximumBytes < 1024 || maximumBytes > 4_194_304)
            throw new IllegalArgumentException("Invalid pending store limits");
        this.maximumEntries = maximumEntries;
        this.maximumBytes = maximumBytes;
    }

    @Override
    public synchronized void save(@NonNull String binding, @NonNull String state, @NonNull String record,
                                  @NonNull Instant expiresAt) {
        requireNonNull(binding); requireNonNull(state); requireNonNull(record); requireNonNull(expiresAt);
        if (binding.isEmpty() || binding.length() > 128 || state.isEmpty() || state.length() > 128
                || record.isEmpty() || record.length() > 65_536)
            throw new IllegalArgumentException("Invalid pending record");
        Instant now = this.clock.instant();
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(Duration.ofMinutes(15))))
            throw new IllegalArgumentException("Invalid pending expiry");
        prune();
        Key key = new Key(binding, state);
        if (this.entries.containsKey(key)) throw new IllegalArgumentException("Duplicate pending record");
        long charged = record.getBytes(StandardCharsets.UTF_8).length + binding.length() + state.length();
        if (charged > 65_792 || this.entries.size() >= this.maximumEntries
                || charged > this.maximumBytes - this.bytes)
            throw new CapacityException();
        this.entries.put(key, new Entry(record, expiresAt, now, charged));
        this.bytes += charged;
    }

    @Override
    public synchronized @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state) {
        requireNonNull(binding); requireNonNull(state);
        prune();
        Entry entry = this.entries.remove(new Key(binding, state));
        if (entry == null) return Optional.empty();
        this.bytes -= entry.bytes();
        return Optional.of(entry.record());
    }

    synchronized void discardBinding(@NonNull String binding) {
        this.entries.entrySet().removeIf(entry -> {
            if (!entry.getKey().binding().equals(binding)) return false;
            this.bytes -= entry.getValue().bytes();
            return true;
        });
    }

    synchronized void prune() {
        Instant now = this.clock.instant();
        Iterator<Map.Entry<Key, Entry>> iterator = this.entries.entrySet().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next().getValue();
            if (!now.isBefore(entry.expiresAt()) || now.isBefore(entry.createdAt())) {
                this.bytes -= entry.bytes();
                iterator.remove();
            }
        }
    }

    synchronized int size() { prune(); return this.entries.size(); }

    static final class CapacityException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        CapacityException() { super("Pending store full"); }
    }

    // Explicit accessors preserve nullness on compiler-visible reference signatures too.
    private record Key(@NonNull String binding, @NonNull String state) {
        @Override public @NonNull String binding() { return this.binding; }
        @Override public @NonNull String state() { return this.state; }
    }
    private record Entry(@NonNull String record, @NonNull Instant expiresAt, @NonNull Instant createdAt, long bytes) {
        @Override public @NonNull String record() { return this.record; }
        @Override public @NonNull Instant expiresAt() { return this.expiresAt; }
        @Override public @NonNull Instant createdAt() { return this.createdAt; }
    }
}
