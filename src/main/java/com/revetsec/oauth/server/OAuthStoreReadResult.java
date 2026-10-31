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

package com.revetsec.oauth.server;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Coherent linearizable issuer entry/absence and admitted time metadata.
 * Unavailable or fenced observations never establish absence.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public sealed interface OAuthStoreReadResult permits OAuthStoreReadResult.Available,
        OAuthStoreReadResult.Fenced, OAuthStoreReadResult.Unavailable {
    /** The exact requested address, entry/absence and metadata from one atomic observation.
     * @since 1.0.0 */
    @Immutable
    @CheckReturnValue
    final class Available implements OAuthStoreReadResult {
        private final @NonNull OAuthStoreKey key;
        private final @Nullable OAuthStoreEntry entry;
        private final @NonNull StoreTimeObservation timeObservation;
        private Available(@NonNull OAuthStoreKey key, @Nullable OAuthStoreEntry entry,
                @NonNull StoreTimeObservation timeObservation) {
            this.key=requireNonNull(key); this.timeObservation=requireNonNull(timeObservation);
            if(entry!=null && !key.equals(entry.getKey())) throw OAuthStoreFormat.invalid();
            this.entry=entry;
        }
        /** Retains one exact coherent backend observation without authenticating its bytes.
         * @param key the requested address
         * @param entry the exact entry, or null for confirmed absence
         * @param timeObservation coherent authority/admission metadata
         * @return the available observation
         * @throws NullPointerException if key or metadata is null
         * @throws IllegalArgumentException if entry has another address
         * @since 1.0.0 */
        public static OAuthStoreReadResult.@NonNull Available fromObservation(@NonNull OAuthStoreKey key,
                @Nullable OAuthStoreEntry entry, @NonNull StoreTimeObservation timeObservation) {
            return new Available(key,entry,timeObservation);
        }
        /** Returns the exact requested address.
         * @return the address
         * @since 1.0.0 */
        public @NonNull OAuthStoreKey getKey(){return this.key;}
        /** Returns the entry or confirmed absence.
         * @return the optional entry
         * @since 1.0.0 */
        public @NonNull Optional<@NonNull OAuthStoreEntry> getEntry(){return Optional.ofNullable(this.entry);}
        /** Returns coherent authority metadata, which need not include healthy time.
         * @return the observation
         * @since 1.0.0 */
        public @NonNull StoreTimeObservation getTimeObservation(){return this.timeObservation;}
        /** Redacts every entry, identity and time.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString(){return "Available{observation=<redacted>}";}
    }
    /** The requested recovery/data incarnation cannot be served.
     * @since 1.0.0 */
    @Immutable
    @CheckReturnValue
    final class Fenced implements OAuthStoreReadResult {
        private static final @NonNull Fenced INSTANCE=new Fenced();
        private Fenced(){}
        /** Returns the fixed refusal.
         * @return the fenced refusal
         * @since 1.0.0 */
        public static OAuthStoreReadResult.@NonNull Fenced get(){return INSTANCE;}
        /** Redacts state.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString(){return "Fenced{}";}
    }
    /** No coherent authoritative observation could be established.
     * @since 1.0.0 */
    @Immutable
    @CheckReturnValue
    final class Unavailable implements OAuthStoreReadResult {
        private static final @NonNull Unavailable INSTANCE=new Unavailable();
        private Unavailable(){}
        /** Returns the fixed refusal.
         * @return the unavailable refusal
         * @since 1.0.0 */
        public static OAuthStoreReadResult.@NonNull Unavailable get(){return INSTANCE;}
        /** Redacts state.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString(){return "Unavailable{}";}
    }
}
