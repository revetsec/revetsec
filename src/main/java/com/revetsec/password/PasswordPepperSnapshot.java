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
package com.revetsec.password;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/** Coherent active and retained pepper keys for one operation. A key remains available until all
 * passwords using its ID have been rehashed or reset.
 * @since 1.0.0 */
@Immutable
public final class PasswordPepperSnapshot {
    private final @NonNull PasswordPepperKey activeKey;
    private final @NonNull Map<@NonNull String, @NonNull PasswordPepperKey> keys;

    private PasswordPepperSnapshot(@NonNull PasswordPepperKey activeKey,
            @NonNull Map<@NonNull String, @NonNull PasswordPepperKey> keys) {
        this.activeKey = activeKey;
        this.keys = Map.copyOf(keys);
    }

    /** Starts a snapshot with the key used for new hashes.
     * @param activeKey active key
     * @return builder for retained keys
     * @since 1.0.0 */
    public static @NonNull Builder withActiveKey(@NonNull PasswordPepperKey activeKey) {
        return new Builder(requireNonNull(activeKey));
    }

    /** Returns the key ID used for new hashes.
     * @return active non-secret key ID
     * @since 1.0.0 */
    public @NonNull String getActiveKeyId() { return activeKey.getKeyId(); }

    @NonNull PasswordPepperKey activeKey() { return activeKey; }
    @Nullable PasswordPepperKey keyForId(@NonNull String keyId) { return keys.get(keyId); }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "PasswordPepperSnapshot{<redacted>}"; }

    /** Snapshot construction; keys are never exposed by iteration.
     * @since 1.0.0 */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull PasswordPepperKey activeKey;
        private final @NonNull Map<@NonNull String, @NonNull PasswordPepperKey> keys = new LinkedHashMap<>();

        private Builder(@NonNull PasswordPepperKey activeKey) {
            this.activeKey = activeKey;
            keys.put(activeKey.getKeyId(), activeKey);
        }

        /** Replaces the complete set of prior verification-only keys. The input is copied before
         * assignment; invalid lists leave the previous builder state unchanged.
         * @param retainedKeys at most 15 keys with distinct IDs, or null to retain none
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder retainedKeys(@Nullable List<@NonNull PasswordPepperKey> retainedKeys) {
            Map<String, PasswordPepperKey> next = new LinkedHashMap<>();
            next.put(activeKey.getKeyId(), activeKey);
            if (retainedKeys != null) {
                if (retainedKeys.size() > 15) throw new IllegalArgumentException("Too many retained pepper keys");
                for (PasswordPepperKey key : retainedKeys) {
                    requireNonNull(key);
                    if (next.putIfAbsent(key.getKeyId(), key) != null)
                        throw new IllegalArgumentException("Duplicate pepper key ID");
                }
            }
            keys.clear();
            keys.putAll(next);
            return this;
        }

        /** Builds a coherent snapshot of the active and retained keys.
         * @return immutable snapshot
         * @since 1.0.0 */
        public @NonNull PasswordPepperSnapshot build() { return new PasswordPepperSnapshot(activeKey, keys); }
    }
}
