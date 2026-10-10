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

package com.revetsec.webauthn;

import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/** Application-approved account information used only to prepare credential enrollment.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnRegistrationOptions {
    private final byte @NonNull [] userHandle;
    private final @NonNull String userName;
    private final @NonNull String userDisplayName;

    private WebAuthnRegistrationOptions(byte @NonNull [] userHandle, @NonNull String userName,
            @NonNull String userDisplayName) {
        this.userHandle = userHandle.clone();
        this.userName = userName;
        this.userDisplayName = userDisplayName;
    }

    /** Starts account-approved enrollment options.
     * @param userHandle stable opaque account handle
     * @return a builder
     * @since 1.0.0 */
    public static @NonNull Builder withUserHandle(byte @NonNull [] userHandle) {
        return new Builder(userHandle);
    }

    /** Returns a defensive handle copy.
     * @return the account handle
     * @since 1.0.0 */
    public byte @NonNull [] getUserHandle() { return this.userHandle.clone(); }
    /** Returns the browser display name.
     * @return the account name
     * @since 1.0.0 */
    public @NonNull String getUserName() { return this.userName; }
    /** Returns the browser display label.
     * @return the display label
     * @since 1.0.0 */
    public @NonNull String getUserDisplayName() { return this.userDisplayName; }
    /** Redacts the account fields.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnRegistrationOptions{account=<redacted>}"; }

    /** One caller-thread builder.
     * @since 1.0.0 */
    @NotThreadSafe
    public static final class Builder {
        private final byte @NonNull [] userHandle;
        private @Nullable String userName;
        private @Nullable String userDisplayName;
        private Builder(byte @NonNull [] userHandle) {
            requireNonNull(userHandle);
            if (userHandle.length < 1 || userHandle.length > 64)
                throw new IllegalArgumentException("Invalid WebAuthn user handle");
            this.userHandle = Arrays.copyOf(userHandle, userHandle.length);
        }
        /** Sets a browser display name, which does not establish identity.
         * @param name bounded account name
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder userName(@NonNull String name) {
            this.userName = boundedName(name); return this;
        }
        /** Sets a browser display label.
         * @param name bounded display label
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder userDisplayName(@NonNull String name) {
            this.userDisplayName = boundedName(name); return this;
        }
        /** Builds immutable enrollment options.
         * @return the options
         * @since 1.0.0 */
        public @NonNull WebAuthnRegistrationOptions build() {
            return new WebAuthnRegistrationOptions(this.userHandle,
                    requireNonNull(this.userName, "userName"),
                    requireNonNull(this.userDisplayName, "userDisplayName"));
        }
        /** Redacts the builder fields.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString() { return "WebAuthnRegistrationOptions.Builder{<redacted>}"; }
    }

    private static @NonNull String boundedName(@NonNull String name) {
        requireNonNull(name);
        JsonString.fromValue(name);
        if (name.isEmpty() || name.codePointCount(0, name.length()) > 64)
            throw new IllegalArgumentException("Invalid WebAuthn display name");
        for (int offset = 0; offset < name.length();) {
            int point = name.codePointAt(offset);
            if (Character.isISOControl(point)) throw new IllegalArgumentException("Invalid WebAuthn display name");
            offset += Character.charCount(point);
        }
        return name;
    }
}
