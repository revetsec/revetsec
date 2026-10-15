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

package com.revetsec.oidc;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import com.revetsec.oauth.OAuthException;

/**
 * The outcome of parsing bounded provider metadata. Parsing approves no provider trust or identity.
 * Rejections contain a fixed reason and no received document.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcProviderMetadataParseResult permits OidcProviderMetadataParseResult.Succeeded, OidcProviderMetadataParseResult.Rejected {
    private OidcProviderMetadataParseResult() { }
    static @NonNull OidcProviderMetadataParseResult succeeded(@NonNull OidcProviderMetadata metadata) { return new Succeeded(metadata); }
    static @NonNull OidcProviderMetadataParseResult rejected(OAuthException.@NonNull Reason reason) { return new Rejected(reason); }
    /** Checked metadata; the application still selects a trusted issuer.
     * @since 1.0.0
     */
    @Immutable
    public static final class Succeeded extends OidcProviderMetadataParseResult {
        private final @NonNull OidcProviderMetadata metadata;
        private Succeeded(@NonNull OidcProviderMetadata metadata) { this.metadata = metadata; }
        /** Returns the checked metadata.
         * @return checked metadata
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull OidcProviderMetadata getMetadata() { return metadata; }
        @Override public @NonNull String toString() { return "OidcProviderMetadataParseResult.Succeeded{metadata=<redacted>}"; }
    }
    /** A rejected metadata document with no received payload.
     * @since 1.0.0
     */
    @Immutable
    public static final class Rejected extends OidcProviderMetadataParseResult {
        private final OAuthException.@NonNull Reason reason;
        private Rejected(OAuthException.@NonNull Reason reason) { this.reason = reason; }
        /** Returns the fixed rejection reason.
         * @return fixed reason
         * @since 1.0.0
         */
        @CheckReturnValue public OAuthException.@NonNull Reason getReason() { return reason; }
        @Override public @NonNull String toString() { return "OidcProviderMetadataParseResult.Rejected{reason=" + reason + "}"; }
    }
}
