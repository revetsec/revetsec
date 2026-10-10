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

package com.revetsec.saml;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * An opaque untrusted SAML HTTP-POST message. Binding parsing is not XML parsing, signature validation,
 * authentication, or permission to use RelayState as a redirect target. Retain the original form body and
 * header multiplicity when calling {@link #fromFormBodyResult(byte[], List, String)}.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlPostBindingMessage {
    private final byte @NonNull [] xml;
    private final @Nullable String relayState;

    private SamlPostBindingMessage(byte @NonNull [] xml, @Nullable String relayState) {
        this.xml = xml.clone();
        this.relayState = relayState;
    }

    /**
     * Decodes the original form body with strict UTF-8, multiplicity, MIME and Base64 checks.
     *
     * @param body original HTTP request body
     * @param contentTypeValues all Content-Type field values
     * @param rawQuery original query string, or null when absent
     * @return a parsed untrusted message or a fixed rejection
     * @since 1.0.0
     */
    public static @NonNull SamlPostBindingParseResult fromFormBodyResult(byte @NonNull [] body,
            @NonNull List<@NonNull String> contentTypeValues, @Nullable String rawQuery) {
        SamlPostBindingDecoder.Result decoded = SamlPostBindingDecoder.decode(requireNonNull(body),
                requireNonNull(contentTypeValues), rawQuery);
        if (decoded instanceof SamlPostBindingDecoder.Rejected rejected)
            return new SamlPostBindingParseResult.Rejected(
                    SamlPostBindingParseResult.Reason.valueOf(rejected.reason().name()));
        SamlPostBindingDecoder.Accepted accepted = (SamlPostBindingDecoder.Accepted) decoded;
        return new SamlPostBindingParseResult.Parsed(new SamlPostBindingMessage(accepted.xml(),
                accepted.relayState()));
    }

    /**
     * Returns the untrusted RelayState value without interpreting it as a URL.
     *
     * @return the opaque RelayState value, if present
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getRelayState() { return Optional.ofNullable(relayState); }

    byte @NonNull [] xml() { return xml.clone(); }
    @Nullable String relayState() { return relayState; }

    /** Redacts the decoded XML and RelayState. @since 1.0.0 */
    @Override public @NonNull String toString() { return "SamlPostBindingMessage{<untrusted>}"; }
}
