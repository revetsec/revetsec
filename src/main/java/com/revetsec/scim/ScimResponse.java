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

package com.revetsec.scim;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A fully bounded HTTP response prepared by a service provider. Intentional body emission may contain personal data.
 * @since 1.0.0
 */
@Immutable
public final class ScimResponse {
    private final int statusCode;
    private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers;
    private final byte @NonNull [] body;

    ScimResponse(int statusCode, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, byte @NonNull [] body) {
        this.statusCode = statusCode;
        LinkedHashMap<String, List<String>> copy = new LinkedHashMap<>();
        headers.forEach((name, values) -> copy.put(name, List.copyOf(values)));
        this.headers = Collections.unmodifiableMap(copy);
        this.body = body.clone();
    }

    /** Returns the prepared HTTP status.
     * @return the status
     * @since 1.0.0
     */
    public @NonNull Integer getStatusCode() { return statusCode; }

    /** Returns the immutable prepared header occurrences.
     * @return the headers
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> getHeaders() { return headers; }

    /** Intentionally emits a defensive copy of the HTTP body, which may contain personal data.
     * @return the complete prepared body
     * @since 1.0.0
     */
    public byte @NonNull [] toHttpBodyWithPersonalData() { return body.clone(); }

    /** Returns a fixed diagnostic without provisioning data or header contents.
     * @return the diagnostic
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimResponse{<redacted>}"; }
}
