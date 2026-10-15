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

package com.revetsec.jose;

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An immutable HTTP response containing only public JWKS data. Emit its prepared status, headers and bytes together;
 * in particular, a HEAD response has no body but describes the GET representation's length.
 *
 * @since 1.0.0
 */
@Immutable
public final class JwksResponse {

	private final int statusCode;
	private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers;
	private final byte @NonNull [] body;
	private final @Nullable JsonObject document;

	JwksResponse(int statusCode,
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, byte @NonNull [] body,
			@Nullable JsonObject document) {
		this.statusCode = statusCode;
		Map<String, List<String>> snapshot = new LinkedHashMap<>();
		headers.forEach((name, values) -> snapshot.put(name, List.copyOf(values)));
		this.headers = Collections.unmodifiableMap(snapshot);
		this.body = body.clone();
		this.document = document;
	}

	/**
	 * Returns the prepared HTTP status.
	 * @return the status code
	 * @since 1.0.0
	 */
	public @NonNull Integer getStatusCode() {
		return this.statusCode;
	}

	/**
	 * Returns immutable HTTP header occurrences.
	 * @return the prepared headers
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> getHeaders() {
		return this.headers;
	}

	/**
	 * Returns a defensive copy of the prepared public response body.
	 * @return the body, empty for HEAD, 304 and method/header rejections
	 * @since 1.0.0
	 */
	public byte @NonNull [] toHttpBody() {
		return this.body.clone();
	}

	/**
	 * Returns the immutable public document when this response has a GET body. This is an explicit public-key
	 * document emission; diagnostics remain redacted. The prepared headers describe {@link #toHttpBody()}, so an
	 * application that serializes this document itself must calculate its own representation length and validator.
	 * @return the document, absent for HEAD, 304 and method/header rejections
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull JsonObject> getDocument() {
		return Optional.ofNullable(this.document);
	}

	/**
	 * Returns a description without keys or header contents.
	 * @return the diagnostic description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "JwksResponse{statusCode=" + this.statusCode + "}";
	}
}
