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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Publishes an immutable snapshot of public verification keys without an OAuth authorization server, signing,
 * storage, network access or background threads. Applications register the endpoint and supply its key snapshot.
 * Replace the publisher to rotate keys, retaining old verification keys until outstanding signatures and cached
 * key sets have expired. Publication does not advertise the endpoint through discovery automatically.
 * <p>
 * A set has at most 100 keys and 256 KiB of UTF-8 JSON. Nonempty key IDs must be unique; keys without IDs are allowed.
 * GET and HEAD support entity tags and bounded If-None-Match input. Outgoing HTTP Cache-Control max-age defaults to
 * 60 seconds and can be configured from zero through 24 hours, in whole seconds. This policy controls downstream
 * response caching; it does not expire or reload the key snapshot and is independent of OAuth issuer policy.
 *
 * @since 1.0.0
 */
@Immutable
public final class JwksPublisher {

	private static final int MAXIMUM_KEYS = 100;
	private static final int MAXIMUM_BODY_BYTES = 262_144;
	private static final int MAXIMUM_CONDITIONAL_HEADER_LENGTH = 8192;
	private static final @NonNull Duration DEFAULT_HTTP_CACHE_MAX_AGE = Duration.ofSeconds(60);
	private static final @NonNull Duration MAXIMUM_HTTP_CACHE_MAX_AGE = Duration.ofHours(24);
	private final @NonNull List<@NonNull PublishedJwk> keys;
	private final @NonNull Duration httpCacheMaxAge;
	private final @NonNull JsonObject json;
	private final byte @NonNull [] body;
	private final @NonNull String entityTag;

	private JwksPublisher(@NonNull Builder builder) {
		this.keys = builder.keys;
		this.httpCacheMaxAge = builder.httpCacheMaxAge;
		List<JsonValue> values = new ArrayList<>();
		Set<String> identifiers = new HashSet<>();
		int size = 0;
		for (PublishedJwk key : this.keys) {
			String identifier = key.getKeyId().orElse(null);
			if (identifier != null && !identifiers.add(identifier))
				throw new IllegalArgumentException("Published key identifiers must be unique.");
			JsonObject value = key.toJsonObject();
			size += JsonCodec.toUtf8Bytes(value).length;
			if (size > MAXIMUM_BODY_BYTES)
				throw new IllegalArgumentException("The published key set exceeds 256 KiB.");
			values.add(value);
		}
		this.json = JsonObject.builder().put("keys", JsonArray.fromElements(values)).build();
		this.body = JsonCodec.toUtf8Bytes(this.json);
		if (this.body.length > MAXIMUM_BODY_BYTES)
			throw new IllegalArgumentException("The published key set exceeds 256 KiB.");
		try {
			this.entityTag = "\"" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(this.body)) + "\"";
		} catch (NoSuchAlgorithmException unavailable) {
			throw new IllegalStateException("SHA-256 is unavailable.", unavailable);
		}
	}

	/**
	 * Starts a publisher builder with a snapshot of the complete ordered key list. An empty list publishes an empty set.
	 * @param keys at most 100 public keys, in publication order
	 * @return the builder
	 * @throws NullPointerException if the list or an element is null
	 * @throws IllegalArgumentException if there are too many keys
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withKeys(@NonNull List<@NonNull PublishedJwk> keys) {
		return new Builder(keys);
	}

	/**
	 * Returns a publisher with the default HTTP cache max-age. Equivalent to {@code withKeys(keys).build()}.
	 * @param keys at most 100 public keys, in publication order
	 * @return the immutable publisher
	 * @throws NullPointerException if the list or an element is null
	 * @throws IllegalArgumentException if the key count, identifiers or document size is invalid
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwksPublisher fromKeys(@NonNull List<@NonNull PublishedJwk> keys) {
		return withKeys(keys).build();
	}

	/**
	 * Returns the immutable ordered public key snapshot.
	 * @return the published keys
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull PublishedJwk> getKeys() {
		return this.keys;
	}

	/**
	 * Returns the max-age advertised in outgoing HTTP Cache-Control headers. It does not control key loading.
	 * @return the HTTP cache max-age in whole seconds
	 * @since 1.0.0
	 */
	public @NonNull Duration getHttpCacheMaxAge() {
		return this.httpCacheMaxAge;
	}

	/**
	 * Serializes the public JWKS document to JSON text, in the supplied key order. The HTTP cache max-age does not
	 * affect the document.
	 * @return the JSON text, matching the UTF-8 document served by GET
	 * @since 1.0.0
	 */
	public @NonNull String toJson() {
		return this.json.toJson();
	}

	/**
	 * Returns the immutable public JWKS document, in the supplied key order.
	 * @return the JSON document
	 * @since 1.0.0
	 */
	public @NonNull JsonObject toJsonObject() {
		return this.json;
	}

	/**
	 * Prepares a GET or HEAD response without a conditional header. Other methods receive 405.
	 * @param httpMethod the exact, case-sensitive HTTP method
	 * @return the prepared response
	 * @throws NullPointerException if the method is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull JwksResponse responseFor(@NonNull String httpMethod) {
		return responseFor(httpMethod, null);
	}

	/**
	 * Prepares a public response. GET/HEAD use weak If-None-Match comparison, including lists and the wildcard, to
	 * return 304 when appropriate. Malformed conditional syntax is ignored; input longer than 8192 characters receives
	 * a bodyless, non-cacheable 400. Combine repeated header occurrences with commas before calling this method.
	 * @param httpMethod the exact, case-sensitive HTTP method
	 * @param ifNoneMatch the complete If-None-Match field value, or null if absent
	 * @return the prepared response, including method or header rejection
	 * @throws NullPointerException if the method is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull JwksResponse responseFor(@NonNull String httpMethod, @Nullable String ifNoneMatch) {
		requireNonNull(httpMethod);
		if (!httpMethod.equals("GET") && !httpMethod.equals("HEAD"))
			return rejection(405);
		if (ifNoneMatch != null && ifNoneMatch.length() > MAXIMUM_CONDITIONAL_HEADER_LENGTH)
			return rejection(400);
		boolean unchanged = ifNoneMatch != null && matches(ifNoneMatch);
		Map<String, List<String>> headers = new LinkedHashMap<>();
		headers.put("Content-Type", List.of("application/jwk-set+json"));
		headers.put("Cache-Control", List.of("public, max-age=" + this.httpCacheMaxAge.toSeconds() + ", must-revalidate"));
		headers.put("ETag", List.of(this.entityTag));
		headers.put("Referrer-Policy", List.of("no-referrer"));
		if (!unchanged)
			headers.put("Content-Length", List.of(Integer.toString(this.body.length)));
		boolean hasBody = !unchanged && httpMethod.equals("GET");
		return new JwksResponse(unchanged ? 304 : 200, headers,
				hasBody ? this.body : new byte[0], hasBody ? this.json : null);
	}

	private static @NonNull JwksResponse rejection(int status) {
		Map<String, List<String>> headers = new LinkedHashMap<>();
		headers.put("Cache-Control", List.of("no-store"));
		headers.put("Content-Length", List.of("0"));
		headers.put("Referrer-Policy", List.of("no-referrer"));
		if (status == 405)
			headers.put("Allow", List.of("GET, HEAD"));
		return new JwksResponse(status, headers, new byte[0], null);
	}

	private boolean matches(@NonNull String field) {
		int position = skipWhitespace(field, 0);
		if (position < field.length() && field.charAt(position) == '*')
			return skipWhitespace(field, position + 1) == field.length();
		boolean matched = false;
		while (position < field.length()) {
			// HTTP list recipients ignore empty members, including those between repeated field lines.
			if (field.charAt(position) == ',') {
				position = skipWhitespace(field, position + 1);
				continue;
			}
			if (field.startsWith("W/", position))
				position += 2;
			if (position >= field.length() || field.charAt(position) != '"')
				return false;
			int start = position++;
			while (position < field.length() && field.charAt(position) != '"') {
				char character = field.charAt(position++);
				if (character < 0x21 || character == 0x7f || character > 0xff)
					return false;
			}
			if (position >= field.length())
				return false;
			matched |= this.entityTag.equals(field.substring(start, ++position));
			position = skipWhitespace(field, position);
			if (position == field.length())
				return matched;
			if (field.charAt(position++) != ',')
				return false;
			position = skipWhitespace(field, position);
		}
		return matched;
	}

	private static int skipWhitespace(@NonNull String value, int position) {
		int end = position;
		while (end < value.length() && (value.charAt(end) == ' ' || value.charAt(end) == '\t'))
			++end;
		return end;
	}

	/**
	 * Returns a diagnostic without keys, key identifiers or certificate contents.
	 * @return the diagnostic description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "JwksPublisher{keys=<redacted>}";
	}

	/**
	 * Configures an immutable public key snapshot. Optional setters replace previous values; null restores defaults.
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull List<@NonNull PublishedJwk> keys;
		private @NonNull Duration httpCacheMaxAge = DEFAULT_HTTP_CACHE_MAX_AGE;

		private Builder(@NonNull List<@NonNull PublishedJwk> keys) {
			requireNonNull(keys);
			if (keys.size() > MAXIMUM_KEYS)
				throw new IllegalArgumentException("A published key set may contain at most 100 keys.");
			this.keys = List.copyOf(keys);
		}

		/**
		 * Replaces the max-age advertised in outgoing HTTP Cache-Control headers. It must be zero through 24 hours
		 * inclusive, expressed in whole seconds. This setting does not expire or reload the immutable key snapshot,
		 * and does not affect {@link JwksPublisher#toJson()} or {@link JwksPublisher#toJsonObject()}.
		 * @param httpCacheMaxAge the HTTP cache max-age, or null to restore 60 seconds
		 * @return this builder
		 * @throws IllegalArgumentException if the max-age is negative, fractional or over 24 hours
		 * @since 1.0.0
		 */
		@CanIgnoreReturnValue
		public @NonNull Builder httpCacheMaxAge(@Nullable Duration httpCacheMaxAge) {
			Duration value = httpCacheMaxAge == null ? DEFAULT_HTTP_CACHE_MAX_AGE : httpCacheMaxAge;
			if (value.isNegative() || !value.equals(value.truncatedTo(ChronoUnit.SECONDS))
					|| value.compareTo(MAXIMUM_HTTP_CACHE_MAX_AGE) > 0)
				throw new IllegalArgumentException("The JWKS HTTP cache max-age must be whole seconds from zero through 24 hours.");
			this.httpCacheMaxAge = value;
			return this;
		}

		/**
		 * Builds an immutable snapshot and its bounded JSON representation and entity tag.
		 * @return the publisher
		 * @throws IllegalArgumentException if identifiers repeat or the document exceeds 256 KiB
		 * @since 1.0.0
		 */
		public @NonNull JwksPublisher build() {
			return new JwksPublisher(this);
		}

		/**
		 * Returns a description without public key metadata.
		 * @return the diagnostic description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() {
			return "JwksPublisher.Builder{keys=<redacted>}";
		}
	}
}
