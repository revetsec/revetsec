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

package com.revetsec.internal.http;

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static java.util.Objects.requireNonNull;

/**
 * One outbound request: a {@code GET}, or a form {@code POST} when {@link #formBody()} is present.
 * <p>
 * {@link HttpExchange} adds {@code Accept} (from the profile) and {@code Accept-Encoding: identity}, and for a
 * {@code POST} {@code Content-Type: application/x-www-form-urlencoded}; {@link #headers()} holds the rest, such as
 * {@code Authorization}. The limits and timeout are passed straight through: public builders check their settings
 * against {@link Limits} first, so this internal type accepts any positive timeout and any non-negative limit, and
 * tests can use small ones.
 * <p>
 * {@link #toString()} shows the method, the URI cut to scheme, host, port and path, the profile, the limits and the
 * header names; never header values or the form body, which carry credentials (R9).
 *
 * @param uri                   the absolute {@code https} (or allowed loopback {@code http}) URI
 * @param profile               what a successful response must look like
 * @param formBody              an {@code application/x-www-form-urlencoded} body, US-ASCII only (as
 *                              {@code FormUrlEncoding} writes it), or {@code null} for a {@code GET}
 * @param headers               extra request headers, by name; names are HTTP tokens, names Revetsec or the JDK sets
 *                              itself are refused, and values are visible US-ASCII, spaces and tabs
 * @param maximumBodyBytes      the largest 2xx body accepted
 * @param maximumErrorBodyBytes the largest non-2xx body kept; a larger one is dropped unread and the status kept
 * @param requestTimeout        the per-request timeout; the exchange uses the smaller of this and the time left on
 *                              its deadline
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record HttpExchangeRequest(@NonNull URI uri,
																	@NonNull ResponseProfile profile,
																	@Nullable String formBody,
																	@NonNull Map<@NonNull String, @NonNull String> headers,
																	int maximumBodyBytes,
																	int maximumErrorBodyBytes,
																	@NonNull Duration requestTimeout) {
	/**
	 * Header names Revetsec or the JDK sets, in lower case; {@link #headers()} may not name them. They include every
	 * name the JDK restricts, as of JDK 27: JDK 26 added {@code alt-used}, which it sets itself for HTTP/3.
	 */
	private static final Set<String> RESERVED_HEADER_NAMES = Set.of("accept", "accept-encoding", "alt-used",
			"connection", "content-length", "content-type", "expect", "host", "te", "trailer", "transfer-encoding",
			"upgrade");

	/**
	 * Checks and copies the components.
	 *
	 * @throws NullPointerException     if a non-null component is {@code null}
	 * @throws IllegalArgumentException if the form body is not US-ASCII, a header name is not a token or is
	 *                                  reserved, a header value has a character other than visible US-ASCII, space
	 *                                  and horizontal tab, a limit is negative, or the timeout is not positive
	 */
	public HttpExchangeRequest {
		requireNonNull(uri);
		requireNonNull(profile);
		requireNonNull(headers);
		requireNonNull(requestTimeout);

		if (formBody != null)
			for (int i = 0; i < formBody.length(); ++i)
				if (formBody.charAt(i) > 0x7F)
					throw new IllegalArgumentException("A form body must be US-ASCII.");

		headers = Map.copyOf(headers);

		for (Map.Entry<String, String> header : headers.entrySet()) {
			String name = header.getKey();

			if (name.isEmpty() || !name.chars().allMatch(c -> MediaType.isTokenCharacter((char) c)))
				throw new IllegalArgumentException("A request header name must be an HTTP token.");

			if (RESERVED_HEADER_NAMES.contains(MediaType.asciiLowerCase(name)))
				throw new IllegalArgumentException("A request header name is one Revetsec or the JDK sets itself.");

			if (!header.getValue().chars().allMatch(c -> c == '\t' || (c >= 0x20 && c <= 0x7E)))
				throw new IllegalArgumentException("A request header value must be visible US-ASCII, spaces and tabs.");
		}

		if (maximumBodyBytes < 0 || maximumErrorBodyBytes < 0)
			throw new IllegalArgumentException("Body limits must not be negative.");

		if (requestTimeout.isNegative() || requestTimeout.isZero())
			throw new IllegalArgumentException("The request timeout must be positive.");
	}

	/**
	 * A {@code GET} with no extra headers and the default limits and timeout: the profile's body-size row, the error
	 * body row and the request-timeout row of {@link Limits}.
	 *
	 * @param uri     the URI
	 * @param profile what a successful response must look like
	 * @return the request
	 * @throws NullPointerException if an argument is {@code null}
	 */
	@NonNull
	public static HttpExchangeRequest fromDefaults(@NonNull URI uri,
																								 @NonNull ResponseProfile profile) {
		requireNonNull(profile);
		return new HttpExchangeRequest(uri, profile, null, Map.of(), profile.getBodySizeLimit().getDefaultIntValue(),
				Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(), Limits.REQUEST_TIMEOUT.getDefaultDuration());
	}

	/**
	 * The request method.
	 *
	 * @return {@code POST} with a form body, otherwise {@code GET}
	 */
	@NonNull
	public String method() {
		return this.formBody == null ? "GET" : "POST";
	}

	/**
	 * Describes this request without credentials (see the class description).
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{method=" + method() + ", uri=" + describe(this.uri) + ", profile="
				+ this.profile + ", headerNames=" + new TreeSet<>(this.headers.keySet()) + ", maximumBodyBytes="
				+ this.maximumBodyBytes + ", maximumErrorBodyBytes=" + this.maximumErrorBodyBytes + ", requestTimeout="
				+ this.requestTimeout + "}";
	}

	/**
	 * The URI cut to scheme, host, port and path (G6-4): no user information, query or fragment.
	 */
	@NonNull
	static String describe(@NonNull URI uri) {
		StringBuilder description = new StringBuilder();

		if (uri.getScheme() != null)
			description.append(uri.getScheme()).append(':');

		if (uri.getHost() != null) {
			description.append("//").append(uri.getHost());

			if (uri.getPort() >= 0)
				description.append(':').append(uri.getPort());
		}

		if (uri.getRawPath() != null)
			description.append(uri.getRawPath());

		return description.toString();
	}
}
