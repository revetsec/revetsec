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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.TreeSet;

import static java.util.Objects.requireNonNull;

/**
 * A response that passed {@link HttpExchange}'s checks: any 2xx that met its {@link ResponseProfile}, or any other
 * status from 100 to 999 except 3xx (M1 plan, "HTTP helper"). The JDK accepts any three-digit status; one above 599
 * has no defined class, and the protocols treat it as an error.
 * <p>
 * A non-2xx response is not an exception here: the protocol reads its status (and, if kept, its body) and raises
 * {@code REMOTE_ERROR}, transient on 429 and 5xx (G6-3). A non-2xx body that was encoded, or larger than the error
 * limit, is dropped unread: {@link #body()} is empty and {@link #errorBodyDropped()} is {@code true}, and the status
 * is kept (G5-5).
 * <p>
 * The body is copied in and copied out, so a response is immutable. A token response body holds credentials, so the
 * caller zeroes the copy it parses once it is done (R9), and {@link #toString()} shows the status, the media type
 * without parameter values, the header names and the body length, never header values or body bytes.
 * {@link #equals(Object)} compares bodies by content.
 *
 * @param status           the HTTP status code
 * @param headers          the response headers, as the JDK parsed them
 * @param body             the body; empty when there was none or it was dropped
 * @param mediaType        the one parsed {@code Content-Type}, or {@code null} if the field was absent, repeated or
 *                         malformed (never {@code null} on a 2xx under a checked profile)
 * @param errorBodyDropped whether a non-2xx body was dropped unread
 * @param elapsed          the time from the start of the exchange to the end of the body, by {@link System#nanoTime()}
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
// The body is copied in and out, and equals, hashCode and toString treat it by content, so an array is safe here.
@SuppressWarnings("ArrayRecordComponent")
public record RawResponse(int status,
													@NonNull HttpHeaders headers,
													byte @NonNull [] body,
													@Nullable MediaType mediaType,
													boolean errorBodyDropped,
													@NonNull Duration elapsed) {
	/**
	 * Checks the components and copies the body.
	 *
	 * @throws NullPointerException     if a non-null component is {@code null}
	 * @throws IllegalArgumentException if the status is outside 100 to 999, a dropped body is not empty, a 2xx claims
	 *                                  a dropped body, or the elapsed time is negative
	 */
	public RawResponse {
		requireNonNull(headers);
		requireNonNull(body);
		requireNonNull(elapsed);

		if (status < 100 || status > 999)
			throw new IllegalArgumentException("An HTTP status must be from 100 to 999.");

		if (errorBodyDropped && (body.length != 0 || isSuccessful(status)))
			throw new IllegalArgumentException("Only a non-2xx response drops its body, and a dropped body is empty.");

		if (elapsed.isNegative())
			throw new IllegalArgumentException("The elapsed time must not be negative.");

		body = body.clone();
	}

	/**
	 * A copy of the body; the caller zeroes it when done with a body that may hold credentials.
	 *
	 * @return a new copy of the body, empty when there was none or it was dropped
	 */
	@Override
	public byte @NonNull [] body() {
		return this.body.clone();
	}

	/**
	 * Whether the status is 2xx.
	 *
	 * @return {@code true} for 200 to 299
	 */
	public boolean isSuccessful() {
		return isSuccessful(this.status);
	}

	/**
	 * Compares every component, bodies by content.
	 *
	 * @param object the other object
	 * @return whether {@code object} is an equal {@code RawResponse}
	 */
	@Override
	public boolean equals(@Nullable Object object) {
		if (this == object)
			return true;

		if (!(object instanceof RawResponse other))
			return false;

		return this.status == other.status && this.headers.equals(other.headers) && Arrays.equals(this.body, other.body)
				&& Objects.equals(this.mediaType, other.mediaType)
				&& this.errorBodyDropped == other.errorBodyDropped && this.elapsed.equals(other.elapsed);
	}

	/**
	 * A hash of every component, the body by content.
	 *
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.status, this.headers, Arrays.hashCode(this.body), this.mediaType,
				this.errorBodyDropped, this.elapsed);
	}

	/**
	 * Describes this response without header values or body bytes (see the class description).
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{status=" + this.status + ", mediaType=" + this.mediaType + ", headerNames="
				+ new TreeSet<>(this.headers.map().keySet()) + ", bodyLength=" + this.body.length + ", errorBodyDropped="
				+ this.errorBodyDropped + ", elapsed=" + this.elapsed + "}";
	}

	static boolean isSuccessful(int status) {
		return status >= 200 && status <= 299;
	}
}
