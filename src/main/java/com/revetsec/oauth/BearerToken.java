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

package com.revetsec.oauth;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * An unverified credential parsed from exactly one Authorization field (RFC 6750 section 2.1).
 * Parsing grants no identity or permission. No public accessor exposes the credential; equality is reference
 * identity and diagnostic text is redacted. Query, form and cookie credentials are not accepted here.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class BearerToken {
	private static final int PREFIX_ALLOWANCE = 64;
	private final @NonNull String value;

	private BearerToken(@NonNull String value) { this.value = value; }

	/**
	 * Parses materialized header values with a 64 KiB credential limit and a 64-byte prefix allowance,
	 * returning absent, present or malformed. Other schemes and duplicate fields are malformed, including identical
	 * duplicates. Applications must preserve duplicates or reject them at a trusted edge. A present credential
	 * remains unverified and grants no identity or permission.
	 * @param values all materialized Authorization values, preserving duplicates
	 * @return the header parsing outcome
	 * @throws NullPointerException if the list or its sole value is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull BearerTokenResult fromAuthorizationHeaderValuesResult(@NonNull List<@NonNull String> values) {
		return fromAuthorizationHeaderValuesResult(values, Limits.BEARER_CREDENTIAL_SIZE.getDefaultIntValue());
	}

	/**
	 * Parses one case-insensitive Bearer scheme, one to 58 ASCII spaces, and RFC 6750 b64token text.
	 * Padding is permitted only at the end. Bounds are checked before copying the credential.
	 * No raw credential appears on absent or malformed outcomes.
	 * @param values all materialized Authorization values, preserving duplicates
	 * @param maximumTokenLength credential limit from 8 KiB through 1 MiB
	 * @return the header parsing outcome
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if the configured limit is invalid
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull BearerTokenResult fromAuthorizationHeaderValuesResult(
			@NonNull List<@NonNull String> values, @NonNull Integer maximumTokenLength) {
		requireNonNull(values);
		int maximum = Limits.BEARER_CREDENTIAL_SIZE.require(requireNonNull(maximumTokenLength));
		if (values.isEmpty())
			return BearerTokenResult.fromAbsent();
		if (values.size() != 1)
			return BearerTokenResult.fromMalformed();
		String field = requireNonNull(values.get(0));
		if (field.length() > maximum + PREFIX_ALLOWANCE || field.length() < 8)
			return BearerTokenResult.fromMalformed();
		String scheme = "bearer";
		for (int index = 0; index < scheme.length(); index++) {
			char c = field.charAt(index);
			if (c >= 'A' && c <= 'Z') c = (char) (c + ('a' - 'A'));
			if (c != scheme.charAt(index)) return BearerTokenResult.fromMalformed();
		}
		int start = scheme.length();
		if (field.charAt(start) != ' ') return BearerTokenResult.fromMalformed();
		while (start < field.length() && field.charAt(start) == ' ') {
			if (++start > PREFIX_ALLOWANCE) return BearerTokenResult.fromMalformed();
		}
		if (start == field.length() || field.length() - start > maximum) return BearerTokenResult.fromMalformed();
		boolean padding = false;
		for (int index = start; index < field.length(); index++) {
			char c = field.charAt(index);
			if (c == '=' && index > start) { padding = true; continue; }
			if (padding || !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
					|| (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
					|| c == '+' || c == '/')) return BearerTokenResult.fromMalformed();
		}
		return BearerTokenResult.fromToken(new BearerToken(field.substring(start)));
	}

	@NonNull String value() { return this.value; }

	/**
	 * Returns a description containing no credential.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "BearerToken{value=<redacted>}"; }
}
