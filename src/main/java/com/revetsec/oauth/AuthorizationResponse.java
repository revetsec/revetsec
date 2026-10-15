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
import com.revetsec.internal.http.MediaType;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * A parsed browser authorization response. It preserves repeated parameters so a duplicate cannot be silently
 * selected. Its delivery mode comes from the application route and method, never from callback data. Parsing does
 * not authenticate the response; {@link OAuthClient} checks its pending state before trusting any error or code.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class AuthorizationResponse {
	private static final Set<String> SINGLETONS = Set.of("code", "state", "iss", "error",
			"error_description", "error_uri");
	private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> parameters;
	private final AuthorizationRequestOptions.@NonNull ResponseMode responseMode;
	private final @Nullable URI errorUri;

	private AuthorizationResponse(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values,
			AuthorizationRequestOptions.@NonNull ResponseMode responseMode, @Nullable URI errorUri) {
		this.parameters = values;
		this.responseMode = responseMode;
		this.errorUri = errorUri;
	}

	/**
	 * Parses a raw URL query, without the question mark, keeping malformed input as a rejected result.
	 * A successful parse grants no identity and does not validate the pending authorization transaction.
	 *
	 * @param rawQuery the raw query
	 * @return the unverified callback or a fixed rejection reason
	 * @throws NullPointerException if rawQuery is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull AuthorizationResponseParseResult fromQueryStringResult(@NonNull String rawQuery) {
		try {
			return AuthorizationResponseParseResult.fromResponse(fromQueryString(rawQuery));
		} catch (OAuthResponseException exception) {
			return AuthorizationResponseParseResult.fromRejected();
		}
	}

	/**
	 * Parses a UTF-8 form-post body. Protocol members in the query reject split-channel responses; safe nonprotocol
	 * query parameters remain untrusted extras. Invalid charset, encoding, size or parameters produce rejection.
	 *
	 * @param body the form bytes
	 * @param charset the application's parsed Content-Type charset, which must be UTF-8
	 * @param rawQueryOrNull the URL's raw query, if any
	 * @return the unverified callback or a fixed rejection reason
	 * @throws NullPointerException if body or charset is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull AuthorizationResponseParseResult fromFormBodyResult(byte @NonNull [] body,
			@NonNull Charset charset, @Nullable String rawQueryOrNull) {
		try {
			return AuthorizationResponseParseResult.fromResponse(fromFormBody(body, charset, rawQueryOrNull));
		} catch (OAuthResponseException exception) {
			return AuthorizationResponseParseResult.fromRejected();
		}
	}

	/**
	 * Parses a form-post callback after validating every raw Content-Type occurrence. Requires exactly one form
	 * field with an absent or UTF-8 charset and no duplicate MIME parameters. The field is capped at 8,192
	 * characters before MIME parsing. Preserve materialized duplicates; a trusted edge rejects physical fields
	 * discarded by a transport. Invalid MIME, body, duplicate parameters and split channels produce rejection.
	 *
	 * @param body the raw form bytes
	 * @param contentTypeHeaderValues all materialized Content-Type values
	 * @param rawQueryOrNull the raw URL query, if any
	 * @return the unverified callback or a fixed rejection reason
	 * @throws NullPointerException if body, header list or its sole field is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull AuthorizationResponseParseResult fromFormBodyResult(byte @NonNull [] body,
			@NonNull List<@NonNull String> contentTypeHeaderValues, @Nullable String rawQueryOrNull) {
		try {
			return AuthorizationResponseParseResult.fromResponse(fromFormBody(body, contentTypeHeaderValues, rawQueryOrNull));
		} catch (OAuthResponseException exception) {
			return AuthorizationResponseParseResult.fromRejected();
		}
	}

	/**
	 * Accepts parameters from an application parser, retaining multiplicity and the explicit route mode.
	 * Malformed, duplicate, oversized or split-channel parameters produce rejection. Success remains unverified.
	 *
	 * @param values decoded parameters, with all values for each name
	 * @param rawQueryOrNull the URL query when the mode is form-post, if any
	 * @param responseMode mode established by trusted application routing
	 * @return the unverified callback or a fixed rejection reason
	 * @throws NullPointerException if values, a parameter name/list/value or responseMode is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull AuthorizationResponseParseResult fromParametersResult(
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values,
			@Nullable String rawQueryOrNull, AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
		try {
			return AuthorizationResponseParseResult.fromResponse(fromParameters(values, rawQueryOrNull, responseMode));
		} catch (OAuthResponseException exception) {
			return AuthorizationResponseParseResult.fromRejected();
		}
	}

	private static @NonNull AuthorizationResponse fromQueryString(@NonNull String rawQuery) {
		return fromEncoded(rawQuery, AuthorizationRequestOptions.ResponseMode.QUERY);
	}

	private static @NonNull AuthorizationResponse fromFormBody(byte @NonNull [] body, @NonNull Charset charset,
			@Nullable String rawQueryOrNull) {
		requireNonNull(body);
		if (!StandardCharsets.UTF_8.equals(requireNonNull(charset)))
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		if (body.length > Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		try {
			return fromParameters(QueryParameters.parse(StrictUtf8.decode(body)).getValuesByName(), rawQueryOrNull,
					AuthorizationRequestOptions.ResponseMode.FORM_POST);
		} catch (EncodingException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private static @NonNull AuthorizationResponse fromFormBody(byte @NonNull [] body,
			@NonNull List<@NonNull String> contentTypeHeaderValues, @Nullable String rawQueryOrNull) {
		requireNonNull(body);
		requireNonNull(contentTypeHeaderValues);
		if (contentTypeHeaderValues.size() != 1)
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		String field = requireNonNull(contentTypeHeaderValues.get(0));
		if (field.length() > Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getDefaultIntValue())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		MediaType type = MediaType.parse(field).orElseThrow(() ->
				OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED));
		if (!type.getEssence().equals("application/x-www-form-urlencoded") || !type.hasUtf8OrNoCharset())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		return fromFormBody(body, StandardCharsets.UTF_8, rawQueryOrNull);
	}

	private static @NonNull AuthorizationResponse fromParameters(
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values,
			@Nullable String rawQueryOrNull, AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
		requireNonNull(values);
		requireNonNull(responseMode);
		Map<String, List<String>> copy = new LinkedHashMap<>();
		int maximumQuerySize = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
		int maximumParameterSize = Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getDefaultIntValue();
		if (values.size() > maximumQuerySize)
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		long aggregate = 0;
		long parameterCount = 0;
		for (Map.Entry<String, List<String>> entry : values.entrySet()) {
			String name = requireNonNull(entry.getKey());
			List<String> supplied = requireNonNull(entry.getValue());
			if (supplied.size() > maximumQuerySize - parameterCount || name.length() > maximumParameterSize)
				throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
			parameterCount += supplied.size();
			if (SINGLETONS.contains(name) && supplied.size() > 1)
				throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
			List<String> list = new ArrayList<>(supplied.size());
			for (String value : supplied) {
				requireNonNull(value);
				if ((long) name.length() + value.length() > maximumParameterSize)
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				long size = (long) utf8Length(name) + utf8Length(value);
				if (size > maximumParameterSize || size > maximumQuerySize - aggregate)
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				aggregate += size;
				list.add(value);
			}
			copy.put(name, List.copyOf(list));
		}
		if (rawQueryOrNull != null && responseMode == AuthorizationRequestOptions.ResponseMode.FORM_POST) {
			Map<String, List<String>> query = parseEncoded(rawQueryOrNull);
			for (Map.Entry<String, List<String>> entry : query.entrySet()) {
				if (entry.getValue().size() > maximumQuerySize - parameterCount)
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				parameterCount += entry.getValue().size();
				if (SINGLETONS.contains(entry.getKey()))
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				if (copy.containsKey(entry.getKey()))
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				copy.put(entry.getKey(), entry.getValue());
				for (String value : entry.getValue())
					aggregate += utf8Length(entry.getKey()) + utf8Length(value);
			}
		}
		if (aggregate > Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue()
				|| (copy.containsKey("code") && copy.containsKey("error")))
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		return new AuthorizationResponse(Collections.unmodifiableMap(copy), responseMode, parseErrorUri(copy));
	}

	private static @NonNull AuthorizationResponse fromEncoded(@NonNull String encoded,
			AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
		return fromParameters(parseEncoded(encoded), null, responseMode);
	}

	private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> parseEncoded(@NonNull String encoded) {
		requireNonNull(encoded);
		if (utf8Length(encoded) > Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		try {
			return QueryParameters.parse(encoded).getValuesByName();
		} catch (EncodingException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private static int utf8Length(@NonNull String value) {
		if (value.length() > Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		try {
			byte[] encoded = StrictUtf8.encode(value);
			try {
				return encoded.length;
			} finally {
				Arrays.fill(encoded, (byte) 0);
			}
		} catch (EncodingException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private static @Nullable URI parseErrorUri(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values) {
		List<String> list = values.get("error_uri");
		if (list == null || list.isEmpty() || list.get(0).isEmpty())
			return null;
		try {
			URI uri = URI.create(list.get(0));
			if (!uri.isAbsolute())
				throw new IllegalArgumentException();
			return uri;
		} catch (IllegalArgumentException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private @NonNull Optional<@NonNull String> first(@NonNull String name) {
		List<String> list = this.parameters.get(name);
		return list == null || list.isEmpty() || list.get(0).isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	/**
	 * Returns the code, if present and nonempty. It is untrusted until completion succeeds.
	 *
	 * @return the code
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getCode() { return first("code"); }

	/**
	 * Returns the state, if present and nonempty.
	 *
	 * @return the state
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getState() { return first("state"); }

	/**
	 * Returns the RFC 9207 issuer, if present and nonempty.
	 *
	 * @return the issuer
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getIssuer() { return first("iss"); }

	/**
	 * Returns an authorization error, if present and nonempty.
	 *
	 * @return the error
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getError() { return first("error"); }

	/**
	 * Returns untrusted error prose, if present, with non-NQSCHAR characters replaced and at most 1,024 characters.
	 * Do not log it without application redaction. The raw value remains available in {@link #getParameters()}.
	 *
	 * @return the prose
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getErrorDescription() {
		return first("error_description").map(AuthorizationResponse::safeErrorDescription);
	}

	private static @NonNull String safeErrorDescription(@NonNull String raw) {
		StringBuilder safe = new StringBuilder(Math.min(raw.length(), 1_024));
		for (int index = 0; index < raw.length() && safe.length() < 1_024; index++) {
			char value = raw.charAt(index);
			safe.append((value == 0x20 || value == 0x21 || (value >= 0x23 && value <= 0x5B)
					|| (value >= 0x5D && value <= 0x7E)) ? value : '?');
		}
		return safe.toString();
	}

	/**
	 * Returns the absolute error URI, if present and nonempty. Parsing rejects a malformed supplied URI.
	 *
	 * @return the URI
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull URI> getErrorUri() {
		return Optional.ofNullable(this.errorUri);
	}

	/**
	 * Returns every decoded parameter, including unsigned provider extras.
	 *
	 * @return immutable parameter lists
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> getParameters() {
		return Collections.unmodifiableMap(new LinkedHashMap<>(this.parameters));
	}

	/**
	 * Returns the callback mode established by trusted application routing.
	 *
	 * @return the mode
	 * @since 1.0.0
	 */
	public AuthorizationRequestOptions.@NonNull ResponseMode getResponseMode() { return this.responseMode; }

	/**
	 * Returns the optional per-flow cookie name derived from state. The suffix is a selector, not an authenticator.
	 *
	 * @return the cookie name when nonempty state is present
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getPerFlowCookieName() {
		return getState().map(OAuthCookieNames::fromState);
	}

	/**
	 * Redacts all callback parameters.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "AuthorizationResponse{parameters=<redacted>}"; }
}
