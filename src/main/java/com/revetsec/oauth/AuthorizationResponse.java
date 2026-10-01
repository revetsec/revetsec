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

	private AuthorizationResponse(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values,
			AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
		this.parameters = values;
		this.responseMode = responseMode;
	}

	/**
	 * Parses a raw URL query, without the question mark.
	 *
	 * @param rawQuery the raw query
	 * @return the parsed callback
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationResponse fromQueryString(@NonNull String rawQuery) {
		return fromEncoded(rawQuery, AuthorizationRequestOptions.ResponseMode.QUERY);
	}

	/**
	 * Parses a UTF-8 form-post body. OAuth protocol members in the URL query are rejected to prevent a response from
	 * being split across channels; safe nonprotocol query parameters are retained as untrusted extras.
	 *
	 * @param body the form bytes
	 * @param charset the application's parsed Content-Type charset, which must be UTF-8
	 * @param rawQueryOrNull the URL's raw query, if any
	 * @return the parsed callback
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationResponse fromFormBody(byte @NonNull [] body, @NonNull Charset charset,
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

	/**
	 * Parses a form-post callback after validating its raw Content-Type values. Requires exactly one form field,
	 * with absent or UTF-8 charset and no duplicate MIME parameters. Caps the field at 8,192 characters before
	 * MIME parsing using the authorization-response parameter default; accepted field characters each occupy one
	 * ISO-8859-1 octet. Preserve materialized duplicates; identical physical fields lost by a transport must be
	 * rejected at a trusted edge. Body/query multiplicity and split-channel checks are the same as the Charset overload.
	 *
	 * @param body the raw form bytes
	 * @param contentTypeHeaderValues all materialized Content-Type values
	 * @param rawQueryOrNull the raw URL query, if any
	 * @return the untrusted parsed callback
	 * @throws OAuthResponseException if MIME, size, charset or callback checks fail
	 * @throws NullPointerException if body, header list or its sole field is null
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationResponse fromFormBody(byte @NonNull [] body,
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

	/**
	 * Accepts parameters from a trusted application parser, keeping their multiplicity and explicit route mode.
	 *
	 * @param values decoded parameters, with all values for each name
	 * @param rawQueryOrNull the URL query when the mode is form-post, if any
	 * @param responseMode mode established by trusted application routing
	 * @return the parsed callback
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationResponse fromParameters(
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> values,
			@Nullable String rawQueryOrNull, AuthorizationRequestOptions.@NonNull ResponseMode responseMode) {
		requireNonNull(values);
		requireNonNull(responseMode);
		Map<String, List<String>> copy = new LinkedHashMap<>();
		long aggregate = 0;
		for (Map.Entry<String, List<String>> entry : values.entrySet()) {
			String name = requireNonNull(entry.getKey());
			List<String> list = List.copyOf(requireNonNull(entry.getValue()));
			if (SINGLETONS.contains(name) && list.size() > 1)
				throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
			for (String value : list) {
				long size = (long) utf8Length(name) + utf8Length(value);
				if (size > Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getDefaultIntValue())
					throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
				aggregate += size;
			}
			copy.put(name, list);
		}
		if (rawQueryOrNull != null && responseMode == AuthorizationRequestOptions.ResponseMode.FORM_POST) {
			Map<String, List<String>> query = parseEncoded(rawQueryOrNull);
			for (Map.Entry<String, List<String>> entry : query.entrySet()) {
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
		return new AuthorizationResponse(Collections.unmodifiableMap(copy), responseMode);
	}

	private static AuthorizationResponse fromEncoded(String encoded,
			AuthorizationRequestOptions.ResponseMode responseMode) {
		return fromParameters(parseEncoded(encoded), null, responseMode);
	}

	private static Map<String, List<String>> parseEncoded(String encoded) {
		requireNonNull(encoded);
		if (utf8Length(encoded) > Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue())
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		try {
			return QueryParameters.parse(encoded).getValuesByName();
		} catch (EncodingException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private static int utf8Length(String value) {
		try {
			return StrictUtf8.encode(value).length;
		} catch (EncodingException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
		}
	}

	private @NonNull Optional<@NonNull String> first(String name) {
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

	private static String safeErrorDescription(String raw) {
		StringBuilder safe = new StringBuilder(Math.min(raw.length(), 1_024));
		for (int index = 0; index < raw.length() && safe.length() < 1_024; index++) {
			char value = raw.charAt(index);
			safe.append((value == 0x20 || value == 0x21 || (value >= 0x23 && value <= 0x5B)
					|| (value >= 0x5D && value <= 0x7E)) ? value : '?');
		}
		return safe.toString();
	}

	/**
	 * Returns an absolute error URI, if present and parseable.
	 *
	 * @return the URI
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull URI> getErrorUri() {
		return first("error_uri").map(value -> {
			try {
				URI uri = URI.create(value);
				if (!uri.isAbsolute())
					throw new IllegalArgumentException();
				return uri;
			} catch (IllegalArgumentException exception) {
				throw OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED);
			}
		});
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
	 * @return the cookie name
	 * @since 1.0.0
	 */
	public @NonNull String getPerFlowCookieName() {
		return OAuthCookieNames.fromState(getState().orElseThrow(() ->
				new IllegalArgumentException("A callback state is required for a per-flow cookie name.")));
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
