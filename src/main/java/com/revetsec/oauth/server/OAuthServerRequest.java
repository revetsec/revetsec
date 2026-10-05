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

package com.revetsec.oauth.server;

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.MediaType;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.INVALID_REQUEST;

/** Bounded, collapse-free wire admission. Trusted edge owns raw allocation, framing, routing and TLS. */
final class OAuthServerRequest {
	enum Endpoint { AUTHORIZATION, TOKEN, REVOCATION, INTROSPECTION }
	private static final @NonNull Set<@NonNull String> RECOGNIZED = Set.of("response_type", "client_id",
			"redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "resource", "grant_type",
			"code", "code_verifier", "refresh_token", "token", "token_type_hint", "client_secret", "client_assertion",
			"client_assertion_type", "request", "request_uri", "response_mode", "authorization_details", "username", "password");
	private static final @NonNull Set<@NonNull String> UNSUPPORTED = Set.of("client_secret", "client_assertion",
			"client_assertion_type", "request", "request_uri", "authorization_details", "username", "password");
	private final @NonNull Endpoint endpoint;
	private final @NonNull Map<@NonNull String, @NonNull String> parameters;
	private final @Nullable String authorization;
	private OAuthServerRequest(@NonNull Endpoint endpoint, @NonNull Map<@NonNull String, @NonNull String> parameters,
			@Nullable String authorization) {
		this.endpoint = endpoint; this.parameters = Map.copyOf(parameters); this.authorization = authorization;
	}
	static @NonNull OAuthServerRequest parse(@NonNull Endpoint endpoint, @NonNull String method,
			@Nullable String rawQuery, byte @NonNull [] body,
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> rawHeaders,
			@NonNull OAuthServerIngressLimits limits) {
		requireNonNull(endpoint); requireNonNull(method); requireNonNull(body); requireNonNull(rawHeaders); requireNonNull(limits);
		// All aggregate caps precede substrings, decoding, copies or normalization of hostile inputs.
		if (body.length > limits.bodyBytes || (rawQuery != null && rawQuery.length() > limits.queryLength)) throw invalid();
		Map<String, String> headers = headers(rawHeaders, limits.headerBytes);
		if (headers.containsKey("content-encoding")) throw invalid();
		boolean authorizationEndpoint = endpoint == Endpoint.AUTHORIZATION;
		if (!method.equals(authorizationEndpoint ? "GET" : "POST")) throw invalid();
		Map<String, String> parameters = new LinkedHashMap<>();
		try {
			int fields = parameters(rawQuery == null ? "" : rawQuery, parameters, limits, !authorizationEndpoint, 0);
			if (authorizationEndpoint) {
				if (body.length != 0 || headers.containsKey("authorization")) throw invalid();
			} else {
				String contentType = headers.get("content-type");
				if (contentType == null) throw invalid();
				MediaType mime = MediaType.parse(contentType).orElseThrow(OAuthServerRequest::invalid);
				if (!mime.getEssence().equals("application/x-www-form-urlencoded") || !mime.hasUtf8OrNoCharset()) throw invalid();
				parameters(StrictUtf8.decode(body), parameters, limits, false, fields);
			}
		} catch (EncodingException failure) { throw invalid(); }
		return new OAuthServerRequest(endpoint, parameters, headers.get("authorization"));
	}
	private static int parameters(@NonNull String raw, @NonNull Map<@NonNull String, @NonNull String> target,
			@NonNull OAuthServerIngressLimits limits, boolean queryOnPost, int previousFields) throws EncodingException {
		// Count before creating the first decoded parameter. Unknown extensions consume the same limits.
		int fields = previousFields;
		for (int start = 0; start < raw.length();) {
			int end = raw.indexOf('&', start); if (end < 0) end = raw.length();
			if (end > start && ++fields > 128) throw invalid();
			start = end + 1;
		}
		for (int start = 0; start < raw.length();) {
			int end = raw.indexOf('&', start); if (end < 0) end = raw.length();
			if (end > start) {
				int separator = start; while (separator < end && raw.charAt(separator) != '=') separator++;
				String name = FormUrlEncoding.decode(raw.substring(start, separator));
				int valueStart = separator < end ? separator + 1 : end;
				if (RECOGNIZED.contains(name)) {
					if (queryOnPost || target.containsKey(name) || UNSUPPORTED.contains(name)) throw invalid();
					int cap = name.equals("state") ? limits.stateLength : name.equals("client_id") ? limits.clientIdLength : raw.length();
					if (end - valueStart > cap) throw invalid();
				}
				String value = FormUrlEncoding.decode(raw.substring(valueStart, end));
				if (RECOGNIZED.contains(name)) target.put(name, value);
			}
			start = end + 1;
		}
		return fields;
	}
	private static @NonNull Map<@NonNull String, @NonNull String> headers(
			@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> raw, int maximumBytes) {
		if (raw.size() > 64) throw invalid();
		int used = 2, count = 0;
		for (Map.Entry<String, List<String>> entry : raw.entrySet()) {
			String name = requireNonNull(entry.getKey()); List<String> values = requireNonNull(entry.getValue());
			if (name.isEmpty() || name.length() > maximumBytes || values.size() > 64 - count) throw invalid();
			for (int i = 0; i < name.length(); i++) if (!token(name.charAt(i))) throw invalid();
			for (String value : values) {
				requireNonNull(value);
				if (value.length() > maximumBytes - used - name.length() - 4) throw invalid();
				used += name.length() + 4 + value.length(); count++;
				for (int i = 0; i < value.length(); i++) {
					char c = value.charAt(i); if ((c < 32 && c != '\t') || c == 127 || c > 255) throw invalid();
				}
			}
		}
		Map<String, String> selected = new LinkedHashMap<>();
		for (Map.Entry<String, List<String>> entry : raw.entrySet()) {
			String name = entry.getKey().toLowerCase(Locale.ROOT);
			if (name.equals("authorization") || name.equals("content-type") || name.equals("content-encoding")) {
				if (entry.getValue().size() != 1 || selected.putIfAbsent(name, entry.getValue().get(0)) != null) throw invalid();
			}
		}
		return selected;
	}
	private static boolean token(char c) {
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
				|| "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
	}
	@NonNull Endpoint endpoint() { return this.endpoint; }
	@Nullable String value(@NonNull String name) { return this.parameters.get(requireNonNull(name)); }
	@NonNull String required(@NonNull String name) {
		String value = value(name); if (value == null || value.isEmpty()) throw invalid(); return value;
	}
	@Nullable String authorization() { return this.authorization; }
	static @NonNull OAuthServerAdmissionFailure invalid() { return new OAuthServerAdmissionFailure(INVALID_REQUEST); }
	@Override public @NonNull String toString() { return "OAuthServerRequest{<redacted>}"; }
}
