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
import org.jspecify.annotations.NonNull;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Pure configuration checks. Carrier ceilings admit the approved server maxima; operations apply narrower caps. */
final class OAuthServerConfiguration {
	static final int MAXIMUM_CLIENT_ID_LENGTH = 4_096;
	static final int MAXIMUM_SUBJECT_LENGTH = 1_024;
	static final int MAXIMUM_TEXT_LENGTH = 4_096;
	static final int MAXIMUM_URI_LENGTH = 65_536;
	static final int MAXIMUM_CONFIGURATION_BYTES = 131_072;
	static final int MAXIMUM_RESOURCES = 1_024;
	static final int MAXIMUM_REDIRECTS = 64;
	static final int MAXIMUM_SCOPES = 128;
	static final int MAXIMUM_SCOPE_LENGTH = 128;
	private static final @NonNull Set<@NonNull String> RESPONSE_PARAMETERS = Set.of(
			"code", "state", "iss", "error", "error_description", "error_uri");
	private OAuthServerConfiguration() {}

	static @NonNull String text(@NonNull String value, int maximumLength) {
		requireNonNull(value);
		if (value.isEmpty() || value.length() > maximumLength || !StrictUtf8.isWellFormed(value))
			throw invalid();
		for (int i = 0; i < value.length(); i++)
			if (Character.isISOControl(value.charAt(i))) throw invalid();
		return value;
	}
	static int utf8Length(@NonNull String value) {
		int bytes = 0;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (Character.isHighSurrogate(c)) { bytes += 4; i++; }
			else bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
		}
		return bytes;
	}
	static int addBytes(int used, @NonNull String value) {
		int next = used + utf8Length(value);
		if (next > MAXIMUM_CONFIGURATION_BYTES) throw invalid();
		return next;
	}
	static @NonNull String resource(@NonNull String value) {
		text(value, MAXIMUM_URI_LENGTH);
		try {
			URI uri = new URI(value);
			if (!uri.isAbsolute() || uri.getRawFragment() != null) throw invalid();
		} catch (URISyntaxException failure) { throw invalid(); }
		return value;
	}
	static @NonNull String scope(@NonNull String value) {
		requireNonNull(value);
		if (value.isEmpty() || value.length() > MAXIMUM_SCOPE_LENGTH) throw invalid();
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c < 0x21 || c > 0x7E || c == '"' || c == '\\') throw invalid();
		}
		return value;
	}
	static @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources(
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> value, int maximumResources) {
		requireNonNull(value);
		if (value.isEmpty() || value.size() > maximumResources) throw invalid();
		Map<String, Set<String>> copy = new LinkedHashMap<>();
		int used = 0;
		for (Map.Entry<String, Set<String>> entry : value.entrySet()) {
			String id = resource(requireNonNull(entry.getKey()));
			used = addBytes(used, id);
			Set<String> scopes = requireNonNull(entry.getValue());
			if (scopes.size() > MAXIMUM_SCOPES) throw invalid();
			Set<String> scopeCopy = new LinkedHashSet<>();
			for (String item : scopes) {
				String checked = scope(requireNonNull(item));
				used = addBytes(used, checked);
				if (!scopeCopy.add(checked)) throw invalid();
			}
			if (copy.put(id, Collections.unmodifiableSet(scopeCopy)) != null) throw invalid();
			if (copy.size() > maximumResources) throw invalid();
		}
		return Collections.unmodifiableMap(copy);
	}
	static @NonNull Set<@NonNull String> introspectionResources(@NonNull Set<@NonNull String> value) {
		requireNonNull(value);
		if (value.size() > MAXIMUM_RESOURCES) throw invalid();
		Set<String> copy = new LinkedHashSet<>();
		int used = 0;
		for (String item : value) {
			String id = resource(requireNonNull(item));
			used = addBytes(used, id);
			if (!copy.add(id) || copy.size() > MAXIMUM_RESOURCES) throw invalid();
		}
		return Collections.unmodifiableSet(copy);
	}
	static @NonNull List<@NonNull URI> redirects(@NonNull List<@NonNull URI> value) {
		requireNonNull(value);
		if (value.isEmpty() || value.size() > MAXIMUM_REDIRECTS) throw invalid();
		List<URI> copy = new ArrayList<>();
		Set<String> spellings = new LinkedHashSet<>();
		int used = 0;
		for (URI item : value) {
			URI uri = requireNonNull(item);
			String spelling = text(uri.toString(), MAXIMUM_URI_LENGTH);
			used = addBytes(used, spelling);
			String scheme = uri.getScheme(); String host = uri.getHost();
			int port = uri.getPort();
			if (scheme == null || host == null || uri.isOpaque() || uri.getRawUserInfo() != null
					|| uri.getRawFragment() != null || port == 0 || port > 65_535 || spelling.indexOf('*') >= 0)
				throw invalid();
			boolean https = scheme.equalsIgnoreCase("https");
			boolean loopback = scheme.equalsIgnoreCase("http") &&
					(host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("localhost"));
			if (!https && !loopback) throw invalid();
			rejectResponseParameters(uri);
			if (!spellings.add(spelling) || copy.size() == MAXIMUM_REDIRECTS) throw invalid();
			copy.add(uri);
		}
		return List.copyOf(copy);
	}
	private static void rejectResponseParameters(@NonNull URI uri) {
		String query = uri.getRawQuery();
		if (query == null) return;
		int start = 0;
		while (start <= query.length()) {
			int end = query.indexOf('&', start); if (end < 0) end = query.length();
			int equals = query.indexOf('=', start); if (equals < 0 || equals > end) equals = end;
			try {
				String name = FormUrlEncoding.decode(query.substring(start, equals));
				if (RESPONSE_PARAMETERS.contains(name)) throw invalid();
			} catch (EncodingException failure) { throw invalid(); }
			if (end == query.length()) break;
			start = end + 1;
		}
	}
	static @NonNull IllegalArgumentException invalid() {
		return new IllegalArgumentException("Invalid authorization-server configuration value.");
	}
}
