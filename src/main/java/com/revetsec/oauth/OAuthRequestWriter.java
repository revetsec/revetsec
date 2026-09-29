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

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.FormUrlEncoding;

import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Writes OAuth UTF-8 form pairs, retaining repeated RFC 8707 resource fields. */
@NotThreadSafe
final class OAuthRequestWriter {
	private final List<String> encodedPairs = new ArrayList<>();

	OAuthRequestWriter add(String name, String value) {
		try {
			this.encodedPairs.add(FormUrlEncoding.encode(name) + "=" + FormUrlEncoding.encode(value));
		} catch (EncodingException exception) {
			throw new IllegalArgumentException("An OAuth form field contains invalid text.");
		}
		return this;
	}

	OAuthRequestWriter addAll(Map<String, String> values) {
		values.forEach(this::add);
		return this;
	}

	OAuthRequestWriter resources(List<URI> resources) {
		for (URI resource : resources) add("resource", resource.toString());
		return this;
	}

	String body() { return String.join("&", this.encodedPairs); }

	URI appendTo(URI endpoint) {
		String raw = endpoint.toASCIIString();
		if (this.encodedPairs.isEmpty()) return endpoint;
		return URI.create(raw + (endpoint.getRawQuery() == null ? "?" : raw.endsWith("?") || raw.endsWith("&") ? "" : "&")
				+ body());
	}
}
