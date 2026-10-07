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

import com.revetsec.M6FuzzOracle;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import static org.junit.jupiter.api.Assertions.*;

/** Independent split/byte-stream/CharsetDecoder oracle. Does not use product form, UTF-8 or MIME parsers. */
final class IssuerIngressFuzzModel {
	private static final @NonNull Set<@NonNull String> NAMES = Set.of("response_type", "client_id", "redirect_uri", "scope", "state",
		"code_challenge", "code_challenge_method", "resource", "grant_type", "code", "code_verifier", "refresh_token", "token",
		"token_type_hint", "client_secret", "client_assertion", "client_assertion_type", "request", "request_uri", "response_mode",
		"authorization_details", "username", "password");
	private static final @NonNull Set<@NonNull String> FORBIDDEN = Set.of("client_secret", "client_assertion", "client_assertion_type",
		"request", "request_uri", "authorization_details", "username", "password");
	private static final @NonNull OAuthServerIngressLimits LIMITS = new OAuthServerIngressLimits(1024, 1024, 1024, 128, 256, 2, 2, 2, 32);
	private IssuerIngressFuzzModel() { }
	static void run(byte @NonNull [] input) throws Exception {
		Wire wire = wire(input);
		Map<String, String> expected = null;
		try { expected = oracle(wire); } catch (Rejected failure) { /* Fixed negative grammar verdict. */ }
		OAuthServerRequest actual = null;
		try { actual = OAuthServerRequest.parse(wire.endpoint(), wire.method(), wire.query(), wire.body(), wire.headers(), LIMITS); }
		catch (OAuthServerAdmissionFailure failure) {
			assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST, failure.reason());
			assertNull(expected, "independent grammar admitted a request the issuer rejected");
		}
		if (actual != null) {
			assertNotNull(expected, "issuer admitted a request the independent grammar rejected");
			for (String name : NAMES) assertEquals(expected.get(name), actual.value(name), "decoded recognized value: " + name);
			assertEquals(expected.get("@authorization"), actual.authorization(), "raw Authorization occurrence must remain exact");
			assertEquals(wire.endpoint(), actual.endpoint());
		}
	}
	private static @NonNull Wire wire(byte @NonNull [] input) {
		OAuthServerRequest.Endpoint endpoint = OAuthServerRequest.Endpoint.values()[M6FuzzOracle.choice(input, 0, 4)];
		boolean auth = endpoint == OAuthServerRequest.Endpoint.AUTHORIZATION;
		String method = switch (M6FuzzOracle.choice(input, 1, 4)) { case 0 -> auth ? "GET" : "POST"; case 1 -> auth ? "POST" : "GET"; case 2 -> auth ? "get" : "post"; default -> "OPTIONS"; };
		byte[] tail = Arrays.copyOfRange(input, Math.min(4, input.length), Math.min(input.length, 8196));
		String extension = new String(tail, StandardCharsets.ISO_8859_1);
		String form = auth ? "client_id=client&response_type=code&state=a%2Bb+c&resource=https%3A%2F%2Fresource.example%2Fmcp" : "grant_type=authorization_code&client_id=client&code=synthetic&resource=synthetic";
		String query = auth ? form : null;
		byte[] body = auth ? new byte[0] : form.getBytes(StandardCharsets.UTF_8);
		int style = M6FuzzOracle.choice(input, 2, 18);
		String changed = switch (style) {
			case 1 -> form + "&ext=" + extension;
			case 2 -> form + "&client%5Fid=again";
			case 3 -> form + "&resource=other";
			case 4 -> form + "&client_secret=forbidden";
			case 5 -> form + "&unknown=%GG";
			case 6 -> form + "&unknown=%C0%AF";
			case 7 -> form + "&unknown=\uD800";
			case 8 -> "x=1&".repeat(129);
			case 9 -> "x=" + "a".repeat(1023);
			case 10 -> "state=" + "%41".repeat(43);
			case 11 -> form + "&unknown=%F0%9F%92%A9&scope=read+write";
			case 12 -> extension;
			case 17 -> "&&" + form + "&&empty&unknown=one=two&";
			default -> form;
		};
		if (auth) query = changed;
		else body = changed.getBytes(StandardCharsets.UTF_8);
		if (style == 13) body = tail;
		if (style == 14) query = "client_id=client";
		if (style == 15) query = "extension=ignored&unknown=%E2%82%AC";
		if (style == 16) body = new byte[]{1};
		Map<String, List<String>> headers = new LinkedHashMap<>();
		if (!auth) headers.put("Content-Type", List.of("application/x-www-form-urlencoded"));
		switch (M6FuzzOracle.choice(input, 3, 18)) {
			case 1 -> headers.put("Authorization", List.of("Basic synthetic"));
			case 2 -> headers.put("Authorization", List.of("Basic same", "Basic same"));
			case 3 -> { headers.put("Authorization", List.of("Basic one")); headers.put("authorization", List.of("Basic two")); }
			case 4 -> { headers.put("Content-Type", List.of("application/x-www-form-urlencoded")); headers.put("content-type", List.of("application/x-www-form-urlencoded")); }
			case 5 -> headers.put("Content-Encoding", List.of("identity"));
			case 6 -> headers.put("Content-Type", List.of("application/x-www-form-urlencoded; charset=ISO-8859-1"));
			case 7 -> headers.put("Content-Type", List.of("Application/X-WWW-Form-Urlencoded; charset=\"UtF-8\""));
			case 8 -> headers.put("Content-Type", List.of("application/json"));
			case 9 -> headers.put("X-Extension", List.of("one\ttwo"));
			case 10 -> headers.put("X-Extension", List.of("one\r\ntwo"));
			case 11 -> { for (int i = 0; i < 65; i++) headers.put("X-" + i, List.of("x")); }
			case 12 -> headers.put("X-☃", List.of("x"));
			case 13 -> headers.put("X-Extension", List.of("\u00ff"));
			case 14 -> headers.put("X-Extension", List.of("x".repeat(1024)));
			case 15 -> headers.put("Authorization", List.of());
			case 16 -> headers.remove("Content-Type");
			case 17 -> headers.put("X-Extension", List.of("\u007f"));
			default -> { }
		}
		return new Wire(endpoint, method, query, body, headers);
	}
	private static @NonNull Map<@NonNull String, @NonNull String> oracle(@NonNull Wire wire) throws Rejected {
		if (wire.body().length > 1024 || wire.query() != null && wire.query().length() > 1024 || wire.headers().size() > 64) throw new Rejected();
		long total = 2; int count = 0;
		Map<String, String> selected = new LinkedHashMap<>();
		for (var header : wire.headers().entrySet()) {
			if (!header.getKey().matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) throw new Rejected();
			for (String value : header.getValue()) {
				total += header.getKey().length() + value.length() + 4; count++;
				if (value.chars().anyMatch(c -> c < 32 && c != 9 || c == 127 || c > 255)) throw new Rejected();
			}
			if (header.getKey().length() > 1024 || total > 1024 || count > 64) throw new Rejected();
			String name = header.getKey().toLowerCase(Locale.ROOT);
			if (Set.of("content-type", "content-encoding", "authorization").contains(name)) {
				if (header.getValue().size() != 1 || selected.containsKey(name)) throw new Rejected();
				selected.put(name, header.getValue().get(0));
			}
		}
		boolean auth = wire.endpoint() == OAuthServerRequest.Endpoint.AUTHORIZATION;
		if (selected.containsKey("content-encoding") || !wire.method().equals(auth ? "GET" : "POST")) throw new Rejected();
		if (auth && (wire.body().length != 0 || selected.containsKey("authorization"))) throw new Rejected();
		if (!auth) {
			// Generated MIME variants have an independently enumerated accepted subset.
			String mime = selected.get("content-type");
			if (!"application/x-www-form-urlencoded".equals(mime) && !"Application/X-WWW-Form-Urlencoded; charset=\"UtF-8\"".equals(mime)) throw new Rejected();
		}
		Map<String, String> result = new LinkedHashMap<>();
		String query = wire.query() == null ? "" : wire.query();
		String body = auth ? "" : strict(wire.body());
		int fields = 0;
		for (String text : List.of(query, body)) for (String field : text.split("&", -1)) if (!field.isEmpty() && ++fields > 128) throw new Rejected();
		fields(query, result, !auth);
		fields(body, result, false);
		String authorization = selected.get("authorization");
		if (authorization != null) result.put("@authorization", authorization);
		return result;
	}
	private static void fields(@NonNull String raw, @NonNull Map<@NonNull String, @NonNull String> result, boolean postQuery) throws Rejected {
		for (String field : raw.split("&", -1)) {
			if (field.isEmpty()) continue;
			int equals = field.indexOf('=');
			String name = decode(equals < 0 ? field : field.substring(0, equals));
			String value = equals < 0 ? "" : field.substring(equals + 1);
			if (NAMES.contains(name) && (postQuery || result.containsKey(name) || FORBIDDEN.contains(name)
				|| name.equals("state") && value.length() > 128 || name.equals("client_id") && value.length() > 256)) throw new Rejected();
			String decoded = decode(value);
			if (NAMES.contains(name)) result.put(name, decoded);
		}
	}
	private static @NonNull String strict(byte @NonNull [] bytes) throws Rejected {
		try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
		catch (CharacterCodingException failure) { throw new Rejected(); }
	}
	private static @NonNull String decode(@NonNull String raw) throws Rejected {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		for (int i = 0; i < raw.length();) {
			char c = raw.charAt(i);
			if (c == '%') {
				if (i + 2 >= raw.length()) throw new Rejected();
				int a = hex(raw.charAt(i + 1)), b = hex(raw.charAt(i + 2));
				if (a < 0 || b < 0) throw new Rejected();
				bytes.write(a * 16 + b); i += 3;
			} else if (c == '+') { bytes.write(32); i++; }
			else {
				int end = i + 1;
				if (Character.isHighSurrogate(c) && end < raw.length() && Character.isLowSurrogate(raw.charAt(end))) end++;
				try {
					ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(raw, i, end));
					while (encoded.hasRemaining()) bytes.write(encoded.get());
				} catch (CharacterCodingException failure) { throw new Rejected(); }
				i = end;
			}
		}
		return strict(bytes.toByteArray());
	}
	private static int hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }
	private record Wire(OAuthServerRequest.@NonNull Endpoint endpoint, @NonNull String method, @Nullable String query,
		byte @NonNull [] body, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) { }
	private static final class Rejected extends Exception {
		private static final long serialVersionUID = 1L;
		private Rejected() { }
	}
}
