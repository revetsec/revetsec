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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.HttpExchangeException.Kind;
import com.revetsec.testing.Sentinels;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * {@link UriChecks}, the one outbound URI check that a builder runs at {@code build()} and {@link HttpExchange} runs
 * before every request (M2 plan, G8-7 and G8-9): absolute and hierarchical with a host and a valid port, no user
 * information, no fragment, {@code https} or plain {@code http} to a loopback literal or exactly {@code localhost}
 * when insecure loopback is allowed, and a permitting {@link OutboundUriPolicy}. A query is allowed.
 * <p>
 * Each row states the outcome under the four combinations of the two presets and the loopback setting, in the order
 * default without loopback, default with loopback, public-addresses-only without loopback, public-addresses-only with
 * loopback: {@code Y} permits, {@code N} rejects.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class UriChecksTests {
	private static final String STRUCTURE = "The URI must be absolute and hierarchical, with a host and, if it has a "
			+ "port, a port from 1 to 65535.";
	private static final String USER_INFORMATION = "The URI must not contain user information.";
	private static final String FRAGMENT = "The URI must not contain a fragment.";
	private static final String SCHEME = "The URI must use https, or plain http to a loopback address or exactly "
			+ "localhost when insecure loopback is allowed.";
	private static final String POLICY = "The outbound URI policy does not permit the URI.";

	private static final List<OutboundUriPolicy> POLICIES = List.of(OutboundUriPolicy.defaultInstance(),
			OutboundUriPolicy.defaultInstance(), OutboundUriPolicy.publicAddressesOnlyInstance(),
			OutboundUriPolicy.publicAddressesOnlyInstance());
	private static final List<Boolean> LOOPBACK = List.of(false, true, false, true);

	/**
	 * Every row: the URI, and its outcome under the four combinations (see the class description).
	 */
	private static final Map<String, String> ROWS = rows();

	private static Map<String, String> rows() {
		Map<String, String> rows = new LinkedHashMap<>();
		// G8-9: absolute and hierarchical, with a host URI can parse and a port from 1 to 65535.
		rows.put("/relative", "NNNN");
		rows.put("mailto:someone@example.com", "NNNN");
		rows.put("https:example.com", "NNNN");
		rows.put("https:///no-host", "NNNN");
		rows.put("http:///no-host", "NNNN");
		rows.put("https://exa_mple.com/", "NNNN");
		rows.put("http://local_host/", "NNNN");
		rows.put("https://example.com:0/", "NNNN");
		rows.put("https://example.com:65536/", "NNNN");
		rows.put("https://example.com:65535/jwks", "YYYY");
		// G8-9: no user information and no fragment, not even an empty one; a query is allowed.
		rows.put("https://user@example.com/", "NNNN");
		rows.put("https://user:secret@example.com/", "NNNN");
		// RFC 3986 section 3.2.1: userinfo may be empty, and an "@" before the host still delimits it.
		rows.put("https://@example.com/", "NNNN");
		rows.put("https://:@example.com/", "NNNN");
		rows.put("http://@localhost/jwks", "NNNN");
		rows.put("https://example.com/jwks#", "NNNN");
		rows.put("https://example.com/jwks?#", "NNNN");
		rows.put("https://example.com/jwks#keys", "NNNN");
		rows.put("https://example.com/jwks?", "YYYY");
		// A percent-encoded "#" is part of the path, not a fragment delimiter.
		rows.put("https://example.com/jwks%23keys", "YYYY");
		rows.put("https://login.microsoftonline.com/common/discovery/v2.0/keys?appid=00000000-0000-0000-0000-000000000000",
				"YYYY");
		// R12: https in any ASCII case; no other scheme.
		rows.put("https://example.com/jwks", "YYYY");
		rows.put("HTTPS://Example.COM:443/jwks", "YYYY");
		rows.put("ftp://example.com/", "NNNN");
		rows.put("ws://example.com/", "NNNN");
		rows.put("wss://example.com/", "NNNN");
		// G8-5 and G8-6: the policy decides the rest; the presets differ on local and non-global destinations.
		rows.put("https://8.8.8.8/jwks", "YYYY");
		rows.put("https://[2001:4860:4860::8888]/jwks", "YYYY");
		rows.put("https://[::ffff:8.8.8.8]/jwks", "YYYY");
		rows.put("https://[::8.8.8.8]/jwks", "YYNN");
		rows.put("https://127.0.0.1/jwks", "YYNN");
		rows.put("https://10.0.0.1/jwks", "YYNN");
		rows.put("https://localhost/jwks", "YYNN");
		rows.put("https://idp.internal/jwks", "YYNN");
		rows.put("https://169.254.169.254/latest/meta-data/", "NNNN");
		rows.put("https://100.100.100.200/", "NNNN");
		rows.put("https://metadata.google.internal/", "NNNN");
		rows.put("https://[64:ff9b:1::a9fe:a9fe]/", "NNNN");
		rows.put("https://0/", "NNNN");
		rows.put("https://127.1/", "NNNN");
		// G8-7: plain http only with insecure loopback, and only to 127/8, [::1], [::ffff:127.x.y.z] and exactly
		// localhost (ASCII case-insensitive, no trailing dot); the policy still applies, so the public-addresses-only
		// preset refuses every one of them.
		rows.put("http://127.0.0.1:8080/jwks", "NYNN");
		rows.put("http://127.255.255.254/jwks", "NYNN");
		rows.put("http://[::1]/jwks", "NYNN");
		rows.put("http://[::ffff:127.0.0.1]/jwks", "NYNN");
		rows.put("http://localhost/jwks", "NYNN");
		rows.put("http://LocalHost:8080/jwks", "NYNN");
		rows.put("HTTP://LOCALHOST/jwks", "NYNN");
		rows.put("http://api.localhost/jwks", "NNNN");
		rows.put("http://localhost./jwks", "NNNN");
		rows.put("http://LOCALHOST./jwks", "NNNN");
		rows.put("http://[::127.0.0.1]/jwks", "NNNN");
		rows.put("http://[::ffff:0:127.0.0.1]/jwks", "NNNN");
		rows.put("http://[64:ff9b::127.0.0.1]/jwks", "NNNN");
		rows.put("http://127.1/jwks", "NNNN");
		rows.put("http://0x7f000001/jwks", "NNNN");
		rows.put("http://example.com/jwks", "NNNN");
		rows.put("http://10.0.0.1/jwks", "NNNN");
		rows.put("http://localhost/jwks#keys", "NNNN");
		rows.put("http://user@localhost/jwks", "NNNN");
		return rows;
	}

	// G8-7 and G8-9: every row has the stated outcome under both presets, with and without insecure loopback, and the
	// two methods agree: requirePermitted returns the URI itself exactly when isPermitted is true, and otherwise throws
	// IllegalArgumentException.
	@TestFactory
	Stream<DynamicTest> everyRowHasItsOutcomeUnderBothPresetsAndBothLoopbackSettings() {
		List<DynamicTest> tests = new ArrayList<>();
		for (Map.Entry<String, String> row : ROWS.entrySet())
			for (int combination = 0; combination < 4; ++combination) {
				URI uri = URI.create(row.getKey());
				OutboundUriPolicy policy = POLICIES.get(combination);
				boolean loopback = LOOPBACK.get(combination);
				boolean expected = row.getValue().charAt(combination) == 'Y';
				tests.add(DynamicTest.dynamicTest(row.getKey() + " " + policy + " loopback " + loopback, () -> {
					Assertions.assertEquals(expected, UriChecks.isPermitted(uri, policy, loopback));
					if (expected)
						Assertions.assertSame(uri, UriChecks.requirePermitted(uri, policy, loopback));
					else
						Assertions.assertThrows(IllegalArgumentException.class,
								() -> UriChecks.requirePermitted(uri, policy, loopback));
				}));
			}
		return tests.stream();
	}

	// G8-9: the build-time and fetch-time checks cannot drift. On every row and combination, HttpExchange sends the
	// request (the stand-in client then fails it with IO) exactly when UriChecks permits the URI, and otherwise fails
	// with URI_REJECTED before the client is asked to send anything.
	@TestFactory
	Stream<DynamicTest> theFetchTimeCheckAgreesWithTheBuildTimeCheckOnEveryRow() {
		List<DynamicTest> tests = new ArrayList<>();
		for (Map.Entry<String, String> row : ROWS.entrySet())
			for (int combination = 0; combination < 4; ++combination) {
				URI uri = URI.create(row.getKey());
				OutboundUriPolicy policy = POLICIES.get(combination);
				boolean loopback = LOOPBACK.get(combination);
				tests.add(DynamicTest.dynamicTest(row.getKey() + " " + policy + " loopback " + loopback, () -> {
					StandInHttpClient standIn = new StandInHttpClient();
					HttpExchange httpExchange = HttpExchange.fromHttpClient(standIn, policy, loopback);

					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> httpExchange.execute(HttpExchangeRequest.fromDefaults(uri, ResponseProfile.JWKS),
									Deadline.fromNow(Duration.ofSeconds(30))));

					boolean permitted = UriChecks.isPermitted(uri, policy, loopback);
					Assertions.assertEquals(permitted ? Kind.IO : Kind.URI_REJECTED, exception.getKind());
					Assertions.assertEquals(permitted ? 1 : 0, standIn.getSendCount());
				}));
			}
		return tests.stream();
	}

	// G8-9: the checks run in order, and the message names the first one that fails, as a fixed sentence.
	@Test
	void theMessageNamesTheFirstFailingCheck() {
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();
		Map<String, String> cases = new LinkedHashMap<>();
		cases.put("/relative", STRUCTURE);
		cases.put("https://example.com:0/", STRUCTURE);
		cases.put("https:///no-host", STRUCTURE);
		cases.put("http:///no-host", STRUCTURE);
		cases.put("https://exa_mple.com/", STRUCTURE);
		cases.put("https://user@example.com/", USER_INFORMATION);
		cases.put("https://@example.com/", USER_INFORMATION);
		cases.put("http://user@example.com/#x", USER_INFORMATION);
		cases.put("https://example.com/#x", FRAGMENT);
		cases.put("http://example.com/#x", FRAGMENT);
		cases.put("http://example.com/", SCHEME);
		cases.put("http://api.localhost/", SCHEME);
		cases.put("https://169.254.169.254/", POLICY);

		for (Map.Entry<String, String> entry : cases.entrySet()) {
			IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
					() -> UriChecks.requirePermitted(URI.create(entry.getKey()), policy, true), entry::getKey);
			Assertions.assertEquals(entry.getValue(), exception.getMessage(), entry::getKey);
		}
	}

	// R9: a rejection's message never repeats the URI, which can carry a secret in its user information, path, query
	// or fragment.
	@Test
	void aRejectionNeverRepeatsTheUri() {
		String secret = Sentinels.secret("uri");
		for (String uri : List.of("https://user:" + secret + "@example.com/", "https://example.com/" + secret + "#x",
				"https://example.com/jwks?key=" + secret + "#" + secret, "http://example.com/" + secret,
				"https://169.254.169.254/" + secret, "/" + secret)) {
			IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
					() -> UriChecks.requirePermitted(URI.create(uri), OutboundUriPolicy.defaultInstance(), false));
			Sentinels.assertAbsent(exception);
		}
	}

	// The URI and the policy are required; a null is a programming error, not a rejection.
	@Test
	void refusesNullArguments() {
		URI uri = URI.create("https://example.com/");
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();
		Assertions.assertThrows(NullPointerException.class, () -> UriChecks.isPermitted(nullValue(), policy, false));
		Assertions.assertThrows(NullPointerException.class, () -> UriChecks.isPermitted(uri, nullValue(), false));
		Assertions.assertThrows(NullPointerException.class, () -> UriChecks.requirePermitted(nullValue(), policy,
				false));
		Assertions.assertThrows(NullPointerException.class, () -> UriChecks.requirePermitted(uri, nullValue(), false));
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
