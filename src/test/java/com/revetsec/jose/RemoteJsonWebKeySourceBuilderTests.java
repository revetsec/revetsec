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

package com.revetsec.jose;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.jose.JwksCacheTests.Answer;
import com.revetsec.jose.JwksCacheTests.MemoryHttpClient;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Stream;

/**
 * {@link RemoteJsonWebKeySource.Builder}: every setting against its {@code Limits} row, the time-to-live order and the
 * unknown-key cooldown within the minimum time to live (M2-8), the runtime floor (plan section 9.6; exit criterion 16),
 * the injected client's redirect policy (G6-5), the URI checks (G8-7, G8-9; exit criterion 18), their order, and a
 * build that does no I/O and loads no default client (G8-4).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceBuilderTests {
	private static final URI URI_OK = URI.create("https://jwks.example.com/keys");
	private static final Runtime.Version FLOOR_17 = Runtime.Version.parse("17.0.3");

	// Exit criterion 19: each setting accepts its row's floor and cap and refuses one unit outside either, with
	// IllegalArgumentException; null restores the default (the StateSealer.Builder convention).
	@TestFactory
	Stream<DynamicTest> everySettingIsCheckedAgainstItsRow() {
		List<DynamicTest> tests = new ArrayList<>();
		addDurationRow(tests, Limits.REQUEST_TIMEOUT, RemoteJsonWebKeySource.Builder::requestTimeout);
		// The cooldown may not exceed the minimum time to live, which is raised with it past its default of 1 minute.
		addDurationRow(tests, Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN, (builder, value) -> builder
				.unknownKeyRefreshCooldown(value)
				.minimumTimeToLive(value == null ? null : max(value, Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration())));
		addDurationRow(tests, Limits.JWKS_MAXIMUM_STALENESS, RemoteJsonWebKeySource.Builder::maximumStaleness);
		// The time-to-live rows are checked together with their order, so each is set with its neighbors at the edge.
		addDurationRow(tests, Limits.JWKS_MINIMUM_TIME_TO_LIVE, (builder, value) -> builder.minimumTimeToLive(value)
				.defaultTimeToLive(value == null ? null : max(value, Limits.JWKS_DEFAULT_TIME_TO_LIVE.getFloorDuration()))
				.maximumTimeToLive(value == null ? null : max(value, Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getFloorDuration())));
		addDurationRow(tests, Limits.JWKS_DEFAULT_TIME_TO_LIVE, (builder, value) -> builder.defaultTimeToLive(value)
				.minimumTimeToLive(value == null ? null : Limits.JWKS_MINIMUM_TIME_TO_LIVE.getFloorDuration())
				.maximumTimeToLive(value == null ? null : Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getCapDuration()));
		addDurationRow(tests, Limits.JWKS_MAXIMUM_TIME_TO_LIVE, (builder, value) -> builder.maximumTimeToLive(value)
				.minimumTimeToLive(value == null ? null : Limits.JWKS_MINIMUM_TIME_TO_LIVE.getFloorDuration())
				.defaultTimeToLive(value == null ? null : min(value, Limits.JWKS_DEFAULT_TIME_TO_LIVE.getCapDuration())));
		addAmountRow(tests, Limits.JWKS_RESPONSE_BODY_SIZE, RemoteJsonWebKeySource.Builder::maximumResponseBytes);
		addAmountRow(tests, Limits.JWKS_KEY_COUNT, RemoteJsonWebKeySource.Builder::maximumKeys);
		return tests.stream();
	}

	// Plan "RemoteJsonWebKeySource.Builder": minimum <= default <= maximum time to live, else IAE; equal values pass.
	@Test
	void timeToLiveSettingsMustBeOrdered() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder()
				.minimumTimeToLive(Duration.ofMinutes(20)).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder()
				.defaultTimeToLive(Duration.ofHours(7)).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder()
				.maximumTimeToLive(Duration.ofMinutes(5)).build());
		Assertions.assertDoesNotThrow(() -> builder().minimumTimeToLive(Duration.ofMinutes(10))
				.defaultTimeToLive(Duration.ofMinutes(10)).maximumTimeToLive(Duration.ofMinutes(10)).build());
	}

	// M2-8, the owner's decision of 2026-09-28: build() refuses an unknown-key refresh cooldown longer than the minimum
	// time to live with IllegalArgumentException and a fixed message, so the limit of two requests per cooldown holds
	// back no refresh after expiry unless fetches were cut short. Equal values pass, one nanosecond more fails, and the
	// defaults (30 s and 1 min), the rows' floors (1 s and 30 s) and the cooldown's 10 min cap under a 10 min minimum
	// pass.
	@Test
	void theUnknownKeyCooldownMayNotExceedTheMinimumTimeToLive() {
		Duration minimum = Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration();
		Assertions.assertDoesNotThrow(() -> builder().build());
		Assertions.assertDoesNotThrow(() -> builder().unknownKeyRefreshCooldown(minimum).build());
		Assertions.assertEquals("JWKS unknown-kid cooldown must not exceed the JWKS minimum time to live.",
				message(Assertions.assertThrows(IllegalArgumentException.class,
						() -> builder().unknownKeyRefreshCooldown(minimum.plusNanos(1)).build())));

		Duration shortest = Limits.JWKS_MINIMUM_TIME_TO_LIVE.getFloorDuration();
		Assertions.assertDoesNotThrow(() -> builder().minimumTimeToLive(shortest)
				.unknownKeyRefreshCooldown(Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getFloorDuration()).build());
		Assertions.assertDoesNotThrow(() -> builder().minimumTimeToLive(shortest).unknownKeyRefreshCooldown(shortest)
				.build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder().minimumTimeToLive(shortest)
				.unknownKeyRefreshCooldown(shortest.plusNanos(1)).build());

		Duration longestCooldown = Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getCapDuration();
		Assertions.assertDoesNotThrow(() -> builder().minimumTimeToLive(longestCooldown)
				.unknownKeyRefreshCooldown(longestCooldown).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder()
				.minimumTimeToLive(longestCooldown.minusNanos(1)).unknownKeyRefreshCooldown(longestCooldown).build());
	}

	// Exit criterion 16 and plan section 9.6: a simulated 17.0.2 or 18.0.0 runtime fails build() with
	// IllegalStateException unless acknowledged (18.0.0 is spelled "18"); when acknowledged, didUseUnpatchedRuntime
	// fires at build() and on every fetch; 17.0.3, 18.0.1 and 21 build without it, acknowledged or not.
	@TestFactory
	Stream<DynamicTest> theRuntimeFloorIsEnforcedAndAnAcknowledgmentIsObserved() {
		// Runtime.Version spells 18.0.0 as "18": trailing zero components are not allowed.
		return Stream.of("17.0.2", "18", "17.0.2.0.1", "17-ea").map(version -> DynamicTest.dynamicTest(version, () -> {
			Runtime.Version runtime = Runtime.Version.parse(version);
			IllegalStateException exception = Assertions.assertThrows(IllegalStateException.class,
					() -> builder().build(runtime));
			Assertions.assertTrue(message(exception).contains("acknowledgeUnpatchedRuntime(true)"));
			Assertions.assertThrows(IllegalStateException.class,
					() -> builder().acknowledgeUnpatchedRuntime(false).build(runtime));

			MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("no-store", "a"));
			TestClock clock = TestClock.fromInstant(JwksCacheTests.START);
			RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
			RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(URI_OK).httpClient(client).clock(clock)
					.observer(observer.getObserver()).acknowledgeUnpatchedRuntime(true).build(runtime);
			Assertions.assertEquals(List.of(List.of(runtime.toString())), arguments(observer, "didUseUnpatchedRuntime"));
			Assertions.assertEquals(0, client.getSendCount());

			Assertions.assertEquals(KeySelection.Kind.FOUND, JwksCacheTests.select(source, "a").getKind());
			clock.advance(Duration.ofMinutes(1));
			source.warmUp();
			Assertions.assertEquals(2, client.getSendCount());
			Assertions.assertEquals(3, arguments(observer, "didUseUnpatchedRuntime").size(), "at build and each fetch");
			// Each fetch reports it before it announces the fetch.
			List<String> order = observer.getCalls().stream().map(RecordingObserver.Call::getMethodName)
					.filter(name -> !name.equals("didFetchJsonWebKeySet")).toList();
			Assertions.assertEquals(List.of("didUseUnpatchedRuntime", "didUseUnpatchedRuntime", "willFetchJsonWebKeySet",
					"didUseUnpatchedRuntime", "willFetchJsonWebKeySet"), order);
		}));
	}

	@TestFactory
	Stream<DynamicTest> aRuntimeAtOrAboveTheFloorIsNeverReported() {
		return Stream.of(FLOOR_17, Runtime.Version.parse("18.0.1"), Runtime.Version.parse("21.0.1"))
				.map(runtime -> DynamicTest.dynamicTest(runtime.toString(), () -> {
					for (@Nullable Boolean acknowledged : new Boolean[]{null, false, true}) {
						RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
						MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
						RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(URI_OK).httpClient(client)
								.observer(observer.getObserver()).acknowledgeUnpatchedRuntime(acknowledged).build(runtime);
						source.warmUp();
						Assertions.assertEquals(0, arguments(observer, "didUseUnpatchedRuntime").size());
					}
				}));
	}

	// G6-5: an injected client that follows redirects is refused at build() with IAE; NEVER is accepted.
	@TestFactory
	Stream<DynamicTest> anInjectedClientMustNeverFollowRedirects() {
		return Stream.of(HttpClient.Redirect.values()).map(redirect -> DynamicTest.dynamicTest(redirect.name(), () -> {
			HttpClient client = new RedirectPolicyClient(redirect);
			if (redirect == HttpClient.Redirect.NEVER)
				Assertions.assertDoesNotThrow(() -> builder().httpClient(client).build());
			else
				Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
						() -> builder().httpClient(client).build())).contains("followRedirects"));
		}));
	}

	// G8-9 and exit criterion 18: an app-supplied URI must be absolute and hierarchical with a host, have no user
	// information (even empty) or fragment (even empty), use https (or plain http to a loopback literal or exactly
	// localhost when allowed, G8-7), and pass the outbound URI policy; a query is allowed. A refusal is IAE whose
	// message names the check and never the URI.
	@TestFactory
	Stream<DynamicTest> theUriIsCheckedAtBuild() {
		return Stream.of(
				new UriCase("keys", OutboundUriPolicy.defaultInstance(), false, "absolute"),
				new UriCase("urn:example:keys", OutboundUriPolicy.defaultInstance(), false, "absolute"),
				new UriCase("https:///keys", OutboundUriPolicy.defaultInstance(), false, "absolute"),
				new UriCase("https://jwks.example.com:0/keys", OutboundUriPolicy.defaultInstance(), false, "absolute"),
				new UriCase("https://user@jwks.example.com/keys", OutboundUriPolicy.defaultInstance(), false,
						"user information"),
				new UriCase("https://@jwks.example.com/keys", OutboundUriPolicy.defaultInstance(), false,
						"user information"),
				new UriCase("https://jwks.example.com/keys#a", OutboundUriPolicy.defaultInstance(), false, "fragment"),
				new UriCase("https://jwks.example.com/keys#", OutboundUriPolicy.defaultInstance(), false, "fragment"),
				new UriCase("http://jwks.example.com/keys", OutboundUriPolicy.defaultInstance(), true, "https"),
				new UriCase("http://127.0.0.1/keys", OutboundUriPolicy.defaultInstance(), false, "https"),
				new UriCase("http://api.localhost/keys", OutboundUriPolicy.defaultInstance(), true, "https"),
				new UriCase("http://localhost./keys", OutboundUriPolicy.defaultInstance(), true, "https"),
				new UriCase("ftp://jwks.example.com/keys", OutboundUriPolicy.defaultInstance(), true, "https"),
				new UriCase("https://169.254.169.254/keys", OutboundUriPolicy.defaultInstance(), false, "policy"),
				new UriCase("https://metadata.google.internal/keys", OutboundUriPolicy.defaultInstance(), false, "policy"),
				new UriCase("https://10.0.0.1/keys", OutboundUriPolicy.publicAddressesOnlyInstance(), false, "policy"),
				new UriCase("https://jwks.example.com/keys?appid=1", OutboundUriPolicy.defaultInstance(), false, null),
				new UriCase("https://10.0.0.1/keys", OutboundUriPolicy.defaultInstance(), false, null),
				new UriCase("HTTPS://jwks.example.com/keys", OutboundUriPolicy.publicAddressesOnlyInstance(), false, null),
				new UriCase("http://127.0.0.1:8080/keys", OutboundUriPolicy.defaultInstance(), true, null),
				new UriCase("http://[::1]/keys", OutboundUriPolicy.defaultInstance(), true, null),
				new UriCase("http://localhost/keys", OutboundUriPolicy.defaultInstance(), true, null),
				new UriCase("http://LocalHost/keys", OutboundUriPolicy.defaultInstance(), true, null))
				.map(uriCase -> DynamicTest.dynamicTest(uriCase.uri + " under " + uriCase.policy + ", loopback "
						+ uriCase.insecureLoopback, () -> {
					URI uri = URI.create(uriCase.uri);
					RemoteJsonWebKeySource.Builder builder = RemoteJsonWebKeySource.withUri(uri)
							.outboundUriPolicy(uriCase.policy).allowInsecureLoopback(uriCase.insecureLoopback);
					@Nullable String failedCheck = uriCase.failedCheck;
					if (failedCheck == null) {
						RemoteJsonWebKeySource source = builder.build();
						Assertions.assertSame(uri, source.getUri());
						return;
					}
					IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
							builder::build);
					Assertions.assertTrue(message(exception).contains(failedCheck), exception::getMessage);
					Assertions.assertFalse(message(exception).contains(uri.toString()), exception::getMessage);
				}));
	}

	// Plan "build() order": each limit, the time-to-live order and the cooldown within the minimum time to live first,
	// then the runtime floor, then the injected client, then the URI.
	@Test
	void buildChecksLimitsThenTheRuntimeThenTheClientThenTheUri() {
		Runtime.Version belowFloor = Runtime.Version.parse("17.0.2");
		URI refusedUri = URI.create("http://x.example.com/keys");
		HttpClient redirecting = new RedirectPolicyClient(HttpClient.Redirect.ALWAYS);

		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).httpClient(redirecting).requestTimeout(Duration.ZERO)
						.build(belowFloor))).startsWith("Request timeout"));
		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).httpClient(redirecting)
						.minimumTimeToLive(Duration.ofMinutes(30)).build(belowFloor))).startsWith("JWKS time to live"));
		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).httpClient(redirecting)
						.defaultTimeToLive(Duration.ofHours(7)).unknownKeyRefreshCooldown(Duration.ofMinutes(2))
						.build(belowFloor))).startsWith("JWKS time to live"), "the time-to-live order, then the cooldown");
		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).httpClient(redirecting)
						.unknownKeyRefreshCooldown(Duration.ofMinutes(2)).build(belowFloor)))
				.startsWith("JWKS unknown-kid cooldown"));
		Assertions.assertThrows(IllegalStateException.class, () -> RemoteJsonWebKeySource.withUri(refusedUri)
				.httpClient(redirecting).build(belowFloor));
		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).httpClient(redirecting).build(FLOOR_17)))
				.contains("followRedirects"));
		Assertions.assertTrue(message(Assertions.assertThrows(IllegalArgumentException.class,
				() -> RemoteJsonWebKeySource.withUri(refusedUri).build(FLOOR_17))).contains("https"));
	}

	// G8-4: build() does no I/O: an injected client sees no request until the first call that needs a key.
	@Test
	void buildSendsNothing() {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(URI_OK).httpClient(client).build();
		RemoteJsonWebKeySource another = RemoteJsonWebKeySource.withUri(URI_OK).httpClient(client).build();
		Assertions.assertNotSame(source, another);
		Assertions.assertEquals(0, client.getSendCount());
		source.warmUp();
		Assertions.assertEquals(1, client.getSendCount());
	}

	// Plan "Public types": the defaults, and null restoring each default; toString shows the URI cut to scheme, host,
	// port and path, and the settings; sources compare by reference.
	@Test
	void defaultsAreTheRowDefaultsAndNullRestoresThem() {
		URI withQuery = URI.create("https://jwks.example.com:8443/tenant/keys?appid=secret-looking");
		String expected = "RemoteJsonWebKeySource{uri=https://jwks.example.com:8443/tenant/keys, requestTimeout=PT10S, "
				+ "minimumTimeToLive=PT1M, defaultTimeToLive=PT10M, maximumTimeToLive=PT6H, "
				+ "unknownKeyRefreshCooldown=PT30S, maximumStaleness=PT12H, maximumResponseBytes=262144, maximumKeys=100, "
				+ "clock=SystemClock[Z]}";
		RemoteJsonWebKeySource defaults = RemoteJsonWebKeySource.withUri(withQuery).build();
		Assertions.assertEquals(expected, defaults.toString());
		Assertions.assertSame(withQuery, defaults.getUri());

		RemoteJsonWebKeySource restored = RemoteJsonWebKeySource.withUri(withQuery)
				.httpClient(new RedirectPolicyClient(HttpClient.Redirect.NEVER)).httpClient(null)
				.outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance()).outboundUriPolicy(null)
				.allowInsecureLoopback(true).allowInsecureLoopback(null)
				.clock(TestClock.fromInstant(JwksCacheTests.START)).clock(null)
				.requestTimeout(Duration.ofSeconds(1)).requestTimeout(null)
				.minimumTimeToLive(Duration.ofMinutes(2)).minimumTimeToLive(null)
				.defaultTimeToLive(Duration.ofMinutes(20)).defaultTimeToLive(null)
				.maximumTimeToLive(Duration.ofHours(7)).maximumTimeToLive(null)
				.unknownKeyRefreshCooldown(Duration.ofMinutes(1)).unknownKeyRefreshCooldown(null)
				.maximumStaleness(Duration.ZERO).maximumStaleness(null)
				.maximumResponseBytes(16 * 1024).maximumResponseBytes(null)
				.maximumKeys(1).maximumKeys(null)
				.observer(RecordingObserver.fromInterface(JoseObserver.class).getObserver()).observer(null)
				.acknowledgeUnpatchedRuntime(true).acknowledgeUnpatchedRuntime(null)
				.build();
		Assertions.assertEquals(expected, restored.toString());
		Assertions.assertEquals("HttpExchange{httpClient=default, outboundUriPolicy=OutboundUriPolicy{name=default}, "
				+ "insecureLoopbackAllowed=false}", restored.httpExchangeForTests().toString());
		Assertions.assertNotEquals(defaults, restored);
		Assertions.assertEquals(defaults, defaults);
		Assertions.assertThrows(IllegalArgumentException.class, () -> RemoteJsonWebKeySource
				.withUri(URI.create("http://127.0.0.1/keys")).allowInsecureLoopback(true).allowInsecureLoopback(null)
				.build());
	}

	// R1: a null URI fails at once; null runtime versions are refused by the test seam too.
	@Test
	@SuppressWarnings("NullAway")
	void nullArgumentsAreRefused() {
		Assertions.assertThrows(NullPointerException.class, () -> RemoteJsonWebKeySource.withUri(null));
		Assertions.assertThrows(NullPointerException.class, () -> builder().build(null));
	}

	private static RemoteJsonWebKeySource.Builder builder() {
		return RemoteJsonWebKeySource.withUri(URI_OK);
	}

	private static String message(Throwable throwable) {
		return String.valueOf(throwable.getMessage());
	}

	private static List<List<@Nullable Object>> arguments(RecordingObserver<JoseObserver> observer, String hook) {
		return observer.getCalls(hook).stream().map(RecordingObserver.Call::getArguments).toList();
	}

	private static void addDurationRow(List<DynamicTest> tests, Limit row,
			BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Duration, RemoteJsonWebKeySource.Builder> setter) {
		Duration floor = row.getFloorDuration();
		Duration cap = row.getCapDuration();
		tests.add(DynamicTest.dynamicTest(row.getName() + ": floor and cap accepted, null restores the default", () -> {
			Assertions.assertDoesNotThrow(() -> setter.apply(builder(), floor).build());
			Assertions.assertDoesNotThrow(() -> setter.apply(builder(), cap).build());
			Assertions.assertDoesNotThrow(() -> setter.apply(setter.apply(builder(), cap.plusNanos(1)), null).build());
		}));
		tests.add(DynamicTest.dynamicTest(row.getName() + ": one nanosecond outside is refused", () -> {
			Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(), cap.plusNanos(1))
					.build());
			if (!floor.isZero())
				Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(),
						floor.minusNanos(1)).build());
			Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(),
					Duration.ofNanos(-1)).build());
		}));
	}

	private static void addAmountRow(List<DynamicTest> tests, Limit row,
			BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Integer, RemoteJsonWebKeySource.Builder> setter) {
		int floor = Math.toIntExact(row.getFloor());
		int cap = Math.toIntExact(row.getCap());
		tests.add(DynamicTest.dynamicTest(row.getName() + ": floor and cap accepted, null restores the default", () -> {
			Assertions.assertDoesNotThrow(() -> setter.apply(builder(), floor).build());
			Assertions.assertDoesNotThrow(() -> setter.apply(builder(), cap).build());
			Assertions.assertDoesNotThrow(() -> setter.apply(setter.apply(builder(), cap + 1), null).build());
		}));
		tests.add(DynamicTest.dynamicTest(row.getName() + ": one outside is refused", () -> {
			Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(), cap + 1).build());
			Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(), floor - 1).build());
			Assertions.assertThrows(IllegalArgumentException.class, () -> setter.apply(builder(), Integer.MIN_VALUE)
					.build());
		}));
	}

	private static Duration max(Duration first, Duration second) {
		return first.compareTo(second) >= 0 ? first : second;
	}

	private static Duration min(Duration first, Duration second) {
		return first.compareTo(second) <= 0 ? first : second;
	}

	/**
	 * One URI check case: the URI text, the policy, whether insecure loopback is allowed, and the words of the failed
	 * check's message, or {@code null} when the URI must pass.
	 */
	private static final class UriCase {
		private final String uri;
		private final OutboundUriPolicy policy;
		private final Boolean insecureLoopback;
		private final @Nullable String failedCheck;

		private UriCase(String uri, OutboundUriPolicy policy, Boolean insecureLoopback, @Nullable String failedCheck) {
			this.uri = uri;
			this.policy = policy;
			this.insecureLoopback = insecureLoopback;
			this.failedCheck = failedCheck;
		}
	}

	/**
	 * A client that only reports a redirect policy; build() reads nothing else, and it is never sent through.
	 */
	private static final class RedirectPolicyClient extends HttpClient {
		private final HttpClient.Redirect redirect;
		private final MemoryHttpClient delegate = MemoryHttpClient.answering(Answer.fromStatus(500));

		private RedirectPolicyClient(HttpClient.Redirect redirect) {
			this.redirect = redirect;
		}

		@Override
		public HttpClient.Redirect followRedirects() {
			return this.redirect;
		}

		@Override
		public java.util.Optional<java.net.CookieHandler> cookieHandler() {
			return this.delegate.cookieHandler();
		}

		@Override
		public java.util.Optional<Duration> connectTimeout() {
			return this.delegate.connectTimeout();
		}

		@Override
		public java.util.Optional<java.net.ProxySelector> proxy() {
			return this.delegate.proxy();
		}

		@Override
		public javax.net.ssl.SSLContext sslContext() {
			return this.delegate.sslContext();
		}

		@Override
		public javax.net.ssl.SSLParameters sslParameters() {
			return this.delegate.sslParameters();
		}

		@Override
		public java.util.Optional<java.net.Authenticator> authenticator() {
			return this.delegate.authenticator();
		}

		@Override
		public HttpClient.Version version() {
			return this.delegate.version();
		}

		@Override
		public java.util.Optional<java.util.concurrent.Executor> executor() {
			return this.delegate.executor();
		}

		@Override
		public <T> java.net.http.HttpResponse<T> send(java.net.http.HttpRequest request,
				java.net.http.HttpResponse.BodyHandler<T> responseBodyHandler) throws java.io.IOException {
			return this.delegate.send(request, responseBodyHandler);
		}

		@Override
		public <T> java.util.concurrent.CompletableFuture<java.net.http.HttpResponse<T>> sendAsync(
				java.net.http.HttpRequest request, java.net.http.HttpResponse.BodyHandler<T> responseBodyHandler) {
			return this.delegate.sendAsync(request, responseBodyHandler);
		}

		@Override
		public <T> java.util.concurrent.CompletableFuture<java.net.http.HttpResponse<T>> sendAsync(
				java.net.http.HttpRequest request, java.net.http.HttpResponse.BodyHandler<T> responseBodyHandler,
				java.net.http.HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
			return this.delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler);
		}
	}
}
