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

import org.jspecify.annotations.NonNull;

import com.revetsec.ErrorCategory;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.KeyQuery;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.jose.RemoteJsonWebKeySourceConcurrencyTests.InjectedError;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.RewindableClock;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * The key set cache's rules at the {@code select(KeyQuery, Deadline)} seam (M2 plan, "RemoteJsonWebKeySource
 * algorithm", M2-8, G8-8; INV-J9, INV-G11), driven by an in-memory {@link HttpClient} ({@link MemoryHttpClient}) and a
 * {@link TestClock} or {@link RewindableClock}, so each rule is shown deterministically and without a network: the
 * backoff formula, its schedule and its decay, {@code Retry-After}, the unknown-key cooldown (variant A-prime), the
 * two-attempt ceiling, staleness, a clock set back, empty snapshots, the leader that never reaches the exchange, and
 * how every response and exchange failure maps to a category and transience.
 * <p>
 * The nested helpers are shared with the other {@code RemoteJsonWebKeySource*Tests}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwksCacheTests {
	static final Instant START = Instant.parse("2026-09-27T00:00:00Z");
	static final URI JWKS_URI = URI.create("https://jwks.example.com/tenant/keys?appid=1");
	static final Duration COOLDOWN = Duration.ofSeconds(30);
	static final Duration WAIT = Duration.ofSeconds(30);
	static final String JWK_SET_MEDIA_TYPE = "application/jwk-set+json";

	// M2-8: the cap is max(cooldown, min(10 x cooldown, 10 min)), with no row of its own. A cooldown above 10 min, which
	// only settings a later milestone checks itself could hold, is its own cap.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theBackoffCapIsTenCooldownsWithinTenMinutes() {
		return Stream.of(
				List.of(Duration.ofSeconds(1), Duration.ofSeconds(10)),
				List.of(Duration.ofSeconds(30), Duration.ofSeconds(300)),
				List.of(Duration.ofSeconds(59), Duration.ofSeconds(590)),
				List.of(Duration.ofSeconds(60), Duration.ofMinutes(10)),
				List.of(Duration.ofSeconds(61), Duration.ofMinutes(10)),
				List.of(Duration.ofMinutes(10), Duration.ofMinutes(10)),
				List.of(Duration.ofMinutes(20), Duration.ofMinutes(20))).map(row -> DynamicTest.dynamicTest(
				"cooldown " + row.get(0), () -> Assertions.assertEquals(row.get(1), JwksCache.backoffCap(row.get(0)))));
	}

	// M2-8: min(cooldown x 2^(n-1), cap): 30, 60, 120, 240, then 300 s at the default cooldown, and 1, 2, 4, 8, then
	// 10 s at the 1 s floor; the doubling stops at the cap, so a huge count cannot overflow.
	@Test
	void backoffStepsDoubleFromTheCooldownUpToTheCap() {
		Duration cap = JwksCache.backoffCap(COOLDOWN);
		List<Duration> steps = new ArrayList<>();
		for (int failures = 1; failures <= 7; ++failures)
			steps.add(JwksCache.backoffStep(COOLDOWN, cap, failures));
		Assertions.assertEquals(List.of(30L, 60L, 120L, 240L, 300L, 300L, 300L),
				steps.stream().map(Duration::toSeconds).toList());
		Assertions.assertEquals(cap, JwksCache.backoffStep(COOLDOWN, cap, Integer.MAX_VALUE));

		Duration second = Duration.ofSeconds(1);
		Duration secondCap = JwksCache.backoffCap(second);
		Assertions.assertEquals(List.of(1L, 2L, 4L, 8L, 10L, 10L), Stream.of(1, 2, 3, 4, 5, 6)
				.map(failures -> JwksCache.backoffStep(second, secondCap, failures).toSeconds()).toList());
	}

	// M2-8, decay not reset: one step less per full cap interval without a failure, never below zero.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theFailureCountFallsByOnePerFullCapInterval() {
		Duration cap = Duration.ofMinutes(5);
		return Stream.of(
				List.of(5, 0, 5), List.of(5, 299, 5), List.of(5, 300, 4), List.of(5, 599, 4), List.of(5, 600, 3),
				List.of(5, 1499, 1), List.of(5, 1500, 0), List.of(5, 86_400, 0), List.of(0, 1_000, 0),
				List.of(1, 300, 0)).map(row -> DynamicTest.dynamicTest(row.get(0) + " failures, " + row.get(1) + " s",
				() -> Assertions.assertEquals(row.get(2).intValue(), JwksCache.decayedFailureCount(row.get(0),
						Duration.ofSeconds(row.get(1)), cap))));
	}

	// M2-8: a snapshot is fresh iff fetchedAt <= now < expiresAt and usable iff fetchedAt <= now < usableUntil, so an
	// instant before fetchedAt (a clock set back) is neither.
	@Test
	void aSnapshotIsFreshAndUsableOnlyInsideItsHalfOpenWindows() {
		Instant expiresAt = START.plusSeconds(60);
		JwksCache.Snapshot snapshot = new JwksCache.Snapshot(List.of(), START, expiresAt, expiresAt.plusSeconds(60));

		Assertions.assertTrue(snapshot.isFresh(START));
		Assertions.assertTrue(snapshot.isFresh(expiresAt.minusNanos(1)));
		Assertions.assertFalse(snapshot.isFresh(expiresAt));
		Assertions.assertFalse(snapshot.isFresh(START.minusNanos(1)), "a clock set back never finds it fresh");
		Assertions.assertTrue(snapshot.isUsable(expiresAt));
		Assertions.assertTrue(snapshot.isUsable(expiresAt.plusSeconds(60).minusNanos(1)));
		Assertions.assertFalse(snapshot.isUsable(expiresAt.plusSeconds(60)));
		Assertions.assertFalse(snapshot.isUsable(START.minusNanos(1)), "a clock set back never finds it usable");
	}

	// Instants saturate instead of failing, so a clock near Instant.MAX cannot make a fetch throw.
	@Test
	void instantArithmeticSaturates() {
		Assertions.assertEquals(Instant.MAX, JwksCache.plus(Instant.MAX.minusSeconds(1), Duration.ofHours(1)));
		Assertions.assertEquals(START.plusSeconds(1), JwksCache.plus(START, Duration.ofSeconds(1)));
		Assertions.assertEquals(Instant.MIN, JwksCache.plus(Instant.MIN.plusSeconds(1), Duration.ofHours(-1)));
	}

	// G6-4, M2-3: hooks and toString see the URI cut to scheme, host, port and path.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theReportedUriIsCutToSchemeHostPortAndPath() {
		return Stream.of(
				List.of("https://jwks.example.com/tenant/keys?appid=1", "https://jwks.example.com/tenant/keys"),
				List.of("https://user:secret@jwks.example.com:8443/k?q#f", "https://jwks.example.com:8443/k"),
				List.of("https://[::1]:8443/keys", "https://[::1]:8443/keys"),
				List.of("https://jwks.example.com", "https://jwks.example.com"),
				List.of("urn:example:keys", ""),
				List.of("keys?x#y", "keys")).map(row -> DynamicTest.dynamicTest(row.get(0),
				() -> Assertions.assertEquals(URI.create(row.get(1)), JwksCache.cut(URI.create(row.get(0))))));
	}

	// M2-8 exit criterion 13: the backoff schedule of 30, 60, 120, 240 and 300 s, with zero requests inside each
	// backoff, warmUp() included, and every held-back call reported to didSuppressJsonWebKeySetFetch.
	@Test
	void failedFetchesBackOffOnTheScheduleAndSendNothingInsideIt() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(503));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		List<Long> attempts = new ArrayList<>();
		for (long second = 0; second <= 1_100; ++second) {
			clock.set(START.plusSeconds(second));
			int before = client.getSendCount();
			JsonWebKeySetUnavailableException exception = second % 2 == 0
					? assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"))
					: assertUnavailable(ErrorCategory.REMOTE_ERROR, true, source::warmUp);
			Assertions.assertNull(exception.getCause());
			if (client.getSendCount() > before)
				attempts.add(second);
		}

		Assertions.assertEquals(List.of(0L, 30L, 90L, 210L, 450L, 750L, 1_050L), attempts);
		Assertions.assertEquals(attempts.size(), observer.getCalls("willFetchJsonWebKeySet").size());
		Assertions.assertEquals(attempts.size(), observer.getCalls("didFailToFetchJsonWebKeySet").size());
		Assertions.assertEquals(1_101 - attempts.size(), observer.getCalls("didSuppressJsonWebKeySetFetch").size());
		// The first held-back call after the first failure reports the whole step, minus the second that passed.
		RecordingObserver.Call firstSuppression = observer.getCalls("didSuppressJsonWebKeySetFetch").get(0);
		Assertions.assertEquals(JwksCache.cut(JWKS_URI), firstSuppression.getArgument(0));
		Assertions.assertEquals(Duration.ofSeconds(29), firstSuppression.getArgument(1));
	}

	// M2-8 and G8-8, decay not reset: a success between failures leaves the step where it was, so a server that
	// answers a valid key set (no-store) after each failure meets the same schedule as one that always fails; a stale
	// key keeps answering meanwhile.
	@Test
	void aSuccessBetweenFailuresDoesNotResetTheBackoff() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(503));
		RemoteJsonWebKeySource source = source(client, clock).build();

		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));   // n = 1, 30 s
		client.answer(Answer.fromKeySet("no-store", "a"));
		clock.set(START.plusSeconds(30));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());   // fresh for 60 s
		client.answer(Answer.fromStatus(503));
		clock.set(START.plusSeconds(90));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "served stale");   // n = 2
		Assertions.assertEquals(3, client.getSendCount());

		clock.set(START.plusSeconds(149));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(3, client.getSendCount(), "the second step is 60 s, not a reset 30 s");
		clock.set(START.plusSeconds(150));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(4, client.getSendCount());   // n = 3, 120 s
		clock.set(START.plusSeconds(269));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(4, client.getSendCount());
		clock.set(START.plusSeconds(270));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(5, client.getSendCount());
	}

	// M2-8: the failure count falls by one per full cap interval (300 s at defaults) without a failure, so after a
	// quiet spell the next failure starts from a lower step, and after five quiet intervals from the first.
	@Test
	void theFailureCountDecaysWhileNoFetchFails() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(500));
		RemoteJsonWebKeySource source = source(client, clock).build();

		// Three failures: n = 3 at t = 90, backoff 120 s.
		for (long second : List.of(0L, 30L, 90L)) {
			clock.set(START.plusSeconds(second));
			assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		}
		Assertions.assertEquals(3, client.getSendCount());

		// One full cap interval later: n = 3 - 1 + 1 = 3, so the step stays 120 s.
		clock.set(START.plusSeconds(390));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(4, client.getSendCount());
		clock.set(START.plusSeconds(509));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(4, client.getSendCount());

		// Two full intervals later: n = 3 - 2 + 1 = 2, a 60 s step.
		clock.set(START.plusSeconds(990));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(5, client.getSendCount());
		clock.set(START.plusSeconds(1_049));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(5, client.getSendCount());
		clock.set(START.plusSeconds(1_050));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(6, client.getSendCount());   // n = 3, 120 s

		// Five quiet intervals return n to zero: the next failure's step is the cooldown again.
		clock.set(START.plusSeconds(1_050 + 1_500));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(7, client.getSendCount());
		clock.set(START.plusSeconds(1_050 + 1_529));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(7, client.getSendCount());
		clock.set(START.plusSeconds(1_050 + 1_530));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(8, client.getSendCount());
	}

	// M2-8 decay with a clock set back: a previous failure recorded in the future of now earns no decay, so the count is
	// kept and the next failure takes the next step. The count never grows because the clock went back, even by more than
	// a cap interval.
	@Test
	void aClockSetBackBeforeThePreviousFailureKeepsTheFailureCount() {
		RewindableClock clock = RewindableClock.fromInstant(START.plusSeconds(1_000));
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(503));
		RemoteJsonWebKeySource source = source(client, clock).build();

		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));   // n = 1 at 1,000 s: 30 s
		clock.advance(COOLDOWN);
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));   // n = 2 at 1,030 s: 60 s
		Assertions.assertEquals(2, client.getSendCount());

		// 330 s before the previous failure, no window applies, so the next call fetches; its failure makes n = 3.
		clock.rewind(Duration.ofSeconds(330));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(3, client.getSendCount());
		clock.advance(Duration.ofSeconds(119));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(3, client.getSendCount(), "a 120 s step");
		clock.advance(Duration.ofSeconds(1));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(4, client.getSendCount(), "not the 240 s of a count grown by the clock set back");
	}

	// M2-8: a Retry-After on a 429 or a 503 may raise the current step, up to the cap; on any other status, and when it
	// asks for less, the step stands.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> retryAfterRaisesAStepUpToTheCapOnlyOn429And503() {
		return Stream.of(
				List.of("503", "100", "100"), List.of("429", "100", "100"), List.of("503", "100000", "300"),
				List.of("429", "10", "30"), List.of("500", "100", "30"), List.of("502", "100", "30"),
				List.of("503", "soon", "30")).map(row -> DynamicTest.dynamicTest(row.get(0) + " Retry-After: " + row.get(1),
				() -> {
					TestClock clock = TestClock.fromInstant(START);
					MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(Integer.parseInt(row.get(0)),
							Map.of("Retry-After", List.of(row.get(1)))));
					RemoteJsonWebKeySource source = source(client, clock).build();
					long step = Long.parseLong(row.get(2));

					assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
					clock.set(START.plusSeconds(step - 1));
					assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
					Assertions.assertEquals(1, client.getSendCount());
					clock.set(START.plusSeconds(step));
					assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
					Assertions.assertEquals(2, client.getSendCount());
				}));
	}

	// OpenID Connect Core section 10.1.1 and M2-8 variant A-prime: an unknown kid right after the first fetch refetches
	// at once; a second unknown kid within the cooldown sends nothing and gets no key; after the cooldown it fetches
	// again.
	@Test
	void unknownKeysRefetchAtMostOncePerCooldown() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		client.answer(Answer.fromKeySet(null, "a", "b"));
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind(), "the rotated-in key verifies");
		Assertions.assertEquals(2, client.getSendCount(), "the first fetch neither consumes nor obeys the cooldown");

		clock.advance(Duration.ofSeconds(30).minusNanos(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(2, client.getSendCount());
		Assertions.assertEquals(List.of(Duration.ofNanos(1)), observer.getCalls("didSuppressJsonWebKeySetFetch").stream()
				.map(call -> call.getArgument(1)).toList());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "known keys stay on the fast path");

		clock.advance(Duration.ofNanos(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(3, client.getSendCount(), "after the cooldown, a fetch");
	}

	// M2-8 variant A-prime: a refresh after expiry neither consumes nor obeys the unknown-key cooldown, and a missing key
	// after a completed fetch is final for that call.
	@Test
	void anExpiryRefreshLeavesTheCooldownAlone() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		clock.advance(Duration.ofSeconds(10));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(), "one refetch, still unknown");
		Assertions.assertEquals(2, client.getSendCount());

		clock.set(START.plusSeconds(70));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(), "expired: a refresh");
		Assertions.assertEquals(3, client.getSendCount());
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind());
		Assertions.assertEquals(4, client.getSendCount(), "the expiry refresh took no cooldown mark");
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind());
		Assertions.assertEquals(4, client.getSendCount());
	}

	// M2-8 variant A-prime, the other half: a refresh after expiry does not obey the unknown-key cooldown either. At the
	// defaults, an unknown-key refetch at 40 s is cut short by an Error after its request was sent, so it keeps its
	// cooldown mark until 70 s, while the key set from 0 s expires at 60 s, inside that cooldown. An unknown key is held
	// back at 50 s, and the expiry at 60 s refreshes at once, neither answering no key nor serving the expired set.
	@Test
	void anExpiryInsideTheUnknownKeyCooldownStillRefreshes() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		clock.set(START.plusSeconds(40));
		client.answer(cutShort());
		assertCutShort(() -> select(source, "b"));
		Assertions.assertEquals(2, client.getSendCount());
		client.answer(Answer.fromKeySet("max-age=60", "a"));

		clock.set(START.plusSeconds(50));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(), "the kept mark");
		Assertions.assertEquals(2, client.getSendCount());
		clock.set(START.plusSeconds(60));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "expired inside the cooldown");
		Assertions.assertEquals(3, client.getSendCount());
	}

	// Plan "Key selection": a kid that fits no key, a duplicate kid and a kid-less token with two candidates are final
	// answers that never refresh; a kid-less token with one candidate verifies (OpenID Connect Core section 10.1).
	@Test
	void onlyAnUnknownKeyEverRefreshes() {
		TestClock clock = TestClock.fromInstant(START);
		String keySet = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("ec").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("twice").toJson(),
				TestJsonWebKeys.withFixture(Fixture.SP_SIGNING_RSA_2048).kid("twice").toJson()));
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromJson(200, null, keySet));
		RemoteJsonWebKeySource source = source(client, clock).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "rsa").getKind());
		Assertions.assertEquals(KeySelection.Kind.ALGORITHM_MISMATCH, select(source, "ec").getKind());
		Assertions.assertEquals(KeySelection.Kind.AMBIGUOUS, select(source, "twice").getKind());
		Assertions.assertEquals(KeySelection.Kind.AMBIGUOUS, select(source, null).getKind());
		Assertions.assertEquals(1, client.getSendCount());

		MemoryHttpClient single = MemoryHttpClient.answering(Answer.fromKeySet(null, "only"));
		RemoteJsonWebKeySource singleSource = source(single, clock).build();
		KeySelection kidless = select(singleSource, null);
		Assertions.assertEquals(KeySelection.Kind.FOUND, kidless.getKind());
		Assertions.assertEquals(Optional.of("only"), kidless.findKey().map(key -> requireNonNull(key.keyId())));
	}

	// M2-8: a 200 whose keys are all skipped is a valid, empty snapshot: warmUp() does nothing while it is fresh, each
	// skip is reported with its index and never its kid, the fetch with its counts, time to live and elapsed time
	// (M2-3), and it heals through the unknown-key refetch.
	@Test
	void anAllSkippedKeySetIsAValidEmptySnapshot() {
		TestClock clock = TestClock.fromInstant(START);
		String allSkipped = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.octWithK("AAAA").kid("secret").toJson(),
				TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).kid("small").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("enc").use("enc").toJson()));
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromJson(200, null, allSkipped));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		long before = System.nanoTime();
		source.warmUp();
		long after = System.nanoTime();
		source.warmUp();
		Assertions.assertEquals(1, client.getSendCount(), "a fresh empty snapshot satisfies warmUp()");
		Assertions.assertEquals(List.of(List.of(JwksCache.cut(JWKS_URI), 0, JsonWebKeySkipReason.SYMMETRIC_KEY),
						List.of(JwksCache.cut(JWKS_URI), 1, JsonWebKeySkipReason.RSA_KEY_SIZE),
						List.of(JwksCache.cut(JWKS_URI), 2, JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY)),
				observer.getCalls("didSkipJsonWebKey").stream().map(RecordingObserver.Call::getArguments).toList());
		RecordingObserver.Call fetched = observer.getCalls("didFetchJsonWebKeySet").get(0);
		Assertions.assertEquals(List.of(0, 3, Duration.ofMinutes(10)), fetched.getArguments().subList(1, 4));
		JwtFixtures.assertElapsedWithin(fetched.getArgument(4), before, after);

		client.answer(Answer.fromKeySet(null, "a"));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "healed by the refetch");
		Assertions.assertEquals(2, client.getSendCount());
	}

	// Exit criterion 7's remote half and M2-3: a key set with one key for every skip reason reports each skip to
	// didSkipJsonWebKey with its index in keys and its reason, never its kid, on every fetch and not only the first,
	// then the fetch with its usable and skipped counts; the one usable key verifies.
	@Test
	void everySkipReasonReachesTheObserverOnEveryFetch() {
		List<String> keys = List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("no-kty").withoutMember("kty").toJson(),
				"{\"kty\":\"RSA2\",\"kid\":\"unknown-type\"}",
				TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").kid("oct").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("private").includePrivateMembers(true)
						.toJson(),
				TestJsonWebKeys.withFixture(Fixture.SP_ENCRYPTION_RSA_2048).kid("enc").use("enc").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("oaep").alg("RSA-OAEP").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("es384").alg("ES384").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("k1").member("crv", "\"secp256k1\"")
						.toJson(),
				TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).kid("small").toJson(),
				TestJsonWebKeys.rsaWithEvenExponent().kid("even").toJson(),
				TestJsonWebKeys.ecOffCurve().kid("off-curve").toJson(),
				TestJsonWebKeys.ed25519SmallOrder().kid("small-order").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("x5c").x5c(List.of(Fixture.SP_SIGNING_RSA_2048
						.getCertificate().orElseThrow())).toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson());
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromJson(200, "no-store",
				TestJsonWebKeys.keySet(keys)));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();
		List<List<@Nullable Object>> onePass = new ArrayList<>();
		for (JsonWebKeySkipReason reason : JsonWebKeySkipReason.values())
			onePass.add(List.of(JwksCache.cut(JWKS_URI), onePass.size(), reason));

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		clock.advance(Duration.ofMinutes(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount());

		List<List<@Nullable Object>> expected = new ArrayList<>(onePass);
		expected.addAll(onePass);
		Assertions.assertEquals(expected, observer.getCalls("didSkipJsonWebKey").stream()
				.map(RecordingObserver.Call::getArguments).toList());
		for (RecordingObserver.Call fetched : observer.getCalls("didFetchJsonWebKeySet"))
			Assertions.assertEquals(List.of(1, 13), fetched.getArguments().subList(1, 3));
		List<String> oneFetch = new ArrayList<>(List.of("willFetchJsonWebKeySet"));
		for (int skip = 0; skip < 13; ++skip)
			oneFetch.add("didSkipJsonWebKey");
		oneFetch.add("didFetchJsonWebKeySet");
		List<String> hooks = new ArrayList<>(oneFetch);
		hooks.addAll(oneFetch);
		Assertions.assertEquals(hooks, observer.getCalls().stream().map(RecordingObserver.Call::getMethodName).toList());
	}

	// Exit criterion 13 (stale keys): an expired key set keeps answering for the keys it holds while a
	// refresh fails, until expiry plus the maximum staleness, and not at that boundary; a key it lacks gets the
	// failure, and warmUp() throws even while stale keys answer.
	@Test
	void staleKeysAnswerForKeysTheyHoldUntilTheStalenessBoundary() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver())
				.maximumStaleness(Duration.ofHours(1)).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Instant expiresAt = START.plus(Duration.ofMinutes(10));

		client.answer(Answer.fromStatus(500));
		clock.set(expiresAt);
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "served stale by the leader");
		RecordingObserver.Call failed = observer.getCalls("didFailToFetchJsonWebKeySet").get(0);
		Assertions.assertEquals(true, failed.getArgument(2));
		Assertions.assertEquals(ErrorCategory.REMOTE_ERROR,
				((JsonWebKeySetUnavailableException) requireNonNull(failed.getArgument(1))).getCategory());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "served stale in the backoff");
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "b"));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, source::warmUp);

		clock.set(expiresAt.plus(Duration.ofHours(1)).minusNanos(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		clock.set(expiresAt.plus(Duration.ofHours(1)));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));

		// A maximum staleness of zero never serves an expired key set.
		MemoryHttpClient strictClient = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		TestClock strictClock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource strict = source(strictClient, strictClock).maximumStaleness(Duration.ZERO).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(strict, "a").getKind());
		strictClient.answer(Answer.fromStatus(500));
		strictClock.set(expiresAt);
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(strict, "a"));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(strict, "a"));
		Assertions.assertEquals(2, strictClient.getSendCount());
	}

	// M2-8 and the RemoteJsonWebKeySource contract: an expired key set answers stale only with a key it finds. A kid it
	// holds twice, a kid whose key does not fit the algorithm, and a token without kid that three of its keys fit get
	// the failed refresh's category and transience, the leader included, like a key it lacks; nothing is sent inside
	// the backoff, and a key it finds is still served stale.
	@Test
	void staleKeysAnswerOnlyWithAKeyTheyFind() {
		String keySet = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("ec").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("twice").toJson(),
				TestJsonWebKeys.withFixture(Fixture.SP_SIGNING_RSA_2048).kid("twice").toJson()));
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromJson(200, null, keySet));
		RemoteJsonWebKeySource source = source(client, clock).maximumStaleness(Duration.ofHours(1)).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "rsa").getKind());

		client.answer(Answer.fromStatus(500));
		clock.set(START.plus(Duration.ofMinutes(10)));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "twice"));
		Assertions.assertEquals(2, client.getSendCount());
		for (@Nullable String keyId : Arrays.asList("twice", "ec", null))
			assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, keyId));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "rsa").getKind(), "served stale");
		Assertions.assertEquals(2, client.getSendCount());
	}

	// M2-8: a refresh that returns no keys replaces the key set like any other, for the leader and every later call.
	// The call after it makes the one unknown-key refetch the expiry refresh left it, and a call inside that refetch's
	// cooldown gets no key and sends nothing: the expired key set is never served in its place.
	@Test
	void aRefreshWithNoKeysReplacesTheKeySet() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		client.answer(Answer.fromKeySet("max-age=60"));
		clock.set(START.plusSeconds(60));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "a").getKind(), "the refresh leader");
		clock.set(START.plusSeconds(61));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "a").getKind(), "a later call");
		Assertions.assertEquals(3, client.getSendCount());
		clock.set(START.plusSeconds(62));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "a").getKind(), "inside the cooldown");
		Assertions.assertEquals(3, client.getSendCount());
	}

	// M2-8 and exit criterion 13: a clock set back makes the snapshot expired and not usable, so the next call
	// refetches.
	@Test
	void aClockSetBackRefetches() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		clock.rewind(Duration.ofHours(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount(), "set back: expired, so refetched");
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount(), "the new key set is fresh at the new time");

		// A key set fetched in the future of now is not usable either, so a failed refresh serves no stale key.
		client.answer(Answer.fromStatus(503));
		clock.rewind(Duration.ofSeconds(1));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "a"));
		Assertions.assertEquals(3, client.getSendCount());
	}

	// M2-8: a clock set back never extends a cooldown or a backoff. A failed unknown-key refetch leaves both a cooldown
	// mark and a backoff; with the clock set back before them, a window whose start is in the future has passed, so the
	// next unknown key fetches at once from the still-fresh key set.
	@Test
	void aClockSetBackExtendsNoCooldownOrBackoff() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		client.answer(Answer.fromStatus(503));
		clock.advance(Duration.ofSeconds(60));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "x"));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "x"));
		Assertions.assertEquals(2, client.getSendCount(), "inside the backoff and the cooldown");

		client.answer(Answer.fromKeySet(null, "a", "x"));
		clock.rewind(Duration.ofSeconds(30));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "x").getKind());
		Assertions.assertEquals(3, client.getSendCount(), "both windows start in the future of now");
	}

	// M2-8: no more than two attempts start within one cooldown, whatever triggered them. At the defaults, a 30 s
	// cooldown within a 1 min minimum time to live (build() refuses a longer cooldown), a success keeps the key set
	// fresh, and a failure starts a backoff, for at least one cooldown, so only attempts cut short (here by an Error
	// after the request was sent) bring the ceiling into play. After a first use cut short at 0 s and a fetch at 1 s, an
	// unknown key on the fresh key set gets no key at 2 s, with no cooldown mark to hold it back. After expiry refreshes
	// cut short at 61 s and 62 s, a caller holding its key is served stale at 63 s, while one lacking it and warmUp() get
	// a transient TRANSPORT failure; the ceiling lifts when the attempt at 61 s leaves the window.
	@Test
	void noMoreThanTwoAttemptsStartWithinOneCooldown() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(cutShort());
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		assertCutShort(() -> select(source, "a"));
		client.answer(Answer.fromKeySet("max-age=60", "a"));
		clock.set(START.plusSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount());

		clock.set(START.plusSeconds(2));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(),
				"no cooldown mark, but the ceiling");
		Assertions.assertEquals(2, client.getSendCount());

		client.answer(cutShort());
		clock.set(START.plusSeconds(61));
		assertCutShort(() -> select(source, "a"));
		clock.set(START.plusSeconds(62));
		assertCutShort(() -> select(source, "a"));
		Assertions.assertEquals(4, client.getSendCount(), "the attempt at 0 s has left the window, so 62 s is the second");

		client.answer(Answer.fromKeySet("max-age=60", "a", "b"));
		clock.set(START.plusSeconds(63));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "stale under the ceiling");
		JsonWebKeySetUnavailableException lacking = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> select(source, "b"));
		Assertions.assertNull(lacking.getCause());
		assertUnavailable(ErrorCategory.TRANSPORT, true, source::warmUp);
		clock.set(START.plusSeconds(91).minusNanos(1));
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> select(source, "b"));
		Assertions.assertEquals(4, client.getSendCount());
		Assertions.assertEquals(List.of(Duration.ofSeconds(28), Duration.ofSeconds(28), Duration.ofSeconds(28),
						Duration.ofSeconds(28), Duration.ofNanos(1)),
				observer.getCalls("didSuppressJsonWebKeySetFetch").stream().map(call -> call.getArgument(1)).toList());

		clock.set(START.plusSeconds(91));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind());
		Assertions.assertEquals(5, client.getSendCount(), "the attempt at 61 s has left the window");
	}

	// M2-8, warmUp(): a fetch when there is no fresh key set; the backoff holds it back with the remembered failure
	// and no request; and it is a no-op on a fresh key set.
	@Test
	void warmUpFollowsTheBackoffAndIsANoOpWhileFresh() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromStatus(404));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		assertUnavailable(ErrorCategory.REMOTE_ERROR, false, source::warmUp);
		assertUnavailable(ErrorCategory.REMOTE_ERROR, false, source::warmUp);
		Assertions.assertEquals(1, client.getSendCount(), "the backoff holds warmUp() back");
		Assertions.assertEquals(1, observer.getCalls("didSuppressJsonWebKeySetFetch").size());

		client.answer(Answer.fromKeySet(null, "a"));
		clock.advance(COOLDOWN);
		source.warmUp();
		source.warmUp();
		clock.advance(Duration.ofMinutes(10).minusNanos(1));
		source.warmUp();
		Assertions.assertEquals(2, client.getSendCount(), "a fresh key set makes warmUp() a no-op");
		clock.advance(Duration.ofNanos(1));
		source.warmUp();
		Assertions.assertEquals(3, client.getSendCount());
	}

	// M2-8, warmUp() neither obeys nor consumes the unknown-key cooldown. A first warm-up takes no mark, so an unknown
	// key fetches at once. An unknown-key refetch at 45 s is cut short by an Error after its request was sent, so it
	// replaces nothing and its mark holds unknown keys back until 75 s (at 50 s the mark alone does, with one attempt in
	// the window), while the key set fetched at 1 s expires at 61 s: warmUp() fetches inside that running cooldown and
	// takes no mark of its own, so the next unknown key fetches at 75 s. The cooldown stays within the minimum time to
	// live, as build() requires, so only a refetch cut short can leave a cooldown running past an expiry.
	@Test
	void warmUpNeitherObeysNorConsumesTheUnknownKeyCooldown() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();

		source.warmUp();
		clock.set(START.plusSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind());
		Assertions.assertEquals(2, client.getSendCount(), "the first warm-up took no cooldown mark");

		client.answer(cutShort());
		clock.set(START.plusSeconds(45));
		assertCutShort(() -> select(source, "c"));
		Assertions.assertEquals(3, client.getSendCount());
		client.answer(Answer.fromKeySet("max-age=60", "a"));
		clock.set(START.plusSeconds(50));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(3, client.getSendCount(), "the refetch cut short at 45 s kept its mark");

		clock.set(START.plusSeconds(61));
		source.warmUp();
		Assertions.assertEquals(4, client.getSendCount(), "warmUp() fetches inside the running cooldown");
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(4, client.getSendCount(), "the mark from 45 s and now the ceiling hold unknown keys back");

		clock.set(START.plusSeconds(75));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(5, client.getSendCount(), "the warm-up at 61 s took no mark of its own");
	}

	// Exit criterion 13 and M2-8: a leader whose deadline is already spent, or whose thread is already interrupted, when
	// it would take the flight sends nothing, counts toward nothing and leaves the cooldown mark as it was.
	@Test
	void aLeaderThatCannotReachTheExchangeSendsNothingAndTakesNoMark() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();

		JsonWebKeySetUnavailableException spent = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> source.select(rs256("a"), Deadline.fromNow(Duration.ZERO)));
		Assertions.assertNull(spent.getCause());
		Assertions.assertEquals(0, client.getSendCount());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		Assertions.assertThrows(JsonWebKeySetUnavailableException.class,
				() -> source.select(rs256("x"), Deadline.fromNow(Duration.ZERO)));
		Thread.currentThread().interrupt();
		try {
			JsonWebKeySetUnavailableException interrupted = assertUnavailable(ErrorCategory.TRANSPORT, false,
					() -> select(source, "x"));
			Assertions.assertNull(interrupted.getCause());
			Assertions.assertTrue(Thread.currentThread().isInterrupted(), "the interrupt flag stays set");
		} finally {
			Assertions.assertTrue(Thread.interrupted());
		}
		Assertions.assertEquals(1, client.getSendCount());
		Assertions.assertEquals(0, observer.getCalls("didFailToFetchJsonWebKeySet").size());

		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "x").getKind());
		Assertions.assertEquals(2, client.getSendCount(), "neither refused leader took the cooldown mark");
	}

	// The plan's category table: each response and exchange failure maps to its category and transience, the leader
	// keeps the JDK's IOException only for an I/O failure, and a failure hook receives the very instance thrown.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> eachFailureMapsToItsCategoryAndTransience() {
		byte[] keySet = keySetJson("a").getBytes(StandardCharsets.UTF_8);
		return Stream.of(
				new FailureCase("404", Answer.fromStatus(404), ErrorCategory.REMOTE_ERROR, false),
				new FailureCase("401", Answer.fromStatus(401), ErrorCategory.REMOTE_ERROR, false),
				new FailureCase("429", Answer.fromStatus(429), ErrorCategory.REMOTE_ERROR, true),
				new FailureCase("500", Answer.fromStatus(500), ErrorCategory.REMOTE_ERROR, true),
				new FailureCase("599", Answer.fromStatus(599), ErrorCategory.REMOTE_ERROR, true),
				new FailureCase("600, which has no class", Answer.fromStatus(600), ErrorCategory.REMOTE_ERROR, false),
				new FailureCase("a 302 redirect", Answer.fromStatus(302, Map.of("Location", List.of("/elsewhere"))),
						ErrorCategory.REMOTE_ERROR, false),
				new FailureCase("a 304, since there are no conditional requests", Answer.fromStatus(304),
						ErrorCategory.REMOTE_ERROR, false),
				new FailureCase("an I/O failure", Answer.failingWithIo(), ErrorCategory.TRANSPORT, true),
				new FailureCase("text/plain", Answer.fromBytes(200, Map.of("Content-Type", List.of("text/plain")), keySet),
						ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("gzip", Answer.fromBytes(200, Map.of("Content-Type", List.of(JWK_SET_MEDIA_TYPE),
						"Content-Encoding", List.of("gzip")), keySet), ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("a 204 with no body", Answer.fromBytes(204, Map.of("Content-Type",
						List.of(JWK_SET_MEDIA_TYPE)), new byte[0]), ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("not JSON", Answer.fromJson(200, null, "keys"), ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("an array", Answer.fromJson(200, null, "[]"), ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("no keys member", Answer.fromJson(200, null, "{}"), ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("keys not an array", Answer.fromJson(200, null, "{\"keys\":{}}"),
						ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("a key that is not an object", Answer.fromJson(200, null, "{\"keys\":[1]}"),
						ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("a duplicate member", Answer.fromJson(200, null, "{\"keys\":[],\"keys\":[]}"),
						ErrorCategory.MALFORMED_INPUT, false),
				new FailureCase("101 keys", Answer.fromJson(200, null, keySetJson(keyIds(101))),
						ErrorCategory.MALFORMED_INPUT, false)).map(failureCase ->
				DynamicTest.dynamicTest(failureCase.name, () -> {
					MemoryHttpClient client = MemoryHttpClient.answering(failureCase.answer);
					RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
					RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START))
							.observer(observer.getObserver()).build();

					JsonWebKeySetUnavailableException exception = assertUnavailable(failureCase.category,
							failureCase.transientFailure, () -> select(source, "a"));
					if (failureCase.category == ErrorCategory.TRANSPORT)
						Assertions.assertInstanceOf(IOException.class, exception.getCause());
					else
						Assertions.assertNull(exception.getCause());
					Assertions.assertSame(exception, observer.getCalls("didFailToFetchJsonWebKeySet").get(0).getArgument(1));

					// A remembered failure keeps the category and transience, and never the cause.
					JsonWebKeySetUnavailableException remembered = assertUnavailable(failureCase.category,
							failureCase.transientFailure, () -> select(source, "a"));
					Assertions.assertNull(remembered.getCause());
					Assertions.assertNotSame(exception, remembered);
					Assertions.assertEquals(1, client.getSendCount());
				}));
	}

	// Exit criterion 15: a failed refresh leaves the previous snapshot in use; 101 keys is MALFORMED_INPUT and
	// not transient, however many the previous key set held.
	@Test
	void aMalformedRefreshKeepsThePreviousSnapshot() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		client.answer(Answer.fromJson(200, null, keySetJson(keyIds(101))));
		clock.advance(Duration.ofSeconds(1));
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(source, "k-1"));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount());

		// Exactly the limit is accepted.
		client.answer(Answer.fromJson(200, null, keySetJson(keyIds(100))));
		clock.advance(Duration.ofMinutes(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "k-100").getKind());
	}

	// Plan "RemoteJsonWebKeySource.Builder": the configured maximumKeys and maximumResponseBytes bound each fetch in both
	// directions. Lowered, a key set one element over (keys counts every element, a skipped key included) or one byte
	// over is MALFORMED_INPUT, not transient, while one at the limit is accepted. Raised to 1,000 keys and 4 MiB, a key
	// set of 1,000 keys (over 256 KiB) is accepted, which the defaults refuse.
	@Test
	void theConfiguredKeyAndBodyLimitsBoundEachFetch() {
		String twoKeys = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("b").toJson()));
		String threeElements = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("b").toJson(),
				TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").kid("oct").toJson()));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(limited(twoKeys, 2, null), "b").getKind());
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(limited(threeElements, 2, null), "a"));

		int bodyLimit = 16 * 1024;
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(limited(paddedTo(twoKeys, bodyLimit), null, bodyLimit),
				"a").getKind());
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(limited(paddedTo(twoKeys, bodyLimit + 1),
				null, bodyLimit), "a"));

		String thousandKeys = keySetJson(keyIds(1_000));
		Assertions.assertTrue(thousandKeys.length() > 256 * 1024, "over the default body limit");
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(limited(thousandKeys, 1_000, 4 * 1024 * 1024),
				"k-1000").getKind());
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(limited(thousandKeys, null, null),
				"k-1000"));
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(limited(thousandKeys, 1_000, null),
				"k-1000"));
		assertUnavailable(ErrorCategory.MALFORMED_INPUT, false, () -> select(limited(thousandKeys, null,
				4 * 1024 * 1024), "k-1000"));
	}

	// G5-5 and plan "Deadlines": the request timeout bounds the one exchange a call makes, even under an embedded
	// caller's longer deadline, and the timeout is a failure like any other. The failure hook's elapsed time (M2-3)
	// spans the exchange the timeout ended, within the time measured around the call.
	@Test
	void theRequestTimeoutBoundsTheExchangeUnderALongerEmbeddedDeadline() {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).requestTimeout(Duration.ofSeconds(1))
				.observer(observer.getObserver()).build();
		Deadline deadline = Deadline.fromNow(WAIT);

		long before = System.nanoTime();
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> source.select(rs256("a"), deadline));
		long after = System.nanoTime();
		Duration elapsed = JwtFixtures.assertElapsedWithin(observer.getCalls("didFailToFetchJsonWebKeySet").get(0)
				.getArgument(3), before, after);
		Assertions.assertTrue(elapsed.compareTo(Duration.ofMillis(500)) >= 0, elapsed::toString);
		Duration timeout = client.getRequests().get(0).timeout().orElseThrow();
		Assertions.assertTrue(timeout.compareTo(Duration.ofSeconds(1)) <= 0, timeout::toString);
		Assertions.assertTrue(deadline.remainingNanos() > Duration.ofSeconds(10).toNanos(), "ended by the request timeout");
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> source.select(rs256("a"), Deadline.fromNow(WAIT)));
		Assertions.assertEquals(1, client.getSendCount(), "the timeout started the backoff");
	}

	// G8-9: the fetch-time backstop. A source made through the package-private constructor with a URI the exchange
	// refuses (here, one with user information) fails with CONFIGURATION, not transient, and sends nothing; the same
	// client with a permitted URI sends one request.
	@Test
	void aUriTheExchangeRefusesIsAConfigurationFailureWithNoRequest() {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource permitted = source(client, TestClock.fromInstant(START)).build();
		RemoteJsonWebKeySource unchecked = new RemoteJsonWebKeySource(
				URI.create("https://user@jwks.example.com/keys"), permitted.httpExchangeForTests(),
				settings(TestClock.fromInstant(START), JoseObserver.disabledInstance()));

		JsonWebKeySetUnavailableException exception = assertUnavailable(ErrorCategory.CONFIGURATION, false,
				() -> select(unchecked, "a"));
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(0, client.getSendCount());
		Assertions.assertEquals("RemoteJsonWebKeySource{uri=https://jwks.example.com/keys, ", unchecked.toString()
				.substring(0, "RemoteJsonWebKeySource{uri=https://jwks.example.com/keys, ".length()));

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(permitted, "a").getKind());
		Assertions.assertEquals(1, client.getSendCount());
	}

	// Plan "RemoteJsonWebKeySource algorithm", leader step 1: one GET of the configured URI, query included, with the
	// JWKS Accept header and identity encoding.
	@Test
	void theLeaderSendsOneJwksProfileGetOfTheConfiguredUri() {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		HttpRequest request = client.getRequests().get(0);
		Assertions.assertEquals("GET", request.method());
		Assertions.assertEquals(JWKS_URI, request.uri());
		Assertions.assertEquals(List.of("application/jwk-set+json, application/json"),
				request.headers().allValues("Accept"));
		Assertions.assertEquals(List.of("identity"), request.headers().allValues("Accept-Encoding"));
		Duration timeout = request.timeout().orElseThrow();
		Assertions.assertTrue(timeout.compareTo(Duration.ofSeconds(10)) <= 0
				&& timeout.compareTo(Duration.ofSeconds(9)) > 0, timeout::toString);
	}

	// M2-8: a TIMEOUT is a failure whoever's deadline ended it, so an embedded caller's short deadline starts the
	// backoff like any other transport failure, and the call after it is held back with TRANSPORT, transient.
	@Test
	void aTimeoutUnderAnEmbeddedDeadlineIsAFailure() {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RemoteJsonWebKeySource source = source(client, clock).build();

		JsonWebKeySetUnavailableException timedOut = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> source.select(rs256("a"), Deadline.fromNow(Duration.ofMillis(100))));
		Assertions.assertNull(timedOut.getCause());
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> select(source, "a"));
		Assertions.assertEquals(1, client.getSendCount());
		clock.advance(COOLDOWN);
		client.answer(Answer.fromKeySet(null, "a"));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, client.getSendCount());
	}

	// The fast path: a fresh key set answers a known key with no lock-held fetch decision and no hook.
	@Test
	void aFreshKeyAnswersWithoutAnyHook() {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer.getObserver())
				.build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		int hooks = observer.getCalls().size();

		for (int call = 0; call < 10; ++call)
			Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(hooks, observer.getCalls().size());
		Assertions.assertEquals(List.of("willFetchJsonWebKeySet", "didFetchJsonWebKeySet"),
				observer.getCalls().stream().map(RecordingObserver.Call::getMethodName).toList());
	}

	// ----- Shared helpers -----

	static RemoteJsonWebKeySource.@NonNull Builder source(@NonNull HttpClient client, @NonNull Clock clock) {
		return RemoteJsonWebKeySource.withUri(JWKS_URI).httpClient(client).clock(clock);
	}

	static @NonNull JwksSettings settings(@NonNull Clock clock, @NonNull JoseObserver observer) {
		return settings(clock, Duration.ofSeconds(10), observer);
	}

	/**
	 * The default settings with another request timeout, which these checked settings allow below the builder's 1 s
	 * floor.
	 */
	static @NonNull JwksSettings settings(@NonNull Clock clock, @NonNull Duration requestTimeout, @NonNull JoseObserver observer) {
		return new JwksSettings(clock, requestTimeout, Duration.ofMinutes(1), Duration.ofMinutes(10), Duration.ofHours(6),
				COOLDOWN, Duration.ofHours(12), 256 * 1024, 100, observer, null);
	}

	/**
	 * An answer that throws an {@link InjectedError} once the request is sent, which cuts the fetch short: it counts as
	 * an attempt, keeps any cooldown mark and starts no backoff.
	 */
	static @NonNull Answer cutShort() {
		return Answer.throwingAfter(new CountDownLatch(0), () -> new InjectedError("cut short"));
	}

	/**
	 * The call fails with the {@link InjectedError} of {@link #cutShort()}.
	 */
	static void assertCutShort(@NonNull Executable executable) {
		Assertions.assertEquals("cut short", Assertions.assertThrows(InjectedError.class, executable).getMessage());
	}

	/**
	 * A source over a client that answers {@code json} with no {@code Content-Length}, built with the given key and
	 * body limits ({@code null} keeps a default).
	 */
	private static @NonNull RemoteJsonWebKeySource limited(@NonNull String json, @Nullable Integer maximumKeys,
			@Nullable Integer maximumResponseBytes) {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromJson(200, null, json));
		return source(client, TestClock.fromInstant(START)).maximumKeys(maximumKeys)
				.maximumResponseBytes(maximumResponseBytes).build();
	}

	/**
	 * {@code json}, an object, with insignificant whitespace before its closing brace to make it exactly {@code bytes}
	 * UTF-8 octets long.
	 */
	private static @NonNull String paddedTo(@NonNull String json, int bytes) {
		int length = json.getBytes(StandardCharsets.UTF_8).length;
		Assertions.assertTrue(json.endsWith("}") && length <= bytes, "cannot pad to " + bytes);
		String padded = json.substring(0, json.length() - 1) + " ".repeat(bytes - length) + "}";
		Assertions.assertEquals(bytes, padded.getBytes(StandardCharsets.UTF_8).length);
		return padded;
	}

	static @NonNull KeyQuery rs256(@Nullable String keyId) {
		return new KeyQuery(JwsAlgorithm.RS256, keyId, Set.of(JwsAlgorithm.RS256));
	}

	static @NonNull KeySelection select(@NonNull RemoteJsonWebKeySource source, @Nullable String keyId) {
		return source.select(rs256(keyId));
	}

	static @NonNull List<@NonNull String> keyIds(int count) {
		List<String> keyIds = new ArrayList<>();
		for (int index = 1; index <= count; ++index)
			keyIds.add("k-" + index);
		return keyIds;
	}

	/**
	 * A key set of the 2048-bit RSA fixture key under each kid, with no {@code alg}.
	 */
	static @NonNull String keySetJson(@NonNull String @NonNull ... keyIds) {
		return keySetJson(List.of(keyIds));
	}

	static @NonNull String keySetJson(@NonNull List<@NonNull String> keyIds) {
		List<String> keys = new ArrayList<>();
		for (String keyId : keyIds)
			keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(keyId).toJson());
		return TestJsonWebKeys.keySet(keys);
	}

	static @NonNull JsonWebKeySetUnavailableException assertUnavailable(@NonNull ErrorCategory category, boolean transientFailure,
			@NonNull Executable executable) {
		JsonWebKeySetUnavailableException exception = Assertions.assertThrows(JsonWebKeySetUnavailableException.class,
				executable);
		Assertions.assertEquals(category, exception.getCategory(), exception::toString);
		Assertions.assertEquals(transientFailure, exception.isTransient(), exception::toString);
		return exception;
	}

	@Immutable
	private static final class FailureCase {
		private final String name;
		private final Answer answer;
		private final ErrorCategory category;
		private final boolean transientFailure;

		private FailureCase(@NonNull String name, @NonNull Answer answer, @NonNull ErrorCategory category, boolean transientFailure) {
			this.name = name;
			this.answer = answer;
			this.category = category;
			this.transientFailure = transientFailure;
		}
	}

	/**
	 * How {@link MemoryHttpClient} answers one request.
	 */
	@Immutable
	static final class Answer {
		private final Kind kind;
		private final int status;
		private final Map<String, List<String>> headers;
		private final byte[] body;
		private final @Nullable Supplier<? extends Error> error;
		private final @Nullable CountDownLatch gate;

		private Answer(@NonNull Kind kind, int status, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, byte @NonNull [] body,
				@Nullable Supplier<? extends @NonNull Error> error, @Nullable CountDownLatch gate) {
			this.kind = kind;
			this.status = status;
			this.headers = Map.copyOf(headers);
			this.body = body.clone();
			this.error = error;
			this.gate = gate;
		}

		/**
		 * A response with {@code status}, the given headers and an empty body.
		 */
		static @NonNull Answer fromStatus(int status) {
			return fromStatus(status, Map.of());
		}

		static @NonNull Answer fromStatus(int status, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) {
			return new Answer(Kind.RESPOND, status, headers, new byte[0], null, null);
		}

		static @NonNull Answer fromBytes(int status, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, byte @NonNull [] body) {
			return new Answer(Kind.RESPOND, status, headers, body, null, null);
		}

		/**
		 * A response with the JWK Set media type, an optional {@code Cache-Control} and {@code json} as its body.
		 */
		static @NonNull Answer fromJson(int status, @Nullable String cacheControl, @NonNull String json) {
			Map<String, List<String>> headers = new LinkedHashMap<>();
			headers.put("Content-Type", List.of(JWK_SET_MEDIA_TYPE));
			if (cacheControl != null)
				headers.put("Cache-Control", List.of(cacheControl));
			return fromBytes(status, headers, json.getBytes(StandardCharsets.UTF_8));
		}

		/**
		 * A 200 key set of the RSA fixture key under each kid ({@link #keySetJson(String...)}).
		 */
		static @NonNull Answer fromKeySet(@Nullable String cacheControl, @NonNull String @NonNull ... keyIds) {
			return fromJson(200, cacheControl, keySetJson(keyIds));
		}

		/**
		 * The exchange fails with an {@link IOException}, as a refused connection does.
		 */
		static @NonNull Answer failingWithIo() {
			return new Answer(Kind.FAIL_WITH_IO, 0, Map.of(), new byte[0], null, null);
		}

		/**
		 * Nothing arrives until the test calls {@link MemoryHttpClient#releaseHeld(Answer)}.
		 */
		static @NonNull Answer holding() {
			return new Answer(Kind.HOLD, 0, Map.of(), new byte[0], null, null);
		}

		/**
		 * {@code sendAsync} waits for {@code gate} (uninterruptibly), then throws the error: an {@link Error} that
		 * leaves the leader after the exchange began.
		 */
		static @NonNull Answer throwingAfter(@NonNull CountDownLatch gate, @NonNull Supplier<? extends @NonNull Error> error) {
			return new Answer(Kind.THROW, 0, Map.of(), new byte[0], requireNonNull(error), requireNonNull(gate));
		}

		/**
		 * {@code sendAsync} waits for {@code gate} (uninterruptibly), then answers with {@code response}, a
		 * {@link Kind#RESPOND} answer: a leader held inside the exchange, where no deadline reaches it, whose response
		 * arrives only when the test lets it.
		 */
		static @NonNull Answer respondingAfter(@NonNull CountDownLatch gate, @NonNull Answer response) {
			if (response.kind != Kind.RESPOND)
				throw new IllegalArgumentException("A gated answer responds");
			return new Answer(Kind.GATED, response.status, response.headers, response.body, null, requireNonNull(gate));
		}

		@NonNull HttpHeaders headers() {
			return HttpHeaders.of(this.headers, (name, value) -> true);
		}

		@Immutable
		enum Kind {
			RESPOND,
			FAIL_WITH_IO,
			HOLD,
			THROW,
			GATED
		}
	}

	/**
	 * A test-only {@link HttpClient} that answers in memory, on the calling thread, with the current {@link Answer}
	 * ({@link #answer(Answer)} replaces it for later requests). It counts and records every {@code sendAsync}. A held
	 * request waits, like a slow server, until {@link #releaseHeld(Answer)} answers it from the test's thread; the
	 * caller meanwhile waits inside {@code HttpExchange} on its own deadline, where an interrupt reaches it. It starts
	 * no thread.
	 */
	@ThreadSafe
	static final class MemoryHttpClient extends HttpClient {
		private final ReentrantLock lock = new ReentrantLock();
		private final Condition changed = this.lock.newCondition();
		// Guarded by lock.
		private Answer answer;
		private final List<HttpRequest> requests = new ArrayList<>();
		private final List<Thread> senders = new ArrayList<>();
		private final List<Held<?>> held = new ArrayList<>();

		private MemoryHttpClient(@NonNull Answer answer) {
			this.answer = answer;
		}

		static @NonNull MemoryHttpClient answering(@NonNull Answer answer) {
			return new MemoryHttpClient(requireNonNull(answer));
		}

		/**
		 * Replaces the answer for requests that arrive from now on.
		 */
		void answer(@NonNull Answer answer) {
			requireNonNull(answer);
			this.lock.lock();
			try {
				this.answer = answer;
			} finally {
				this.lock.unlock();
			}
		}

		int getSendCount() {
			this.lock.lock();
			try {
				return this.requests.size();
			} finally {
				this.lock.unlock();
			}
		}

		@NonNull List<@NonNull HttpRequest> getRequests() {
			this.lock.lock();
			try {
				return List.copyOf(this.requests);
			} finally {
				this.lock.unlock();
			}
		}

		/**
		 * The thread that sent each request, in order: the leader of each flight.
		 */
		@NonNull List<@NonNull Thread> getSenders() {
			this.lock.lock();
			try {
				return List.copyOf(this.senders);
			} finally {
				this.lock.unlock();
			}
		}

		/**
		 * Waits until at least {@code count} requests have been sent, the timeout passes, or the thread is interrupted.
		 */
		boolean awaitSendCount(int count, @NonNull Duration timeout) throws InterruptedException {
			long remaining = timeout.toNanos();
			this.lock.lock();
			try {
				while (this.requests.size() < count) {
					if (remaining <= 0)
						return false;
					remaining = this.changed.awaitNanos(remaining);
				}
				return true;
			} finally {
				this.lock.unlock();
			}
		}

		/**
		 * Answers every held request with {@code response} (a {@link Answer.Kind#RESPOND} answer), and returns how many
		 * it answered: a request its caller gave up on (its future cancelled, as an interrupted or timed-out exchange
		 * does) is dropped instead.
		 */
		int releaseHeld(@NonNull Answer response) {
			List<Held<?>> released;
			this.lock.lock();
			try {
				released = List.copyOf(this.held);
				this.held.clear();
			} finally {
				this.lock.unlock();
			}
			int answered = 0;
			for (Held<?> request : released)
				if (request.deliver(response))
					++answered;
			return answered;
		}

		/**
		 * Fails every held request with an {@link IOException}, as a connection reset does, and returns how many it
		 * failed; a request its caller gave up on is dropped instead.
		 */
		int failHeld() {
			List<Held<?>> failed;
			this.lock.lock();
			try {
				failed = List.copyOf(this.held);
				this.held.clear();
			} finally {
				this.lock.unlock();
			}
			int answered = 0;
			for (Held<?> request : failed)
				if (request.fail())
					++answered;
			return answered;
		}

		@Override
		public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,
				HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler) {
			Answer current;
			CompletableFuture<HttpResponse<T>> future = new CompletableFuture<>();
			this.lock.lock();
			try {
				current = this.answer;
				this.requests.add(request);
				this.senders.add(Thread.currentThread());
				if (current.kind == Answer.Kind.HOLD)
					this.held.add(new Held<>(responseBodyHandler, future));
				this.changed.signalAll();
			} finally {
				this.lock.unlock();
			}

			switch (current.kind) {
				case RESPOND -> deliver(responseBodyHandler, current);
				case FAIL_WITH_IO -> future.completeExceptionally(new IOException("MemoryHttpClient: connection refused"));
				case HOLD -> {
					// Answered later by releaseHeld.
				}
				case THROW -> {
					awaitUninterruptibly(requireNonNull(current.gate));
					throw requireNonNull(current.error).get();
				}
				case GATED -> {
					awaitUninterruptibly(requireNonNull(current.gate));
					deliver(responseBodyHandler, current);
				}
			}
			return future;
		}

		/**
		 * Waits for {@code gate} whatever interrupts arrive, then sets the interrupt flag again if one did.
		 */
		private static void awaitUninterruptibly(@NonNull CountDownLatch gate) {
			boolean interrupted = false;
			while (gate.getCount() > 0) {
				try {
					gate.await();
				} catch (InterruptedException e) {
					interrupted = true;
				}
			}
			if (interrupted)
				Thread.currentThread().interrupt();
		}

		@Override
		public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,
				HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler, HttpResponse.@NonNull PushPromiseHandler<@NonNull T> pushPromiseHandler) {
			return sendAsync(request, responseBodyHandler);
		}

		@Override
		public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler)
				throws IOException {
			throw new IOException("MemoryHttpClient only sends asynchronously");
		}

		private static <T> void deliver(HttpResponse.@NonNull BodyHandler<@NonNull T> handler, @NonNull Answer response) {
			HttpResponse.BodySubscriber<T> subscriber = handler.apply(new Info(response.status, response.headers()));
			subscriber.onSubscribe(new Flow.Subscription() {
				@Override
				public void request(long n) {
					// The whole body is delivered below, within the first demand.
				}

				@Override
				public void cancel() {
					// Nothing to close.
				}
			});
			if (response.body.length > 0)
				subscriber.onNext(List.of(ByteBuffer.wrap(response.body.clone())));
			subscriber.onComplete();
		}

		@Override
		public @NonNull Optional<@NonNull CookieHandler> cookieHandler() {
			return Optional.empty();
		}

		@Override
		public @NonNull Optional<@NonNull Duration> connectTimeout() {
			return Optional.empty();
		}

		@Override
		public HttpClient.@NonNull Redirect followRedirects() {
			return HttpClient.Redirect.NEVER;
		}

		@Override
		public @NonNull Optional<@NonNull ProxySelector> proxy() {
			return Optional.empty();
		}

		@Override
		public @NonNull SSLContext sslContext() {
			try {
				return SSLContext.getDefault();
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public @NonNull SSLParameters sslParameters() {
			return new SSLParameters();
		}

		@Override
		public @NonNull Optional<@NonNull Authenticator> authenticator() {
			return Optional.empty();
		}

		@Override
		public HttpClient.@NonNull Version version() {
			return HttpClient.Version.HTTP_1_1;
		}

		@Override
		public @NonNull Optional<@NonNull Executor> executor() {
			return Optional.empty();
		}

		/**
		 * A held request's body handler.
		 */
		@Immutable
		private static final class Held<T> {
			private final HttpResponse.BodyHandler<T> handler;
			private final CompletableFuture<HttpResponse<T>> future;

			private Held(HttpResponse.@NonNull BodyHandler<@NonNull T> handler, @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> future) {
				this.handler = handler;
				this.future = future;
			}

			boolean deliver(@NonNull Answer response) {
				if (this.future.isCancelled())
					return false;
				MemoryHttpClient.deliver(this.handler, response);
				return true;
			}

			boolean fail() {
				return !this.future.isCancelled()
						&& this.future.completeExceptionally(new IOException("MemoryHttpClient: connection reset"));
			}
		}

		/**
		 * The status and headers a body handler sees.
		 */
		@Immutable
		private static final class Info implements HttpResponse.ResponseInfo {
			private final int status;
			private final HttpHeaders headers;

			private Info(int status, @NonNull HttpHeaders headers) {
				this.status = status;
				this.headers = headers;
			}

			@Override
			public int statusCode() {
				return this.status;
			}

			@Override
			public @NonNull HttpHeaders headers() {
				return this.headers;
			}

			@Override
			public HttpClient.@NonNull Version version() {
				return HttpClient.Version.HTTP_1_1;
			}
		}
	}
}
