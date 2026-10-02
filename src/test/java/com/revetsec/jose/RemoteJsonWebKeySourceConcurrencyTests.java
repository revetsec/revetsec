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
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.jose.JwksCacheTests.Answer;
import com.revetsec.jose.JwksCacheTests.MemoryHttpClient;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.RewindableClock;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestHttpsServer.HeldScript;
import com.revetsec.testing.TestHttpsServer.Response;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static com.revetsec.jose.JwksCacheTests.START;
import static com.revetsec.jose.JwksCacheTests.WAIT;
import static com.revetsec.jose.JwksCacheTests.assertUnavailable;
import static com.revetsec.jose.JwksCacheTests.keySetJson;
import static com.revetsec.jose.JwksCacheTests.rs256;
import static com.revetsec.jose.JwksCacheTests.select;
import static com.revetsec.jose.JwksCacheTests.source;

/**
 * Single-flight and the flight outcomes of the key set cache (G8-4, M2-8; exit criteria 11 and 13): one fetch for
 * many concurrent callers, waiters' own deadlines and interrupts, a leader interrupted or thrown out by an
 * {@link Error} after the exchange began, a flight abandoned before it, a failed flight's exceptions, and stale keys
 * served without waiting. Callers run on their own threads; every wait is on a latch, a condition or a
 * count ({@link JwksCache#awaitWaitersForTests(Integer, Duration)},
 * {@link MemoryHttpClient#awaitSendCount}), never a sleep.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceConcurrencyTests {
	private static final int CALLERS = 100;
	/**
	 * The request timeout of {@link #quickSource}: a flight is overdue once it is older than twice this.
	 */
	private static final Duration QUICK_REQUEST_TIMEOUT = Duration.ofMillis(250);
	/**
	 * How long each call of {@link #probeUntilOverdue} waits on the stuck flight.
	 */
	private static final Duration PROBE_DEADLINE = Duration.ofMillis(300);

	// Exit criterion 11: 100 concurrent unknown-kid calls, cold (no key set yet) and warm
	// (a fresh key set without the kid), make exactly one fetch. The server holds the one request until the other 99
	// callers are waiting for it, then every caller gets the new key.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> oneHundredConcurrentUnknownKeyCallsMakeOneFetch() {
		return Stream.of(false, true).map(warm -> DynamicTest.dynamicTest(warm ? "warm" : "cold", () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				HttpClient client = TestTls.httpClient();
				RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(server.uri("/jwks")).httpClient(client)
						.requestTimeout(Duration.ofSeconds(60)).build();
				if (warm) {
					server.script("/jwks", TestHttpsServer.Script.fromResponse(Response.fromJsonWebKeySet(keySetJson("a"))));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
				}
				HeldScript held = HeldScript.fromResponse(Response.fromJsonWebKeySet(keySetJson("a", "b")));
				server.script("/jwks", held);

				List<Call<KeySelection>> calls = new ArrayList<>();
				for (int caller = 0; caller < CALLERS; ++caller)
					calls.add(Call.start("caller-" + caller, () -> select(source, "b")));

				Assertions.assertTrue(held.awaitHeldCount(1, WAIT), "the leader's request reached the server");
				Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(CALLERS - 1, WAIT),
						"the other callers joined its flight");
				held.release();

				for (Call<KeySelection> call : calls)
					Assertions.assertEquals(KeySelection.Kind.FOUND, call.await().getKind());
				Assertions.assertEquals(1, held.getArrivalCount());
				Assertions.assertEquals(warm ? 2 : 1, server.getHitCount("/jwks"));
				Assertions.assertFalse(source.cacheForTests().awaitWaitersForTests(1, Duration.ZERO),
						"nobody is left waiting");
			}
		}));
	}

	// Plan "Rules throughout": a call leads or joins at most one completed flight, and after it a missing key is final.
	// A waiter that joined a first fetch without its key gets no key; it does not fetch again, although no cooldown
	// mark holds it back.
	@Test
	void aWaiterWhoseKeyIsMissingAfterTheFlightItJoinedGetsNoKey() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "missing"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));

		client.answer(Answer.fromKeySet(null, "a", "missing"));
		Assertions.assertEquals(1, client.releaseHeld(Answer.fromKeySet(null, "a")));
		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, waiter.await().getKind());
		Assertions.assertEquals(1, client.getSendCount());
	}

	// Plan decision rule 1: a caller whose snapshot another caller's fetch replaced before it decided rechecks against
	// the new snapshot and sends nothing, even when its key is missing and no cooldown mark would hold a refetch back.
	// Here the racer reads the expired key set, then pauses; a refresh on expiry (which takes no cooldown mark) completes
	// on the test's thread; the racer then gets no key and no third request is sent. A caller that reads the new key
	// set itself still leads the unknown-key refetch at once (variant A-prime), the control.
	@Test
	void aCallerWhoseSnapshotWasReplacedBeforeItDecidedRechecksWithoutAFetch() throws Exception {
		TestClock testClock = TestClock.fromInstant(START);
		PausingClock clock = new PausingClock(testClock);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		testClock.advance(Duration.ofSeconds(60));

		clock.pauseNextReadingOn("racer");
		Call<KeySelection> racer = Call.start("racer", () -> select(source, "b"));
		Assertions.assertTrue(clock.awaitPaused(), "the racer read the expired key set");
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "the refresh on expiry");
		Assertions.assertEquals(2, client.getSendCount());
		clock.resume();

		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, racer.await().getKind());
		Assertions.assertEquals(2, client.getSendCount(), "the racer rechecked the new key set and sent nothing");
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind());
		Assertions.assertEquals(3, client.getSendCount(), "a caller that read the new key set refetches at once");
	}

	// Plan decision rule 1 and M2-8: the recheck without a fetch applies only to a replacement that is fresh. When the
	// clock moves past the new key set's expiry before the racer decides, the racer is an EXPIRED caller like any other
	// and refreshes, instead of answering from a key set that is no longer fresh.
	@Test
	void aReplacedSnapshotThatIsNoLongerFreshIsDecidedByTheOtherRules() throws Exception {
		TestClock testClock = TestClock.fromInstant(START);
		PausingClock clock = new PausingClock(testClock);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a"));
		RemoteJsonWebKeySource source = source(client, clock).maximumStaleness(Duration.ZERO).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		testClock.advance(Duration.ofSeconds(60));

		clock.pauseNextReadingOn("racer");
		Call<KeySelection> racer = Call.start("racer", () -> select(source, "a"));
		Assertions.assertTrue(clock.awaitPaused());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "the refresh on expiry");
		testClock.advance(Duration.ofSeconds(60));
		clock.resume();

		Assertions.assertEquals(KeySelection.Kind.FOUND, racer.await().getKind());
		Assertions.assertEquals(3, client.getSendCount(), "the racer refreshed the expired replacement");
	}

	// Plan "Outcomes": a waiter whose own deadline ends gets TRANSPORT, transient, with no cause, while the leader's
	// flight carries on and completes for the leader.
	@Test
	void aWaiterWhoseDeadlineEndsFailsAloneAndTheFlightCarriesOn() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));

		JsonWebKeySetUnavailableException exception = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> source.select(rs256("a"), Deadline.fromNow(Duration.ofMillis(200))));
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(1, client.getSendCount(), "the waiter joined and sent nothing");

		Assertions.assertEquals(1, client.releaseHeld(Answer.fromKeySet(null, "a")));
		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertEquals(1, client.getSendCount());
	}

	// Plan "Deadlines": a standalone call (a validation's key lookup, or warmUp()) waits for another caller's fetch at
	// most this source's request timeout, then fails with TRANSPORT, transient. The leader's exchange is itself bounded
	// by the request timeout, so the leader here uses an injected client that blocks inside sendAsync, where no
	// deadline reaches it.
	@Test
	void aStandaloneWaiterWaitsAtMostTheRequestTimeout() throws Exception {
		CountDownLatch gate = new CountDownLatch(1);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.throwingAfter(gate,
				() -> new InjectedError("released")));
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).requestTimeout(Duration.ofSeconds(1))
				.build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));

		long started = System.nanoTime();
		Call<KeySelection> selecting = Call.start("selecting waiter", () -> select(source, "a"));
		Call<Boolean> warming = Call.start("warming waiter", () -> {
			source.warmUp();
			return true;
		});
		for (Call<?> waiter : List.of(selecting, warming)) {
			JsonWebKeySetUnavailableException exception = waiter.awaitFailure(JsonWebKeySetUnavailableException.class);
			Assertions.assertEquals(ErrorCategory.TRANSPORT, exception.getCategory());
			Assertions.assertTrue(exception.isTransient());
		}
		Duration waited = Duration.ofNanos(System.nanoTime() - started);
		Assertions.assertTrue(waited.compareTo(Duration.ofMillis(999)) > 0, waited::toString);
		Assertions.assertTrue(waited.compareTo(Duration.ofSeconds(20)) < 0, waited::toString);

		gate.countDown();
		Assertions.assertEquals("released", leader.awaitFailure(InjectedError.class).getMessage());
		Assertions.assertEquals(1, client.getSendCount());
	}

	// Plan "Outcomes": when a refresh fails, an EXPIRED caller whose usable key set holds its key is served stale,
	// waiters as well as the leader. A waiter normally never gets there, because rule 2 serves it without waiting, so
	// the key set is made usable only while the flight runs: the clock is set back before the fetch time when the
	// callers decide, and forward again before the refresh fails.
	@Test
	void anExpiredWaiterIsServedStaleWhenTheFlightItJoinedFails() throws Exception {
		RewindableClock clock = RewindableClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, clock).observer(observer.getObserver()).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		client.answer(Answer.holding());
		clock.rewind(Duration.ofSeconds(1));

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "a"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		clock.advance(Duration.ofSeconds(2));
		Assertions.assertEquals(1, client.failHeld());

		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.FOUND, waiter.await().getKind());
		Assertions.assertEquals(true, observer.getCalls("didFailToFetchJsonWebKeySet").get(0).getArgument(2));
		Assertions.assertEquals(2, client.getSendCount());
	}

	// Plan "Outcomes": an interrupted waiter gets TRANSPORT, not transient, with its interrupt flag set again; the
	// leader is unaffected.
	@Test
	void anInterruptedWaiterFailsAloneWithItsFlagSetAgain() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "a"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));

		waiter.interrupt();
		JsonWebKeySetUnavailableException exception = waiter.awaitFailure(JsonWebKeySetUnavailableException.class);
		Assertions.assertEquals(ErrorCategory.TRANSPORT, exception.getCategory());
		Assertions.assertFalse(exception.isTransient());
		Assertions.assertNull(exception.getCause());
		Assertions.assertTrue(waiter.wasInterruptedAtEnd());

		client.releaseHeld(Answer.fromKeySet(null, "a"));
		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertFalse(leader.wasInterruptedAtEnd());
	}

	// Exit criterion 13: a leader interrupted after the exchange began fails with TRANSPORT, not transient, its flag
	// set again. The flight is cut short: no backoff step, and its waiters decide again, so a first-use waiter leads a
	// second fetch at once, and the rest join it.
	@Test
	void aLeaderInterruptedAfterTheExchangeBeganLetsItsWaitersContendAgain() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer.getObserver())
				.build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		Call<KeySelection> selecting = Call.start("selecting waiter", () -> select(source, "a"));
		Call<Boolean> warming = Call.start("warming waiter", () -> {
			source.warmUp();
			return true;
		});
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(2, WAIT));

		leader.interrupt();
		JsonWebKeySetUnavailableException exception = leader.awaitFailure(JsonWebKeySetUnavailableException.class);
		Assertions.assertEquals(ErrorCategory.TRANSPORT, exception.getCategory());
		Assertions.assertFalse(exception.isTransient());
		Assertions.assertTrue(leader.wasInterruptedAtEnd());
		Assertions.assertSame(exception, observer.getCalls("didFailToFetchJsonWebKeySet").get(0).getArgument(1));

		// One waiter leads the second attempt at once (no backoff), and the other joins it.
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		Assertions.assertEquals(1, client.releaseHeld(Answer.fromKeySet(null, "a")));
		Assertions.assertEquals(KeySelection.Kind.FOUND, selecting.await().getKind());
		Assertions.assertEquals(true, warming.await());
		Assertions.assertEquals(2, client.getSendCount());
		Assertions.assertEquals(0, observer.getCalls("didSuppressJsonWebKeySetFetch").size());
	}

	// Exit criterion 13 and INV-G11: an unknown-key refetch whose leader is interrupted keeps its cooldown mark, so an
	// unknown-key waiter deciding again gets no key and sends nothing. The refetch starts 31 s after the first fetch,
	// outside the ceiling's window, so only the kept mark can hold the waiter back; a full cooldown after the refetch
	// started, the next unknown key is fetched.
	@Test
	void anInterruptedUnknownKeyRefetchKeepsItsCooldownMark() throws Exception {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		client.answer(Answer.holding());
		clock.advance(Duration.ofSeconds(31));

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "x"));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "y"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		// Were the mark not kept, the waiter would fetch this key set, with its key, at once.
		client.answer(Answer.fromKeySet(null, "a", "y", "z"));

		leader.interrupt();
		Assertions.assertEquals(ErrorCategory.TRANSPORT,
				leader.awaitFailure(JsonWebKeySetUnavailableException.class).getCategory());
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, waiter.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "z").getKind());
		Assertions.assertEquals(2, client.getSendCount());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "the key set is unchanged");

		clock.advance(Duration.ofSeconds(30));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "y").getKind(), "the mark ran one cooldown");
		Assertions.assertEquals(3, client.getSendCount());
	}

	// M2-8 and INV-G11: a sent unknown-key refetch keeps its cooldown mark whatever its outcome, even a failure whose
	// backoff a clock set back during the flight has made end before the cooldown: the mark still holds the next
	// unknown key back until a full cooldown after the request started.
	@Test
	void aFailedUnknownKeyRefetchKeepsItsMarkWhenAClockSetBackShortensItsBackoff() throws Exception {
		RewindableClock clock = RewindableClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		client.answer(Answer.holding());
		clock.advance(Duration.ofSeconds(60));

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "x"));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		clock.rewind(Duration.ofSeconds(20));
		Assertions.assertEquals(1, client.releaseHeld(Answer.fromStatus(503)));
		Assertions.assertEquals(ErrorCategory.REMOTE_ERROR,
				leader.awaitFailure(JsonWebKeySetUnavailableException.class).getCategory());
		client.answer(Answer.fromKeySet(null, "a", "y"));

		// The backoff started 20 s before the request did and has ended; the cooldown mark has not.
		clock.advance(Duration.ofSeconds(35));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "y").getKind());
		Assertions.assertEquals(2, client.getSendCount());
		clock.advance(Duration.ofSeconds(15));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "y").getKind());
		Assertions.assertEquals(3, client.getSendCount());
	}

	// Exit criterion 13 and M2-8: leaders interrupted in turn start at most two requests per cooldown. After two
	// cut-short attempts at the same instant, the remaining first-use waiters are held back by the ceiling with
	// TRANSPORT, transient, and no third request.
	@Test
	void leadersInterruptedInTurnStartAtMostTwoRequestsPerCooldown() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer.getObserver())
				.build();
		List<Call<KeySelection>> calls = new ArrayList<>();
		calls.add(Call.start("caller-0", () -> select(source, "a")));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		for (int caller = 1; caller <= 3; ++caller)
			calls.add(Call.start("caller-" + caller, () -> select(source, "a")));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(3, WAIT));

		interruptSender(calls, client.getSenders().get(0));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT), "a waiter leads the second attempt");
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(2, WAIT));
		interruptSender(calls, client.getSenders().get(1));

		int interrupted = 0;
		int heldBack = 0;
		for (Call<KeySelection> call : calls) {
			JsonWebKeySetUnavailableException exception = call.awaitFailure(JsonWebKeySetUnavailableException.class);
			Assertions.assertEquals(ErrorCategory.TRANSPORT, exception.getCategory());
			if (exception.isTransient())
				++heldBack;
			else
				++interrupted;
		}
		Assertions.assertEquals(2, interrupted);
		Assertions.assertEquals(2, heldBack);
		Assertions.assertEquals(2, client.getSendCount());
		Assertions.assertEquals(2, observer.getCalls("didSuppressJsonWebKeySetFetch").size());
	}

	// Exit criterion 13: an Error that leaves the leader after the exchange began propagates to it unchanged; the flight
	// is cut short (no backoff step, the attempt counts), so a first-use waiter leads again at once, while an unknown-key
	// waiter meets the kept cooldown mark. The unknown-key refetch starts 31 s after the first fetch, outside the
	// ceiling's window, so only the kept mark can hold its waiter back.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anErrorInTheLeaderPropagatesAndItsWaitersContendAgain() {
		return Stream.of(false, true).map(unknownKey -> DynamicTest.dynamicTest(unknownKey ? "unknown key" : "first use",
				() -> {
					TestClock clock = TestClock.fromInstant(START);
					MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
					RemoteJsonWebKeySource source = source(client, clock).build();
					int sentBefore = 0;
					if (unknownKey) {
						Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
						sentBefore = 1;
						clock.advance(Duration.ofSeconds(31));
					}
					CountDownLatch gate = new CountDownLatch(1);
					client.answer(Answer.throwingAfter(gate, () -> new InjectedError("thrown after the exchange began")));

					Call<KeySelection> leader = Call.start("leader", () -> select(source, unknownKey ? "x" : "a"));
					Assertions.assertTrue(client.awaitSendCount(sentBefore + 1, WAIT));
					Call<KeySelection> waiter = Call.start("waiter", () -> select(source, unknownKey ? "y" : "a"));
					Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
					client.answer(Answer.fromKeySet(null, "a", "y"));
					gate.countDown();

					InjectedError error = leader.awaitFailure(InjectedError.class);
					Assertions.assertEquals("thrown after the exchange began", error.getMessage());
					if (unknownKey) {
						Assertions.assertEquals(KeySelection.Kind.UNKNOWN, waiter.await().getKind(), "the mark was kept");
						Assertions.assertEquals(sentBefore + 1, client.getSendCount());
					} else {
						Assertions.assertEquals(KeySelection.Kind.FOUND, waiter.await().getKind(), "led again, no backoff");
						Assertions.assertEquals(sentBefore + 2, client.getSendCount());
					}
				}));
	}

	// M2-8: a flight that ends before its exchange (here an Error from the fetch announcement) sent nothing, so it is
	// abandoned: its cooldown mark and attempt record are restored, the Error propagates, and its waiter decides again
	// and leads the refetch itself.
	@Test
	void aFlightAbandonedBeforeTheExchangeRestoresItsMark() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		AnnouncementFailingObserver observer = new AnnouncementFailingObserver();
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		observer.arm();

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "x"));
		Assertions.assertTrue(observer.awaitAnnouncement());
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "y"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		observer.release();

		Assertions.assertEquals("injected by the observer", leader.awaitFailure(InternalError.class).getMessage());
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, waiter.await().getKind());
		Assertions.assertEquals(2, client.getSendCount(), "the waiter's own refetch, with the mark restored");
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "z").getKind());
		Assertions.assertEquals(2, client.getSendCount(), "now the waiter's refetch holds the cooldown mark");
	}

	// Exit criterion 12, for a waiter: a caller that joined the refresh that removed its key gets no key from it, like
	// the leader, and sends nothing of its own. With no staleness allowed, the expired key set answers nobody at once.
	@Test
	void aWaiterOnTheRefreshThatRemovedItsKeyGetsNoKey() throws Exception {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet("max-age=60", "a", "b"));
		RemoteJsonWebKeySource source = source(client, clock).maximumStaleness(Duration.ZERO).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind());
		client.answer(Answer.holding());
		clock.advance(Duration.ofSeconds(60));

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> select(source, "b"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		Assertions.assertEquals(1, client.releaseHeld(Answer.fromKeySet("max-age=60", "a")));

		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, waiter.await().getKind());
		Assertions.assertEquals(2, client.getSendCount());
	}

	// A flight its leader never publishes (a VirtualMachineError, such as a StackOverflowError, can stop a leader before
	// its finally runs) does not hold later callers for their whole deadlines forever. Once it is overdue, older than
	// its leader's exchange could take plus one more request timeout (here 2 s and 2 s), the next caller takes it as cut
	// short: the caller waiting on it decides again, and the next caller leads a fetch of its own. The stuck leader here
	// is blocked inside an injected client, where no deadline reaches it. When it finally ends, its outcome no longer
	// clears the flight that replaced it: a caller that arrives during a later refresh still joins that refresh.
	@Test
	void aFlightItsLeaderNeverPublishesIsTakenAsCutShortOnceOverdue() throws Exception {
		CountDownLatch gate = new CountDownLatch(1);
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.throwingAfter(gate, () -> new InjectedError("stuck")));
		AnnouncementHoldingObserver observer = new AnnouncementHoldingObserver();
		RemoteJsonWebKeySource source = source(client, clock).requestTimeout(Duration.ofSeconds(2))
				.maximumStaleness(Duration.ZERO).observer(observer).build();
		Call<KeySelection> stuck = Call.start("stuck leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		Call<KeySelection> waiter = Call.start("waiter", () -> source.select(rs256("a"), Deadline.fromNow(WAIT)));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
		client.answer(Answer.fromKeySet(null, "a"));

		// Each probe joins the stuck flight and gives up after 250 ms, until the flight is overdue; then a probe leads.
		long started = System.nanoTime();
		@Nullable KeySelection probed = null;
		while (probed == null && System.nanoTime() - started < WAIT.toNanos()) {
			try {
				probed = source.select(rs256("a"), Deadline.fromNow(Duration.ofMillis(250)));
			} catch (JsonWebKeySetUnavailableException e) {
				Assertions.assertEquals(ErrorCategory.TRANSPORT, e.getCategory());
				Assertions.assertTrue(e.isTransient());
			}
		}
		Duration waited = Duration.ofNanos(System.nanoTime() - started);
		Assertions.assertEquals(KeySelection.Kind.FOUND, Assertions.assertInstanceOf(KeySelection.class, probed,
				"a caller replaced the stuck flight").getKind());
		Assertions.assertTrue(waited.compareTo(Duration.ofSeconds(2)) > 0, "not before it was overdue: " + waited);
		Assertions.assertEquals(KeySelection.Kind.FOUND, waiter.await().getKind(), "released to decide again");
		Assertions.assertEquals(2, client.getSendCount());

		// A refresh is in flight, its leader held in the fetch announcement, when the stuck leader ends. The refresher's
		// own deadline is long, so only its flight's budget (4 s) bounds this part.
		clock.advance(Duration.ofMinutes(10));
		observer.arm();
		Call<KeySelection> refresher = Call.start("refresher", () -> source.select(rs256("a"), Deadline.fromNow(WAIT)));
		Assertions.assertTrue(observer.awaitAnnouncement());
		gate.countDown();
		Assertions.assertEquals("stuck", stuck.awaitFailure(InjectedError.class).getMessage());
		Call<KeySelection> joiner = Call.start("joiner", () -> select(source, "a"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT), "the refresh's flight stayed");
		observer.release();

		Assertions.assertEquals(KeySelection.Kind.FOUND, refresher.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.FOUND, joiner.await().getKind());
		Assertions.assertEquals(3, client.getSendCount());
	}

	// A late success installs its key set only if it is not older than the current one. A leader held inside its exchange
	// outlives its flight, which the next caller takes as cut short once it is overdue; that caller leads a fetch of its
	// own. When the held leader's response finally arrives, the leader answers from it, and its key set replaces the
	// current one when there is none yet (the replacing fetch failed), or when it was received no earlier than the
	// current one, at the same instant included; a key set received earlier (the clock set back while the leader was
	// held) is not installed, so the newer key set keeps answering.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aLateSuccessInstallsItsKeySetOnlyIfItIsNotOlder() {
		return Stream.of(LateSuccess.values()).map(late -> DynamicTest.dynamicTest(late.description, () -> {
			RewindableClock clock = RewindableClock.fromInstant(START);
			CountDownLatch gate = new CountDownLatch(1);
			MemoryHttpClient client = MemoryHttpClient.answering(Answer.respondingAfter(gate,
					Answer.fromKeySet(null, "late")));
			RemoteJsonWebKeySource source = quickSource(client, clock, JoseObserver.disabledInstance());
			Call<KeySelection> held = Call.start("held leader", () -> source.select(rs256("late"),
					Deadline.fromNow(WAIT)));
			Assertions.assertTrue(client.awaitSendCount(1, WAIT));

			client.answer(late == LateSuccess.NO_KEY_SET ? Answer.fromStatus(503) : Answer.fromKeySet(null, "current"));
			Probe replacing = probeUntilOverdue(source, "current");
			if (late == LateSuccess.NO_KEY_SET)
				Assertions.assertEquals(ErrorCategory.REMOTE_ERROR, replacing.requireFailure().getCategory());
			else
				Assertions.assertEquals(KeySelection.Kind.FOUND, replacing.requireSelection().getKind());
			Assertions.assertEquals(2, client.getSendCount());

			if (late == LateSuccess.NEWER)
				clock.advance(Duration.ofSeconds(1));
			else if (late == LateSuccess.OLDER)
				clock.rewind(Duration.ofSeconds(1));
			gate.countDown();
			Assertions.assertEquals(KeySelection.Kind.FOUND, held.await().getKind(), "the leader's own key set answers it");
			if (late == LateSuccess.OLDER)
				clock.advance(Duration.ofSeconds(1));

			if (late == LateSuccess.OLDER) {
				Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "current").getKind());
				// The older key set was not installed; the ceiling (both fetches started at 0 s) holds back a refetch.
				Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "late").getKind());
			} else {
				Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "late").getKind(), "installed");
			}
			Assertions.assertEquals(2, client.getSendCount(), "every answer came from a cached key set");
		}));
	}

	// A flight abandoned before its exchange after it was already taken as cut short leaves the marks alone: the attempt
	// and cooldown mark of the flight that replaced it stand. An unknown-key refetch at 31 s holds its leader in the
	// fetch announcement until it is overdue; the next unknown key, at 61 s once that refetch's cooldown has passed,
	// takes it as cut short and leads a refetch of its own. When the held announcement then fails with an Error, the
	// abandoned flight restores nothing, so the refetch at 61 s still holds unknown keys back.
	@Test
	void aFlightAbandonedAfterItWasTakenAsOverdueRestoresNoMarks() throws Exception {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		AnnouncementFailingObserver observer = new AnnouncementFailingObserver();
		RemoteJsonWebKeySource source = quickSource(client, clock, observer);
		Assertions.assertEquals(KeySelection.Kind.FOUND, source.select(rs256("a"), Deadline.fromNow(WAIT)).getKind());

		clock.advance(Duration.ofSeconds(31));
		observer.arm();
		Call<KeySelection> abandoning = Call.start("abandoning leader", () -> source.select(rs256("x"),
				Deadline.fromNow(WAIT)));
		Assertions.assertTrue(observer.awaitAnnouncement());
		clock.advance(Duration.ofSeconds(30));
		client.answer(Answer.fromKeySet(null, "a", "y"));

		Assertions.assertEquals(KeySelection.Kind.FOUND, probeUntilOverdue(source, "y").requireSelection().getKind());
		Assertions.assertEquals(2, client.getSendCount());
		observer.release();
		Assertions.assertEquals("injected by the observer", abandoning.awaitFailure(InternalError.class).getMessage());

		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, source.select(rs256("z"), Deadline.fromNow(WAIT)).getKind());
		Assertions.assertEquals(2, client.getSendCount(), "the refetch at 61 s kept its cooldown mark");
	}

	// Plan "Outcomes": when a flight fails, the leader's exception keeps the JDK's IOException, and each waiter gets its
	// own instance with the same category and transience and no cause; the failure hook gets the leader's instance.
	@Test
	void aFailedFlightGivesEachWaiterItsOwnExceptionWithNoCause() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.holding());
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer.getObserver())
				.build();
		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(1, WAIT));
		List<Call<KeySelection>> waiters = new ArrayList<>();
		for (int waiter = 0; waiter < 3; ++waiter)
			waiters.add(Call.start("waiter-" + waiter, () -> select(source, "a")));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(3, WAIT));

		Assertions.assertEquals(1, client.failHeld());
		JsonWebKeySetUnavailableException leaderException = leader.awaitFailure(JsonWebKeySetUnavailableException.class);
		Assertions.assertEquals(ErrorCategory.TRANSPORT, leaderException.getCategory());
		Assertions.assertTrue(leaderException.isTransient());
		Assertions.assertInstanceOf(IOException.class, leaderException.getCause());
		Assertions.assertSame(leaderException, observer.getCalls("didFailToFetchJsonWebKeySet").get(0).getArgument(1));

		Set<JsonWebKeySetUnavailableException> distinct = new HashSet<>();
		distinct.add(leaderException);
		for (Call<KeySelection> waiter : waiters) {
			JsonWebKeySetUnavailableException exception = waiter.awaitFailure(JsonWebKeySetUnavailableException.class);
			Assertions.assertEquals(ErrorCategory.TRANSPORT, exception.getCategory());
			Assertions.assertTrue(exception.isTransient());
			Assertions.assertNull(exception.getCause());
			distinct.add(exception);
		}
		Assertions.assertEquals(4, distinct.size(), "every caller has its own instance");
		Assertions.assertEquals(1, client.getSendCount());
		Assertions.assertEquals(1, observer.getCalls("didFailToFetchJsonWebKeySet").size(), "only the leader reports");
	}

	// Plan rule 2: while a refresh is in flight, an EXPIRED caller whose usable key set holds its key is served stale
	// at once; one whose key is missing waits for the flight and then gets the new key.
	@Test
	void staleKeysAnswerAtOnceWhileARefreshIsInFlight() throws Exception {
		TestClock clock = TestClock.fromInstant(START);
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		RemoteJsonWebKeySource source = source(client, clock).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		client.answer(Answer.holding());
		clock.advance(Duration.ofMinutes(10));

		Call<KeySelection> leader = Call.start("leader", () -> select(source, "a"));
		Assertions.assertTrue(client.awaitSendCount(2, WAIT));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind(), "stale, without waiting");
		Assertions.assertFalse(source.cacheForTests().awaitWaitersForTests(1, Duration.ZERO));
		Call<KeySelection> lacking = Call.start("lacking", () -> select(source, "b"));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));

		client.releaseHeld(Answer.fromKeySet(null, "a", "b"));
		Assertions.assertEquals(KeySelection.Kind.FOUND, leader.await().getKind());
		Assertions.assertEquals(KeySelection.Kind.FOUND, lacking.await().getKind());
		Assertions.assertEquals(2, client.getSendCount());
	}

	// G6-4 and plan leader step 5: hooks run outside the lock, so a hook on the leader's thread that waits for another
	// thread's call on the same source does not deadlock it.
	@Test
	void hooksRunOutsideTheLock() throws Exception {
		MemoryHttpClient client = MemoryHttpClient.answering(Answer.fromKeySet(null, "a"));
		CrossThreadObserver observer = new CrossThreadObserver();
		RemoteJsonWebKeySource source = source(client, TestClock.fromInstant(START)).observer(observer).build();
		observer.source = source;

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(List.of("willFetchJsonWebKeySet: TRANSPORT", "didFetchJsonWebKeySet: TRANSPORT"),
				observer.getResults());
	}

	/**
	 * A source built through the package-private constructor, whose checked settings allow a request timeout below the
	 * builder's 1 s floor, so that a stuck flight is overdue after half a second instead of 20 s.
	 */
	private static @NonNull RemoteJsonWebKeySource quickSource(@NonNull MemoryHttpClient client, @NonNull Clock clock, @NonNull JoseObserver observer) {
		RemoteJsonWebKeySource built = source(client, clock).build();
		return new RemoteJsonWebKeySource(JwksCacheTests.JWKS_URI, built.httpExchangeForTests(),
				JwksCacheTests.settings(clock, QUICK_REQUEST_TIMEOUT, observer));
	}

	/**
	 * Selects {@code keyId} with a short deadline until one call finds the stuck flight overdue, takes it as cut short
	 * and leads a fetch of its own, and returns that call's outcome: its selection, or the failure its fetch ended
	 * with. Each earlier call joins the stuck flight and gives up at its deadline with a transient TRANSPORT failure,
	 * so every wait is a call's own deadline, never a sleep.
	 */
	private static @NonNull Probe probeUntilOverdue(@NonNull RemoteJsonWebKeySource source, @NonNull String keyId) {
		long started = System.nanoTime();
		while (System.nanoTime() - started < WAIT.toNanos()) {
			try {
				return new Probe(source.select(rs256(keyId), Deadline.fromNow(PROBE_DEADLINE)), null);
			} catch (JsonWebKeySetUnavailableException e) {
				if (e.getCategory() != ErrorCategory.TRANSPORT)
					return new Probe(null, e);
				Assertions.assertTrue(e.isTransient(), "a waiter whose deadline ended");
			}
		}
		throw new AssertionError("The stuck flight never became overdue");
	}

	private static void interruptSender(@NonNull List<@NonNull Call<@NonNull KeySelection>> calls, @NonNull Thread sender) {
		for (Call<KeySelection> call : calls)
			if (call.thread.equals(sender)) {
				call.interrupt();
				return;
			}
		throw new AssertionError("No caller sent from " + sender);
	}

	/**
	 * What the key set held when a late success arrived, and when that key set was received.
	 */
	@Immutable
	private enum LateSuccess {
		NO_KEY_SET("no key set yet, so the late one is installed"),
		NEWER("a key set received before the late one, which replaces it"),
		SAME_INSTANT("a key set received at the same instant as the late one, which replaces it"),
		OLDER("a key set received after the late one, which stays");

		private final String description;

		LateSuccess(@NonNull String description) {
			this.description = description;
		}
	}

	/**
	 * The outcome of the call that replaced an overdue flight: a selection or a failure.
	 */
	@Immutable
	private record Probe(@Nullable KeySelection selection, @Nullable JsonWebKeySetUnavailableException failure) {
		@NonNull KeySelection requireSelection() {
			return Assertions.assertInstanceOf(KeySelection.class, this.selection, () -> "failed: " + this.failure);
		}

		@NonNull JsonWebKeySetUnavailableException requireFailure() {
			return Assertions.assertInstanceOf(JsonWebKeySetUnavailableException.class, this.failure,
					() -> "selected: " + this.selection);
		}
	}

	/**
	 * One call on its own daemon thread, with its outcome and whether its interrupt flag was set when it ended.
	 */
	@ThreadSafe
	static final class Call<T> {
		private final Thread thread;
		private final CompletableFuture<T> result = new CompletableFuture<>();
		private final AtomicBoolean interruptedAtEnd = new AtomicBoolean();

		private Call(@NonNull String name, @NonNull Callable<@NonNull T> callable) {
			this.thread = new Thread(() -> {
				try {
					this.result.complete(callable.call());
				} catch (Throwable t) {
					this.result.completeExceptionally(t);
				} finally {
					this.interruptedAtEnd.set(Thread.currentThread().isInterrupted());
				}
			}, name);
			this.thread.setDaemon(true);
		}

		static <T> @NonNull Call<@NonNull T> start(@NonNull String name, @NonNull Callable<@NonNull T> callable) {
			Call<T> call = new Call<>(name, callable);
			call.thread.start();
			return call;
		}

		void interrupt() {
			this.thread.interrupt();
		}

		@NonNull T await() throws Exception {
			try {
				return this.result.get(WAIT.toNanos(), TimeUnit.NANOSECONDS);
			} catch (ExecutionException e) {
				throw new AssertionError("The call failed", e.getCause());
			}
		}

		<E extends Throwable> @NonNull E awaitFailure(@NonNull Class<@NonNull E> type) throws Exception {
			try {
				T value = this.result.get(WAIT.toNanos(), TimeUnit.NANOSECONDS);
				throw new AssertionError("The call returned " + value);
			} catch (ExecutionException e) {
				return Assertions.assertInstanceOf(type, e.getCause());
			}
		}

		boolean wasInterruptedAtEnd() throws InterruptedException {
			this.thread.join(WAIT.toMillis());
			return this.interruptedAtEnd.get();
		}
	}

	/**
	 * A {@link Clock} over a {@link TestClock} that holds the next reading on one named thread until the test resumes
	 * it. A caller reads the cached snapshot and then the clock, so pausing its first reading lets the test complete
	 * another caller's fetch between the two.
	 */
	@ThreadSafe
	private static final class PausingClock extends Clock {
		private final TestClock clock;
		private final AtomicReference<@Nullable String> pausedThreadName = new AtomicReference<>();
		private final CountDownLatch paused = new CountDownLatch(1);
		private final CountDownLatch resumed = new CountDownLatch(1);

		private PausingClock(@NonNull TestClock clock) {
			this.clock = clock;
		}

		void pauseNextReadingOn(@NonNull String threadName) {
			this.pausedThreadName.set(threadName);
		}

		boolean awaitPaused() throws InterruptedException {
			return this.paused.await(WAIT.toNanos(), TimeUnit.NANOSECONDS);
		}

		void resume() {
			this.resumed.countDown();
		}

		@Override
		public @NonNull Instant instant() {
			if (this.pausedThreadName.compareAndSet(Thread.currentThread().getName(), null)) {
				this.paused.countDown();
				try {
					if (!this.resumed.await(WAIT.toNanos(), TimeUnit.NANOSECONDS))
						throw new IllegalStateException("never resumed");
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			return this.clock.instant();
		}

		@Override
		public @NonNull ZoneId getZone() {
			return this.clock.getZone();
		}

		@Override
		public @NonNull Clock withZone(@NonNull ZoneId zone) {
			throw new UnsupportedOperationException("PausingClock has one zone");
		}
	}

	/**
	 * An {@link Error} a test throws from inside the exchange.
	 */
	static final class InjectedError extends Error {
		private static final long serialVersionUID = 1L;

		InjectedError(@NonNull String message) {
			super(message);
		}
	}

	/**
	 * Once armed, fails the next fetch announcement with an {@link InternalError}, a {@link VirtualMachineError} that
	 * observer dispatch never contains, after the test lets it.
	 */
	@ThreadSafe
	private static final class AnnouncementFailingObserver implements JoseObserver {
		private final AtomicBoolean armed = new AtomicBoolean();
		private final CountDownLatch announced = new CountDownLatch(1);
		private final CountDownLatch released = new CountDownLatch(1);

		void arm() {
			this.armed.set(true);
		}

		boolean awaitAnnouncement() throws InterruptedException {
			return this.announced.await(WAIT.toNanos(), TimeUnit.NANOSECONDS);
		}

		void release() {
			this.released.countDown();
		}

		@Override
		public void willFetchJsonWebKeySet(@NonNull URI jwksUri) {
			if (!this.armed.getAndSet(false))
				return;
			this.announced.countDown();
			try {
				if (!this.released.await(WAIT.toNanos(), TimeUnit.NANOSECONDS))
					throw new IllegalStateException("never released");
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			throw new InternalError("injected by the observer");
		}
	}

	/**
	 * Once armed, holds the next fetch announcement, on the leader's thread before its exchange, until the test
	 * releases it.
	 */
	@ThreadSafe
	private static final class AnnouncementHoldingObserver implements JoseObserver {
		private final AtomicBoolean armed = new AtomicBoolean();
		private final CountDownLatch announced = new CountDownLatch(1);
		private final CountDownLatch released = new CountDownLatch(1);

		void arm() {
			this.armed.set(true);
		}

		boolean awaitAnnouncement() throws InterruptedException {
			return this.announced.await(WAIT.toNanos(), TimeUnit.NANOSECONDS);
		}

		void release() {
			this.released.countDown();
		}

		@Override
		public void willFetchJsonWebKeySet(@NonNull URI jwksUri) {
			if (!this.armed.getAndSet(false))
				return;
			this.announced.countDown();
			try {
				if (!this.released.await(WAIT.toNanos(), TimeUnit.NANOSECONDS))
					throw new IllegalStateException("never released");
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * From each hook on the leader's thread, runs a call on the same source on another thread and waits for it: a hook
	 * run while the lock was held would deadlock that call's decision.
	 */
	@ThreadSafe
	private static final class CrossThreadObserver implements JoseObserver {
		private final List<String> results = new java.util.concurrent.CopyOnWriteArrayList<>();
		volatile @Nullable RemoteJsonWebKeySource source;

		@NonNull List<@NonNull String> getResults() {
			return List.copyOf(this.results);
		}

		@Override
		public void willFetchJsonWebKeySet(@NonNull URI jwksUri) {
			this.results.add("willFetchJsonWebKeySet: " + otherThreadDecides());
		}

		@Override
		public void didFetchJsonWebKeySet(@NonNull URI jwksUri, @NonNull Integer usableKeyCount, @NonNull Integer skippedKeyCount,
				@NonNull Duration timeToLive, @NonNull Duration elapsed) {
			this.results.add("didFetchJsonWebKeySet: " + otherThreadDecides());
		}

		/**
		 * Another thread asks for a key that is not cached, with a spent deadline: it takes the lock to decide (joining
		 * the flight, or leading), then fails at once with TRANSPORT. It can return only if the lock is free.
		 */
		private @NonNull String otherThreadDecides() {
			RemoteJsonWebKeySource current = this.source;
			if (current == null)
				return "no source";
			try {
				Call<KeySelection> call = Call.start("hook-caller", () -> current.select(rs256("x"),
						Deadline.fromNow(Duration.ZERO)));
				return call.awaitFailure(JsonWebKeySetUnavailableException.class).getCategory().name();
			} catch (Exception | AssertionError e) {
				return "failed: " + e;
			}
		}
	}
}
