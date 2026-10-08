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

import com.revetsec.ErrorCategory;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.http.CacheLifetime;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.http.RetryAfter;
import com.revetsec.internal.jose.JoseFailure;
import com.revetsec.internal.jose.JwkSetParser;
import com.revetsec.internal.jose.KeyQuery;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.internal.jose.KeySelector;
import com.revetsec.internal.jose.ParsedKeySet;
import com.revetsec.internal.jose.VerificationKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * The key set cache behind a {@link RemoteJsonWebKeySource}: it fetches the key set on callers' threads, one fetch at
 * a time, and decides when a fetch may start (M2 plan, "RemoteJsonWebKeySource algorithm"; G8-4, G8-8, M2-8).
 * <p>
 * <strong>State.</strong> The snapshot (the parsed keys, when they were fetched, when they expire and until when they
 * may still answer while refreshes fail) is immutable and published through a volatile field. A short lock protects
 * each clock observation so an observed rollback invalidates even a snapshot still inside its original TTL.
 * Everything else is guarded by {@link #lock}: the fetch in progress (the flight);
 * the start of the last unknown-key refetch that sent its request (the cooldown mark); the starts of the last two
 * attempts of any kind (the ceiling); and the negative cache (when the last failure happened, the consecutive failure
 * count, the current backoff step and the failure's category). The lock is never held while an observer runs, while
 * waiting for a flight, or during the exchange. Instants come from the injected {@link java.time.Clock}; deadlines and
 * elapsed times from {@link System#nanoTime()}.
 * <p>
 * <strong>Windows.</strong> A snapshot is fresh iff {@code fetchedAt <= now < expiresAt}, and usable iff
 * {@code fetchedAt <= now < usableUntil}, where {@code usableUntil} is the expiry plus the maximum staleness. A
 * cooldown, backoff or ceiling window applies iff {@code start <= now < start + duration}. An instant recorded in the
 * future of {@code now} therefore counts as elapsed: a clock set back makes the snapshot expired and never extends
 * anything.
 * <p>
 * <strong>Triggers</strong> for a call that finds no answer in a fresh snapshot: {@code FIRST_USE} (no snapshot),
 * {@code EXPIRED} (a snapshot that is not fresh), {@code UNKNOWN_KID} (a fresh snapshot with no key for the query:
 * only {@link KeySelection.Kind#UNKNOWN} ever leads to a fetch) and {@code WARM_UP}. Under the lock, the trigger is
 * taken from the snapshot as it is then, and the first matching rule decides:
 * <ol>
 *   <li>the snapshot changed since the caller read it, because another caller's fetch completed in between, and is
 *   fresh: the caller rechecks against it and never fetches, so a key still missing is final for the call;</li>
 *   <li>a flight is in progress: an {@code EXPIRED} caller whose usable snapshot holds its key is served stale without
 *   waiting; every other caller joins the flight and waits for it within its own deadline. A flight older than its
 *   leader's exchange could take plus one more request timeout is overdue: it is taken as cut short (below), its
 *   waiters decide again, and the caller goes on to the next rule;</li>
 *   <li>the backoff applies: no request; an {@code EXPIRED} caller whose usable snapshot holds its key is served stale,
 *   and every other caller gets the remembered failure's category and transience, with no cause;</li>
 *   <li>an {@code UNKNOWN_KID} caller inside the unknown-key cooldown: no request, and no key;</li>
 *   <li>two attempts started within the last cooldown (the ceiling): no request; an {@code EXPIRED} caller is served
 *   stale if it can be, an {@code UNKNOWN_KID} caller gets no key, and every other caller a transient
 *   {@link ErrorCategory#TRANSPORT} failure with no cause. {@link RemoteJsonWebKeySource.Builder#build()} keeps the
 *   cooldown within the minimum time to live, so a success leaves a snapshot fresh, and a failure starts a backoff,
 *   for at least one cooldown: unless a flight was cut short, a fresh snapshot or rules 1 to 4 answer every call that
 *   the ceiling would hold back, and it never binds;</li>
 *   <li>otherwise the caller leads: unless its deadline is already spent or its thread interrupted (then it fails
 *   with {@link ErrorCategory#TRANSPORT}, and nothing is sent or counted), it starts a flight, records the attempt
 *   and, for {@code UNKNOWN_KID}, the cooldown mark, and fetches on its own thread.</li>
 * </ol>
 * Rules 3 to 5 report {@link JoseObserver#didSuppressJsonWebKeySetFetch(URI, Duration)} on every such call.
 * <p>
 * <strong>Flights.</strong> The leader runs one exchange (profile {@code JWKS}, the caller's deadline), parses the
 * body through {@link JwkSetParser} and computes the time to live through {@link CacheLifetime}. In a {@code finally},
 * it publishes the outcome under the lock and clears the flight; then it completes the flight's future, which has no
 * dependent stages, and only then fires the fetch hooks. A {@link VirtualMachineError}, such as a
 * {@link StackOverflowError}, can stop a leader before that {@code finally} runs; its flight then stays until it is
 * overdue (rule 2), and a flight taken as cut short or replaced never clears or rewinds a newer one when its leader
 * does publish. A call leads or joins at most one completed flight, and after it a missing key is final for that
 * call. Outcomes:
 * <ul>
 *   <li>success: the new snapshot replaces the old one, whatever keys it holds (an all-skipped key set is a valid,
 *   empty snapshot), and the leader and waiters select from it. The failure count is left as it is;</li>
 *   <li>failure (any response or exchange failure except the leader's interrupt, a timeout included, whoever's
 *   deadline ended it): the backoff advances; an {@code EXPIRED} caller whose usable snapshot holds its key is served
 *   stale, and everyone else gets a {@link JsonWebKeySetUnavailableException}, the leader with the JDK's
 *   {@link IOException} as its cause for an I/O failure, waiters their own instance with no cause;</li>
 *   <li>cut short (the leader's thread interrupted during the exchange, an {@link Error} after the exchange began, or
 *   the flight overdue): no backoff step, but the attempt counts and an unknown-key refetch keeps its cooldown mark.
 *   The leader fails (or the {@code Error} propagates), and waiters decide again from rule 1, where an
 *   {@code UNKNOWN_KID} waiter meets the kept mark and the ceiling bounds the others;</li>
 *   <li>abandoned (an {@link Error} from an observer before the exchange began): the cooldown mark and the attempt
 *   record are restored, and waiters decide again.</li>
 * </ul>
 * <strong>Backoff.</strong> After a failure that brings the count to n, no fetch of any kind starts before
 * {@code failedAt + min(cooldown * 2^(n-1), cap)}, with {@code cap = max(cooldown, min(10 * cooldown, 10 min))}: 30,
 * 60, 120, 240, then 300 seconds at the default cooldown. A {@code Retry-After} on a 429 or 503 may raise the step, up
 * to the cap. Before a failure increments n, n drops by one for each full cap interval since the previous failure,
 * never below zero; a success leaves n unchanged, so a server that answers a valid key set between failures meets the
 * same schedule as one that always fails (G8-8).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class JwksCache {
	/**
	 * The largest backoff cap, reached with a cooldown of one minute or more.
	 */
	@NonNull
	private static final Duration MAXIMUM_BACKOFF_CAP = Duration.ofMinutes(10);

	/**
	 * The cap in cooldowns, below {@link #MAXIMUM_BACKOFF_CAP}.
	 */
	private static final int BACKOFF_CAP_COOLDOWNS = 10;

	@NonNull
	private final URI reportedUri;
	@NonNull
	private final HttpExchange httpExchange;
	@NonNull
	private final JwksSettings settings;
	@NonNull
	private final HttpExchangeRequest request;
	@NonNull
	private final Duration backoffCap;

	/**
	 * Guards every field below except {@link #snapshot}, which is written only while it is held.
	 */
	@NonNull
	private final ReentrantLock lock = new ReentrantLock();

	/**
	 * Signalled, under {@link #lock}, whenever {@link #waiterCount} changes.
	 */
	@NonNull
	private final Condition waitersChanged = this.lock.newCondition();

	/**
	 * The current key set, or {@code null} before the first successful fetch; written only while {@link #lock} is
	 * held, and read without it.
	 */
	@Nullable
	private volatile Snapshot snapshot;

	// Guarded by lock: the last observed wall-clock instant.
	@Nullable
	private Instant lastClock;

	// Guarded by lock: the fetch in progress, or null.
	@Nullable
	private Flight flight;

	// Guarded by lock: the start of the last unknown-key refetch that reached the exchange (the cooldown mark).
	@Nullable
	private Instant lastUnknownKidFetchStart;

	// Guarded by lock: the starts of the last two attempts of any trigger and outcome (the ceiling).
	@Nullable
	private Instant latestAttemptStart;
	@Nullable
	private Instant earlierAttemptStart;

	// Guarded by lock: the negative cache.
	@Nullable
	private Instant failedAt;
	private int consecutiveFailures;
	@NonNull
	private Duration backoff = Duration.ZERO;
	@Nullable
	private Failure lastFailure;

	// Guarded by lock: how many callers are waiting for a flight another caller leads.
	private int waiterCount;

	/**
	 * Creates the cache for one key set URI. It does no I/O.
	 *
	 * @param uri          the key set's URI, used as given (the caller checked it, or a fetch refuses it)
	 * @param httpExchange the component's exchange helper
	 * @param settings     the checked settings
	 */
	JwksCache(@NonNull URI uri,
						@NonNull HttpExchange httpExchange,
						@NonNull JwksSettings settings) {
		requireNonNull(uri);
		this.reportedUri = cut(uri);
		this.httpExchange = requireNonNull(httpExchange);
		this.settings = requireNonNull(settings);
		this.request = new HttpExchangeRequest(uri, ResponseProfile.JWKS, null, Map.of(),
				settings.maximumResponseBytes(), Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(),
				settings.requestTimeout());
		this.backoffCap = backoffCap(settings.unknownKeyRefreshCooldown());
	}

	/**
	 * Selects the key for {@code query}, fetching the key set first when the rules above call for it.
	 *
	 * @param query    the token's algorithm, key ID and effective algorithm set
	 * @param deadline this call's deadline, which bounds its exchange or its wait for another caller's
	 * @return the selection; {@link KeySelection.Kind#UNKNOWN} is final for this call
	 * @throws JsonWebKeySetUnavailableException if no usable key set is available for this call
	 */
	@NonNull
	KeySelection select(@NonNull KeyQuery query,
											@NonNull Deadline deadline) {
		requireNonNull(query);
		requireNonNull(deadline);

		@Nullable Snapshot observed = this.snapshot;
		Instant now = this.settings.clock().instant();
		@Nullable Snapshot current;
		this.lock.lock();
		try {
			current = observeClock(now);
			if (current != null && current.isFresh(now)) {
				KeySelection selection = KeySelector.select(current.keys(), query);
				if (current != observed || selection.getKind() != KeySelection.Kind.UNKNOWN)
					return selection;
			}
		} finally {
			this.lock.unlock();
		}

		return requireNonNull(resolve(query, deadline, observed));
	}

	/**
	 * Fetches the key set unless a fresh one is cached (even an empty one); respects the backoff and the ceiling,
	 * ignores the unknown-key cooldown, and throws on failure even when an expired key set could still answer.
	 *
	 * @param deadline this call's deadline
	 * @throws JsonWebKeySetUnavailableException if the fetch failed or was suppressed
	 */
	void warmUp(@NonNull Deadline deadline) {
		requireNonNull(deadline);
		@Nullable Snapshot observed = this.snapshot;
		Instant now = this.settings.clock().instant();
		@Nullable Snapshot current;
		this.lock.lock();
		try {
			current = observeClock(now);
			if (current != null && current.isFresh(now))
				return;
		} finally {
			this.lock.unlock();
		}

		resolve(null, deadline, observed);
	}

	// Called under lock. An observed rollback invalidates cached keys even inside their original TTL.
	private @Nullable Snapshot observeClock(@NonNull Instant now) {
		boolean rollback = this.lastClock != null && now.isBefore(this.lastClock);
		this.lastClock = now;
		if (rollback)
			this.snapshot = null;
		return this.snapshot;
	}

	private @Nullable KeySelection currentStaleSelection(@Nullable KeyQuery query) {
		this.lock.lock();
		try {
			Instant now = this.settings.clock().instant();
			return staleSelection(observeClock(now), query, now);
		} finally {
			this.lock.unlock();
		}
	}

	/**
	 * Waits until at least {@code count} callers are waiting for a flight another caller leads, so a test can hold a
	 * response until every caller has joined without polling (plan A-2).
	 *
	 * @param count   how many waiting callers to wait for
	 * @param timeout the longest wait
	 * @return whether that many callers were waiting
	 * @throws InterruptedException if interrupted while waiting
	 */
	@NonNull
	Boolean awaitWaitersForTests(@NonNull Integer count,
															 @NonNull Duration timeout) throws InterruptedException {
		requireNonNull(count);
		long remainingNanos = requireNonNull(timeout).toNanos();

		this.lock.lock();

		try {
			while (this.waiterCount < count) {
				if (remainingNanos <= 0)
					return false;

				remainingNanos = this.waitersChanged.awaitNanos(remainingNanos);
			}

			return true;
		} finally {
			this.lock.unlock();
		}
	}

	/**
	 * The URI the hooks report: the key set's URI cut to its scheme, host, port and path.
	 *
	 * @return the reported URI
	 */
	@NonNull
	URI getReportedUri() {
		return this.reportedUri;
	}

	/**
	 * The slow path: decide under the lock, then act outside it, until the call has its answer.
	 *
	 * @param query    the query, or {@code null} for {@link #warmUp(Deadline)}
	 * @param observed the snapshot the call read before it took this path, or {@code null} if there was none
	 * @return the selection, or {@code null} for a warm-up
	 */
	@Nullable
	private KeySelection resolve(@Nullable KeyQuery query,
															 @NonNull Deadline deadline,
															 @Nullable Snapshot observed) {
		while (true) {
			Decision decision = decide(query, deadline, observed);

			switch (decision.action) {
				case ANSWER -> {
					return decision.selection;
				}
				case SUPPRESS -> {
					Duration untilNextAttempt = requireNonNull(decision.untilNextAttempt);
					ObserverDispatch.dispatch(this.settings.observer(),
							hook -> hook.didSuppressJsonWebKeySetFetch(this.reportedUri, untilNextAttempt));

					if (decision.failure != null)
						throw decision.failure.toException();

					return decision.selection;
				}
				case REFUSE -> throw requireNonNull(decision.failure).toException();
				case LEAD -> {
					return lead(query, requireNonNull(decision.flight), decision.trigger, deadline);
				}
				case JOIN -> {
					FlightResult result = await(requireNonNull(decision.flight), deadline);

					switch (result.outcome) {
						case SUCCEEDED -> {
							return query == null ? null : KeySelector.select(requireNonNull(result.snapshot).keys(), query);
						}
						case FAILED -> {
							@Nullable KeySelection stale = decision.trigger == Trigger.EXPIRED
									? currentStaleSelection(query) : null;

							if (stale != null)
								return stale;

							throw requireNonNull(result.failure).toException();
						}
						case CUT_SHORT, ABANDONED -> {
							// Not a completed flight for this call: decide again.
						}
					}
				}
			}
		}
	}

	/**
	 * Applies the decision rules under the lock (see the class description).
	 *
	 * @param observed the snapshot the call read before it took the slow path; a flight cut short or abandoned never
	 *                 replaces it, so it stays the call's reference while the call decides again
	 */
	@NonNull
	private Decision decide(@Nullable KeyQuery query,
													@NonNull Deadline deadline,
													@Nullable Snapshot observed) {
		this.lock.lock();

		try {
			Instant now = this.settings.clock().instant();
			@Nullable Snapshot current = observeClock(now);

			// Rule 1: another caller's fetch completed since this call read the snapshot. The call rechecks against the new
			// snapshot and never fetches, so a key still missing from it is final for the call, as if it had joined that
			// fetch. A snapshot that is not fresh (a clock moved during the fetch) is decided on by the rules below.
			if (current != observed && current != null && current.isFresh(now))
				return Decision.answer(query == null ? null : KeySelector.select(current.keys(), query));

			Trigger trigger;

			// Otherwise the call decides on the snapshot as it is now.
			if (query == null) {
				if (current != null && current.isFresh(now))
					return Decision.answer(null);

				trigger = Trigger.WARM_UP;
			} else if (current == null) {
				trigger = Trigger.FIRST_USE;
			} else if (!current.isFresh(now)) {
				trigger = Trigger.EXPIRED;
			} else {
				KeySelection selection = KeySelector.select(current.keys(), query);

				if (selection.getKind() != KeySelection.Kind.UNKNOWN)
					return Decision.answer(selection);

				trigger = Trigger.UNKNOWN_KID;
			}

			@Nullable KeySelection stale = trigger == Trigger.EXPIRED ? staleSelection(current, query, now) : null;

			// Rule 2: join the flight in progress, unless stale keys answer at once. A flight its leader can no longer
			// publish (a VirtualMachineError can stop a leader before its finally runs) would otherwise hold every later
			// caller for its whole deadline: once it has outlived its leader's exchange by one more request timeout, it is
			// taken as cut short. Its attempt and any cooldown mark stay, there is no backoff step, the callers waiting on
			// it decide again, and this caller goes on to the rules below.
			@Nullable Flight inProgress = this.flight;

			if (inProgress != null && inProgress.isOverdue(System.nanoTime())) {
				this.flight = null;
				inProgress.result.complete(FlightResult.CUT_SHORT);
				inProgress = null;
			}

			if (inProgress != null) {
				if (stale != null)
					return Decision.answer(stale);

				++this.waiterCount;
				this.waitersChanged.signalAll();
				return Decision.join(inProgress, trigger);
			}

			// Rule 3: the backoff after a failure holds back every trigger.
			@Nullable Instant failureStart = this.failedAt;
			@Nullable Failure failure = this.lastFailure;

			if (failureStart != null && failure != null && applies(failureStart, this.backoff, now)) {
				Duration untilNextAttempt = remaining(failureStart, this.backoff, now);
				return stale != null ? Decision.suppress(stale, untilNextAttempt)
						: Decision.suppress(failure, untilNextAttempt);
			}

			// Rule 4: the unknown-key cooldown holds back unknown-key refetches only (variant A-prime).
			@Nullable Instant cooldownMark = this.lastUnknownKidFetchStart;
			Duration cooldown = this.settings.unknownKeyRefreshCooldown();

			if (trigger == Trigger.UNKNOWN_KID && cooldownMark != null && applies(cooldownMark, cooldown, now))
				return Decision.suppress(KeySelection.fromKind(KeySelection.Kind.UNKNOWN),
						remaining(cooldownMark, cooldown, now));

			// Rule 5: no more than two attempts start within one cooldown, whatever their outcome.
			@Nullable Instant latest = this.latestAttemptStart;
			@Nullable Instant earlier = this.earlierAttemptStart;

			if (latest != null && earlier != null && applies(latest, cooldown, now) && applies(earlier, cooldown, now)) {
				Duration untilNextAttempt = min(remaining(latest, cooldown, now), remaining(earlier, cooldown, now));

				if (stale != null)
					return Decision.suppress(stale, untilNextAttempt);

				if (trigger == Trigger.UNKNOWN_KID)
					return Decision.suppress(KeySelection.fromKind(KeySelection.Kind.UNKNOWN), untilNextAttempt);

				return Decision.suppress(new Failure(ErrorCategory.TRANSPORT, true), untilNextAttempt);
			}

			// Rule 6: lead, unless the flight would be abandoned before its request anyway. Such a caller sends nothing,
			// so it takes no cooldown mark and counts toward nothing.
			if (deadline.isExpired())
				return Decision.refuse(new Failure(ErrorCategory.TRANSPORT, true));

			if (Thread.currentThread().isInterrupted())
				return Decision.refuse(new Failure(ErrorCategory.TRANSPORT, false));

			// Everything this decision allocates comes before the field stores, so that as little as possible can fail
			// between registering the flight and the leader's finally that publishes it.
			long requestTimeoutNanos = this.settings.requestTimeout().toNanos();
			Flight started = new Flight(this.lastUnknownKidFetchStart, this.latestAttemptStart,
					this.earlierAttemptStart, System.nanoTime(),
					Math.min(deadline.remainingNanos(), requestTimeoutNanos) + requestTimeoutNanos);
			Decision leading = Decision.lead(started, trigger);

			this.flight = started;

			if (trigger == Trigger.UNKNOWN_KID)
				this.lastUnknownKidFetchStart = now;

			this.earlierAttemptStart = this.latestAttemptStart;
			this.latestAttemptStart = now;
			return leading;
		} finally {
			this.lock.unlock();
		}
	}

	/**
	 * Waits for another caller's flight within this caller's deadline.
	 *
	 * @throws JsonWebKeySetUnavailableException {@link ErrorCategory#TRANSPORT}: transient when the deadline ended,
	 *                                           and not transient, with the interrupt flag set again, when
	 *                                           interrupted
	 */
	@NonNull
	private FlightResult await(@NonNull Flight joined,
														 @NonNull Deadline deadline) {
		try {
			return joined.result.get(Math.max(0L, deadline.remainingNanos()), TimeUnit.NANOSECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw JsonWebKeySetUnavailableException.fromCategory(ErrorCategory.TRANSPORT, false);
		} catch (TimeoutException e) {
			throw JsonWebKeySetUnavailableException.fromCategory(ErrorCategory.TRANSPORT, true);
		} catch (ExecutionException e) {
			// A flight's future is only ever completed normally; were it not, deciding again is the safe answer.
			return FlightResult.CUT_SHORT;
		} finally {
			this.lock.lock();

			try {
				--this.waiterCount;
				this.waitersChanged.signalAll();
			} finally {
				this.lock.unlock();
			}
		}
	}

	/**
	 * Leads a flight: the exchange on this thread, then the outcome published, the flight completed and the hooks
	 * fired, in that order.
	 */
	@Nullable
	private KeySelection lead(@Nullable KeyQuery query,
														@NonNull Flight started,
														@NonNull Trigger trigger,
														@NonNull Deadline deadline) {
		long startNanos = System.nanoTime();
		JoseObserver observer = this.settings.observer();
		boolean executed = false;
		@Nullable Fetch attempt = null;

		try {
			@Nullable String unpatchedRuntimeVersion = this.settings.unpatchedRuntimeVersion();

			if (unpatchedRuntimeVersion != null)
				ObserverDispatch.dispatch(observer, hook -> hook.didUseUnpatchedRuntime(unpatchedRuntimeVersion));

			ObserverDispatch.dispatch(observer, hook -> hook.willFetchJsonWebKeySet(this.reportedUri));

			// From here on the flight is an attempt: the exchange may send its request.
			executed = true;
			attempt = fetch(deadline);
		} finally {
			publish(started, attempt, executed);
		}

		Fetch outcome = requireNonNull(attempt);
		Duration elapsed = Duration.ofNanos(Math.max(0L, System.nanoTime() - startNanos));

		switch (outcome.result) {
			case SUCCEEDED -> {
				Snapshot fetched = requireNonNull(outcome.snapshot);

				for (ParsedKeySet.Skip skip : outcome.skips)
					ObserverDispatch.dispatch(observer, hook -> hook.didSkipJsonWebKey(this.reportedUri, skip.index(),
							skip.reason()));

				Duration timeToLive = requireNonNull(outcome.timeToLive);
				ObserverDispatch.dispatch(observer, hook -> hook.didFetchJsonWebKeySet(this.reportedUri,
						fetched.keys().size(), outcome.skips.size(), timeToLive, elapsed));

				return query == null ? null : KeySelector.select(fetched.keys(), query);
			}
			case FAILED -> {
				Failure failure = requireNonNull(outcome.failure);
				JsonWebKeySetUnavailableException exception = JsonWebKeySetUnavailableException.fromCategory(
						failure.category, failure.transientFailure, outcome.cause);
				@Nullable KeySelection stale = trigger == Trigger.EXPIRED
						? currentStaleSelection(query) : null;
				ObserverDispatch.dispatch(observer, hook -> hook.didFailToFetchJsonWebKeySet(this.reportedUri, exception,
						stale != null, elapsed));

				if (stale != null)
					return stale;

				throw exception;
			}
			case INTERRUPTED -> {
				// HttpExchange has already set the thread's interrupt flag again.
				JsonWebKeySetUnavailableException exception = JsonWebKeySetUnavailableException.fromCategory(
						ErrorCategory.TRANSPORT, false);
				ObserverDispatch.dispatch(observer, hook -> hook.didFailToFetchJsonWebKeySet(this.reportedUri, exception,
						false, elapsed));
				throw exception;
			}
		}

		throw new IllegalStateException("Unknown fetch outcome.");
	}

	/**
	 * Runs the exchange and reads the key set: a snapshot, a failure with its category and transience, or the
	 * leader's interrupt. It never throws for anything the server sends.
	 */
	@NonNull
	private Fetch fetch(@NonNull Deadline deadline) {
		RawResponse response;

		try {
			response = this.httpExchange.execute(this.request, deadline);
		} catch (HttpExchangeException e) {
			return Fetch.fromExchangeFailure(e);
		}

		Instant receivedAt = this.settings.clock().instant();
		int status = response.status();

		if (!response.isSuccessful()) {
			// Any other status is an error (a 3xx never gets here): transient on 429 and 5xx (G6-3).
			boolean transientFailure = status == 429 || (status >= 500 && status <= 599);
			@Nullable Duration retryAfter = status == 429 || status == 503
					? RetryAfter.parse(response.headers(), receivedAt).orElse(null) : null;
			return Fetch.failed(new Failure(ErrorCategory.REMOTE_ERROR, transientFailure), null, retryAfter);
		}

		ParsedKeySet parsedKeySet;

		try {
			parsedKeySet = JwkSetParser.parse(response.body(), this.settings.maximumResponseBytes(),
					this.settings.maximumKeys());
		} catch (JoseFailure | RuntimeException e) {
			// A document failure, or anything unexpected in parsing (INV-G1): the response is malformed.
			return Fetch.failed(new Failure(ErrorCategory.MALFORMED_INPUT, false), null, null);
		}

		Duration timeToLive = CacheLifetime.timeToLive(response.headers(), receivedAt,
				this.settings.minimumTimeToLive(), this.settings.defaultTimeToLive(), this.settings.maximumTimeToLive());
		Instant expiresAt = plus(receivedAt, timeToLive);
		Snapshot fetched = new Snapshot(parsedKeySet.keys(), receivedAt, expiresAt,
				plus(expiresAt, this.settings.maximumStaleness()));

		return Fetch.succeeded(fetched, parsedKeySet.skips(), timeToLive);
	}

	/**
	 * Publishes a flight's outcome under the lock, clears the flight, then completes its future outside the lock. It
	 * runs in the leader's {@code finally}, so an {@link Error} that leaves the leader still publishes; a
	 * {@link VirtualMachineError} before that {@code finally} leaves the flight to be taken as cut short once it is
	 * overdue (rule 2). A flight taken as cut short, or replaced since, no longer clears the current flight or restores
	 * the marks, and its key set replaces the current one only if it is not older.
	 *
	 * @param fetch    the outcome, or {@code null} when the leader stopped with an {@link Error}
	 * @param executed whether the leader reached the exchange
	 */
	private void publish(@NonNull Flight finished,
											 @Nullable Fetch fetch,
											 boolean executed) {
		FlightResult result = FlightResult.CUT_SHORT;

		try {
			this.lock.lock();

			try {
				boolean current = this.flight == finished;

				if (current)
					this.flight = null;

				if (!executed) {
					// Abandoned before any request: nothing counts, so the marks go back to what they were, unless the
					// flight was already taken as cut short and counted.
					if (current) {
						this.lastUnknownKidFetchStart = finished.previousUnknownKidFetchStart;
						this.latestAttemptStart = finished.previousLatestAttemptStart;
						this.earlierAttemptStart = finished.previousEarlierAttemptStart;
					}

					result = FlightResult.ABANDONED;
				} else if (fetch != null && fetch.result == Fetch.Result.SUCCEEDED) {
					Snapshot fetched = requireNonNull(fetch.snapshot);
					@Nullable Snapshot existing = this.snapshot;

					if (current || existing == null || !fetched.fetchedAt.isBefore(existing.fetchedAt))
						this.snapshot = fetched;

					result = FlightResult.succeeded(fetched);
				} else if (fetch != null && fetch.result == Fetch.Result.FAILED) {
					Failure failure = requireNonNull(fetch.failure);
					recordFailure(this.settings.clock().instant(), failure, fetch.retryAfter);
					result = FlightResult.failed(failure);
				}
				// Otherwise cut short: the attempt and any cooldown mark stay, and there is no backoff step.
			} finally {
				this.lock.unlock();
			}
		} finally {
			finished.result.complete(result);
		}
	}

	/**
	 * Advances the negative cache for a failure at {@code now}. Called with the lock held.
	 */
	private void recordFailure(@NonNull Instant now,
														 @NonNull Failure failure,
														 @Nullable Duration retryAfter) {
		@Nullable Instant previousFailure = this.failedAt;
		int failures = this.consecutiveFailures;

		// Decay, not reset: one step less for each full cap interval since the previous failure. A previous failure
		// recorded in the future of now (a clock set back) earns no decay.
		if (previousFailure != null && !now.isBefore(previousFailure))
			failures = decayedFailureCount(failures, Duration.between(previousFailure, now), this.backoffCap);

		if (failures < Integer.MAX_VALUE)
			++failures;

		Duration step = backoffStep(this.settings.unknownKeyRefreshCooldown(), this.backoffCap, failures);

		if (retryAfter != null && retryAfter.compareTo(step) > 0)
			step = min(retryAfter, this.backoffCap);

		this.consecutiveFailures = failures;
		this.failedAt = now;
		this.backoff = step;
		this.lastFailure = failure;
	}

	/**
	 * The backoff cap for a cooldown: {@code max(cooldown, min(10 * cooldown, 10 min))}.
	 *
	 * @param cooldown the unknown-key cooldown
	 * @return the cap
	 */
	@NonNull
	static Duration backoffCap(@NonNull Duration cooldown) {
		Duration tenCooldowns = cooldown.multipliedBy(BACKOFF_CAP_COOLDOWNS);
		Duration capped = min(tenCooldowns, MAXIMUM_BACKOFF_CAP);
		return capped.compareTo(cooldown) < 0 ? cooldown : capped;
	}

	/**
	 * The backoff after the {@code failures}-th consecutive failure: {@code min(cooldown * 2^(failures-1), cap)}.
	 *
	 * @param cooldown the unknown-key cooldown
	 * @param cap      the backoff cap
	 * @param failures the consecutive failure count, at least 1
	 * @return the backoff step
	 */
	@NonNull
	static Duration backoffStep(@NonNull Duration cooldown,
															@NonNull Duration cap,
															int failures) {
		Duration step = cooldown;

		for (int doubling = 1; doubling < failures && step.compareTo(cap) < 0; ++doubling)
			step = step.multipliedBy(2);

		return min(step, cap);
	}

	/**
	 * The consecutive failure count after {@code sinceLastFailure} without a failure: one less for each full cap
	 * interval, never below zero.
	 *
	 * @param failures         the count at the last failure
	 * @param sinceLastFailure the time since the last failure, zero or positive
	 * @param cap              the backoff cap
	 * @return the decayed count
	 */
	static int decayedFailureCount(int failures,
																 @NonNull Duration sinceLastFailure,
																 @NonNull Duration cap) {
		long intervals = sinceLastFailure.dividedBy(cap);
		return intervals >= failures ? 0 : failures - (int) intervals;
	}

	/**
	 * The stale answer an {@code EXPIRED} caller may get: the selection from a usable snapshot, only when it found the
	 * key.
	 */
	@Nullable
	private static KeySelection staleSelection(@Nullable Snapshot usable,
																						 @Nullable KeyQuery query,
																						 @NonNull Instant now) {
		if (usable == null || query == null || !usable.isUsable(now))
			return null;

		KeySelection selection = KeySelector.select(usable.keys(), query);
		return selection.getKind() == KeySelection.Kind.FOUND ? selection : null;
	}

	/**
	 * Whether a window that started at {@code start} and lasts {@code duration} applies at {@code now}: a start in the
	 * future of {@code now} counts as elapsed.
	 */
	private static boolean applies(@NonNull Instant start,
																 @NonNull Duration duration,
																 @NonNull Instant now) {
		return !now.isBefore(start) && now.isBefore(plus(start, duration));
	}

	@NonNull
	private static Duration remaining(@NonNull Instant start,
																		@NonNull Duration duration,
																		@NonNull Instant now) {
		return Duration.between(now, plus(start, duration));
	}

	@NonNull
	private static Duration min(@NonNull Duration first,
															@NonNull Duration second) {
		return first.compareTo(second) <= 0 ? first : second;
	}

	/**
	 * {@code instant + duration}, saturating at {@link Instant#MAX} instead of failing.
	 */
	@NonNull
	static Instant plus(@NonNull Instant instant,
											@NonNull Duration duration) {
		try {
			return instant.plus(duration);
		} catch (DateTimeException | ArithmeticException e) {
			return duration.isNegative() ? Instant.MIN : Instant.MAX;
		}
	}

	/**
	 * The URI cut to its scheme, host, port and path, with no user information, query or fragment (G6-4).
	 *
	 * @param uri the URI
	 * @return the cut URI; an empty relative URI if nothing of it can be kept
	 */
	@NonNull
	static URI cut(@NonNull URI uri) {
		StringBuilder text = new StringBuilder();
		@Nullable String scheme = uri.getScheme();
		@Nullable String host = uri.getHost();
		@Nullable String path = uri.getRawPath();

		if (scheme != null)
			text.append(scheme).append(':');

		if (host != null) {
			text.append("//").append(host);

			if (uri.getPort() >= 0)
				text.append(':').append(uri.getPort());
		}

		if (path != null)
			text.append(path);

		try {
			return new URI(text.toString());
		} catch (URISyntaxException e) {
			return URI.create("");
		}
	}

	/**
	 * Why a call found no answer in a fresh snapshot.
	 */
	@Immutable
	private enum Trigger {
		FIRST_USE,
		EXPIRED,
		UNKNOWN_KID,
		WARM_UP
	}

	/**
	 * A failure's category and transience, which every caller but the leader receives without a cause.
	 */
	@Immutable
	private static final class Failure {
		@NonNull
		private final ErrorCategory category;
		private final boolean transientFailure;

		private Failure(@NonNull ErrorCategory category,
										boolean transientFailure) {
			this.category = category;
			this.transientFailure = transientFailure;
		}

		@NonNull
		JsonWebKeySetUnavailableException toException() {
			return JsonWebKeySetUnavailableException.fromCategory(this.category, this.transientFailure);
		}
	}

	/**
	 * An immutable key set: its usable keys and its lifetime.
	 */
	@Immutable
	static final class Snapshot {
		@NonNull
		private final List<@NonNull VerificationKey> keys;
		@NonNull
		private final Instant fetchedAt;
		@NonNull
		private final Instant expiresAt;
		@NonNull
		private final Instant usableUntil;

		Snapshot(@NonNull List<@NonNull VerificationKey> keys,
						 @NonNull Instant fetchedAt,
						 @NonNull Instant expiresAt,
						 @NonNull Instant usableUntil) {
			this.keys = List.copyOf(keys);
			this.fetchedAt = requireNonNull(fetchedAt);
			this.expiresAt = requireNonNull(expiresAt);
			this.usableUntil = requireNonNull(usableUntil);
		}

		@NonNull
		List<@NonNull VerificationKey> keys() {
			return this.keys;
		}

		boolean isFresh(@NonNull Instant now) {
			return !now.isBefore(this.fetchedAt) && now.isBefore(this.expiresAt);
		}

		boolean isUsable(@NonNull Instant now) {
			return !now.isBefore(this.fetchedAt) && now.isBefore(this.usableUntil);
		}
	}

	/**
	 * The fetch in progress. Its future is completed normally, by the leader or, once the flight is overdue, by the
	 * caller that takes it as cut short, and has no dependent stages. It remembers the marks from before it started,
	 * which an abandoned flight restores, and when it started on {@link System#nanoTime()}, with how long its leader
	 * may take: the leader's exchange, which is bounded by its deadline and the request timeout, and one more request
	 * timeout for the hooks and the parsing around it.
	 */
	@ThreadSafe
	private static final class Flight {
		@NonNull
		private final CompletableFuture<@NonNull FlightResult> result = new CompletableFuture<>();
		@Nullable
		private final Instant previousUnknownKidFetchStart;
		@Nullable
		private final Instant previousLatestAttemptStart;
		@Nullable
		private final Instant previousEarlierAttemptStart;
		private final long startNanos;
		private final long budgetNanos;

		private Flight(@Nullable Instant previousUnknownKidFetchStart,
									 @Nullable Instant previousLatestAttemptStart,
									 @Nullable Instant previousEarlierAttemptStart,
									 long startNanos,
									 long budgetNanos) {
			this.previousUnknownKidFetchStart = previousUnknownKidFetchStart;
			this.previousLatestAttemptStart = previousLatestAttemptStart;
			this.previousEarlierAttemptStart = previousEarlierAttemptStart;
			this.startNanos = startNanos;
			this.budgetNanos = budgetNanos;
		}

		/**
		 * Whether the flight is complete already, or has outlived the time its leader may take. A complete flight is
		 * still registered only when its leader's publish could not take the lock (a {@link VirtualMachineError} there),
		 * which no test can bring about; taking it at once keeps callers from joining it again and again until it is
		 * overdue.
		 *
		 * @param nowNanos the current {@link System#nanoTime()}
		 */
		boolean isOverdue(long nowNanos) {
			return this.result.isDone() || nowNanos - this.startNanos > this.budgetNanos;
		}
	}

	/**
	 * What waiters learn from a flight.
	 */
	@Immutable
	private static final class FlightResult {
		@NonNull
		private static final FlightResult CUT_SHORT = new FlightResult(Outcome.CUT_SHORT, null, null);
		@NonNull
		private static final FlightResult ABANDONED = new FlightResult(Outcome.ABANDONED, null, null);

		@NonNull
		private final Outcome outcome;
		@Nullable
		private final Snapshot snapshot;
		@Nullable
		private final Failure failure;

		private FlightResult(@NonNull Outcome outcome,
												 @Nullable Snapshot snapshot,
												 @Nullable Failure failure) {
			this.outcome = outcome;
			this.snapshot = snapshot;
			this.failure = failure;
		}

		@NonNull
		static FlightResult succeeded(@NonNull Snapshot snapshot) {
			return new FlightResult(Outcome.SUCCEEDED, snapshot, null);
		}

		@NonNull
		static FlightResult failed(@NonNull Failure failure) {
			return new FlightResult(Outcome.FAILED, null, failure);
		}

		@Immutable
		private enum Outcome {
			SUCCEEDED,
			FAILED,
			CUT_SHORT,
			ABANDONED
		}
	}

	/**
	 * What the leader's exchange produced.
	 */
	@Immutable
	private static final class Fetch {
		@NonNull
		private static final Fetch INTERRUPTED = new Fetch(Result.INTERRUPTED, null, List.of(), null, null, null, null);

		@NonNull
		private final Result result;
		@Nullable
		private final Snapshot snapshot;
		@NonNull
		private final List<ParsedKeySet.@NonNull Skip> skips;
		@Nullable
		private final Duration timeToLive;
		@Nullable
		private final Failure failure;
		@Nullable
		private final IOException cause;
		@Nullable
		private final Duration retryAfter;

		private Fetch(@NonNull Result result,
									@Nullable Snapshot snapshot,
									@NonNull List<ParsedKeySet.@NonNull Skip> skips,
									@Nullable Duration timeToLive,
									@Nullable Failure failure,
									@Nullable IOException cause,
									@Nullable Duration retryAfter) {
			this.result = result;
			this.snapshot = snapshot;
			this.skips = List.copyOf(skips);
			this.timeToLive = timeToLive;
			this.failure = failure;
			this.cause = cause;
			this.retryAfter = retryAfter;
		}

		@NonNull
		static Fetch succeeded(@NonNull Snapshot snapshot,
													 @NonNull List<ParsedKeySet.@NonNull Skip> skips,
													 @NonNull Duration timeToLive) {
			return new Fetch(Result.SUCCEEDED, snapshot, skips, timeToLive, null, null, null);
		}

		@NonNull
		static Fetch failed(@NonNull Failure failure,
												@Nullable IOException cause,
												@Nullable Duration retryAfter) {
			return new Fetch(Result.FAILED, null, List.of(), null, failure, cause, retryAfter);
		}

		/**
		 * Maps an exchange failure to its category and transience (the M2 plan's table; G8-8, G8-9).
		 */
		@NonNull
		static Fetch fromExchangeFailure(@NonNull HttpExchangeException exception) {
			return switch (exception.getKind()) {
				case INTERRUPTED -> INTERRUPTED;
				case TIMEOUT -> failed(new Failure(ErrorCategory.TRANSPORT, true), null, null);
				case IO -> failed(new Failure(ErrorCategory.TRANSPORT, true),
						exception.getCause() instanceof IOException ioException ? ioException : null, null);
				case REDIRECT -> failed(new Failure(ErrorCategory.REMOTE_ERROR, false), null, null);
				case TOO_LARGE, CONTENT_ENCODING, FRAMING, MEDIA_TYPE ->
						failed(new Failure(ErrorCategory.MALFORMED_INPUT, false), null, null);
				// The URI was checked at build(), so URI_REJECTED is an unreachable backstop (G8-9).
				case URI_REJECTED, DEFAULT_CLIENT_UNAVAILABLE, PINNED_TLS_UNAVAILABLE ->
						failed(new Failure(ErrorCategory.CONFIGURATION, false), null, null);
			};
		}

		@Immutable
		private enum Result {
			SUCCEEDED,
			FAILED,
			INTERRUPTED
		}
	}

	/**
	 * What {@link #decide(KeyQuery, Deadline, Snapshot)} chose.
	 */
	@Immutable
	private static final class Decision {
		@NonNull
		private final Action action;
		@Nullable
		private final KeySelection selection;
		@Nullable
		private final Failure failure;
		@Nullable
		private final Duration untilNextAttempt;
		@Nullable
		private final Flight flight;
		@NonNull
		private final Trigger trigger;

		private Decision(@NonNull Action action,
										 @Nullable KeySelection selection,
										 @Nullable Failure failure,
										 @Nullable Duration untilNextAttempt,
										 @Nullable Flight flight,
										 @NonNull Trigger trigger) {
			this.action = action;
			this.selection = selection;
			this.failure = failure;
			this.untilNextAttempt = untilNextAttempt;
			this.flight = flight;
			this.trigger = trigger;
		}

		@NonNull
		static Decision answer(@Nullable KeySelection selection) {
			return new Decision(Action.ANSWER, selection, null, null, null, Trigger.FIRST_USE);
		}

		@NonNull
		static Decision suppress(@NonNull KeySelection selection,
														 @NonNull Duration untilNextAttempt) {
			return new Decision(Action.SUPPRESS, selection, null, untilNextAttempt, null, Trigger.FIRST_USE);
		}

		@NonNull
		static Decision suppress(@NonNull Failure failure,
														 @NonNull Duration untilNextAttempt) {
			return new Decision(Action.SUPPRESS, null, failure, untilNextAttempt, null, Trigger.FIRST_USE);
		}

		@NonNull
		static Decision refuse(@NonNull Failure failure) {
			return new Decision(Action.REFUSE, null, failure, null, null, Trigger.FIRST_USE);
		}

		@NonNull
		static Decision join(@NonNull Flight flight,
												 @NonNull Trigger trigger) {
			return new Decision(Action.JOIN, null, null, null, flight, trigger);
		}

		@NonNull
		static Decision lead(@NonNull Flight flight,
												 @NonNull Trigger trigger) {
			return new Decision(Action.LEAD, null, null, null, flight, trigger);
		}

		@Immutable
		private enum Action {
			ANSWER,
			SUPPRESS,
			REFUSE,
			JOIN,
			LEAD
		}
	}
}
