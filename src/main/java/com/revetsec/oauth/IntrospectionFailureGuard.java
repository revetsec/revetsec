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

import com.revetsec.internal.http.Deadline;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.function.LongSupplier;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Endpoint health only: 401/429 or transport failure opens backoff immediately; three 5xx responses
 * within one cooldown window open it without retaining a credential verdict. RFC7662 section2.2.
 */
@ThreadSafe
final class IntrospectionFailureGuard {

	private final ReentrantLock lock = new ReentrantLock();

	private final Condition waiterChanged = this.lock.newCondition();

	private final Duration cooldown;

	private final LongSupplier nanoTime;

	private boolean unhealthy;
	private static final int SERVER_FAILURE_THRESHOLD = 3;
	private int serverFailures;
	private long serverWindowStartedNanos;
	private long serverRetryAfterNanos;

	@Nullable
	private Attempt probe;

	private long generation;

	private int failures;

	private long failedAtNanos;

	private long backoffNanos;

	private int waiters;

	IntrospectionFailureGuard(@NonNull Duration cooldown, @NonNull LongSupplier nanoTime) {
		this.cooldown = cooldown;
		this.nanoTime = nanoTime;
	}

	@NonNull Attempt acquire(@NonNull Deadline deadline, @NonNull Duration requestTimeout) {
		for (; ; ) {
			requireActive(deadline);
			Attempt waitFor;
			this.lock.lock();
			try {
				requireActive(deadline);
				long now = this.nanoTime.getAsLong();
				if (this.unhealthy && now - this.failedAtNanos < this.backoffNanos)
					throw unavailable();
				if (this.probe != null && now - this.probe.startedNanos > this.probe.overdueAfterNanos) {
					this.probe.future.completeExceptionally(unavailable());
					this.probe = null;
					this.generation++;
				}
				if (this.probe == null) {
					long budget = Math.min(Math.max(0, deadline.remainingNanos()), requestTimeout.toNanos()) + requestTimeout.toNanos();
					Attempt attempt = new Attempt(this.generation, now, budget);
					if (this.unhealthy)
						this.probe = attempt;
					return attempt;
				}
				waitFor = this.probe;
				this.waiters++;
				this.waiterChanged.signalAll();
			} finally {
				this.lock.unlock();
			}
			try {
				await(waitFor.future, deadline);
			} finally {
				this.lock.lock();
				try {
					this.waiters--;
					this.waiterChanged.signalAll();
				} finally {
					this.lock.unlock();
				}
			}
			// Only health is shared. Every awakened caller acquires its own attempt and POSTs its own credential.
		}
	}

	void healthy(@NonNull Attempt attempt) {
		this.lock.lock();
		try {
			if (attempt.generation == this.generation) {
				this.serverFailures = 0;
				this.serverRetryAfterNanos = 0;
				this.failures = 0;
				if (this.unhealthy) {
					this.unhealthy = false;
					this.generation++;
				}
			}
			if (this.probe == attempt) {
				this.probe = null;
				attempt.future.complete(true);
			}
		} finally { this.lock.unlock(); }
	}

	void failed(@NonNull Attempt attempt, @NonNull OAuthException failure) {
		if (failure.getReason() == OAuthException.Reason.INTERRUPTED) {
			abandon(attempt);
			return;
		}
		boolean serverError = failure instanceof OAuthErrorResponseException response
				&& response.getStatus() >= 500 && response.getStatus() <= 599;
		boolean endpointSignal = failure instanceof OAuthErrorResponseException response
				? response.getStatus() == 401 || response.getStatus() == 429
				: failure instanceof OAuthTransportException && failure.getReason() == OAuthException.Reason.NETWORK_FAILURE;
		if (!endpointSignal && !serverError) {
			finishWithoutHealth(attempt, true);
			return;
		}
		this.lock.lock();
		try {
			boolean opened = false;
			if (attempt.generation == this.generation) {
				long now = this.nanoTime.getAsLong();
				if (this.serverFailures != 0 && now - this.serverWindowStartedNanos >= this.cooldown.toNanos()) {
					this.serverFailures = 0;
					this.serverRetryAfterNanos = 0;
				}
				if (serverError) {
					if (this.serverFailures == 0 || now - this.serverWindowStartedNanos >= this.cooldown.toNanos()) {
						this.serverWindowStartedNanos = now;
						this.serverFailures = 0;
						this.serverRetryAfterNanos = 0;
					}
					this.serverFailures++;
					this.serverRetryAfterNanos = Math.max(this.serverRetryAfterNanos, retryAfterNanos(failure));
				}
				if (endpointSignal || this.serverFailures >= SERVER_FAILURE_THRESHOLD) {
					this.unhealthy = true;
					this.failedAtNanos = now;
					this.generation++;
					this.failures = Math.min(5, this.failures + 1);
					this.backoffNanos = Math.min(this.cooldown.toNanos() << (this.failures - 1),
							Math.min(this.cooldown.toNanos() * 10, Duration.ofMinutes(10).toNanos()));
					this.backoffNanos = Math.max(this.backoffNanos, Math.max(this.serverRetryAfterNanos, retryAfterNanos(failure)));
					this.serverFailures = 0;
					this.serverRetryAfterNanos = 0;
					opened = true;
				}
			}
			if (this.probe == attempt) {
				this.probe = null;
				if (!opened) this.generation++;
				attempt.future.completeExceptionally(unavailable());
			}
		} finally { this.lock.unlock(); }
	}

	void abandon(@NonNull Attempt attempt) { finishWithoutHealth(attempt, false); }

	private void finishWithoutHealth(@NonNull Attempt attempt, boolean retryWaiters) {
		this.lock.lock();
		try {
			if (this.probe == attempt) {
				this.probe = null;
				this.generation++;
				if (retryWaiters) attempt.future.complete(true);
				else attempt.future.completeExceptionally(unavailable());
			}
		} finally { this.lock.unlock(); }
	}

	boolean awaitWaitersForTests(int expected, @NonNull Duration timeout) throws InterruptedException {
		long remaining = timeout.toNanos();
		this.lock.lock();
		try {
			while (this.waiters < expected && remaining > 0) remaining = this.waiterChanged.awaitNanos(remaining);
			return this.waiters >= expected;
		} finally {
			this.lock.unlock();
		}
	}

	private static void await(@NonNull CompletableFuture<@NonNull Boolean> future, @NonNull Deadline deadline) {
		try {
			long remaining = deadline.remainingNanos();
			if (remaining <= 0)
				throw unavailable();
			future.get(remaining, TimeUnit.NANOSECONDS);
		} catch (InterruptedException interrupted) {
			Thread.currentThread().interrupt();
			throw OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
		} catch (TimeoutException timeout) {
			throw unavailable();
		} catch (ExecutionException failure) {
			// A shared probe carries health only; every waiter receives its own exception.
			throw unavailable();
		}
	}

	private static void requireActive(@NonNull Deadline deadline) {
		if (Thread.currentThread().isInterrupted())
			throw OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
		if (deadline.isExpired()) throw unavailable();
	}

	private static long retryAfterNanos(@NonNull OAuthException failure) {
		if (!(failure instanceof OAuthErrorResponseException response)) return 0;
		Duration delay = response.getRetryAfter().orElse(Duration.ZERO);
		if (delay.isNegative()) return 0;
		return delay.compareTo(Duration.ofMinutes(10)) >= 0 ? Duration.ofMinutes(10).toNanos() : delay.toNanos();
	}

	private static @NonNull OAuthTransportException unavailable() {
		return OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
	}

	static final class Attempt {

		final long generation;

		final long startedNanos;

		final long overdueAfterNanos;

		final CompletableFuture<Boolean> future = new CompletableFuture<>();

		Attempt(long generation, long startedNanos, long overdueAfterNanos) {
			this.generation = generation;
			this.startedNanos = startedNanos;
			this.overdueAfterNanos = overdueAfterNanos;
		}
	}
}
