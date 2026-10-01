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
 * Endpoint-wide provider-failure backoff. Never stores credentials or credential verdicts. RFC7662 section2.2.
 */
@ThreadSafe
final class IntrospectionFailureGuard {

	private final ReentrantLock lock = new ReentrantLock();

	private final Condition waiterChanged = this.lock.newCondition();

	private final Duration cooldown;

	private final LongSupplier nanoTime;

	@Nullable
	private OAuthException failure;

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
			if (deadline.isExpired())
				throw unavailable();
			if (Thread.currentThread().isInterrupted())
				throw OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
			Attempt waitFor;
			this.lock.lock();
			try {
				long now = this.nanoTime.getAsLong();
				if (this.failure != null && now - this.failedAtNanos < this.backoffNanos)
					throw this.failure;
				if (this.probe != null && now - this.probe.startedNanos > this.probe.overdueAfterNanos) {
					this.probe.future.completeExceptionally(unavailable());
					this.probe = null;
					this.generation++;
				}
				if (this.probe == null) {
					long budget = Math.min(Math.max(0, deadline.remainingNanos()), requestTimeout.toNanos()) + requestTimeout.toNanos();
					Attempt attempt = new Attempt(this.generation, now, budget);
					if (this.failure != null)
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
			if (attempt.generation == this.generation && this.failure != null) {
				this.failure = null;
				this.failures = 0;
				this.generation++;
			}
			if (this.probe == attempt) {
				this.probe = null;
				attempt.future.complete(true);
			}
		} finally {
			this.lock.unlock();
		}
	}

	void failed(@NonNull Attempt attempt, @NonNull OAuthException failure) {
		this.lock.lock();
		try {
			if (attempt.generation == this.generation && failure.getReason() != OAuthException.Reason.INTERRUPTED) {
				this.failure = failure;
				this.failedAtNanos = this.nanoTime.getAsLong();
				this.generation++;
				this.failures = Math.min(5, this.failures + 1);
				this.backoffNanos = Math.min(this.cooldown.toNanos() << (this.failures - 1), Math.min(this.cooldown.toNanos() * 10, Duration.ofMinutes(10).toNanos()));
				if (failure instanceof OAuthErrorResponseException error) {
					Duration delay = error.getRetryAfter().orElse(Duration.ZERO);
					long nanos = delay.compareTo(Duration.ofMinutes(10)) >= 0 ? Duration.ofMinutes(10).toNanos() : delay.toNanos();
					this.backoffNanos = Math.max(this.backoffNanos, nanos);
				}
			}
			if (this.probe == attempt) {
				this.probe = null;
				attempt.future.completeExceptionally(failure);
			}
		} finally {
			this.lock.unlock();
		}
	}

	void abandon(@NonNull Attempt attempt) {
		this.lock.lock();
		try {
			if (this.probe == attempt) {
				this.probe = null;
				attempt.future.completeExceptionally(unavailable());
			}
		} finally {
			this.lock.unlock();
		}
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
			if (failure.getCause() instanceof OAuthException oauth)
				throw oauth;
			throw unavailable();
		}
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
