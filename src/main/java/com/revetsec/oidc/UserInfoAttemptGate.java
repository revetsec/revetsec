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

package com.revetsec.oidc;

import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthErrorResponseException;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * Endpoint-wide transient-failure backoff, without storing tokens, subjects or successful UserInfo. Healthy calls
 * may run concurrently; after a transient failure only one recovery probe may run. Old calls cannot reset newer
 * health state, and overdue probes may be replaced. No request is automatically retried.
 */
@ThreadSafe
final class UserInfoAttemptGate {
	private final ReentrantLock lock = new ReentrantLock();
	private final Duration cooldown;
	private final LongSupplier nanoTime;
	private @Nullable OAuthException failure;
	private @Nullable Attempt probe;
	private long generation;
	private int failures;
	private int consecutiveServerFailures;
	private long failedAtNanos;
	private long backoffNanos;
	UserInfoAttemptGate(@NonNull Duration cooldown, @NonNull LongSupplier nanoTime) { this.cooldown = cooldown; this.nanoTime = nanoTime; }
	@NonNull Attempt acquire(@NonNull Deadline deadline, @NonNull Duration requestTimeout) {
		requireActive(deadline);
		this.lock.lock();
		try {
			requireActive(deadline);
			long now = this.nanoTime.getAsLong();
			if (this.failure != null && now - this.failedAtNanos < this.backoffNanos)
				throw OidcTransactionAccess.get().copyEndpointFailure(this.failure);
			if (this.probe != null && now - this.probe.startedNanos > this.probe.overdueAfterNanos) {
				this.probe = null; this.generation++;
			}
			if (this.probe != null) throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.ATTEMPT_LIMIT);
			long budget = Math.min(Math.max(0, deadline.remainingNanos()), requestTimeout.toNanos()) + requestTimeout.toNanos();
			Attempt attempt = new Attempt(this.generation, now, budget, deadline);
			if (this.failure != null) this.probe = attempt;
			return attempt;
		} finally { this.lock.unlock(); }
	}
	void healthy(@NonNull Attempt attempt) {
		this.lock.lock();
		try {
			if (attempt.generation == this.generation && this.failure != null) {
				this.failure = null; this.failures = 0; this.consecutiveServerFailures = 0; this.generation++;
			}
			else if (attempt.generation == this.generation) this.consecutiveServerFailures = 0;
			if (this.probe == attempt) this.probe = null;
		} finally { this.lock.unlock(); }
	}
	void failed(@NonNull Attempt attempt, @NonNull OAuthException failure) {
		boolean interrupted = failure.getReason() == OAuthException.Reason.INTERRUPTED
				|| Thread.currentThread().isInterrupted();
		boolean callerLocal = interrupted || attempt.deadline.isExpired();
		if (interrupted) Thread.currentThread().interrupt();
		this.lock.lock();
		try {
			if (attempt.generation == this.generation && failure.isTemporaryCondition() && !callerLocal) {
				boolean serverFailure = failure instanceof OAuthErrorResponseException error
						&& error.getStatus() >= 500 && error.getStatus() < 600;
				boolean record = !serverFailure || ++this.consecutiveServerFailures >= 3;
				if (record) {
					this.consecutiveServerFailures = 0;
					this.failure = OidcTransactionAccess.get().copyEndpointFailure(failure);
					this.failedAtNanos = this.nanoTime.getAsLong(); this.generation++;
					this.failures = Math.min(5, this.failures + 1);
					this.backoffNanos = Math.min(this.cooldown.toNanos() << (this.failures - 1),
							Math.min(this.cooldown.toNanos() * 10, Duration.ofMinutes(10).toNanos()));
				}
				if (record && failure instanceof OAuthErrorResponseException error) {
					Duration delay = error.getRetryAfter().orElse(Duration.ZERO);
					long nanos = delay.compareTo(Duration.ofMinutes(10)) >= 0 ? Duration.ofMinutes(10).toNanos() : delay.toNanos();
					this.backoffNanos = Math.max(this.backoffNanos, nanos);
				}
			}
			if (this.probe == attempt) this.probe = null;
		} finally { this.lock.unlock(); }
	}
	// No credential or subject is used as a cache key or retained by this lease.
	static final class Attempt {
		final long generation;
		final long startedNanos;
		final long overdueAfterNanos;
		final @NonNull Deadline deadline;
		Attempt(long generation, long startedNanos, long overdueAfterNanos, @NonNull Deadline deadline) {
			this.generation = generation; this.startedNanos = startedNanos; this.overdueAfterNanos = overdueAfterNanos;
			this.deadline = deadline;
		}
	}
	private static void requireActive(@NonNull Deadline deadline) {
		if (Thread.currentThread().isInterrupted())
			throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.INTERRUPTED);
		if (deadline.isExpired())
			throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.NETWORK_FAILURE);
	}
}
