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
import com.revetsec.oauth.*;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

final class UserInfoAttemptGateTests {
	private static final Duration REQUEST = Duration.ofSeconds(1);
	private static Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
	private static OAuthException failure() { return OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.NETWORK_FAILURE); }
	@Test
	void concurrentHealthyCompletionDoesNotMaskANewFailureAndOldSuccessCannotClearIt() {
		AtomicLong time = new AtomicLong(); UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), time::get);
		UserInfoAttemptGate.Attempt first = gate.acquire(deadline(), REQUEST), second = gate.acquire(deadline(), REQUEST), third = gate.acquire(deadline(), REQUEST);
		gate.healthy(first); OAuthException failed = failure(); gate.failed(second, failed); gate.healthy(third);
		assertSame(failed, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST)));
		time.set(Duration.ofSeconds(1).toNanos()); UserInfoAttemptGate.Attempt recovery = gate.acquire(deadline(), REQUEST);
		assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST)).getReason());
		gate.healthy(recovery); gate.failed(third, failure()); gate.healthy(gate.acquire(deadline(), REQUEST));
	}
	@Test
	void overdueReplacementCannotBePoisonedOrClearedByOldProbe() {
		AtomicLong time = new AtomicLong(); UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), time::get);
		gate.failed(gate.acquire(deadline(), REQUEST), failure()); time.set(Duration.ofSeconds(1).toNanos());
		UserInfoAttemptGate.Attempt old = gate.acquire(deadline(), REQUEST); time.addAndGet(Duration.ofSeconds(3).toNanos());
		UserInfoAttemptGate.Attempt replacement = gate.acquire(deadline(), REQUEST); gate.healthy(old); gate.failed(old, failure());
		assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST)).getReason());
		OAuthException newest = failure(); gate.failed(replacement, newest); assertSame(newest, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST)));
	}
	@Test
	void exponentialBackoffIsMonotonicAndCappedAndRecoveryResetsIt() {
		AtomicLong time = new AtomicLong(); UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), time::get);
		for (int seconds : new int[]{1, 2, 4, 8, 10, 10, 10}) {
			OAuthException failed = failure(); gate.failed(gate.acquire(deadline(), REQUEST), failed);
			time.addAndGet(Duration.ofSeconds(seconds).toNanos() - 1); assertSame(failed, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST))); time.incrementAndGet();
		}
		gate.healthy(gate.acquire(deadline(), REQUEST)); gate.failed(gate.acquire(deadline(), REQUEST), failure());
		time.addAndGet(Duration.ofSeconds(1).toNanos()); gate.healthy(gate.acquire(deadline(), REQUEST));
	}
	@Test
	void retryAfterIsCappedAtTenMinutesAndNeverShortensNormalBackoff() {
		for (Duration retry : new Duration[]{Duration.ofDays(1000), Duration.ZERO}) {
			AtomicLong time = new AtomicLong(); UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), time::get);
			OAuthException failed = OidcTransactionAccess.get().endpointStatusFailure(429, retry); gate.failed(gate.acquire(deadline(), REQUEST), failed);
			long delay = (retry.isZero() ? Duration.ofSeconds(1) : Duration.ofMinutes(10)).toNanos();
			time.set(delay - 1); assertSame(failed, assertThrows(OAuthException.class, () -> gate.acquire(deadline(), REQUEST))); time.incrementAndGet(); gate.healthy(gate.acquire(deadline(), REQUEST));
		}
	}
	@Test
	void interruptionsAndNonTransientErrorsDoNotPoisonOtherCredentials() {
		AtomicLong time = new AtomicLong(); UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), time::get);
		gate.failed(gate.acquire(deadline(), REQUEST), OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.INTERRUPTED));
		gate.failed(gate.acquire(deadline(), REQUEST), OidcTransactionAccess.get().endpointStatusFailure(401, null));
		gate.healthy(gate.acquire(deadline(), REQUEST));
	}
}
