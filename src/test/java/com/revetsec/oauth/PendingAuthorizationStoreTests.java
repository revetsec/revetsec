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

import com.revetsec.ErrorCategory;
import com.revetsec.testing.RewindableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PendingAuthorizationStoreTests {
	private static final Instant START = Instant.parse("2026-09-28T12:00:00Z");

	@Test
	void boundedStoreRejectsLiveCountWithoutEviction() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder()
				.maximumLiveEntries(16).clock(clock).build();
		for (int i = 0; i < 16; i++)
			store.save("browser", "state-" + i, "record", START.plusSeconds(60));
		PendingAuthorizationStoreException full = assertThrows(PendingAuthorizationStoreException.class,
				() -> store.save("browser", "overflow", "record", START.plusSeconds(60)));
		assertEquals(OAuthException.Reason.CAPACITY_EXCEEDED, full.getReason());
		assertEquals(ErrorCategory.CONFIGURATION, full.getCategory());
		assertFalse(full.isTransient());
		assertEquals("record", store.consume("browser", "state-0").orElseThrow());
		store.save("browser", "replacement", "record", START.plusSeconds(60));
	}

	@Test
	void chargesUtf8BytesAndRejectsDuplicateAndOversize() {
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder()
				.maximumChargedBytes(64L * 1_024).maximumOpaqueRecordBytes(64 * 1_024)
				.clock(RewindableClock.fromInstant(START)).build();
		String record = "€".repeat(13_000); // 39,000 UTF-8 bytes, 13,000 UTF-16 units.
		store.save("binding", "a", record, START.plusSeconds(60));
		assertThrows(IllegalArgumentException.class,
				() -> store.save("binding", "a", "other", START.plusSeconds(60)));
		assertThrows(PendingAuthorizationStoreException.class,
				() -> store.save("binding", "b", record, START.plusSeconds(60)));
		assertThrows(IllegalArgumentException.class,
				() -> store.save("binding", "c", "x".repeat(65_537), START.plusSeconds(60)));
		assertEquals(record, store.consume("binding", "a").orElseThrow());
	}

	@Test
	void expiryIsExactAndNeverExtendedByStore() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(clock).build();
		assertThrows(IllegalArgumentException.class,
				() -> store.save("b", "past", "r", START));
		assertThrows(IllegalArgumentException.class,
				() -> store.save("b", "future", "r", START.plus(Duration.ofMinutes(60)).plusNanos(1)));
		store.save("b", "one", "r", START.plus(Duration.ofMinutes(1)));
		store.save("b", "sixty", "r", START.plus(Duration.ofMinutes(60)));
		clock.advance(Duration.ofMinutes(1));
		assertTrue(store.consume("b", "one").isEmpty());
		assertEquals("r", store.consume("b", "sixty").orElseThrow());
	}

	@Test
	void concurrentConsumeReturnsRecordOnce() throws Exception {
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder()
				.clock(RewindableClock.fromInstant(START)).build();
		store.save("browser", "state", "record", START.plusSeconds(60));
		int callers = 32;
		CountDownLatch start = new CountDownLatch(1);
		ExecutorService executor = Executors.newFixedThreadPool(callers);
		try {
			List<Future<Boolean>> results = new ArrayList<>();
			for (int i = 0; i < callers; i++)
				results.add(executor.submit(() -> {
					start.await();
					return store.consume("browser", "state").isPresent();
				}));
			start.countDown();
			int successes = 0;
			for (Future<Boolean> result : results)
				if (result.get())
					successes++;
			assertEquals(1, successes);
		} finally {
			executor.shutdownNow();
		}
	}
}
