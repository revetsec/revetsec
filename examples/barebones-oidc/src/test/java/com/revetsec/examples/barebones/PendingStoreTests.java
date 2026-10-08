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
package com.revetsec.examples.barebones;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Optional;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

final class PendingStoreTests {
	@Test
	void exhaustedBudgetLeavesRecordAvailableForAValidConsume() {
		var clock = new OidcApplicationTests.MutableClock();
		PendingStore store = new PendingStore(clock, 16, 65_536);
		store.save("browser", "state", "opaque", clock.instant().plusSeconds(60), Duration.ofSeconds(2));
		assertThrows(IllegalStateException.class, () -> store.consume("browser", "state", Duration.ZERO));
		assertEquals(Optional.of("opaque"), store.consume("browser", "state", Duration.ofSeconds(2)));
	}
    @Test
    void atomicConsumeHasOneWinnerAndBindingCannotBeSwapped() throws Exception {
        var clock = new OidcApplicationTests.MutableClock();
        var store = new PendingStore(clock, 2, 4096);
        store.save("browser", "state", "opaque", clock.instant().plusSeconds(60));
        assertTrue(store.consume("other-browser", "state").isEmpty());
        assertTrue(store.consume("browser", "other-state").isEmpty());
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            var attempts = new ArrayList<Future<Optional<String>>>();
            for (int index = 0; index < 32; index++) attempts.add(executor.submit(() -> store.consume("browser", "state")));
            int winners = 0;
            for (var attempt : attempts) if (attempt.get().isPresent()) winners++;
            assertEquals(1, winners); assertEquals(0, store.size());
        } finally { executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)); }
    }

    @Test
    void expiryByteEntryDuplicateAndRegressionGuardsNeverEvictLiveRecord() {
        var clock = new OidcApplicationTests.MutableClock();
        var store = new PendingStore(clock, 1, 1024);
        store.save("browser", "state", "opaque", clock.instant().plusSeconds(60));
        assertThrows(IllegalArgumentException.class, () -> store.save("browser", "state", "new", clock.instant().plusSeconds(60)));
        assertThrows(PendingStore.CapacityException.class, () -> store.save("other", "state", "new", clock.instant().plusSeconds(60)));
        assertEquals(Optional.of("opaque"), store.consume("browser", "state"));
        assertThrows(PendingStore.CapacityException.class, () -> store.save("browser", "state", "x".repeat(1024), clock.instant().plusSeconds(60)));
        assertThrows(IllegalArgumentException.class, () -> store.save("browser", "state", "opaque", clock.instant()));
        assertThrows(IllegalArgumentException.class, () -> store.save("browser", "state", "opaque", clock.instant().plusSeconds(901)));
        store.save("browser", "state", "opaque", clock.instant().plusSeconds(60));
        clock.advance(Duration.ofSeconds(60)); assertTrue(store.consume("browser", "state").isEmpty());
        store.save("browser", "state", "opaque", clock.instant().plusSeconds(60));
        clock.advance(Duration.ofSeconds(-1)); assertTrue(store.consume("browser", "state").isEmpty());
    }

    @Test
    void discardBindingRemovesAllItsFlowsAndReturnsCapacity() {
        var clock = new OidcApplicationTests.MutableClock();
        var store = new PendingStore(clock, 2, 1024);
        store.save("browser", "first", "opaque", clock.instant().plusSeconds(60));
        store.save("browser", "second", "opaque", clock.instant().plusSeconds(60));
        store.discardBinding("browser"); assertEquals(0, store.size());
        store.save("other", "third", "opaque", clock.instant().plusSeconds(60));
        assertEquals(Optional.of("opaque"), store.consume("other", "third"));
    }
}
