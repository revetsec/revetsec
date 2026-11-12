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

import com.revetsec.BrowserBinding;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BiFunction;
import static org.junit.jupiter.api.Assertions.*;

final class PendingAuthorizationSaveResultTests {
	private static final Instant NOW = Instant.parse("2026-09-28T12:00:00Z");

	@Test void providerOutcomesAreExplicitAndNeverAutomaticallyRetried() {
		for (PendingAuthorizationSaveResult outcome : PendingAuthorizationSaveResult.values()) {
			AtomicInteger calls = new AtomicInteger();
			PendingAuthorizationStore store = provider((opaque, remaining) -> {
				calls.incrementAndGet(); assertFalse(opaque.isEmpty());
				assertTrue(remaining.compareTo(Duration.ZERO) > 0); return outcome;
			});
			assertSame(outcome, pending().saveToResult(store, "TEST-ONLY-binding"));
			assertEquals(1, calls.get()); assertFalse(outcome.toString().contains("TEST-ONLY"));
		}
	}

	@Test void typedOAuthBoundaryAcceptsExact65536ButRetainsStrictUtf8BeforeStoreEntry() {
		AtomicInteger calls = new AtomicInteger();
		AtomicReference<String> received = new AtomicReference<>();
		PendingAuthorizationStore store = new PendingAuthorizationStore() {
			@Override public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding,
					@NonNull String state, @NonNull String opaque, @NonNull Instant expiry,
					@NonNull Duration remaining) {
				calls.incrementAndGet(); received.set(binding); return PendingAuthorizationSaveResult.SAVED;
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding,
					@NonNull String state, @NonNull Duration remaining) { return Optional.empty(); }
		};
		String exact = "a".repeat(BrowserBinding.MAXIMUM_CODE_UNITS);
		assertEquals(PendingAuthorizationSaveResult.SAVED,
				pending().saveToResult(store, BrowserBinding.fromTrustedPersistence(exact)));
		assertSame(exact, received.get());
		assertEquals(1, calls.get());
		assertThrows(IllegalArgumentException.class,
				() -> BrowserBinding.fromTrustedPersistence(exact + "a"));

		BrowserBinding malformed = BrowserBinding.fromTrustedPersistence("oauth-\uD800");
		assertThrows(IllegalArgumentException.class,
				() -> pending().saveToResult(store, malformed));
		assertEquals(1, calls.get());
	}

	@Test void expiredOrInterruptedBudgetRefusesBeforeDispatchWithoutClearingTheFlag() {
		AtomicInteger calls = new AtomicInteger();
		PendingAuthorizationStore store = provider((opaque, remaining) -> {
			calls.incrementAndGet(); return PendingAuthorizationSaveResult.SAVED;
		});
		PendingAuthorization pending = pending();
		assertEquals(PendingAuthorizationSaveResult.UNAVAILABLE, pending.saveToResult(store, "binding", Duration.ZERO));
		assertEquals(PendingAuthorizationSaveResult.UNAVAILABLE, pending.saveToResult(store, "binding", Duration.ofSeconds(-1)));
		try {
			Thread.currentThread().interrupt();
			assertEquals(PendingAuthorizationSaveResult.UNAVAILABLE, pending.saveToResult(store, "binding"));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally { Thread.interrupted(); }
		assertEquals(0, calls.get());
	}

	@Test void nullOrFaultAfterDispatchDoesNotClaimTheRecordWasAbsent() {
		for (boolean throwsAfterWrite : new boolean[]{false, true}) {
			AtomicInteger calls = new AtomicInteger(); AtomicReference<String> recorded = new AtomicReference<>();
			PendingAuthorizationStore store = provider((opaque, remaining) -> {
				calls.incrementAndGet(); recorded.set(opaque);
				if (throwsAfterWrite) throw new IllegalStateException("TEST-ONLY-private-store-detail");
				return null;
			});
			assertEquals(PendingAuthorizationSaveResult.INDETERMINATE, pending().saveToResult(store, "binding"));
			assertNotNull(recorded.get()); assertEquals(1, calls.get());
		}
	}

	@Test void lateProviderReturnIsIndeterminateEvenWhenItsOwnVerdictClaimsNoWrite() {
		for (PendingAuthorizationSaveResult outcome : new PendingAuthorizationSaveResult[]{
				PendingAuthorizationSaveResult.SAVED, PendingAuthorizationSaveResult.UNAVAILABLE}) {
			AtomicInteger calls = new AtomicInteger();
			PendingAuthorizationStore store = provider((opaque, remaining) -> {
				calls.incrementAndGet();
				long stop = System.nanoTime() + remaining.plusMillis(20).toNanos();
				for (long left; (left = stop - System.nanoTime()) > 0;) LockSupport.parkNanos(left);
				return outcome;
			});
			assertEquals(PendingAuthorizationSaveResult.INDETERMINATE,
					pending().saveToResult(store, "binding", Duration.ofMillis(500)));
			assertEquals(1, calls.get());
		}
	}

	@Test void interruptionAfterInMemoryMutationIsIndeterminateAndDoesNotLoseTheRecord() {
		var entries = new HashMap<@NonNull Object, @NonNull Object>() {
			private static final long serialVersionUID = 1L;
			@Override public @Nullable Object put(@NonNull Object key, @NonNull Object value) {
				Object previous = super.put(key, value); Thread.currentThread().interrupt(); return previous;
			}
		};
		InMemoryPendingAuthorizationStore store = new InMemoryPendingAuthorizationStore(
				InMemoryPendingAuthorizationStore.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC)), entries);
		try {
			assertEquals(PendingAuthorizationSaveResult.INDETERMINATE,
					store.save("binding", "state", "TEST-ONLY-record", NOW.plusSeconds(60)));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally { Thread.interrupted(); }
		assertEquals("TEST-ONLY-record", store.consume("binding", "state").orElseThrow());
	}

	@Test void injectedInMemoryStorageMustStartEmpty() {
		assertThrows(IllegalArgumentException.class, () -> new InMemoryPendingAuthorizationStore(
				InMemoryPendingAuthorizationStore.builder(), Map.of("unexpected", "entry")));
	}

	@SuppressWarnings("NullAway") // Deliberate required-argument misuse.
	@Test void programmerNullsAndEmptyBindingDoNotBecomeStorageVerdicts() {
		PendingAuthorization pending = pending();
		PendingAuthorizationStore store = provider((opaque, remaining) -> PendingAuthorizationSaveResult.SAVED);
		assertThrows(NullPointerException.class, () -> pending.saveToResult(null, "binding"));
		assertThrows(NullPointerException.class, () -> pending.saveToResult(store, (com.revetsec.BrowserBinding) null));
		assertThrows(NullPointerException.class, () -> pending.saveToResult(store, "binding", null));
		assertThrows(IllegalArgumentException.class, () -> pending.saveToResult(store, ""));
	}

	@SuppressWarnings("NullAway") // Fault fixtures deliberately violate the provider's nonnull return contract.
	private static @NonNull PendingAuthorizationStore provider(@NonNull BiFunction<@NonNull String,
			@NonNull Duration, @Nullable PendingAuthorizationSaveResult> operation) {
		return new PendingAuthorizationStore() {
			@Override public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding, @NonNull String state,
					@NonNull String opaque, @NonNull Instant expiry, @NonNull Duration remaining) {
				return operation.apply(opaque, remaining);
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding,
					@NonNull String state, @NonNull Duration remaining) { return Optional.empty(); }
		};
	}

	private static @NonNull PendingAuthorization pending() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token")).build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("TEST-ONLY-client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(URI.create("https://app.example/callback"))
				.clock(Clock.fixed(NOW, ZoneOffset.UTC)).build().beginAuthorization().getPendingAuthorization();
	}
}
