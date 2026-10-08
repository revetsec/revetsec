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

import org.jspecify.annotations.NonNull;

import com.revetsec.StateSealer;
import com.revetsec.internal.http.Deadline;
import com.revetsec.testing.RewindableClock;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static java.util.Objects.requireNonNull;

final class PendingAuthorizationSourceTests {
	private static final Instant START = Instant.parse("2026-09-28T12:00:00Z");

	@Test
	void sealedFormRoundTripsButWrongContextAndAppLabelDoNotOpen() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("pending"))
				.clock(clock).build();
		PendingAuthorization pending = pending("state-A");
		String sealed = pending.toSealedForm(sealer, "provider-A");
		assertTrue(sealed.length() < 3_800);
		PendingAuthorization opened = PendingAuthorizationResolver.resolve(
				PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider-A"), "state-A", clock);
		assertEquals(pending.getRedirectUri(), opened.getRedirectUri());
		assertEquals(pending.getApplicationData(), opened.getApplicationData());
		assertTrue(opened.toString().startsWith("PendingAuthorization{"));
		assertFalse(opened.toString().contains("state-A"));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider-B"), "state-A", clock))
						.getReason());
		String appSeal = sealer.seal(PendingAuthorizationCodec.encode(pending, null), "provider-A",
				Duration.ofMinutes(15));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromSealedForm(appSeal, sealer, "provider-A"), "state-A", clock))
						.getReason());
	}

	@Test
	void sealedPendingRejectsTamperingUniformlyAndOpensAcrossKeyRotation() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		StateSealer oldSealer = StateSealer.withActiveKey(TestSealers.fixedKey("old"))
				.clock(clock).build();
		StateSealer newSealer = StateSealer.withActiveKey(TestSealers.fixedKey("new"))
				.clock(clock).build();
		StateSealer rotated = StateSealer.withActiveKey(TestSealers.fixedKey("new"))
				.verificationKeys(List.of(TestSealers.fixedKey("old")))
				.clock(clock).build();
		String sealed = pending("state-A").toSealedForm(oldSealer, "provider");
		assertEquals("state-A", PendingAuthorizationResolver.resolve(
				PendingAuthorizationSource.fromSealedForm(sealed, rotated, "provider"),
				"state-A", clock).state());
		String bitFlip = sealed.substring(0, sealed.length() / 2)
				+ (sealed.charAt(sealed.length() / 2) == 'A' ? 'B' : 'A')
				+ sealed.substring(sealed.length() / 2 + 1);
		for (String bad : List.of(bitFlip, sealed.substring(0, sealed.length() - 8), "not-base64!"))
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
					assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
							PendingAuthorizationSource.fromSealedForm(bad, oldSealer, "provider"),
							"state-A", clock)).getReason());
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromSealedForm(sealed, newSealer, "provider"),
						"state-A", clock)).getReason());
		clock.advance(Duration.ofMinutes(15));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_EXPIRED,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromSealedForm(sealed, rotated, "provider"),
						"state-A", clock)).getReason());
	}

	@Test
	void validOtherFlowCookieFailsStateComparison() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("pending"))
				.clock(clock).build();
		String sealedB = pending("state-B").toSealedForm(sealer, "provider");
		assertEquals(OAuthException.Reason.STATE_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromSealedForm(sealedB, sealer, "provider"), "state-A", clock))
						.getReason());
	}

	@Test
	void storeDigestRejectsWrongBrowserEvenWhenStoreIgnoresBinding() {
		PendingAuthorization pending = pending("state-A");
		PendingAuthorizationStore defective = new PendingAuthorizationStore() {
			private @Nullable String record;
			@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String opaque, @NonNull Instant expiry, @NonNull Duration remaining) {
				this.record = opaque;
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state, @NonNull Duration remaining) {
				String value = this.record;
				this.record = null;
				return Optional.ofNullable(value);
			}
		};
		pending.saveTo(defective, "browser-A");
		assertEquals(OAuthException.Reason.BROWSER_BINDING_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
						PendingAuthorizationSource.fromStore(defective, "browser-B"), "state-A",
						RewindableClock.fromInstant(START))).getReason());
	}

	@Test
	void atomicStoreConsumesOnceAndExpiryIsChecked() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(clock).build();
		pending("state-A").saveTo(store, "browser-A");
		PendingAuthorizationSource source = PendingAuthorizationSource.fromStore(store, "browser-A");
		assertEquals("state-A", PendingAuthorizationResolver.resolve(source, "state-A", clock).state());
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND,
				assertThrows(OAuthValidationException.class,
						() -> PendingAuthorizationResolver.resolve(source, "state-A", clock)).getReason());
		pending("state-B").saveTo(store, "browser-A");
		clock.advance(Duration.ofMinutes(15));
		assertThrows(OAuthValidationException.class, () -> PendingAuthorizationResolver.resolve(
				PendingAuthorizationSource.fromStore(store, "browser-A"), "state-B", clock));
	}

	@Test
	void customStoreReceivesPositiveBudgetsAndSpentDeadlineDoesNotConsume() {
		AtomicReference<Duration> savedBudget = new AtomicReference<>();
		AtomicReference<Duration> consumedBudget = new AtomicReference<>();
		AtomicReference<String> saved = new AtomicReference<>();
		AtomicInteger consumes = new AtomicInteger();
		PendingAuthorizationStore store = new PendingAuthorizationStore() {
			@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String opaque,
					@NonNull Instant expiry, @NonNull Duration remaining) {
				savedBudget.set(remaining); saved.set(opaque);
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state,
					@NonNull Duration remaining) {
				consumedBudget.set(remaining); consumes.incrementAndGet(); return Optional.ofNullable(saved.getAndSet(null));
			}
		};
		pending("state-A").saveTo(store, "browser-A", Duration.ofSeconds(2));
		Duration saveRemaining = requireNonNull(savedBudget.get());
		assertTrue(saveRemaining.compareTo(Duration.ZERO) > 0);
		assertTrue(saveRemaining.compareTo(Duration.ofSeconds(2)) <= 0);
		PendingAuthorizationSource source = PendingAuthorizationSource.fromStore(store, "browser-A");
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE,
				assertThrows(PendingAuthorizationStoreException.class, () -> PendingAuthorizationResolver.resolve(
					source, "state-A", RewindableClock.fromInstant(START), Deadline.fromNow(Duration.ZERO))).getReason());
		assertEquals(0, consumes.get());
		assertEquals("state-A", PendingAuthorizationResolver.resolve(source, "state-A",
				RewindableClock.fromInstant(START), Deadline.fromNow(Duration.ofSeconds(2))).state());
		assertEquals(1, consumes.get());
		Duration consumeRemaining = requireNonNull(consumedBudget.get());
		assertTrue(consumeRemaining.compareTo(Duration.ZERO) > 0);
		assertTrue(consumeRemaining.compareTo(Duration.ofSeconds(2)) <= 0);
	}

	@Test
	void customStoreFaultsUseFixedReasonWithoutProviderText() {
		PendingAuthorizationStore broken = new PendingAuthorizationStore() {
			@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String opaque,
					@NonNull Instant expiry, @NonNull Duration remaining) {
				throw new IllegalStateException("TEST-ONLY-secret-store-detail");
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state,
					@NonNull Duration remaining) {
				throw new IllegalStateException("TEST-ONLY-secret-store-detail");
			}
		};
		PendingAuthorizationStoreException save = assertThrows(PendingAuthorizationStoreException.class,
				() -> pending("state-A").saveTo(broken, "browser-A", Duration.ofSeconds(2)));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE, save.getReason());
		assertFalse(save.toString().contains("TEST-ONLY-secret-store-detail"));
		assertFalse(Thread.currentThread().isInterrupted());
		PendingAuthorizationStoreException consume = assertThrows(PendingAuthorizationStoreException.class,
				() -> PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(broken, "browser-A"),
					"state-A", RewindableClock.fromInstant(START), Deadline.fromNow(Duration.ofSeconds(2))));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE, consume.getReason());
		assertFalse(consume.toString().contains("TEST-ONLY-secret-store-detail"));
		assertFalse(Thread.currentThread().isInterrupted());
	}

	@Test
	void interruptedStoreFaultsRestoreCallerInterruptWithoutReleasingPendingData() {
		PendingAuthorizationStore interrupted = new PendingAuthorizationStore() {
			@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String opaque,
					@NonNull Instant expiry, @NonNull Duration remaining) {
				throwUnchecked(new InterruptedException("TEST-ONLY-store-interrupted"));
			}
			@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state,
					@NonNull Duration remaining) {
				throwUnchecked(new InterruptedException("TEST-ONLY-store-interrupted"));
				return Optional.empty();
			}
		};
		assertFalse(Thread.currentThread().isInterrupted());
		try {
			PendingAuthorizationStoreException save = assertThrows(PendingAuthorizationStoreException.class,
					() -> pending("state-A").saveTo(interrupted, "browser-A", Duration.ofSeconds(2)));
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE, save.getReason());
			assertTrue(Thread.currentThread().isInterrupted());
			Thread.interrupted();
			PendingAuthorizationStoreException consume = assertThrows(PendingAuthorizationStoreException.class,
					() -> PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(interrupted, "browser-A"),
							"state-A", RewindableClock.fromInstant(START), Deadline.fromNow(Duration.ofSeconds(2))));
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE, consume.getReason());
			assertTrue(Thread.currentThread().isInterrupted());
		} finally {
			Thread.interrupted();
		}
	}

	@SuppressWarnings("unchecked")
	private static <E extends Throwable> void throwUnchecked(@NonNull Throwable failure) throws E {
		throw (E) failure;
	}

	private static @NonNull PendingAuthorization pending(@NonNull String state) {
		return new PendingAuthorization("oauth", "https://issuer.example", "client",
				URI.create("https://app.example/callback"), state, "verifier", null,
				Set.of("openid"), List.of(URI.create("https://api.example")),
				AuthorizationRequestOptions.ResponseMode.QUERY, START, START.plus(Duration.ofMinutes(15)),
				Map.of("returnTo", "/account"), true, URI.create("https://issuer.example/authorize"),
				URI.create("https://issuer.example/token"));
	}
}
