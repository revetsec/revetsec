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

package com.revetsec.internal.crypto;

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * The set-once accessor to the internal type labels (M1 plan G6-10 and exit criterion 9): {@code get()} installs the
 * operations by initializing {@code StateSealer} even when no sealer has been built (shown in a fresh JVM, because
 * class initialization happens once per JVM), a second installation throws, and the operations round {@code expiresAt}
 * up to a whole second, take {@code now} from the caller's clock and report expiry separately.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SealedStateAccessTests {
	private static final Instant START = Instant.parse("2026-09-24T12:00:00Z");
	private static final String CHILD_SUCCESS = "sealed-state-access-ok";

	// G6-10 and exit criterion 9: get() works before any StateSealer has been built. Only a fresh JVM can show it.
	@Test
	void getInstallsTheOperationsInAFreshJvmBeforeAnyStateSealerIsBuilt() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(FreshJvmMain.class).build().run();

		Assertions.assertFalse(result.isTimedOut(), result::toString);
		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertTrue(result.getStandardOutput().contains(CHILD_SUCCESS), result::toString);
	}

	// G6-10: the accessor is set once, and only with operations StateSealer defined.
	@Test
	void aSecondInstallationThrowsIllegalStateExceptionAndForeignOperationsAreRefused() {
		SealedStateAccess.Operations installed = SealedStateAccess.get();

		Assertions.assertThrows(IllegalStateException.class, () -> SealedStateAccess.set(installed));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.set(new ForeignOperations()));
		Assertions.assertThrows(NullPointerException.class, () -> SealedStateAccess.set(nullValue()));
		Assertions.assertSame(installed, SealedStateAccess.get());
		Assertions.assertTrue(SealedStateAccess.isInstalled());
	}

	// M1 plan "Internal API": notAfter is expiresAt rounded up to a whole second, and now comes from the caller's clock.
	@TestFactory
	Stream<DynamicTest> expiresAtTheFirstWholeSecondAtOrAfterExpiresAt() {
		return Stream.of(Duration.ZERO, Duration.ofMillis(1), Duration.ofMillis(999), Duration.ofNanos(1))
				.map(offset -> DynamicTest.dynamicTest("expiresAt = whole second + " + offset, () -> {
					StateSealer sealer = TestSealers.fromFixedKey();
					Instant expiresAt = START.plus(offset);
					Instant notAfter = offset.isZero() ? START : START.plusSeconds(1);
					String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_AUTHORIZATION, "pending",
							"google", expiresAt);
					TestClock clock = TestClock.fromInstant(notAfter.minusNanos(1));

					Assertions.assertEquals("pending", SealedStateAccess.get().unseal(sealer,
							SealedStateType.PENDING_AUTHORIZATION, sealed, "google", clock));
					clock.set(notAfter);
					Assertions.assertEquals(UnsealException.Kind.EXPIRED, unsealFailure(sealer,
							SealedStateType.PENDING_AUTHORIZATION, sealed, "google", clock));
				}));
	}

	// The caller's clock decides expiry, not the sealer's: pending state follows the protocol's Clock (R11).
	@Test
	void unsealUsesTheCallersClockNotTheSealersClock() throws UnsealException {
		TestClock sealerClock = TestClock.fromInstant(Instant.parse("2100-01-01T00:00:00Z"));
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("k")).clock(sealerClock).build();
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_SAML, "saml", "idp",
				START.plus(Duration.ofMinutes(15)));

		Assertions.assertEquals("saml", SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_SAML, sealed,
				"idp", TestClock.fromInstant(START)));
		Assertions.assertEquals(UnsealException.Kind.EXPIRED, unsealFailure(sealer, SealedStateType.PENDING_SAML,
				sealed, "idp", sealerClock));
	}

	// G6-10: the internal labels separate pending OAuth state, pending SAML state, OIDC sessions and app data.
	@Test
	void eachTypeOpensOnlyItsOwnValues() throws UnsealException {
		StateSealer sealer = TestSealers.fromFixedKey();
		Clock clock = TestClock.fromInstant(START);

		for (SealedStateType sealedType : SealedStateType.values()) {
			String sealed = SealedStateAccess.get().seal(sealer, sealedType, "value", "context",
					START.plus(Duration.ofMinutes(10)));

			for (SealedStateType openedType : SealedStateType.values()) {
				if (openedType == sealedType)
					Assertions.assertEquals("value", SealedStateAccess.get().unseal(sealer, openedType, sealed, "context",
							clock));
				else
					Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer, openedType, sealed,
							"context", clock), sealedType + " opened as " + openedType);
			}
		}
	}

	// Expiry is reported only for authentic values; every other failure is INVALID.
	@Test
	void reportsInvalidForEveryFailureButAnAuthenticExpiry() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		StateSealer otherKey = TestSealers.fromFixedKeys("other", List.of());
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.OIDC_SESSION, "session", "rp",
				START.plusSeconds(60));
		byte[] tampered = Base64Url.decode(sealed);
		tampered[tampered.length - 1] ^= 0x01;
		TestClock expired = TestClock.fromInstant(START.plusSeconds(3_600));

		Assertions.assertEquals(UnsealException.Kind.EXPIRED, unsealFailure(sealer, SealedStateType.OIDC_SESSION,
				sealed, "rp", expired));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer, SealedStateType.OIDC_SESSION,
				Base64Url.encode(tampered), "rp", expired));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer, SealedStateType.OIDC_SESSION,
				sealed, "other-rp", TestClock.fromInstant(START)));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(otherKey, SealedStateType.OIDC_SESSION,
				sealed, "rp", TestClock.fromInstant(START)));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer, SealedStateType.OIDC_SESSION,
				"A".repeat(3_801), "rp", TestClock.fromInstant(START)));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer, SealedStateType.OIDC_SESSION,
				"not sealed", "rp", TestClock.fromInstant(START)));
	}

	// M1 plan unseal step 1 and R8: the internal path bounds the value by the sealer's own maximum sealed length
	// before decoding, like the public one. The value here is authentic, so only the length check can reject it.
	@Test
	void rejectsAnAuthenticValueLongerThanTheSealersMaximumSealedLength() throws UnsealException {
		StateSealer roomy = StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.maximumSealedLength(16_384)
				.build();
		StateSealer sealer = TestSealers.fromFixedKey();
		Clock clock = TestClock.fromInstant(START);
		// Key ID "test": 2,793 bytes seal to 3,802 characters, just over the default maximum of 3,800.
		String justTooLong = SealedStateAccess.get().seal(roomy, SealedStateType.PENDING_AUTHORIZATION, "x".repeat(2_793),
				"google", START.plusSeconds(600));
		String largest = SealedStateAccess.get().seal(roomy, SealedStateType.PENDING_AUTHORIZATION, "x".repeat(2_792),
				"google", START.plusSeconds(600));

		Assertions.assertEquals(3_802, justTooLong.length());
		Assertions.assertEquals(3_800, largest.length());
		Assertions.assertEquals("x".repeat(2_793), SealedStateAccess.get().unseal(roomy,
				SealedStateType.PENDING_AUTHORIZATION, justTooLong, "google", clock));
		Assertions.assertEquals("x".repeat(2_792), SealedStateAccess.get().unseal(sealer,
				SealedStateType.PENDING_AUTHORIZATION, largest, "google", clock));
		Assertions.assertEquals(UnsealException.Kind.INVALID, unsealFailure(sealer,
				SealedStateType.PENDING_AUTHORIZATION, justTooLong, "google", clock));
	}

	// Arguments are checked first: NullPointerException or IllegalArgumentException, never UnsealException.
	@Test
	void checksArgumentsFirst() {
		SealedStateAccess.Operations operations = SealedStateAccess.get();
		StateSealer sealer = TestSealers.fromFixedKey();
		SealedStateType type = SealedStateType.PENDING_AUTHORIZATION;
		Clock clock = TestClock.fromInstant(START);

		Assertions.assertThrows(NullPointerException.class, () -> operations.seal(nullValue(), type, "p", "c", START));
		Assertions.assertThrows(NullPointerException.class, () -> operations.seal(sealer, nullValue(), "p", "c", START));
		Assertions.assertThrows(NullPointerException.class, () -> operations.seal(sealer, type, nullValue(), "c", START));
		Assertions.assertThrows(NullPointerException.class, () -> operations.seal(sealer, type, "p", nullValue(), START));
		Assertions.assertThrows(NullPointerException.class, () -> operations.seal(sealer, type, "p", "c", nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> operations.unseal(nullValue(), type, "s", "c", clock));
		Assertions.assertThrows(NullPointerException.class, () -> operations.unseal(sealer, nullValue(), "s", "c",
				clock));
		Assertions.assertThrows(NullPointerException.class, () -> operations.unseal(sealer, type, nullValue(), "c",
				clock));
		Assertions.assertThrows(NullPointerException.class, () -> operations.unseal(sealer, type, "s", nullValue(),
				clock));
		Assertions.assertThrows(NullPointerException.class, () -> operations.unseal(sealer, type, "s", "c",
				nullValue()));

		for (String context : List.of("", "x".repeat(257), "\ud800")) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> operations.seal(sealer, type, "p", context,
					START));
			Assertions.assertThrows(IllegalArgumentException.class, () -> operations.unseal(sealer, type, "s", context,
					clock));
		}

		Assertions.assertThrows(IllegalArgumentException.class, () -> operations.seal(sealer, type, "\udc00", "c",
				START));
		Assertions.assertThrows(IllegalArgumentException.class, () -> operations.seal(sealer, type, "x".repeat(3_000),
				"c", START));
	}

	private static UnsealException.Kind unsealFailure(StateSealer sealer,
																										SealedStateType type,
																										String sealed,
																										String context,
																										Clock clock) {
		UnsealException e = Assertions.assertThrows(UnsealException.class,
				() -> SealedStateAccess.get().unseal(sealer, type, sealed, context, clock));
		Assertions.assertNull(e.getCause());
		return e.getKind();
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		return null;
	}

	/**
	 * Operations that {@code StateSealer} did not define, which {@link SealedStateAccess#set} must refuse.
	 */
	static final class ForeignOperations implements SealedStateAccess.Operations {
		@Override
		public String seal(StateSealer sealer,
											 SealedStateType type,
											 String plaintext,
											 String context,
											 Instant expiresAt) {
			return plaintext;
		}

		@Override
		public String unseal(StateSealer sealer,
												 SealedStateType type,
												 String sealed,
												 String context,
												 Clock clock) {
			return sealed;
		}
	}

	/**
	 * Runs in a fresh child JVM, where {@code StateSealer} has not been initialized, and exits 0 only if every check
	 * holds.
	 */
	public static final class FreshJvmMain {
		private FreshJvmMain() {
			// Only main runs.
		}

		public static void main(String[] arguments) throws Exception {
			// Nothing has initialized StateSealer, whose static initializer is what installs the operations.
			Assertions.assertFalse(SealedStateAccess.isInstalled(), "installed before get()");

			// Operations that StateSealer did not define are refused, even before StateSealer installs its own.
			Assertions.assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.set(new ForeignOperations()));
			Assertions.assertFalse(SealedStateAccess.isInstalled(), "foreign operations were installed");

			// get() initializes StateSealer, which installs the operations, and they work at once.
			SealedStateAccess.Operations operations = SealedStateAccess.get();
			Assertions.assertTrue(SealedStateAccess.isInstalled());
			Assertions.assertSame(operations, SealedStateAccess.get());

			StateSealer sealer = TestSealers.fromFixedKey();
			String sealed = operations.seal(sealer, SealedStateType.PENDING_AUTHORIZATION, "pending", "google",
					START.plusSeconds(600));
			Assertions.assertEquals("pending", operations.unseal(sealer, SealedStateType.PENDING_AUTHORIZATION, sealed,
					"google", TestClock.fromInstant(START)));

			// The accessor is set once.
			Assertions.assertThrows(IllegalStateException.class, () -> SealedStateAccess.set(operations));

			System.out.println(CHILD_SUCCESS);
			System.out.flush();
		}
	}
}
