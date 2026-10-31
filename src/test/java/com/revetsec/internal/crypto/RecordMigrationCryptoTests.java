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
import com.revetsec.StoreAdmission;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Restricted authenticated metadata paths; old opening semantics remain separately pinned by existing KATs. */
final class RecordMigrationCryptoTests {
	private static final Instant EXPIRY = Instant.parse("2026-10-29T12:00:00Z");
	private static final Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());
	private static final String ID = Base64Url.encode(new byte[32]);
	private static final String STORAGE = "revetsec:as:1:" + ID + ":ISSUER_STATE:" + ID;
	private static final String CONTEXT = "revetsec/as-record/v2:" + STORAGE;

	@Test
	void intentCopiesFormatsAndSeparatesMetadataFromAdmission() {
		Set<ClosedMigrationIntent.Format> formats = new HashSet<>();
		formats.add(ClosedMigrationIntent.Format.ISSUER_SCHEMA2);
		StoreAdmission admission = StoreAdmission.fromIdentifiers(ID, ID);
		ClosedMigrationIntent intent = ClosedMigrationIntent.fromExternalIntent(ID, admission, formats);
		formats.clear();
		intent.requireFormat(ClosedMigrationIntent.Format.ISSUER_SCHEMA2);
		assertSame(admission, intent.getTargetAdmission());
		assertEquals(ID, intent.getMigrationId());
		assertThrows(IllegalArgumentException.class, () -> intent.requireFormat(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));
		assertThrows(IllegalArgumentException.class, () -> ClosedMigrationIntent.fromExternalIntent(ID, admission, Set.of()));
		assertThrows(IllegalArgumentException.class, () -> ClosedMigrationIntent.fromExternalIntent("bad", admission,
				Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		assertFalse(intent.toString().contains(ID));
	}

	@Test
	void ordinaryMetadataOpenRetainsExactExpiryAndRefusesAtEquality() throws Exception {
		StateSealer sealer = sealer();
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, "payload", CONTEXT, EXPIRY);
		try (AuthenticatedRecord opened = SealedStateAccess.get().openRecord(sealer, SealedStateType.AS_RECORD,
				sealed, CONTEXT, fixed(EXPIRY.minusNanos(1)))) {
			assertEquals("payload", opened.getPlaintext());
			assertEquals(EXPIRY, opened.getNotAfter());
		}
		UnsealException failure = assertThrows(UnsealException.class, () -> SealedStateAccess.get().openRecord(sealer,
				SealedStateType.AS_RECORD, sealed, CONTEXT, fixed(EXPIRY)));
		assertEquals(UnsealException.Kind.EXPIRED, failure.getKind());
		assertEquals(UnsealException.Kind.EXPIRED, assertThrows(UnsealException.class,
				() -> SealedStateAccess.get().unseal(sealer, SealedStateType.AS_RECORD, sealed, CONTEXT,
						fixed(EXPIRY))).getKind());
	}

	@Test
	void closedMigrationCanAuthenticateExpiredRecordWithoutAnyClockReadAndPreservesOriginalExpiry() throws Exception {
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("migration")).clock(new UnreadableClock()).build();
		for (String context : Set.of("revetsec/as-record/v1:" + STORAGE, CONTEXT)) {
			String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, "expired", context, EXPIRY);
			try (AuthenticatedRecord opened = SealedStateAccess.get().openForMigration(sealer, SealedStateType.AS_RECORD,
					sealed, context, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2))) {
				assertEquals("expired", opened.getPlaintext());
				assertEquals(EXPIRY, opened.getNotAfter());
			}
		}
	}

	@Test
	void migrationNeverBypassesAuthenticationTypeContextKeyOrSelectedFamily() throws Exception {
		StateSealer sealer = sealer();
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, "payload", CONTEXT, EXPIRY);
		assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().openForMigration(sealer,
				SealedStateType.AS_RECORD, sealed, CONTEXT, intent(ClosedMigrationIntent.Format.WEBAUTHN_WAR2)));
		assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().openForMigration(sealer,
				SealedStateType.APP, sealed, CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().openForMigration(sealer,
				SealedStateType.TOTP_RECORD, sealed, CONTEXT, intent(ClosedMigrationIntent.Format.TOTP_TTR3)));
		assertInvalid(() -> SealedStateAccess.get().openForMigration(sealer, SealedStateType.AS_RECORD, sealed,
				CONTEXT + "x", intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		byte[] wire = Base64Url.decode(sealed); wire[wire.length - 1] ^= 1;
		assertInvalid(() -> SealedStateAccess.get().openForMigration(sealer, SealedStateType.AS_RECORD,
				Base64Url.encode(wire), CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		StateSealer wrongKey = StateSealer.withActiveKey(TestSealers.fixedKey("other")).build();
		assertInvalid(() -> SealedStateAccess.get().openForMigration(wrongKey, SealedStateType.AS_RECORD,
				sealed, CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
	}

	@Test
	void webauthnMetadataUsesItsOwnDomainAndCeilingExpiry() throws Exception {
		StateSealer sealer = sealer();
		String context = "revetsec/wa-record/v1:" + ID + ":record:1:1:0";
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.WEBAUTHN_RECORD,
				"AA", context, EXPIRY.plusNanos(1));
		try (AuthenticatedRecord opened = SealedStateAccess.get().openForMigration(sealer,
				SealedStateType.WEBAUTHN_RECORD, sealed, context, intent(ClosedMigrationIntent.Format.WEBAUTHN_WAR2))) {
			assertEquals(EXPIRY.plusSeconds(1), opened.getNotAfter());
			assertEquals("AA", opened.getPlaintext());
		}
	}

	@Test
	void permanentFenceOpeningRequiresExactEncryptedSentinelAndOnlyNewFenceAddresses() throws Exception {
		StateSealer sealer = sealer();
		for (String kind : Set.of("ISSUER_STATE", "SUBJECT_STATE")) {
			String context = "revetsec/as-record/v2:revetsec:as:1:" + ID + ":" + kind + ":" + ID;
			String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, "fence", context, PERMANENT);
			try (AuthenticatedRecord opened = SealedStateAccess.get().openPermanentFence(sealer, sealed, context)) {
				assertEquals(PERMANENT, opened.getNotAfter());
				assertEquals("fence", opened.getPlaintext());
			}
			String finite = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD,
					"fence", context, PERMANENT.minusSeconds(1));
			assertInvalid(() -> SealedStateAccess.get().openPermanentFence(sealer, finite, context));
		}
		String old = CONTEXT.replace("/v2:", "/v1:");
		assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().openPermanentFence(sealer, "x", old));
		String code = CONTEXT.replace("ISSUER_STATE", "CODE");
		assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().openPermanentFence(sealer, "x", code));
	}

	@Test
	void ownedPlaintextIsErasedAndClosedHolderCannotBeReused() throws Exception {
		StateSealer sealer = sealer();
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, "private", CONTEXT, EXPIRY);
		AuthenticatedRecord opened = SealedStateAccess.get().openForMigration(sealer, SealedStateType.AS_RECORD,
				sealed, CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2));
		Field field = AuthenticatedRecord.class.getDeclaredField("plaintext"); field.setAccessible(true);
		byte[] retained = (byte[]) field.get(opened);
		assertTrue(retained.length > 0);
		assertFalse(opened.toString().contains("private"));
		opened.close(); opened.close();
		assertArrayEquals(new byte[retained.length], retained);
		assertThrows(IllegalStateException.class, opened::getPlaintext);
		assertThrows(IllegalStateException.class, opened::getNotAfter);
	}

	@Test
	void authenticatedMalformedUtf8AndUnrepresentableExpiryAreRejected() throws Exception {
		byte[] master = new byte[32];
		for (int i = 0; i < master.length; i++) master[i] = (byte) i;
		SealerV1.Key key = SealerV1.Key.fromMasterKey("k", master);
		String malformed = SealerV1.seal(key, SealedStateType.AS_RECORD, CONTEXT, EXPIRY.getEpochSecond(),
				new byte[]{(byte) 0xc0, (byte) 0xaf}, new byte[16], new byte[12]);
		assertInvalid(() -> SealerV1.openForMigration(malformed, 3800, Map.of("k", key), SealedStateType.AS_RECORD,
				CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		String impossible = SealerV1.seal(key, SealedStateType.AS_RECORD, CONTEXT, Long.MAX_VALUE,
				"{}".getBytes(StandardCharsets.UTF_8), new byte[16], new byte[12]);
		assertInvalid(() -> SealerV1.openForMigration(impossible, 3800, Map.of("k", key), SealedStateType.AS_RECORD,
				CONTEXT, intent(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
		Arrays.fill(master, (byte) 0);
	}

	private static @NonNull StateSealer sealer() { return TestSealers.fromFixedKey(); }
	private static @NonNull Clock fixed(@NonNull Instant at) { return Clock.fixed(at, ZoneOffset.UTC); }
	private static @NonNull ClosedMigrationIntent intent(ClosedMigrationIntent.@NonNull Format format) {
		return ClosedMigrationIntent.fromExternalIntent(ID, StoreAdmission.fromIdentifiers(ID, ID), Set.of(format));
	}
	private static void assertInvalid(@NonNull Open operation) {
		assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class, () -> {
			try (AuthenticatedRecord opened = operation.open()) {
				assertNotNull(opened.getPlaintext());
				fail("Unexpected authenticated open");
			}
		}).getKind());
	}
	private interface Open { @NonNull AuthenticatedRecord open() throws Exception; }
	private static final class UnreadableClock extends Clock {
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
		@Override public @NonNull Instant instant() { throw new AssertionError("Migration must not read worker time"); }
	}
}
