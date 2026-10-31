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

package com.revetsec.internal.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** WAR2 format and closed legacy transformations; frozen WAR1 fixtures preserve migration inputs. */
final class WebAuthnRecordCodecV2Tests {
	private static final Instant NOW = Instant.parse("2026-10-29T12:00:00.123456789Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final Instant PERMANENT = WebAuthnRecordPayloadV2.PERMANENT;
	private static final String NS = "tenant";
	private static final String RP = "login.example.com";
	private static final byte[] ID = {1, 2, 3};
	private static final byte[] HANDLE = {4, 5, 6};
	private static final WebAuthnStoreKey ROOT = WebAuthnStoreKey.forNamespaceClock(NS, RP);
	private static final WebAuthnStoreKey CREDENTIAL = WebAuthnStoreKey.forCredential(NS, RP, ID);

	@Test void exactGoldenRootHasAuthorityAndFractionalImmutableMinimumIn45Bytes() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		WebAuthnRecordCodec old = new WebAuthnRecordCodec(sealer);
		byte[] oldRoot = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		WebAuthnRecordMigration migration = new WebAuthnRecordMigration(sealer);
		ClosedMigrationIntent intent = intent(1);
		var root = migration.authenticateRoot(intent, ROOT.getStorageKey(), oldRoot);
		var prepared = migration.prepare(intent, root, ROOT.getStorageKey(), new byte[] {1}, oldRoot);
		assertEquals(NOW, prepared.floor());
		assertArrayEquals(new byte[] {1}, prepared.expectedVersion());
		assertArrayEquals(oldRoot, prepared.expectedBytes());
		assertEquals(32, prepared.version().length);
		assertEquals("WAR2", new String(prepared.sealedBytes(), 0, 4, StandardCharsets.US_ASCII));
		try (var opened = new WebAuthnRecordCodecV2(sealer).openWithMetadata(ROOT, prepared.sealedBytes(), CLOCK)) {
			byte[] plain = opened.plaintext();
			assertEquals(45, plain.length);
			byte[] expected = ByteBuffer.allocate(45).put((byte) 2)
					.put(Base64Url.decode(intent.getTargetAdmission().getAuthorityId()))
					.putLong(NOW.getEpochSecond()).putInt(NOW.getNano()).array();
			assertArrayEquals(expected, plain);
			assertEquals(PERMANENT.getEpochSecond(), opened.notAfter());
		}
		try (var decoded = new WebAuthnRecordCodecV2(sealer).openRecord(ROOT, prepared.sealedBytes(), CLOCK)) {
			assertEquals(NOW, decoded.floor());
			assertEquals(intent.getTargetAdmission().getAuthorityId(), decoded.authorityId().orElseThrow());
		}
		assertThrows(WebAuthnRecordException.class, () -> old.open(ROOT, prepared.sealedBytes(), CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).open(ROOT, oldRoot, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> migration.authenticateRoot(intent, ROOT.getStorageKey(), prepared.sealedBytes()));
	}

	@Test void migrationPreservesAllSixLogicalFormsAndOriginalInnerBytes() throws Exception {
		StateSealer sealer = sealer("k".repeat(64), 1_024);
		WebAuthnRecordCodec old = new WebAuthnRecordCodec(sealer);
		WebAuthnRecordCodecV2 next = new WebAuthnRecordCodecV2(sealer);
		WebAuthnRecordMigration migration = new WebAuthnRecordMigration(sealer);
		byte[] oldRoot = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW.minusSeconds(1));
		ClosedMigrationIntent intent = intent(1);
		var root = migration.authenticateRoot(intent, ROOT.getStorageKey(), oldRoot);
		for (Fixture fixture : fixtures(old)) {
			byte[] expectedInner = old.open(fixture.key, fixture.sealed, CLOCK);
			var prepared = migration.prepare(intent, root, fixture.key.getStorageKey(), new byte[] {7}, fixture.sealed);
			assertEquals(fixture.key, prepared.key());
			assertEquals(fixture.expiresAt, prepared.expiresAt());
			assertEquals(fixture.key.getKind() == WebAuthnStoreKey.Kind.CEREMONY ? NOW : NOW.minusSeconds(1), prepared.floor());
			try (var decoded = next.openRecord(fixture.key, prepared.sealedBytes(), CLOCK)) {
				assertArrayEquals(expectedInner, decoded.innerPayload());
				assertEquals(prepared.floor(), decoded.floor());
				assertEquals(fixture.expiresAt, decoded.expiresAt());
			}
			assertFalse(Arrays.equals(prepared.version(), prepared.expectedVersion()));
			byte[] copy = prepared.sealedBytes(); copy[0] = 0;
			assertEquals('W', prepared.sealedBytes()[0]);
		}
	}

	@Test void fullJavaInstantFloorsIncludingNegativeAndSentinelRemainExact() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		for (Instant value : List.of(Instant.MIN, Instant.EPOCH.minusNanos(1), PERMANENT, Instant.MAX)) {
			byte[] rootBytes = new LegacyWebAuthnNamespaceClock(NS, RP, new WebAuthnRecordCodec(sealer)).encode(value);
			var migration = new WebAuthnRecordMigration(sealer);
			var root = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), rootBytes);
			var prepared = migration.prepare(intent(1), root, ROOT.getStorageKey(), new byte[] {1}, rootBytes);
			try (var decoded = new WebAuthnRecordCodecV2(sealer).openRecord(ROOT, prepared.sealedBytes(), CLOCK)) {
				assertEquals(value, decoded.floor());
			}
		}
		// Representability is deliberately separate from the engine's narrower timed-admission range.
	}

	@Test void expiredCeremonyOpensOnlyUnderClosedIntentAndRemainsExactlyExpired() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		WebAuthnRecordCodec old = new WebAuthnRecordCodec(sealer);
		Instant issued = NOW.minusSeconds(60);
		Instant expires = issued.plusSeconds(30);
		var state = WebAuthnCeremonyState.discoverableAuthentication(bytes(1), bytes(2), bytes(3),
				Set.of("https://login.example.com"), issued, expires).consume();
		var legacy = new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old).encode(state);
		assertThrows(WebAuthnRecordException.class, () -> old.open(legacy.key(), legacy.sealedBytes(), CLOCK));
		var migration = new WebAuthnRecordMigration(sealer);
		byte[] rootBytes = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(issued.minusSeconds(1));
		var root = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), rootBytes);
		var prepared = migration.prepare(intent(1), root, legacy.key().getStorageKey(), new byte[] {1}, legacy.sealedBytes());
		assertEquals(issued, prepared.floor());
		assertEquals(expires, prepared.expiresAt());
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(legacy.key(), prepared.sealedBytes(), CLOCK));
		Clock justBefore = Clock.fixed(expires.minusNanos(1), ZoneOffset.UTC);
		try (var decoded = new WebAuthnRecordCodecV2(sealer).openRecord(legacy.key(), prepared.sealedBytes(), justBefore)) {
			assertEquals(1, decoded.innerPayload()[1]);
			assertEquals(expires, decoded.expiresAt());
		}
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(
				legacy.key(), prepared.sealedBytes(), Clock.fixed(expires, ZoneOffset.UTC)));
		assertThrows(IllegalArgumentException.class, () -> migration.authenticateRoot(
				ClosedMigrationIntent.fromExternalIntent(identifier(1), admission(), Set.of(ClosedMigrationIntent.Format.TOTP_TTR3)),
				ROOT.getStorageKey(), rootBytes));
	}


	@Test void genuineLegacyCeremonyAtInstantMaximumPreservesUnrepresentableCeilingSeconds() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		WebAuthnRecordCodec old = new WebAuthnRecordCodec(sealer);
		Instant issued = Instant.MAX.minusSeconds(60);
		WebAuthnCeremonyState state = WebAuthnCeremonyState.discoverableAuthentication(bytes(1), bytes(2), bytes(3),
				Set.of("https://login.example.com"), issued, Instant.MAX);
		var ceremony = new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old).encode(state);
		assertEquals(Instant.MAX, new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old)
				.decode(ceremony.key(), ceremony.sealedBytes(), CLOCK).expiresAt());
		byte[] expectedInner = old.open(ceremony.key(), ceremony.sealedBytes(), CLOCK);
		byte[] rootBytes = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		var migration = new WebAuthnRecordMigration(sealer);
		var root = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), rootBytes);
		var prepared = migration.prepare(intent(1), root, ceremony.key().getStorageKey(), new byte[] {1}, ceremony.sealedBytes());
		assertEquals(issued, prepared.floor());
		assertEquals(Instant.MAX, prepared.expiresAt());
		var next = new WebAuthnRecordCodecV2(sealer);
		try (var opened = next.openWithMetadata(ceremony.key(), prepared.sealedBytes(), CLOCK)) {
			assertEquals(Instant.MAX.getEpochSecond() + 1, opened.notAfter());
		}
		try (var decoded = next.openRecord(ceremony.key(), prepared.sealedBytes(), CLOCK)) {
			assertArrayEquals(expectedInner, decoded.innerPayload());
			assertEquals(issued, decoded.floor());
			assertEquals(Instant.MAX, decoded.expiresAt());
		}
		assertThrows(WebAuthnRecordException.class, () -> next.openRecord(ceremony.key(), prepared.sealedBytes(),
				Clock.fixed(Instant.MAX, ZoneOffset.UTC)));
	}

	@Test void exactRetentionBindingsRejectAuthenticatedButMisboundLegacyAndNewRecords() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var old = new WebAuthnRecordCodec(sealer);
		var migration = new WebAuthnRecordMigration(sealer);
		byte[] root = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		var anchor = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), root);
		byte[] revoked = revoked(ID, HANDLE);
		byte[] wrongOld = old.seal(CREDENTIAL, revoked, NOW.plusSeconds(100));
		assertThrows(WebAuthnRecordException.class, () -> migration.prepare(intent(1), anchor, CREDENTIAL.getStorageKey(), new byte[] {1}, wrongOld));
		byte[] payload = WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, revoked);
		byte[] wrongNew = new WebAuthnRecordCodecV2(sealer).seal(CREDENTIAL, payload, NOW.plusSeconds(100));
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(CREDENTIAL, wrongNew, CLOCK));
		byte[] wrongRoot = old.seal(ROOT, ByteBuffer.allocate(13).put((byte) 1).putLong(NOW.getEpochSecond()).putInt(NOW.getNano()).array(), NOW.plusSeconds(100));
		assertThrows(WebAuthnRecordException.class, () -> migration.authenticateRoot(intent(1), ROOT.getStorageKey(), wrongRoot));
	}

	@Test void minimumSeedsCeremonyFloorWithoutInventingFutureExpiryAsObservation() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		WebAuthnRecordCodec old = new WebAuthnRecordCodec(sealer);
		var ceremony = new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old).encode(WebAuthnCeremonyState.discoverableAuthentication(
				bytes(1), bytes(2), bytes(3), Set.of("https://login.example.com"), NOW, NOW.plusSeconds(30)));
		for (Instant minimum : List.of(NOW.minusNanos(1), NOW.plusNanos(1), NOW.plusSeconds(5))) {
			var migration = new WebAuthnRecordMigration(sealer);
			byte[] root = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(minimum);
			var anchor = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), root);
			var prepared = migration.prepare(intent(1), anchor, ceremony.key().getStorageKey(), new byte[] {1}, ceremony.sealedBytes());
			assertEquals(minimum.isAfter(NOW) ? minimum : NOW, prepared.floor());
			assertEquals(NOW.plusSeconds(30), prepared.expiresAt());
		}
	}

	@Test void addressReconstructionIsBoundedCanonicalAndRechecksRecoveredIdentifier() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var old = new WebAuthnRecordCodec(sealer);
		var migration = new WebAuthnRecordMigration(sealer);
		byte[] root = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		for (String invalid : List.of(ROOT.getStorageKey() + ":extra", "x".repeat(584),
				ROOT.getStorageKey().replace("wa1:", "wa2:"), ROOT.getStorageKey().replace(":NAMESPACE_CLOCK:", ":OTHER:"),
				ROOT.getStorageKey().substring(0, ROOT.getStorageKey().length() - 1) + "B"))
			assertThrows(WebAuthnRecordException.class, () -> migration.authenticateRoot(intent(1), invalid, root));
		var anchor = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), root);
		byte[] misbound = old.seal(CREDENTIAL, revoked(new byte[] {9}, HANDLE), PERMANENT);
		assertThrows(WebAuthnRecordException.class, () -> migration.prepare(intent(1), anchor, CREDENTIAL.getStorageKey(), new byte[] {1}, misbound));
		WebAuthnStoreKey other = WebAuthnStoreKey.forCredential("other", RP, ID);
		assertThrows(WebAuthnRecordException.class, () -> migration.prepare(intent(1), anchor, other.getStorageKey(), new byte[] {1}, misbound));
		assertThrows(IllegalArgumentException.class, () -> migration.prepare(intent(2), anchor, CREDENTIAL.getStorageKey(), new byte[] {1}, misbound));
	}

	@Test void legacyRootAnchorCannotBeReplacedWithinOnePreparedPlan() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var old = new WebAuthnRecordCodec(sealer);
		var migration = new WebAuthnRecordMigration(sealer);
		byte[] root = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		var anchor = migration.authenticateRoot(intent(1), ROOT.getStorageKey(), root);
		byte[] independentlyResealedRoot = new LegacyWebAuthnNamespaceClock(NS, RP, old).encode(NOW);
		assertThrows(WebAuthnRecordException.class, () -> migration.prepare(intent(1), anchor, ROOT.getStorageKey(), new byte[] {1}, independentlyResealedRoot));
		assertThrows(IllegalArgumentException.class, () -> migration.prepare(intent(1), anchor, ROOT.getStorageKey(), new byte[0], root));
		assertThrows(IllegalArgumentException.class, () -> migration.prepare(intent(1), anchor, ROOT.getStorageKey(), new byte[129], root));
	}

	@Test void strictPayloadDecodersRejectUnknownVersionsInvalidNanosBooleansAndTrailingData() throws Exception {
		byte[] revoked = revoked(ID, HANDLE);
		byte[] valid = WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, revoked);
		for (byte[] bad : List.of(Arrays.copyOf(valid, 12), Arrays.copyOf(valid, valid.length + 1),
				changed(valid, 12, 3), changedInt(valid, 8, -1), changedInt(valid, 8, 1_000_000_000),
				changed(valid, 16, 9)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.decode(CREDENTIAL.getStorageKey(), bad, PERMANENT.getEpochSecond()));
		byte[] root = WebAuthnRecordPayloadV2.namespace(ROOT, identifier(1), NOW);
		for (byte[] bad : List.of(changed(root, 0, 1), changedInt(root, 41, 1_000_000_000), Arrays.copyOf(root, 46)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.decode(ROOT.getStorageKey(), bad, PERMANENT.getEpochSecond()));
		WebAuthnStoreKey fence = WebAuthnStoreKey.forAccountFence(NS, RP, HANDLE);
		byte[] invalidFence = {1, 2, 3, 4, 5, 6};
		assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(fence, NOW, invalidFence));
	}

	@Test void sortedIndexAndCredentialSemanticsAreRetainedExactly() throws Exception {
		WebAuthnStoreKey index = WebAuthnStoreKey.forAccountCredentialIndex(NS, RP, HANDLE);
		byte[] unordered = index(HANDLE, List.of(new byte[] {2}, new byte[] {1}));
		byte[] duplicate = index(HANDLE, List.of(new byte[] {1}, new byte[] {1}));
		for (byte[] invalid : List.of(unordered, duplicate, changed(index(HANDLE, List.of()), 2, 65)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(index, NOW, invalid));
		byte[] publicKey = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
		for (byte[] invalid : List.of(active(ID, HANDLE, publicKey, -7, 1, 0),
				active(ID, HANDLE, publicKey, -8, 1, 2), active(ID, HANDLE, publicKey, -8, 1, 4),
				active(ID, HANDLE, new byte[] {0}, -8, 1, 0)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, invalid));
	}

	@Test void malformedCeremonyKindOriginPurposeAndExpiryNeverAcquireANewFloor() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var old = new WebAuthnRecordCodec(sealer);
		var ceremony = new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old).encode(WebAuthnCeremonyState.discoverableAuthentication(
				bytes(1), bytes(2), bytes(3), Set.of("https://login.example.com"), NOW, NOW.plusSeconds(30)));
		byte[] valid = old.open(ceremony.key(), ceremony.sealedBytes(), CLOCK);
		for (byte[] invalid : List.of(changed(valid, 0, 2), changed(valid, 1, 2), changed(valid, 2, 0),
				changedInt(valid, 107, 1_000_000_000), Arrays.copyOf(valid, valid.length + 1), changed(valid, valid.length - 1, ' ')))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(ceremony.key(), NOW, invalid));
	}

	@Test void recordEnvelopeTamperingAndCrossChunkSplicingFailClosed() throws Exception {
		var codec = new WebAuthnRecordCodecV2(sealer("k".repeat(64), 1_024));
		byte[] record = codec.seal(CREDENTIAL, pattern(5_000), PERMANENT);
		for (int offset : new int[] {0, 4, 6, 8, 25, record.length - 1})
			assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, changed(record, offset, record[offset] ^ 1), CLOCK));
		for (byte[] invalid : List.of(Arrays.copyOf(record, record.length - 1), Arrays.copyOf(record, record.length + 1),
				new byte[262_145])) assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, invalid, CLOCK));
		int first = unsignedShort(record, 24);
		int secondOffset = 26 + first;
		int second = unsignedShort(record, secondOffset);
		assertEquals(first, second);
		byte[] swapped = record.clone();
		System.arraycopy(record, secondOffset + 2, swapped, 26, first);
		System.arraycopy(record, 26, swapped, secondOffset + 2, second);
		assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, swapped, CLOCK));
		byte[] different = codec.seal(CREDENTIAL, pattern(5_000), PERMANENT);
		byte[] spliced = record.clone();
		System.arraycopy(different, 26, spliced, 26, first);
		assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, spliced, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> codec.open(WebAuthnStoreKey.forCredential(NS, RP, new byte[] {9}), record, CLOCK));
	}

	@Test void minimumCapCarries236ChunksAndMaximumLogicalIndexWithoutTrimming() throws Exception {
		var codec = new WebAuthnRecordCodecV2(sealer("k".repeat(64), 1_024));
		byte[] record = codec.seal(CREDENTIAL, pattern(110_000), PERMANENT);
		assertEquals(236, unsignedShort(record, 4));
		assertEquals(467, unsignedShort(record, 6));
		assertTrue(record.length <= 262_144);
		assertArrayEquals(pattern(110_000), codec.open(CREDENTIAL, record, CLOCK));
		assertThrows(IllegalArgumentException.class, () -> codec.seal(CREDENTIAL, new byte[110_001], PERMANENT));
		assertThrows(IllegalArgumentException.class, () -> codec.seal(CREDENTIAL, new byte[0], PERMANENT));
		byte[] handle = pattern(64);
		List<byte[]> ids = new ArrayList<>();
		for (int i = 0; i < 64; i++) { byte[] id = pattern(1_023); id[0] = (byte) i; ids.add(id); }
		WebAuthnStoreKey key = WebAuthnStoreKey.forAccountCredentialIndex(NS, RP, handle);
		byte[] payload = WebAuthnRecordPayloadV2.entity(key, NOW, index(handle, ids));
		assertEquals(65_679, payload.length);
		try (var decoded = codec.openRecord(key, codec.seal(key, payload, PERMANENT), CLOCK)) {
			assertEquals(65_667, decoded.innerPayload().length);
		}
	}

	@Test void frameCapacityFormulaHoldsAtSelectedCapsAndThe1026ArithmeticMaximum() throws Exception {
		for (int cap : List.of(1_024, 1_026, 3_800, 16_384)) {
			var codec = new WebAuthnRecordCodecV2(sealer("k".repeat(64), cap));
			byte[] record = codec.seal(CREDENTIAL, pattern(110_000), PERMANENT);
			assertTrue(record.length <= 262_144);
			assertEquals(cap == 1_026 ? 468 : (cap * 3 / 4 - 54 - 64 - 16) * 3 / 4 - 8, unsignedShort(record, 6));
			assertArrayEquals(pattern(110_000), codec.open(CREDENTIAL, record, CLOCK));
			if (cap == 1_026) assertEquals(233_340, record.length);
		}
	}

	@Test void decodedPlaintextAndPublicDiagnosticsDoNotEscapeMutableSecrets() throws Exception {
		byte[] payload = WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, revoked(ID, HANDLE));
		var codec = new WebAuthnRecordCodecV2(sealer("k", 3_800));
		var decoded = codec.openRecord(CREDENTIAL, codec.seal(CREDENTIAL, payload, PERMANENT), CLOCK);
		byte[] first = decoded.innerPayload(); first[0] = 0;
		assertEquals(2, decoded.innerPayload()[0]);
		assertFalse(decoded.toString().contains(CREDENTIAL.getStorageKey()));
		decoded.close();
		assertArrayEquals(new byte[revoked(ID, HANDLE).length], decoded.innerPayload());
	}

	private static @NonNull List<@NonNull Fixture> fixtures(@NonNull WebAuthnRecordCodec old) throws Exception {
		List<Fixture> fixtures = new ArrayList<>();
		byte[] cose = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
		var credentials = new LegacyWebAuthnCredentialRecordCodec(NS, RP, old);
		var active = credentials.encode(WebAuthnCredentialState.checked(ID, HANDLE, cose, -8, 0xffff_ffffL, true, true));
		assertEquals(0xffff_ffffL, credentials.decode(active.key(), active.sealedBytes(), CLOCK).counter());
		fixtures.add(new Fixture(active.key(), active.sealedBytes(), PERMANENT));
		var revoked = credentials.encodeRevoked(ID, HANDLE);
		assertTrue(credentials.decodeRecord(revoked.key(), revoked.sealedBytes(), CLOCK).isRevoked());
		fixtures.add(new Fixture(revoked.key(), revoked.sealedBytes(), PERMANENT));
		var indexes = new LegacyWebAuthnCredentialIndex(NS, RP, old);
		var index = indexes.encode(indexes.empty(HANDLE).withAdded(ID));
		assertEquals(1, indexes.decode(index.key(), index.sealedBytes(), CLOCK).size());
		fixtures.add(new Fixture(index.key(), index.sealedBytes(), PERMANENT));
		var empty = indexes.encode(indexes.empty(HANDLE));
		fixtures.add(new Fixture(empty.key(), empty.sealedBytes(), PERMANENT));
		var fences = new LegacyWebAuthnAccountFence(NS, RP, old);
		var fence = fences.encode(HANDLE, false);
		assertFalse(fences.decode(fence.key(), fence.sealedBytes(), CLOCK).isActive());
		fixtures.add(new Fixture(fence.key(), fence.sealedBytes(), PERMANENT));
		var ceremonies = new LegacyWebAuthnCeremonyRecordCodec(NS, RP, old);
		var ceremony = ceremonies.encode(WebAuthnCeremonyState.accountReauthentication(bytes(1), bytes(2), bytes(3),
				Set.of("https://login.example.com"), HANDLE, "remove credential", NOW, NOW.plusSeconds(30)).consume());
		assertTrue(ceremonies.decode(ceremony.key(), ceremony.sealedBytes(), CLOCK).isConsumed());
		fixtures.add(new Fixture(ceremony.key(), ceremony.sealedBytes(), NOW.plusSeconds(30)));
		return fixtures;
	}

	private static @NonNull ClosedMigrationIntent intent(int value) {
		return ClosedMigrationIntent.fromExternalIntent(identifier(value), admission(), Set.of(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));
	}
	private static @NonNull StoreAdmission admission() { return StoreAdmission.fromIdentifiers(identifier(3), identifier(4)); }
	private static @NonNull String identifier(int value) { return Base64Url.encode(bytes(value)); }
	private static byte @NonNull [] bytes(int value) { byte[] b = new byte[32]; for (int i = 0; i < b.length; i++) b[i] = (byte) (value + i); return b; }
	private static @NonNull StateSealer sealer(@NonNull String id, int cap) {
		return StateSealer.withActiveKey(SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(bytes(1))))
				.maximumSealedLength(cap).clock(CLOCK).build();
	}
	private static byte @NonNull [] pattern(int count) { byte[] result = new byte[count]; for (int i = 0; i < count; i++) result[i] = (byte) (i * 37 + 11); return result; }
	private static byte @NonNull [] changed(byte @NonNull [] original, int offset, int value) { byte[] copy = original.clone(); copy[offset] = (byte) value; return copy; }
	private static byte @NonNull [] changedInt(byte @NonNull [] original, int offset, int value) { byte[] copy = original.clone(); ByteBuffer.wrap(copy).putInt(offset, value); return copy; }
	private static int unsignedShort(byte @NonNull [] bytes, int offset) { return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff); }
	private static byte @NonNull [] revoked(byte @NonNull [] id, byte @NonNull [] handle) { return ByteBuffer.allocate(4 + id.length + handle.length).put((byte) 2).putShort((short) id.length).put((byte) handle.length).put(id).put(handle).array(); }
	private static byte @NonNull [] active(byte @NonNull [] id, byte @NonNull [] handle, byte @NonNull [] key, int algorithm, long counter, int flags) {
		return ByteBuffer.allocate(13 + id.length + handle.length + key.length).put((byte) 1).putShort((short) algorithm)
				.putInt((int) counter).put((byte) flags).putShort((short) id.length).put((byte) handle.length).putShort((short) key.length).put(id).put(handle).put(key).array();
	}
	private static byte @NonNull [] index(byte @NonNull [] handle, @NonNull List<byte @NonNull []> ids) {
		int size = 3 + handle.length; for (byte[] id : ids) size += 2 + id.length;
		ByteBuffer writer = ByteBuffer.allocate(size).put((byte) 1).put((byte) handle.length).put((byte) ids.size()).put(handle);
		for (byte[] id : ids) writer.putShort((short) id.length).put(id); return writer.array();
	}
	private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
		byte[] spki = pair.getPublic().getEncoded();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (int value : new int[] {0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 32}) out.write(value);
		out.write(spki, spki.length - 32, 32); return out.toByteArray();
	}
	private static final class Fixture {
		private final @NonNull WebAuthnStoreKey key;
		private final byte @NonNull [] sealed;
		private final @NonNull Instant expiresAt;
		private Fixture(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealed, @NonNull Instant expiresAt) {
			this.key = key; this.sealed = sealed; this.expiresAt = expiresAt;
		}
	}
}
