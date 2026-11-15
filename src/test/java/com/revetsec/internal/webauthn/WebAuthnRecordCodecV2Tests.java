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
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** WAR2, the only WebAuthn record format; the removed WAR1 framing and active-v1 credentials fail closed. */
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
		byte[] root = new WebAuthnRecordCodec(sealer).sealNamespace(ROOT, identifier(3), NOW);
		assertEquals("WAR2", new String(root, 0, 4, StandardCharsets.US_ASCII));
		try (var opened = new WebAuthnRecordCodecV2(sealer).openWithMetadata(ROOT, root, CLOCK)) {
			byte[] plain = opened.plaintext();
			assertEquals(45, plain.length);
			byte[] expected = ByteBuffer.allocate(45).put((byte) 2).put(Base64Url.decode(identifier(3)))
					.putLong(NOW.getEpochSecond()).putInt(NOW.getNano()).array();
			assertArrayEquals(expected, plain);
			assertEquals(PERMANENT.getEpochSecond(), opened.notAfter());
		}
		try (var decoded = new WebAuthnRecordCodecV2(sealer).openRecord(ROOT, root, CLOCK)) {
			assertEquals(NOW, decoded.floor());
			assertEquals(identifier(3), decoded.authorityId().orElseThrow());
			assertEquals(PERMANENT, decoded.expiresAt());
		}
		byte[] finite = new WebAuthnRecordCodecV2(sealer).seal(ROOT,
				WebAuthnRecordPayloadV2.namespace(ROOT, identifier(3), NOW), NOW.plusSeconds(100));
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(ROOT, finite, CLOCK));
	}

	@Test void retiredWar1FramesAndActiveVersionOneCredentialsFailClosed() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var codec = new WebAuthnRecordCodecV2(sealer);
		var records = new WebAuthnRecordCodec(sealer);
		byte[] tombstone = WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, revoked(ID, HANDLE));
		byte[] current = WebAuthnTestPayloads.frame(sealer, CREDENTIAL, tombstone, "WAR2", "revetsec/wa-record/v2:");
		try (var decoded = codec.openRecord(CREDENTIAL, current, CLOCK)) { assertEquals(NOW, decoded.floor()); }
		byte[] war1 = WebAuthnTestPayloads.removedWar1(sealer, CREDENTIAL, tombstone);
		byte[] relabeled = war1.clone();
		relabeled[3] = '2';
		byte[] retiredContext = WebAuthnTestPayloads.frame(sealer, CREDENTIAL, tombstone, "WAR2", "revetsec/wa-record/v1:");
		for (byte[] retired : List.of(war1, relabeled, retiredContext)) {
			assertFalse(assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, retired, CLOCK)).isExpired());
			assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(CREDENTIAL, retired, CLOCK));
			assertThrows(WebAuthnRecordException.class, () -> records.openAdmitted(CREDENTIAL, retired, CLOCK));
			assertThrows(WebAuthnRecordException.class, () -> records.resealAdmitted(CREDENTIAL, retired, CLOCK));
			assertThrows(WebAuthnRecordException.class,
					() -> new WebAuthnCredentialRecordCodec(NS, RP, records).decodeRecord(CREDENTIAL, retired, CLOCK));
		}
		String context = "revetsec/wa-record/v1:" + digest(CREDENTIAL) + ":record:1:1:0";
		String chunk = SealedStateAccess.get().seal(sealer, SealedStateType.WEBAUTHN_RECORD, "AA", context, PERMANENT);
		assertThrows(IllegalArgumentException.class,
				() -> SealedStateAccess.get().openRecord(sealer, SealedStateType.WEBAUTHN_RECORD, chunk, context, CLOCK));

		byte[] publicKey = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
		byte[] versionOne = activeVersionOne(ID, HANDLE, publicKey, -8, 7, 0);
		byte[] payload = ByteBuffer.allocate(12 + versionOne.length).putLong(NOW.getEpochSecond()).putInt(NOW.getNano())
				.put(versionOne).array();
		byte[] sealed = codec.seal(CREDENTIAL, payload, PERMANENT);
		assertArrayEquals(payload, codec.open(CREDENTIAL, sealed, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(CREDENTIAL, sealed, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> records.openAdmitted(CREDENTIAL, sealed, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> records.resealAdmitted(CREDENTIAL, sealed, CLOCK));
		var credentials = new WebAuthnCredentialRecordCodec(NS, RP, records);
		assertThrows(WebAuthnRecordException.class, () -> credentials.decodeRecord(CREDENTIAL, sealed, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> credentials.decode(CREDENTIAL, sealed, CLOCK));
		assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.decode(
				CREDENTIAL.getStorageKey(), payload, PERMANENT.getEpochSecond()));
		assertThrows(IllegalArgumentException.class, () -> records.sealEntity(CREDENTIAL, versionOne, PERMANENT, NOW));
		byte[] versionThree = active(ID, HANDLE, publicKey, -8, 7, 0);
		assertEquals(7, credentials.decode(CREDENTIAL, records.sealEntity(CREDENTIAL, versionThree, PERMANENT, NOW), CLOCK).counter());
	}

	@Test void fullJavaInstantFloorsIncludingNegativeAndSentinelRemainExact() throws Exception {
		var codec = new WebAuthnRecordCodecV2(sealer("k", 3_800));
		for (Instant value : List.of(Instant.MIN, Instant.EPOCH.minusNanos(1), PERMANENT, Instant.MAX)) {
			byte[] root = codec.seal(ROOT, WebAuthnRecordPayloadV2.namespace(ROOT, identifier(1), value), PERMANENT);
			try (var decoded = codec.openRecord(ROOT, root, CLOCK)) {
				assertEquals(value, decoded.floor());
			}
			byte[] entity = codec.seal(CREDENTIAL, WebAuthnRecordPayloadV2.entity(CREDENTIAL, value, revoked(ID, HANDLE)), PERMANENT);
			try (var decoded = codec.openRecord(CREDENTIAL, entity, CLOCK)) {
				assertEquals(value, decoded.floor());
			}
		}
		// Representability is deliberately separate from the engine's narrower timed-admission range.
	}

	@Test void consumedCeremonyRemainsExactlyExpired() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		Instant issued = NOW.minusSeconds(60);
		Instant expires = issued.plusSeconds(30);
		var state = WebAuthnCeremonyState.discoverableAuthentication(bytes(1), bytes(2), bytes(3),
				Set.of("https://login.example.com"), issued, expires).consume();
		var ceremony = new WebAuthnCeremonyRecordCodec(NS, RP, new WebAuthnRecordCodec(sealer)).encode(state, issued);
		assertEquals(expires, ceremony.expiresAt());
		var codec = new WebAuthnRecordCodecV2(sealer);
		assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(ceremony.key(), ceremony.sealedBytes(), CLOCK));
		Clock justBefore = Clock.fixed(expires.minusNanos(1), ZoneOffset.UTC);
		try (var decoded = codec.openRecord(ceremony.key(), ceremony.sealedBytes(), justBefore)) {
			assertEquals(1, decoded.innerPayload()[1]);
			assertEquals(issued, decoded.floor());
			assertEquals(expires, decoded.expiresAt());
		}
		assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(
				ceremony.key(), ceremony.sealedBytes(), Clock.fixed(expires, ZoneOffset.UTC)));
	}

	@Test void ceremonyAtInstantMaximumPreservesUnrepresentableCeilingSeconds() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		Instant issued = Instant.MAX.minusSeconds(60);
		WebAuthnCeremonyState state = WebAuthnCeremonyState.discoverableAuthentication(bytes(1), bytes(2), bytes(3),
				Set.of("https://login.example.com"), issued, Instant.MAX);
		var ceremony = new WebAuthnCeremonyRecordCodec(NS, RP, new WebAuthnRecordCodec(sealer)).encode(state, issued);
		var next = new WebAuthnRecordCodecV2(sealer);
		try (var opened = next.openWithMetadata(ceremony.key(), ceremony.sealedBytes(), CLOCK)) {
			assertEquals(Instant.MAX.getEpochSecond() + 1, opened.notAfter());
		}
		try (var decoded = next.openRecord(ceremony.key(), ceremony.sealedBytes(), CLOCK)) {
			assertEquals(issued, decoded.floor());
			assertEquals(Instant.MAX, decoded.expiresAt());
		}
		assertThrows(WebAuthnRecordException.class, () -> next.openRecord(ceremony.key(), ceremony.sealedBytes(),
				Clock.fixed(Instant.MAX, ZoneOffset.UTC)));
	}

	@Test void exactRetentionBindingsRejectAuthenticatedButMisboundRecords() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		byte[] payload = WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, revoked(ID, HANDLE));
		byte[] wrongNew = new WebAuthnRecordCodecV2(sealer).seal(CREDENTIAL, payload, NOW.plusSeconds(100));
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(CREDENTIAL, wrongNew, CLOCK));
		byte[] wrongVersion = WebAuthnRecordPayloadV2.namespace(ROOT, identifier(1), NOW);
		wrongVersion[0] = 1;
		byte[] wrongRoot = new WebAuthnRecordCodecV2(sealer).seal(ROOT, wrongVersion, PERMANENT);
		assertThrows(WebAuthnRecordException.class, () -> new WebAuthnRecordCodecV2(sealer).openRecord(ROOT, wrongRoot, CLOCK));
	}

	@Test void addressReconstructionIsBoundedCanonicalAndRechecksRecoveredIdentifier() throws Exception {
		var codec = new WebAuthnRecordCodecV2(sealer("k", 3_800));
		for (String invalid : List.of(ROOT.getStorageKey() + ":extra", "x".repeat(584),
				ROOT.getStorageKey().replace("wa1:", "wa2:"), ROOT.getStorageKey().replace(":NAMESPACE_CLOCK:", ":OTHER:"),
				ROOT.getStorageKey().substring(0, ROOT.getStorageKey().length() - 1) + "B"))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.namespaceKeyForAddress(invalid));
		assertEquals(ROOT, WebAuthnRecordPayloadV2.namespaceKeyForAddress(CREDENTIAL.getStorageKey()));
		byte[] foreign = revoked(new byte[] {9}, HANDLE);
		byte[] misbound = codec.seal(CREDENTIAL, ByteBuffer.allocate(12 + foreign.length).putLong(NOW.getEpochSecond())
				.putInt(NOW.getNano()).put(foreign).array(), PERMANENT);
		assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(CREDENTIAL, misbound, CLOCK));
		WebAuthnStoreKey other = WebAuthnStoreKey.forCredential("other", RP, ID);
		assertThrows(WebAuthnRecordException.class, () -> codec.openRecord(other, misbound, CLOCK));
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

	@Test void scApi02AuthenticatedRootAndEntityBoundariesRetainNanosAndRejectRawNanoOverflow() throws Exception {
		var codec=new WebAuthnRecordCodecV2(sealer("k",3800));
		Instant maximum=Instant.ofEpochSecond(253402300799L,999999999);
		for(Instant time:List.of(Instant.EPOCH,Instant.EPOCH.plusNanos(1),Instant.ofEpochSecond(0,999999999),
				Instant.ofEpochSecond(253402300799L),maximum.minusNanos(1),maximum)){
			byte[] root=WebAuthnRecordPayloadV2.namespace(ROOT,identifier(1),time);
			try(var decoded=codec.openRecord(ROOT,codec.seal(ROOT,root,PERMANENT),CLOCK)){
				assertEquals(time,decoded.floor());assertEquals(identifier(1),decoded.authorityId().orElseThrow());
			}
			byte[] entity=WebAuthnRecordPayloadV2.entity(CREDENTIAL,time,revoked(ID,HANDLE));
			try(var decoded=codec.openRecord(CREDENTIAL,codec.seal(CREDENTIAL,entity,PERMANENT),CLOCK)){assertEquals(time,decoded.floor());}
		}
		for(int nanos:List.of(-1,1000000000)){
			byte[] root=changedInt(WebAuthnRecordPayloadV2.namespace(ROOT,identifier(1),NOW),41,nanos);
			assertThrows(WebAuthnRecordException.class,()->codec.openRecord(ROOT,codec.seal(ROOT,root,PERMANENT),CLOCK));
			byte[] entity=changedInt(WebAuthnRecordPayloadV2.entity(CREDENTIAL,NOW,revoked(ID,HANDLE)),8,nanos);
			assertThrows(WebAuthnRecordException.class,()->codec.openRecord(CREDENTIAL,codec.seal(CREDENTIAL,entity,PERMANENT),CLOCK));
		}
	}

	@Test void sortedIndexAndCredentialSemanticsAreRetainedExactly() throws Exception {
		WebAuthnStoreKey index = WebAuthnStoreKey.forAccountCredentialIndex(NS, RP, HANDLE);
		byte[] unordered = index(HANDLE, List.of(new byte[] {2}, new byte[] {1}));
		byte[] duplicate = index(HANDLE, List.of(new byte[] {1}, new byte[] {1}));
		for (byte[] invalid : List.of(unordered, duplicate, changed(index(HANDLE, List.of()), 2, 65)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(index, NOW, invalid));
		byte[] publicKey = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
		for (byte[] invalid : List.of(active(ID, HANDLE, publicKey, -7, 1, 0),
				active(ID, HANDLE, publicKey, -8, 1, 2), active(ID, HANDLE, publicKey, -8, 1, 8),
				active(ID, HANDLE, new byte[] {0}, -8, 1, 0)))
			assertThrows(WebAuthnRecordException.class, () -> WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, invalid));
		for (int flags = 0; flags < 8; flags++) {
			if (flags == 2 || flags == 6) continue;
			byte[] valid = active(ID, HANDLE, publicKey, -8, 1, flags);
			assertEquals(12 + valid.length, WebAuthnRecordPayloadV2.entity(CREDENTIAL, NOW, valid).length);
		}
	}

	@Test void malformedCeremonyKindOriginPurposeAndExpiryNeverAcquireANewFloor() throws Exception {
		StateSealer sealer = sealer("k", 3_800);
		var records = new WebAuthnRecordCodec(sealer);
		var ceremony = new WebAuthnCeremonyRecordCodec(NS, RP, records).encode(WebAuthnCeremonyState.discoverableAuthentication(
				bytes(1), bytes(2), bytes(3), Set.of("https://login.example.com"), NOW, NOW.plusSeconds(30)), NOW);
		byte[] valid = records.openAdmitted(ceremony.key(), ceremony.sealedBytes(), CLOCK);
		WebAuthnRecordPayloadV2.entity(ceremony.key(), NOW, valid);
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
		return ByteBuffer.allocate(29 + id.length + handle.length + key.length).put((byte) 3).putShort((short) algorithm)
				.putInt((int) counter).put((byte) flags).put(new byte[16]).putShort((short) id.length).put((byte) handle.length)
				.putShort((short) key.length).put(id).put(handle).put(key).array();
	}
	/** The retired, never-released active-credential layout: version 1 without AAGUID. */
	private static byte @NonNull [] activeVersionOne(byte @NonNull [] id, byte @NonNull [] handle, byte @NonNull [] key, int algorithm, long counter, int flags) {
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
	private static @NonNull String digest(@NonNull WebAuthnStoreKey key) throws Exception {
		return Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(key.getStorageKey().getBytes(StandardCharsets.US_ASCII)));
	}
}
