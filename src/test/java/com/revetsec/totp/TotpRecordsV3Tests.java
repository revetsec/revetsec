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

package com.revetsec.totp;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Active TTR3 component vectors. */
final class TotpRecordsV3Tests {
	private static final Instant T = Instant.ofEpochSecond(1_700_000_000L, 123_456_789);
	private static final Instant MAX = Instant.ofEpochSecond(253_402_300_799L, 999_999_999);
	private static final String AUTHORITY = id(1);
	private static final String VERSION = id(2);
	private static final TotpStoreKey ROOT = TotpStoreKey.forNamespace("namespace", "old-recovery-epoch");
	private static final TotpStoreKey ACCOUNT = TotpStoreKey.forAccount("namespace", "old-recovery-epoch", "account-é");

	@Test void rootGoldenOrderContextAndAddressRemainExact() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		TotpStoreRecord record = codec.sealNamespace(ROOT, new TotpRecordsV3.Namespace(AUTHORITY, T));
		assertEquals(ROOT, record.getKey());
		assertArrayEquals(rootBytes(0x54545233, ROOT, record.getVersion(), AUTHORITY, T), plaintext(sealer, record, true));
		try (TotpRecordsV3.Decoded decoded = codec.open(record)) {
			assertEquals(AUTHORITY, require(decoded.namespace).getAuthorityId());
			assertEquals(T, require(decoded.namespace).getMinimum());
			assertNull(decoded.account);
			assertEquals("key", decoded.keyId);
		}
	}

	@Test void accountGoldenPreservesEverySecretReplayRecoveryAndChargeField() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		TotpRecordState.Account original = account();
		try {
			TotpStoreRecord record = codec.sealAccount(ACCOUNT, original);
			assertArrayEquals(accountBytes(0x54545233, ACCOUNT, record.getVersion(), original), plaintext(sealer, record, true));
			try (TotpRecordsV3.Decoded decoded = codec.open(record)) {
				assertNull(decoded.namespace);
				assertSameAccount(original, require(decoded.account));
			}
		} finally { original.erase(); }
	}

	@Test void newFloorCanExceedStableMinimumWithoutAnOldNamespaceInvariant() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		TotpRecordState.Account account = account();
		try {
			TotpStoreRecord root = codec.sealNamespace(ROOT, new TotpRecordsV3.Namespace(AUTHORITY, T.minusSeconds(1)));
			TotpStoreRecord row = codec.sealAccount(ACCOUNT, account);
			try (TotpRecordsV3.Decoded decodedRoot = codec.open(root); TotpRecordsV3.Decoded decoded = codec.open(row)) {
				assertTrue(require(decoded.account).observedAt.isAfter(require(decodedRoot.namespace).getMinimum()));
			}
		} finally { account.erase(); }
	}

	@Test void decoderHasNoFallbackForUnknownEarlierFormatMagic() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		for (int magic : List.of(0x54545231, 0x54545232)) {
			TotpStoreRecord legacy = raw(sealer, ROOT, VERSION, rootBytes(magic, ROOT, VERSION, null, T), false);
			assertThrows(IOException.class, () -> codec.open(legacy));
			// Even authentic legacy magic under the new context is never interpreted as TTR3.
			TotpStoreRecord transplanted = raw(sealer, ROOT, VERSION, rootBytes(magic, ROOT, VERSION, null, T), true);
			assertThrows(IOException.class, () -> codec.open(transplanted));
		}
	}

	@Test void exactKeyVersionContextAndAuthorityBindingsRejectTampering() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		byte[] valid = rootBytes(0x54545233, ROOT, VERSION, AUTHORITY, T);
		TotpStoreRecord row = raw(sealer, ROOT, VERSION, valid, true);
		assertThrows(IOException.class, () -> codec.open(TotpStoreRecord.fromStoredForm(ROOT, id(9), row.getSealedBytes())));
		TotpStoreKey foreign = TotpStoreKey.forNamespace("other", "old-recovery-epoch");
		assertThrows(IOException.class, () -> codec.open(TotpStoreRecord.fromStoredForm(foreign, VERSION, row.getSealedBytes())));
		assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, valid, false)));
		byte[] modified = row.getSealedBytes(); modified[modified.length - 2] ^= 1;
		assertThrows(IOException.class, () -> codec.open(TotpStoreRecord.fromStoredForm(ROOT, VERSION, modified)));
		for (String authority : List.of("A".repeat(42) + "B", "A".repeat(42), "A".repeat(42) + "+"))
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION,
					rootBytes(0x54545233, ROOT, VERSION, authority, T), true)));
	}

	@Test void strictIntegerNanosUnknownMagicTruncationAndTrailingDataFailClosed() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		byte[] valid = rootBytes(0x54545233, ROOT, VERSION, AUTHORITY, T);
		for (int nanos : List.of(-1, 1_000_000_000)) {
			byte[] changed = valid.clone(); ByteBuffer.wrap(changed, changed.length - 4, 4).putInt(nanos);
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, changed, true)));
		}
		for (long seconds : List.of(-1L, 253_402_300_800L)) {
			byte[] changed = valid.clone(); ByteBuffer.wrap(changed, changed.length - 12, 8).putLong(seconds);
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, changed, true)));
		}
		byte[] magic = valid.clone(); magic[3]++;
		assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, magic, true)));
		byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
		assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, trailing, true)));
		for (int length : List.of(0, 3, valid.length - 1)) {
			byte[] truncated = Arrays.copyOf(valid, length);
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ROOT, VERSION, truncated, true)));
		}
	}

	@Test void supportedTimeEndpointsAndStableRootRepresentationHaveNoMutableMinimum() throws Exception {
		StateSealer sealer = sealer("key");
		for (Instant time : List.of(Instant.EPOCH, MAX)) {
			TotpStoreRecord row = new TotpRecordsV3(sealer).sealNamespace(ROOT, new TotpRecordsV3.Namespace(AUTHORITY, time));
			try (TotpRecordsV3.Decoded opened = new TotpRecordsV3(sealer).open(row)) {
				assertEquals(time, require(opened.namespace).getMinimum());
			}
		}
		for (var field : TotpRecordsV3.Namespace.class.getDeclaredFields()) {
			assertTrue(Modifier.isPrivate(field.getModifiers()));
			assertTrue(Modifier.isFinal(field.getModifiers()));
		}
		assertThrows(IllegalArgumentException.class, () -> new TotpRecordsV3.Namespace(AUTHORITY, Instant.EPOCH.minusNanos(1)));
		assertThrows(IllegalArgumentException.class, () -> new TotpRecordsV3.Namespace(AUTHORITY, MAX.plusNanos(1)));
	}

	@Test void scApi02RootAndAccountFloorsPreserveEveryCommonBoundaryWithoutRounding() throws Exception {
		TotpRecordsV3 codec=new TotpRecordsV3(sealer("key"));
		for(Instant time:List.of(Instant.EPOCH,Instant.EPOCH.plusNanos(1),Instant.ofEpochSecond(0,999999999),
				Instant.ofEpochSecond(253402300799L),MAX.minusNanos(1),MAX)){
			TotpStoreRecord root=codec.sealNamespace(ROOT,new TotpRecordsV3.Namespace(AUTHORITY,time));
			try(var decoded=codec.open(root)){assertEquals(time,require(decoded.namespace).getMinimum());assertEquals(AUTHORITY,require(decoded.namespace).getAuthorityId());}
			TotpRecordState.Account account=new TotpRecordState.Account("account-é",id(3),time);
			try{
				TotpStoreRecord row=codec.sealAccount(ACCOUNT,account);
				try(var decoded=codec.open(row)){assertEquals(time,require(decoded.account).observedAt);}
			}finally{account.erase();}
		}
	}

	@Test void decoderRejectsInvalidFlagsCountsDuplicateChargesFutureChargeAndAccountBindings() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		TotpRecordState.Account state = account();
		try {
			state.charges.add(new TotpRecordState.Charge(state.charges.get(0).id, T));
			assertThrows(IllegalArgumentException.class, () -> codec.sealAccount(ACCOUNT, state));
			state.charges.remove(state.charges.size() - 1);
			state.totpCharges.add(new TotpRecordState.Charge(id(27), T.plusNanos(1)));
			assertThrows(IllegalArgumentException.class, () -> codec.sealAccount(ACCOUNT, state));
			state.totpCharges.remove(state.totpCharges.size() - 1);
			for (int i = 0; i < 10; i++) state.totpCharges.add(new TotpRecordState.Charge(id(30 + i), T));
			assertThrows(IllegalArgumentException.class, () -> codec.sealAccount(ACCOUNT, state));
			state.totpCharges.clear();
			TotpStoreKey foreign = TotpStoreKey.forAccount("namespace", "old-recovery-epoch", "wrong-account");
			assertThrows(IllegalArgumentException.class, () -> codec.sealAccount(foreign, state));
			state.batchId = null;
			assertThrows(IllegalArgumentException.class, () -> codec.sealAccount(ACCOUNT, state));
			state.batchId = id(8);
			byte[] encoded = accountBytes(0x54545233, ACCOUNT, VERSION, state);
			int firstFlag = headerLength(ACCOUNT, VERSION) + 4 + state.accountId.getBytes(StandardCharsets.UTF_8).length + 4 + 43 + 12;
			encoded[firstFlag] = 2;
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ACCOUNT, VERSION, encoded, true)));
		} finally { state.erase(); }
	}

	@Test void decoderRejectsNegativeCountsMalformedUtf8AndOverlongTextBeforeConstruction() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordsV3 codec = new TotpRecordsV3(sealer);
		TotpRecordState.Account state = new TotpRecordState.Account("account-é", id(4), T);
		try {
			byte[] valid = accountBytes(0x54545233, ACCOUNT, VERSION, state);
			byte[] count = valid.clone(); ByteBuffer.wrap(count, count.length - 4, 4).putInt(-1);
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ACCOUNT, VERSION, count, true)));
			byte[] length = valid.clone(); ByteBuffer.wrap(length, headerLength(ACCOUNT, VERSION), 4).putInt(4097);
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ACCOUNT, VERSION, length, true)));
			byte[] utf8 = valid.clone(); utf8[headerLength(ACCOUNT, VERSION) + 4] = (byte) 0xff;
			assertThrows(IOException.class, () -> codec.open(raw(sealer, ACCOUNT, VERSION, utf8, true)));
		} finally { state.erase(); }
	}

	@Test void maximumAccountCountsAndAddressTextFitDurable64KeyWithoutTrimming() throws Exception {
		StateSealer sealer = sealer("k".repeat(64));
		TotpRecordState.Account state = new TotpRecordState.Account("a".repeat(1024), id(3), MAX);
		state.active = new TotpRecordState.Active(id(4), bytes(20, 21), MAX, Long.MAX_VALUE);
		state.pending = new TotpRecordState.Pending(id(5), id(6), bytes(20, 22), bytes(32, 23), MAX, id(4));
		state.batchId = id(7);
		for (int i = 0; i < 10; i++) state.recoveryHashes.add(bytes(32, 40 + i));
		for (int i = 0; i < 5; i++) state.charges.add(new TotpRecordState.Charge(id(60 + i), MAX));
		for (int i = 0; i < 10; i++) state.totpCharges.add(new TotpRecordState.Charge(id(80 + i), MAX));
		TotpStoreKey key = TotpStoreKey.forAccount("n".repeat(128), "e".repeat(128), state.accountId);
		try {
			TotpStoreRecord row = new TotpRecordsV3(sealer).sealAccount(key, state);
			assertTrue(row.getSealedBytes().length < 65_536);
			try (TotpRecordsV3.Decoded decoded = new TotpRecordsV3(sealer).open(row)) {
				assertSameAccount(state, require(decoded.account));
			}
			state.charges.add(new TotpRecordState.Charge(id(95), MAX));
			assertThrows(IllegalArgumentException.class, () -> new TotpRecordsV3(sealer).sealAccount(key, state));
			state.charges.remove(state.charges.size() - 1);
			state.recoveryHashes.add(bytes(32, 96));
			assertThrows(IllegalArgumentException.class, () -> new TotpRecordsV3(sealer).sealAccount(key, state));
		} finally { state.erase(); }
	}

	@Test void closingDecodedAccountsErasesEveryOwnedSensitiveBuffer() throws Exception {
		StateSealer sealer = sealer("key");
		TotpRecordState.Account state = account();
		try {
			TotpRecordsV3.Decoded opened = new TotpRecordsV3(sealer).open(new TotpRecordsV3(sealer).sealAccount(ACCOUNT, state));
			TotpRecordState.Account decoded = require(opened.account);
			byte[] active = require(decoded.active).secret;
			byte[] pending = require(decoded.pending).secret;
			byte[] browser = require(decoded.pending).browserHash;
			byte[] hash = decoded.recoveryHashes.get(0);
			opened.close();
			for (byte[] bytes : List.of(active, pending, browser, hash)) assertArrayEquals(new byte[bytes.length], bytes);
		} finally { state.erase(); }
	}

	@Test void durableMaximumWireProjectionWith64CharacterKeyFitsWithoutOrdinaryCapExpansion() throws Exception {
		StateSealer sealer = sealer("k".repeat(64));
		byte[] raw = new byte[32_000]; Arrays.fill(raw, (byte) 31);
		String plaintext = Base64Url.encode(raw);
		assertEquals(42_667, plaintext.length());
		String sealed = SealedStateAccess.get().sealDurable(sealer, plaintext, context(ROOT, true));
		assertEquals(57_047, sealed.length());
		assertTrue(sealed.length() < 65_536);
		// This is an exact crypto-framing boundary, not a claim that arbitrary 32k bytes are a valid account.
		TotpStoreRecord malformed = TotpStoreRecord.fromStoredForm(ROOT, VERSION, sealed.getBytes(StandardCharsets.US_ASCII));
		assertThrows(IOException.class, () -> new TotpRecordsV3(sealer).open(malformed));
		byte[] over = new byte[32_001];
		assertThrows(IOException.class, () -> new TotpRecordsV3(sealer).open(raw(sealer, ROOT, VERSION, over, true)));
		TotpStoreRecord valid = new TotpRecordsV3(sealer).sealNamespace(ROOT, new TotpRecordsV3.Namespace(AUTHORITY, T));
		try (TotpRecordsV3.Decoded opened = new TotpRecordsV3(sealer).open(valid)) { assertEquals("k".repeat(64), opened.keyId); }
	}

	private static @NonNull StateSealer sealer(@NonNull String keyId) {
		byte[] key = new byte[32]; for (int i = 0; i < key.length; i++) key[i] = (byte) (i + 23);
		return StateSealer.withActiveKey(SealingKey.fromBase64(keyId, Base64.getEncoder().encodeToString(key))).build();
	}

	private static TotpRecordState.@NonNull Account account() {
		TotpRecordState.Account account = new TotpRecordState.Account("account-é", id(3), T);
		account.active = new TotpRecordState.Active(id(4), bytes(20, 21), T.minusSeconds(1), 123_456_789L);
		account.pending = new TotpRecordState.Pending(id(5), id(6), bytes(20, 22), bytes(32, 23), T.plusSeconds(60), id(4));
		account.batchId = id(7);
		account.recoveryHashes.add(bytes(32, 24)); account.recoveryHashes.add(bytes(32, 25));
		account.charges.add(new TotpRecordState.Charge(id(8), T.minusNanos(1)));
		account.charges.add(new TotpRecordState.Charge(id(9), T));
		account.totpCharges.add(new TotpRecordState.Charge(id(10), T.minusSeconds(61)));
		return account;
	}

	private static void assertSameAccount(TotpRecordState.@NonNull Account expected, TotpRecordState.@NonNull Account actual) {
		assertEquals(expected.accountId, actual.accountId); assertEquals(expected.fence, actual.fence);
		assertEquals(expected.observedAt, actual.observedAt); assertEquals(expected.batchId, actual.batchId);
		assertEquals(require(expected.active).factorId, require(actual.active).factorId);
		assertEquals(require(expected.active).enrolledAt, require(actual.active).enrolledAt);
		assertEquals(require(expected.active).usedStep, require(actual.active).usedStep);
		assertArrayEquals(require(expected.active).secret, require(actual.active).secret);
		assertEquals(require(expected.pending).enrollmentId, require(actual.pending).enrollmentId);
		assertEquals(require(expected.pending).factorId, require(actual.pending).factorId);
		assertEquals(require(expected.pending).expiresAt, require(actual.pending).expiresAt);
		assertEquals(require(expected.pending).expectedFactorId, require(actual.pending).expectedFactorId);
		assertArrayEquals(require(expected.pending).secret, require(actual.pending).secret);
		assertArrayEquals(require(expected.pending).browserHash, require(actual.pending).browserHash);
		assertEquals(expected.recoveryHashes.size(), actual.recoveryHashes.size());
		for (int i = 0; i < expected.recoveryHashes.size(); i++) assertArrayEquals(expected.recoveryHashes.get(i), actual.recoveryHashes.get(i));
		assertEquals(expected.charges.size(), actual.charges.size());
		for (int i = 0; i < expected.charges.size(); i++) {
			assertEquals(expected.charges.get(i).id, actual.charges.get(i).id); assertEquals(expected.charges.get(i).at, actual.charges.get(i).at);
		}
		assertEquals(expected.totpCharges.size(), actual.totpCharges.size());
		for (int i = 0; i < expected.totpCharges.size(); i++) {
			assertEquals(expected.totpCharges.get(i).id, actual.totpCharges.get(i).id); assertEquals(expected.totpCharges.get(i).at, actual.totpCharges.get(i).at);
		}
	}

	private static byte @NonNull [] plaintext(@NonNull StateSealer sealer, @NonNull TotpStoreRecord row, boolean target) throws Exception {
		return Base64Url.decode(SealedStateAccess.get().unsealDurable(sealer,
				new String(row.getSealedBytes(), StandardCharsets.US_ASCII), context(row.getKey(), target)));
	}

	private static @NonNull TotpStoreRecord raw(@NonNull StateSealer sealer, @NonNull TotpStoreKey key,
			@NonNull String version, byte @NonNull [] bytes, boolean target) {
		String sealed = SealedStateAccess.get().sealDurable(sealer, Base64Url.encode(bytes), context(key, target));
		return TotpStoreRecord.fromStoredForm(key, version, sealed.getBytes(StandardCharsets.US_ASCII));
	}

	private static @NonNull String context(@NonNull TotpStoreKey key, boolean target) {
		byte[] hash = TotpPrimitives.digest("revetsec/totp/address/v1", key.getStorageKey());
		try { return "revetsec/totp/durable/v" + (target ? "2:" : "1:") + Base64Url.encode(hash); }
		finally { Arrays.fill(hash, (byte) 0); }
	}

	private static byte @NonNull [] rootBytes(int magic, @NonNull TotpStoreKey key, @NonNull String version,
			@Nullable String authority, @NonNull Instant minimum) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try (DataOutputStream out = new DataOutputStream(buffer)) {
			out.writeInt(magic); text(out, key.getStorageKey()); text(out, version);
			if (magic == 0x54545233) text(out, require(authority));
			instant(out, minimum);
		}
		return buffer.toByteArray();
	}

	private static byte @NonNull [] accountBytes(int magic, @NonNull TotpStoreKey key, @NonNull String version,
			TotpRecordState.@NonNull Account account) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try (DataOutputStream out = new DataOutputStream(buffer)) {
			out.writeInt(magic); text(out, key.getStorageKey()); text(out, version);
			text(out, account.accountId); text(out, account.fence); instant(out, account.observedAt);
			TotpRecordState.Active active = account.active;
			out.writeBoolean(active != null);
			if (active != null) { text(out, active.factorId); blob(out, active.secret); instant(out, active.enrolledAt); out.writeLong(active.usedStep); }
			TotpRecordState.Pending pending = account.pending;
			out.writeBoolean(pending != null);
			if (pending != null) { text(out, pending.enrollmentId); text(out, pending.factorId); blob(out, pending.secret); blob(out, pending.browserHash); instant(out, pending.expiresAt); text(out, pending.expectedFactorId == null ? "" : pending.expectedFactorId); }
			text(out, account.batchId == null ? "" : account.batchId);
			out.writeInt(account.recoveryHashes.size()); for (byte[] hash : account.recoveryHashes) blob(out, hash);
			out.writeInt(account.charges.size()); for (TotpRecordState.Charge charge : account.charges) { text(out, charge.id); instant(out, charge.at); }
			if (magic != 0x54545231) { out.writeInt(account.totpCharges.size()); for (TotpRecordState.Charge charge : account.totpCharges) { text(out, charge.id); instant(out, charge.at); } }
		}
		return buffer.toByteArray();
	}

	private static int headerLength(@NonNull TotpStoreKey key, @NonNull String version) {
		return 4 + 4 + key.getStorageKey().getBytes(StandardCharsets.UTF_8).length + 4 + version.length();
	}
	private static void text(@NonNull DataOutputStream out, @NonNull String value) throws IOException {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8); out.writeInt(bytes.length); out.write(bytes);
	}
	private static void blob(@NonNull DataOutputStream out, byte @NonNull [] value) throws IOException { out.writeInt(value.length); out.write(value); }
	private static void instant(@NonNull DataOutputStream out, @NonNull Instant value) throws IOException { out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano()); }
	private static @NonNull String id(int number) { return Base64Url.encode(bytes(32, number)); }
	private static byte @NonNull [] bytes(int size, int number) { byte[] result = new byte[size]; for (int i = 0; i < size; i++) result[i] = (byte) (number + i); return result; }
	private static <T> @NonNull T require(@Nullable T value) { return java.util.Objects.requireNonNull(value); }
}
