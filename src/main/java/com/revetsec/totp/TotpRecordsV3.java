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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Active TTR3 normal codec; legacy authentication remains restricted to the closed migration helper.
 * The stable namespace minimum is immutable; an account's preparation floor may legitimately exceed it.
 * No decode or migration operation establishes external recovery admission or trusted UTC.
 */
@ThreadSafe
final class TotpRecordsV3 {
	private static final int MAGIC = 0x54545233;
	private final @NonNull StateSealer sealer;
	private final @NonNull TotpRecords legacy;

	TotpRecordsV3(@NonNull StateSealer sealer) {
		this.sealer = requireNonNull(sealer);
		this.legacy = new TotpRecords(sealer);
	}

	@NonNull String freshId() { return this.legacy.freshId(); }

	@NonNull TotpStoreRecord sealNamespace(@NonNull TotpStoreKey key, @NonNull Namespace namespace) {
		requireNonNull(namespace);
		if (key.getKind() != TotpStoreKey.Kind.NAMESPACE_STATE)
			throw new IllegalArgumentException("Invalid TOTP namespace kind");
		return seal(key, namespace, null);
	}

	@NonNull TotpStoreRecord sealAccount(@NonNull TotpStoreKey key, TotpRecords.@NonNull Account account) {
		requireNonNull(account);
		if (key.getKind() != TotpStoreKey.Kind.ACCOUNT_STATE)
			throw new IllegalArgumentException("Invalid TOTP account kind");
		return seal(key, null, account);
	}

	private @NonNull TotpStoreRecord seal(@NonNull TotpStoreKey key, @Nullable Namespace namespace,
			TotpRecords.@Nullable Account account) {
		requireNonNull(key);
		String version = this.legacy.freshId();
		byte[] bytes;
		try (PlaintextBuffer buffer = new PlaintextBuffer(); DataOutputStream out = new DataOutputStream(buffer)) {
			out.writeInt(MAGIC);
			text(out, key.getStorageKey()); text(out, version);
			if (key.getKind() == TotpStoreKey.Kind.NAMESPACE_STATE) {
				Namespace root = requireNonNull(namespace);
				text(out, root.getAuthorityId()); instant(out, root.getMinimum());
			} else {
				writeAccount(out, requireNonNull(account));
			}
			out.flush(); bytes = buffer.toByteArray();
		} catch (IOException failure) {
			throw new IllegalArgumentException("Invalid TOTP stored state", failure);
		}
		try {
			// Mutable account working state is validated before its bytes are sealed.
			Decoded validated = decode(key, version, bytes, "");
			validated.close();
			String encoded = SealedStateAccess.get().sealDurable(this.sealer, Base64Url.encode(bytes), context(key));
			return TotpStoreRecord.fromStoredForm(key, version, encoded.getBytes(StandardCharsets.US_ASCII));
		} catch (IOException failure) {
			throw new IllegalArgumentException("Invalid TOTP stored state", failure);
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	@NonNull Decoded open(@NonNull TotpStoreRecord record) throws IOException {
		requireNonNull(record);
		byte[] raw = record.getSealedBytes();
		byte[] bytes = null;
		try {
			for (byte value : raw)
				if (value < 0 || !Base64Url.isAlphabet((char) value)) throw invalid();
			String sealed = new String(raw, StandardCharsets.US_ASCII);
			String plaintext = SealedStateAccess.get().unsealDurable(this.sealer, sealed, context(record.getKey()));
			bytes = Base64Url.decode(plaintext);
			byte[] wire = Base64Url.decode(sealed);
			String keyId;
			try { keyId = new String(wire, 2, wire[1] & 255, StandardCharsets.US_ASCII); }
			finally { Arrays.fill(wire, (byte) 0); }
			return decode(record.getKey(), record.getVersion(), bytes, keyId);
		} catch (UnsealException | EncodingException | RuntimeException failure) {
			throw invalid();
		} finally {
			Arrays.fill(raw, (byte) 0);
			if (bytes != null) Arrays.fill(bytes, (byte) 0);
		}
	}

	private static @NonNull Decoded decode(@NonNull TotpStoreKey key, @NonNull String version,
			byte @NonNull [] bytes, @NonNull String keyId) throws IOException {
		if (bytes.length > 32_000) throw invalid();
		TotpRecords.Account account = null;
		try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
			if (in.readInt() != MAGIC || !text(in).equals(key.getStorageKey()) || !text(in).equals(version))
				throw invalid();
			Namespace namespace = null;
			if (key.getKind() == TotpStoreKey.Kind.NAMESPACE_STATE)
				namespace = new Namespace(identifier(in), instant(in));
			else {
				account = readAccount(in);
				if (!key.equals(TotpStoreKey.forAccount(key.getCredentialNamespace(), key.getRecoveryEpoch(), account.accountId)))
					throw invalid();
			}
			if (in.read() != -1) throw invalid();
			Decoded decoded = new Decoded(namespace, account, keyId);
			account = null;
			return decoded;
		} catch (RuntimeException failure) {
			throw invalid();
		} finally {
			if (account != null) account.erase();
		}
	}

	private static @NonNull String context(@NonNull TotpStoreKey key) {
		byte[] hash = TotpPrimitives.digest("revetsec/totp/address/v1", key.getStorageKey());
		try { return "revetsec/totp/durable/v2:" + Base64Url.encode(hash); }
		finally { Arrays.fill(hash, (byte) 0); }
	}

	private static void writeAccount(@NonNull DataOutputStream out, TotpRecords.@NonNull Account account) throws IOException {
		if (account.recoveryHashes.size() > 10 || account.charges.size() > 5 || account.totpCharges.size() > 10)
			throw invalid();
		text(out, account.accountId); text(out, account.fence); instant(out, account.observedAt);
		out.writeBoolean(account.active != null);
		TotpRecords.Active active = account.active;
		if (active != null) {
			text(out, active.factorId); blob(out, active.secret); instant(out, active.enrolledAt); out.writeLong(active.usedStep);
		}
		out.writeBoolean(account.pending != null);
		TotpRecords.Pending pending = account.pending;
		if (pending != null) {
			text(out, pending.enrollmentId); text(out, pending.factorId); blob(out, pending.secret);
			blob(out, pending.browserHash); instant(out, pending.expiresAt);
			text(out, pending.expectedFactorId == null ? "" : pending.expectedFactorId);
		}
		text(out, account.batchId == null ? "" : account.batchId);
		out.writeInt(account.recoveryHashes.size());
		for (byte[] hash : account.recoveryHashes) blob(out, hash);
		out.writeInt(account.charges.size());
		for (TotpRecords.Charge charge : account.charges) { text(out, charge.id); instant(out, charge.at); }
		out.writeInt(account.totpCharges.size());
		for (TotpRecords.Charge charge : account.totpCharges) { text(out, charge.id); instant(out, charge.at); }
	}
	private static TotpRecords.@NonNull Account readAccount(@NonNull DataInputStream in) throws IOException {
		TotpRecords.Account account = new TotpRecords.Account(text(in), identifier(in), instant(in));
		boolean accepted = false;
		try {
			if (flag(in)) {
				String factorId = identifier(in);
				byte[] secret = blob(in, 20);
				boolean transferred = false;
				try {
					Instant enrolled = instant(in);
					long used = in.readLong();
					if (used < 0) throw invalid();
					account.active = new TotpRecords.Active(factorId, secret, enrolled, used);
					transferred = true;
				} finally { if (!transferred) Arrays.fill(secret, (byte) 0); }
			}
			if (flag(in)) {
				String id = identifier(in); String factor = identifier(in);
				byte[] secret = blob(in, 20);
				byte @Nullable [] browser = null;
				boolean transferred = false;
				try {
					browser = blob(in, 32);
					Instant expires = instant(in); String expected = text(in);
					if (!expected.isEmpty()) requireIdentifier(expected);
					account.pending = new TotpRecords.Pending(id, factor, secret, browser, expires, expected.isEmpty() ? null : expected);
					transferred = true;
				} finally {
					if (!transferred) {
						Arrays.fill(secret, (byte) 0);
						if (browser != null) Arrays.fill(browser, (byte) 0);
					}
				}
			}
			String batch = text(in);
			if (!batch.isEmpty()) { requireIdentifier(batch); account.batchId = batch; }
			int hashes = count(in, 10);
			for (int i = 0; i < hashes; i++) account.recoveryHashes.add(blob(in, 32));
			int charges = count(in, 5);
			for (int i = 0; i < charges; i++) {
				String id = identifier(in); Instant at = instant(in);
				if (at.isAfter(account.observedAt)) throw invalid();
				for (TotpRecords.Charge previous : account.charges) if (previous.id.equals(id)) throw invalid();
				account.charges.add(new TotpRecords.Charge(id, at));
			}
			int totpCharges = count(in, 10);
			for (int i = 0; i < totpCharges; i++) {
				String id = identifier(in); Instant at = instant(in);
				if (at.isAfter(account.observedAt)) throw invalid();
				for (TotpRecords.Charge previous : account.totpCharges) if (previous.id.equals(id)) throw invalid();
				account.totpCharges.add(new TotpRecords.Charge(id, at));
			}
			if ((account.active == null && (account.batchId != null || hashes != 0))
					|| (account.active != null && account.batchId == null)) throw invalid();
			accepted = true; return account;
		} finally { if (!accepted) account.erase(); }
	}
	private static boolean flag(@NonNull DataInputStream in) throws IOException {
		int value = in.readUnsignedByte(); if (value > 1) throw invalid(); return value == 1;
	}
	private static int count(@NonNull DataInputStream in, int maximum) throws IOException {
		int value = in.readInt(); if (value < 0 || value > maximum) throw invalid(); return value;
	}
	private static @NonNull String identifier(@NonNull DataInputStream in) throws IOException {
		String value = text(in); requireIdentifier(value); return value;
	}
	private static void requireIdentifier(@NonNull String value) throws IOException {
		try { if (value.length() != 43 || Base64Url.decode(value).length != 32) throw invalid(); }
		catch (EncodingException failure) { throw invalid(); }
	}
	private static void text(@NonNull DataOutputStream out, @NonNull String value) throws IOException {
		byte[] bytes;
		try { bytes = StrictUtf8.encode(value); } catch (EncodingException failure) { throw invalid(); }
		try { if (bytes.length > 4096) throw invalid(); out.writeInt(bytes.length); out.write(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}
	private static @NonNull String text(@NonNull DataInputStream in) throws IOException {
		int length = count(in, 4096); if (length > in.available()) throw invalid();
		byte[] bytes = in.readNBytes(length);
		try { return StrictUtf8.decode(bytes); } catch (EncodingException failure) { throw invalid(); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}
	private static void blob(@NonNull DataOutputStream out, byte @NonNull [] bytes) throws IOException {
		if (bytes.length != 20 && bytes.length != 32) throw invalid();
		out.writeInt(bytes.length); out.write(bytes);
	}
	private static byte @NonNull [] blob(@NonNull DataInputStream in, int length) throws IOException {
		if (in.readInt() != length || length > in.available()) throw invalid(); return in.readNBytes(length);
	}
	private static void instant(@NonNull DataOutputStream out, @NonNull Instant value) throws IOException {
		out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano());
	}
	private static @NonNull Instant instant(@NonNull DataInputStream in) throws IOException {
		long seconds = in.readLong(); int nanos = in.readInt();
		if (seconds < 0 || seconds > 253_402_300_799L || nanos < 0 || nanos > 999_999_999) throw invalid();
		return Instant.ofEpochSecond(seconds, nanos);
	}
	private static @NonNull IOException invalid() { return new IOException("Invalid TOTP stored state"); }

	@NotThreadSafe private static final class PlaintextBuffer extends ByteArrayOutputStream {
		@Override public void close() { Arrays.fill(this.buf, (byte) 0); reset(); }
		@Override public @NonNull String toString() { return "PlaintextBuffer{<redacted>}"; }
	}

	/** Stable root metadata; ordinary time passage has no setter or advance path. */
	@Immutable
	static final class Namespace {
		private final @NonNull String authorityId;
		private final @NonNull Instant minimum;

		Namespace(@NonNull String authorityId, @NonNull Instant minimum) {
			TotpStoreKey.validateDigest(authorityId);
			requireNonNull(minimum);
			if (minimum.getEpochSecond() < 0 || minimum.getEpochSecond() > 253_402_300_799L)
				throw new IllegalArgumentException("Invalid TOTP minimum");
			this.authorityId = authorityId;
			this.minimum = minimum;
		}
		@NonNull String getAuthorityId() { return this.authorityId; }
		@NonNull Instant getMinimum() { return this.minimum; }
		@Override public @NonNull String toString() { return "Namespace{root=<redacted>}"; }
	}

	/** Thread-confined decoded state; closing always erases account secret/hash buffers. */
	@NotThreadSafe
	static final class Decoded implements AutoCloseable {
		final @Nullable Namespace namespace;
		final TotpRecords.@Nullable Account account;
		final @NonNull String keyId;
		Decoded(@Nullable Namespace namespace, TotpRecords.@Nullable Account account, @NonNull String keyId) {
			this.namespace = namespace;
			this.account = account;
			this.keyId = keyId;
		}
		@Override public void close() {
			TotpRecords.Account value = this.account;
			if (value != null) value.erase();
		}
		@Override public @NonNull String toString() { return "Decoded{record=<redacted>}"; }
	}
}
