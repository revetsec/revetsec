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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/** Exact WAR2 payloads for active admitted-time operation and closed migration. This helper never admits a credential or chooses authority time. */
@ThreadSafe
final class WebAuthnRecordPayloadV2 {
	static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());
	private static final int MAXIMUM_ADDRESS_LENGTH = 583;

	private WebAuthnRecordPayloadV2() { }

	static byte @NonNull [] namespace(@NonNull WebAuthnStoreKey key, @NonNull String authorityId,
			@NonNull Instant minimum) {
		requireNonNull(key);
		requireNonNull(authorityId);
		requireNonNull(minimum);
		try {
			Address address = address(key.getStorageKey());
			if (address.kind != WebAuthnStoreKey.Kind.NAMESPACE_CLOCK || authorityId.length() != 43)
				throw new IllegalArgumentException("Invalid WebAuthn root payload.");
			byte[] authority = Base64Url.decode(authorityId);
			try {
				if (authority.length != 32) throw new IllegalArgumentException("Invalid WebAuthn authority.");
				return ByteBuffer.allocate(45).put((byte) 2).put(authority)
						.putLong(minimum.getEpochSecond()).putInt(minimum.getNano()).array();
			} finally { Arrays.fill(authority, (byte) 0); }
		} catch (EncodingException | WebAuthnRecordException failure) {
			throw new IllegalArgumentException("Invalid WebAuthn root payload.");
		}
	}

	static byte @NonNull [] entity(@NonNull WebAuthnStoreKey key, @NonNull Instant floor,
			byte @NonNull [] inner) throws WebAuthnRecordException {
		requireNonNull(key);
		requireNonNull(floor);
		requireNonNull(inner);
		Address address = address(key.getStorageKey());
		if (address.kind == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) throw new WebAuthnRecordException();
		validateInner(address, inner);
		return ByteBuffer.allocate(12 + inner.length).putLong(floor.getEpochSecond()).putInt(floor.getNano())
				.put(inner).array();
	}

	static @NonNull Decoded decode(@NonNull String storageKey, byte @NonNull [] plaintext,
			long authenticatedNotAfter) throws WebAuthnRecordException {
		requireNonNull(plaintext);
		Address address = address(storageKey);
		try {
			if (address.kind == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) {
				if (plaintext.length != 45 || plaintext[0] != 2 || authenticatedNotAfter != PERMANENT.getEpochSecond())
					throw new WebAuthnRecordException();
				ByteBuffer reader = ByteBuffer.wrap(plaintext);
				reader.get();
				byte[] authority = new byte[32];
				try {
					reader.get(authority);
					Instant minimum = readInstant(reader);
					return new Decoded(address.root(), minimum, Base64Url.encode(authority), plaintext, PERMANENT);
				} finally { Arrays.fill(authority, (byte) 0); }
			}
			if (plaintext.length < 13 || plaintext.length > 110_000) throw new WebAuthnRecordException();
			Instant floor = readInstant(ByteBuffer.wrap(plaintext));
			byte[] inner = Arrays.copyOfRange(plaintext, 12, plaintext.length);
			try {
				Inner info = validateInner(address, inner);
				if (authenticatedNotAfter != info.notAfter) throw new WebAuthnRecordException();
				return new Decoded(info.key, floor, null, inner, info.expiresAt);
			} finally { Arrays.fill(inner, (byte) 0); }
		} catch (IllegalArgumentException | DateTimeException failure) {
			throw new WebAuthnRecordException();
		}
	}

	static @NonNull Instant legacyMinimum(@NonNull String storageKey, byte @NonNull [] plaintext,
			long authenticatedNotAfter) throws WebAuthnRecordException {
		Address address = address(storageKey);
		if (address.kind != WebAuthnStoreKey.Kind.NAMESPACE_CLOCK || plaintext.length != 13
				|| plaintext[0] != 1 || authenticatedNotAfter != PERMANENT.getEpochSecond()) throw new WebAuthnRecordException();
		try {
			ByteBuffer reader = ByteBuffer.wrap(plaintext);
			reader.get();
			return readInstant(reader);
		} catch (IllegalArgumentException | DateTimeException failure) { throw new WebAuthnRecordException(); }
	}

	static @NonNull Decoded legacyEntity(@NonNull String storageKey, byte @NonNull [] plaintext,
			long authenticatedNotAfter, @NonNull Instant minimum) throws WebAuthnRecordException {
		requireNonNull(minimum);
		Address address = address(storageKey);
		if (address.kind == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) throw new WebAuthnRecordException();
		Inner info = validateInner(address, plaintext);
		if (authenticatedNotAfter != info.notAfter) throw new WebAuthnRecordException();
		Instant floor = info.issuedAt != null && info.issuedAt.isAfter(minimum) ? info.issuedAt : minimum;
		return new Decoded(info.key, floor, null, plaintext, info.expiresAt);
	}

	static @NonNull WebAuthnStoreKey namespaceKeyForAddress(@NonNull String storageKey)
			throws WebAuthnRecordException {
		return address(storageKey).root();
	}

	private static @NonNull Inner validateInner(@NonNull Address address, byte @NonNull [] payload)
			throws WebAuthnRecordException {
		try {
			return switch (address.kind) {
				case CREDENTIAL -> credential(address, payload);
				case ACCOUNT_CREDENTIAL_INDEX -> index(address, payload);
				case ACCOUNT_FENCE -> fence(address, payload);
				case CEREMONY -> ceremony(address, payload);
				case NAMESPACE_CLOCK -> throw new WebAuthnRecordException();
			};
		} catch (IllegalArgumentException | DateTimeException | WebAuthnCborException failure) {
			throw new WebAuthnRecordException();
		}
	}

	private static @NonNull Inner credential(@NonNull Address address, byte @NonNull [] payload)
			throws WebAuthnRecordException, WebAuthnCborException {
		if (payload.length < 1) throw new WebAuthnRecordException();
		ByteBuffer reader = ByteBuffer.wrap(payload);
		int version = reader.get() & 0xff;
		int algorithm = 0;
		long counter = 0;
		int flags = 0;
		int idLength;
		int handleLength;
		int keyLength = 0;
		if (version == 1) {
			if (payload.length < 13 || payload.length > 2_124) throw new WebAuthnRecordException();
			algorithm = reader.getShort();
			counter = Integer.toUnsignedLong(reader.getInt());
			flags = reader.get() & 0xff;
			idLength = Short.toUnsignedInt(reader.getShort());
			handleLength = reader.get() & 0xff;
			keyLength = Short.toUnsignedInt(reader.getShort());
			if ((flags & ~3) != 0 || keyLength < 1 || keyLength > 1_024) throw new WebAuthnRecordException();
		} else if (version == 2) {
			if (payload.length < 6 || payload.length > 1_091) throw new WebAuthnRecordException();
			idLength = Short.toUnsignedInt(reader.getShort());
			handleLength = reader.get() & 0xff;
		} else throw new WebAuthnRecordException();
		if (idLength < 1 || idLength > 1_023 || handleLength < 1 || handleLength > 64
				|| idLength + handleLength + keyLength != reader.remaining()) throw new WebAuthnRecordException();
		byte[] id = new byte[idLength];
		byte[] handle = new byte[handleLength];
		byte[] publicKey = new byte[keyLength];
		try {
			reader.get(id).get(handle).get(publicKey);
			WebAuthnStoreKey key = WebAuthnStoreKey.forCredential(address.namespace, address.rp, id);
			address.requireKey(key);
			if (version == 1) WebAuthnCredentialState.checked(id, handle, publicKey, algorithm, counter,
					(flags & 1) != 0, (flags & 2) != 0);
			return new Inner(key, PERMANENT, null);
		} finally { Arrays.fill(id, (byte) 0); Arrays.fill(handle, (byte) 0); Arrays.fill(publicKey, (byte) 0); }
	}

	private static @NonNull Inner index(@NonNull Address address, byte @NonNull [] payload)
			throws WebAuthnRecordException {
		if (payload.length < 4 || payload.length > 65_667 || payload[0] != 1) throw new WebAuthnRecordException();
		ByteBuffer reader = ByteBuffer.wrap(payload);
		reader.get();
		int length = reader.get() & 0xff;
		int count = reader.get() & 0xff;
		if (length < 1 || length > 64 || count > 64 || reader.remaining() < length + count * 3)
			throw new WebAuthnRecordException();
		byte[] handle = new byte[length];
		reader.get(handle);
		List<byte[]> ids = new ArrayList<>(count);
		try {
			byte[] previous = null;
			for (int i = 0; i < count; i++) {
				if (reader.remaining() < 2) throw new WebAuthnRecordException();
				int idLength = Short.toUnsignedInt(reader.getShort());
				if (idLength < 1 || idLength > 1_023 || reader.remaining() < idLength) throw new WebAuthnRecordException();
				byte[] id = new byte[idLength];
				reader.get(id);
				ids.add(id);
				if (previous != null && Arrays.compareUnsigned(previous, id) >= 0) throw new WebAuthnRecordException();
				previous = id;
			}
			if (reader.hasRemaining()) throw new WebAuthnRecordException();
			WebAuthnStoreKey key = WebAuthnStoreKey.forAccountCredentialIndex(address.namespace, address.rp, handle);
			address.requireKey(key);
			return new Inner(key, PERMANENT, null);
		} finally { Arrays.fill(handle, (byte) 0); for (byte[] id : ids) Arrays.fill(id, (byte) 0); }
	}

	private static @NonNull Inner fence(@NonNull Address address, byte @NonNull [] payload)
			throws WebAuthnRecordException {
		if (payload.length < 4 || payload.length > 67 || payload[0] != 1 || payload[1] < 0 || payload[1] > 1
				|| (payload[2] & 0xff) != payload.length - 3) throw new WebAuthnRecordException();
		byte[] handle = Arrays.copyOfRange(payload, 3, payload.length);
		try {
			WebAuthnStoreKey key = WebAuthnStoreKey.forAccountFence(address.namespace, address.rp, handle);
			address.requireKey(key);
			return new Inner(key, PERMANENT, null);
		} finally { Arrays.fill(handle, (byte) 0); }
	}

	private static @NonNull Inner ceremony(@NonNull Address address, byte @NonNull [] payload)
			throws WebAuthnRecordException {
		if (payload.length < 126 || payload.length > 2_400) throw new WebAuthnRecordException();
		ByteBuffer reader = ByteBuffer.wrap(payload);
		int version = reader.get() & 0xff;
		int consumed = reader.get() & 0xff;
		int kind = reader.get() & 0xff;
		if (version != 1 || consumed > 1 || kind < 1 || kind > 3) throw new WebAuthnRecordException();
		byte[] id = new byte[32];
		byte[] challenge = new byte[32];
		byte[] binding = new byte[32];
		byte[] handle = null;
		byte[] purpose = null;
		try {
			reader.get(id).get(challenge).get(binding);
			Instant issuedAt = readInstant(reader);
			Instant expiresAt = readInstant(reader);
			int handleLength = reader.get() & 0xff;
			int purposeLength = reader.get() & 0xff;
			int originCount = reader.get() & 0xff;
			if (handleLength > 64 || purposeLength > 128 || originCount < 1 || originCount > 8
					|| reader.remaining() < handleLength + purposeLength + originCount * 3) throw new WebAuthnRecordException();
			handle = new byte[handleLength];
			purpose = new byte[purposeLength];
			reader.get(handle).get(purpose);
			List<String> origins = new ArrayList<>(originCount);
			String previous = null;
			for (int i = 0; i < originCount; i++) {
				if (reader.remaining() < 2) throw new WebAuthnRecordException();
				int length = Short.toUnsignedInt(reader.getShort());
				if (length < 1 || length > 267 || reader.remaining() < length) throw new WebAuthnRecordException();
				byte[] bytes = new byte[length];
				try {
					reader.get(bytes);
					for (byte value : bytes) if (value < 0x21 || value > 0x7e) throw new WebAuthnRecordException();
					String origin = new String(bytes, StandardCharsets.US_ASCII);
					if (previous != null && previous.compareTo(origin) >= 0) throw new WebAuthnRecordException();
					origins.add(origin);
					previous = origin;
				} finally { Arrays.fill(bytes, (byte) 0); }
			}
			for (byte value : purpose) if (value < 0x20 || value > 0x7e) throw new WebAuthnRecordException();
			if (reader.hasRemaining()) throw new WebAuthnRecordException();
			Set<String> originSet = Set.copyOf(origins);
			new WebAuthnClientData(address.rp, originSet, WebAuthnClientData.DEFAULT_MAXIMUM_BYTES);
			WebAuthnCeremonyState.Kind ceremonyKind = switch (kind) {
				case 1 -> WebAuthnCeremonyState.Kind.REGISTRATION;
				case 2 -> WebAuthnCeremonyState.Kind.DISCOVERABLE_AUTHENTICATION;
				case 3 -> WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION;
				default -> throw new WebAuthnRecordException();
			};
			WebAuthnCeremonyState.restored(ceremonyKind, id, challenge, binding,
					originSet, handleLength == 0 ? null : handle,
					purposeLength == 0 ? null : new String(purpose, StandardCharsets.US_ASCII), issuedAt, expiresAt, consumed == 1);
			WebAuthnStoreKey key = WebAuthnStoreKey.forCeremony(address.namespace, address.rp, id);
			address.requireKey(key);
			return new Inner(key, expiresAt, issuedAt);
		} finally {
			Arrays.fill(id, (byte) 0); Arrays.fill(challenge, (byte) 0); Arrays.fill(binding, (byte) 0);
			if (handle != null) Arrays.fill(handle, (byte) 0);
			if (purpose != null) Arrays.fill(purpose, (byte) 0);
		}
	}

	private static @NonNull Instant readInstant(@NonNull ByteBuffer reader) {
		if (reader.remaining() < 12) throw new IllegalArgumentException("Truncated instant.");
		long seconds = reader.getLong();
		int nanos = reader.getInt();
		if (nanos < 0 || nanos > 999_999_999) throw new IllegalArgumentException("Invalid instant.");
		return Instant.ofEpochSecond(seconds, nanos);
	}

	private static @NonNull Address address(@NonNull String storageKey) throws WebAuthnRecordException {
		requireNonNull(storageKey);
		if (storageKey.length() > MAXIMUM_ADDRESS_LENGTH) throw new WebAuthnRecordException();
		String[] parts = storageKey.split(":", -1);
		if (parts.length != 5 || !parts[0].equals("wa1")) throw new WebAuthnRecordException();
		byte[] namespace = null;
		byte[] rp = null;
		byte[] digest = null;
		try {
			namespace = Base64Url.decode(parts[1]);
			rp = Base64Url.decode(parts[2]);
			digest = Base64Url.decode(parts[4]);
			if (digest.length != 32) throw new WebAuthnRecordException();
			for (byte value : namespace) if (value < 0x21 || value > 0x7e) throw new WebAuthnRecordException();
			for (byte value : rp) if (value < 0x21 || value > 0x7e) throw new WebAuthnRecordException();
			String ns = new String(namespace, StandardCharsets.US_ASCII);
			String relyingParty = new String(rp, StandardCharsets.US_ASCII);
			WebAuthnStoreKey root = WebAuthnStoreKey.forNamespaceClock(ns, relyingParty);
			WebAuthnStoreKey.Kind kind = WebAuthnStoreKey.Kind.valueOf(parts[3]);
			if (kind == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK && !root.getStorageKey().equals(storageKey))
				throw new WebAuthnRecordException();
			return new Address(ns, relyingParty, kind, storageKey);
		} catch (EncodingException | IllegalArgumentException failure) { throw new WebAuthnRecordException(); }
		finally {
			if (namespace != null) Arrays.fill(namespace, (byte) 0);
			if (rp != null) Arrays.fill(rp, (byte) 0);
			if (digest != null) Arrays.fill(digest, (byte) 0);
		}
	}

	private static final class Address {
		private final @NonNull String namespace;
		private final @NonNull String rp;
		private final WebAuthnStoreKey.@NonNull Kind kind;
		private final @NonNull String storageKey;
		private Address(@NonNull String namespace, @NonNull String rp, WebAuthnStoreKey.@NonNull Kind kind,
				@NonNull String storageKey) { this.namespace = namespace; this.rp = rp; this.kind = kind; this.storageKey = storageKey; }
		private @NonNull WebAuthnStoreKey root() { return WebAuthnStoreKey.forNamespaceClock(this.namespace, this.rp); }
		private void requireKey(@NonNull WebAuthnStoreKey key) throws WebAuthnRecordException {
			if (!this.storageKey.equals(key.getStorageKey())) throw new WebAuthnRecordException();
		}
	}

	private static final class Inner {
		private final @NonNull WebAuthnStoreKey key;
		private final long notAfter;
		private final @NonNull Instant expiresAt;
		private final @Nullable Instant issuedAt;
		private Inner(@NonNull WebAuthnStoreKey key, @NonNull Instant expiresAt, @Nullable Instant issuedAt) {
			this.key = key; this.expiresAt = expiresAt; this.issuedAt = issuedAt;
			this.notAfter = expiresAt.getNano() == 0 ? expiresAt.getEpochSecond() : Math.addExact(expiresAt.getEpochSecond(), 1);
		}
	}

	/** Thread-confined authenticated bytes, erased when the bounded transformer is finished. */
	@NotThreadSafe
	static final class Decoded implements AutoCloseable {
		private final @NonNull WebAuthnStoreKey key;
		private final @NonNull Instant floor;
		private final @Nullable String authorityId;
		private final byte @NonNull [] inner;
		private final @NonNull Instant expiresAt;
		private Decoded(@NonNull WebAuthnStoreKey key, @NonNull Instant floor, @Nullable String authorityId,
				byte @NonNull [] inner, @NonNull Instant expiresAt) {
			this.key = key; this.floor = floor; this.authorityId = authorityId; this.inner = inner.clone(); this.expiresAt = expiresAt;
		}
		@NonNull WebAuthnStoreKey key() { return this.key; }
		@NonNull Instant floor() { return this.floor; }
		@NonNull Optional<@NonNull String> authorityId() { return Optional.ofNullable(this.authorityId); }
		byte @NonNull [] innerPayload() { return this.inner.clone(); }
		@NonNull Instant expiresAt() { return this.expiresAt; }
		@Override public void close() { Arrays.fill(this.inner, (byte) 0); }
		@Override public @NonNull String toString() { return "Decoded{record=<redacted>, no proof}"; }
	}
}
