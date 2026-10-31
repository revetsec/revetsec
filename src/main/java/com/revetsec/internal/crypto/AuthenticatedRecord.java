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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Bounded thread-confined authenticated record plaintext and original encrypted expiry, never a credential.
 * The owned UTF-8 bytes are erased on close. A returned String cannot be erased; internal codec callers retain
 * it only for bounded parsing, as with the existing codecs, and never export this holder through public results.
 */
@NotThreadSafe
@CheckReturnValue
public final class AuthenticatedRecord implements AutoCloseable {
	private final byte @NonNull [] plaintext;
	private final long notAfterEpochSecond;
	private boolean closed;

	AuthenticatedRecord(byte @NonNull [] plaintext, long notAfterEpochSecond) throws EncodingException {
		requireNonNull(plaintext);
		// Validate before retaining an owned copy. The discarded String is subject to the existing JDK limitation.
		StrictUtf8.decode(plaintext);
		this.plaintext = plaintext.clone();
		this.notAfterEpochSecond = notAfterEpochSecond;
	}

	/** Returns a transient UTF-16 copy for bounded strict payload parsing. */
	public @NonNull String getPlaintext() {
		requireOpen();
		try {
			return StrictUtf8.decode(this.plaintext);
		} catch (EncodingException impossible) {
			throw new IllegalStateException("Authenticated record text is unavailable.");
		}
	}

	/** Returns representable authenticated expiry; WA callers use the raw getter for the full-Instant ceiling edge. */
	public @NonNull Instant getNotAfter() {
		requireOpen();
		return Instant.ofEpochSecond(this.notAfterEpochSecond);
	}

	/**
	 * Returns the exact authenticated encrypted whole-second expiry without narrowing it to Java Instant.
	 * A legacy WebAuthn ceremony at fractional Instant.MAX has a ceiling one second beyond Instant.MAX.
	 */
	public long getNotAfterEpochSecond() {
		requireOpen();
		return this.notAfterEpochSecond;
	}

	/** Erases this holder's owned plaintext bytes; idempotent. */
	@Override
	public void close() {
		Arrays.fill(this.plaintext, (byte) 0);
		this.closed = true;
	}

	private void requireOpen() {
		if (this.closed)
			throw new IllegalStateException("Authenticated record is closed.");
	}

	@Override
	public @NonNull String toString() {
		return "AuthenticatedRecord{record=<redacted>}";
	}
}
