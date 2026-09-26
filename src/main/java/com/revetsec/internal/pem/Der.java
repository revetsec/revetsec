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

package com.revetsec.internal.pem;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * The little DER that {@link Pem} needs (X.690 section 10): reading one element's tag and length strictly, and
 * writing a definite length.
 * <p>
 * The reader accepts only low-tag-number identifiers and minimal definite lengths of at most four octets. It rejects
 * the BER indefinite form ({@code 0x80}), long forms with a leading zero octet or for lengths below 128, and any
 * length that runs past the enclosing element. It never recurses.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class Der {
	static final int INTEGER = 0x02;
	static final int BIT_STRING = 0x03;
	static final int OCTET_STRING = 0x04;
	static final int NULL = 0x05;
	static final int OBJECT_IDENTIFIER = 0x06;
	static final int SEQUENCE = 0x30;
	/**
	 * {@code [0] IMPLICIT}, constructed: PKCS#8 {@code attributes} (RFC 5958 section 2).
	 */
	static final int CONTEXT_0_CONSTRUCTED = 0xA0;
	/**
	 * {@code [1] IMPLICIT BIT STRING}, primitive: PKCS#8 v2 {@code publicKey} (RFC 5958 section 2).
	 */
	static final int CONTEXT_1_PRIMITIVE = 0x81;

	private Der() {
	}

	/**
	 * One element: its identifier octet and the bounds of its contents.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	static final class Element {
		private final int tag;
		private final int start;
		private final int end;

		private Element(int tag, int start, int end) {
			this.tag = tag;
			this.start = start;
			this.end = end;
		}

		/**
		 * The identifier octet.
		 */
		int getTag() {
			return this.tag;
		}

		/**
		 * The index of the first content octet.
		 */
		int getStart() {
			return this.start;
		}

		/**
		 * The index just past the last content octet, which is also where the next element starts.
		 */
		int getEnd() {
			return this.end;
		}

		/**
		 * The number of content octets.
		 */
		int getLength() {
			return this.end - this.start;
		}
	}

	/**
	 * Reads the element that starts at {@code offset}, which must end at or before {@code limit}.
	 *
	 * @throws PemException with {@link PemException.Kind#MALFORMED_DER} if the element is truncated or not DER
	 */
	static @NonNull Element read(byte @NonNull [] der, int offset, int limit) throws PemException {
		if (limit - offset < 2)
			throw new PemException(PemException.Kind.MALFORMED_DER);
		int tag = der[offset] & 0xFF;
		// Tag numbers of 31 or more use the multi-octet form, which nothing Pem reads needs.
		if ((tag & 0x1F) == 0x1F)
			throw new PemException(PemException.Kind.MALFORMED_DER);

		int position = offset + 1;
		int first = der[position++] & 0xFF;
		long length;
		if (first < 0x80) {
			length = first;
		} else {
			int count = first & 0x7F;
			// count 0 is BER's indefinite form; more than four octets exceeds any array.
			if (count == 0 || count > 4 || limit - position < count || der[position] == 0)
				throw new PemException(PemException.Kind.MALFORMED_DER);
			length = 0;
			for (int index = 0; index < count; ++index)
				length = (length << 8) | (der[position++] & 0xFF);
			if (length < 0x80)
				throw new PemException(PemException.Kind.MALFORMED_DER);
		}

		if (length > limit - position)
			throw new PemException(PemException.Kind.MALFORMED_DER);
		return new Element(tag, position, position + (int) length);
	}

	/**
	 * Reads the element at {@code offset} and requires its identifier octet to be {@code tag}.
	 *
	 * @throws PemException with {@link PemException.Kind#MALFORMED_DER} if it is not
	 */
	static @NonNull Element read(byte @NonNull [] der, int offset, int limit, int tag) throws PemException {
		Element element = read(der, offset, limit);
		if (element.getTag() != tag)
			throw new PemException(PemException.Kind.MALFORMED_DER);
		return element;
	}

	/**
	 * The number of octets {@link #putLength(byte[], int, int)} writes for {@code length}.
	 */
	static int lengthOfLength(int length) {
		if (length < 0x80)
			return 1;
		// The long form: one octet giving the count, then the length's significant octets.
		int octets = 1;
		for (int remaining = length; remaining != 0; remaining >>>= 8)
			++octets;
		return octets;
	}

	/**
	 * Writes {@code length} in minimal definite form at {@code position} and returns the position after it.
	 */
	static int putLength(byte @NonNull [] out, int position, int length) {
		int count = lengthOfLength(length) - 1;
		int next = position;
		if (count == 0) {
			out[next++] = (byte) length;
			return next;
		}
		out[next++] = (byte) (0x80 | count);
		for (int shift = (count - 1) * 8; shift >= 0; shift -= 8)
			out[next++] = (byte) (length >> shift);
		return next;
	}
}
