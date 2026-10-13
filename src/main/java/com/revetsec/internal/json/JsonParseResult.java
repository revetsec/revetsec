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

package com.revetsec.internal.json;

import com.revetsec.internal.json.JsonParseException.Kind;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * Closed outcome of the internal direct JSON parser. Rejections retain only a fixed kind and byte offset; neither
 * outcome retains input bytes, exception objects, or partially parsed documents.
 */
@Immutable
public abstract sealed class JsonParseResult permits JsonParseResult.Succeeded, JsonParseResult.Rejected {
	private JsonParseResult() {
	}

	static @NonNull Succeeded succeeded(@NonNull JsonDocument document) {
		return new Succeeded(document);
	}

	static @NonNull Rejected rejected(@NonNull Kind kind, int byteOffset) {
		return new Rejected(kind, byteOffset);
	}

	/** A complete parsed document. */
	@Immutable
	public static final class Succeeded extends JsonParseResult {
		private final @NonNull JsonDocument document;

		private Succeeded(@NonNull JsonDocument document) {
			this.document = requireNonNull(document);
		}

		/** @return the complete document */
		public @NonNull JsonDocument getDocument() {
			return this.document;
		}

		@Override
		public @NonNull String toString() {
			return "JsonParseResult.Succeeded{document=<redacted>}";
		}
	}

	/** A fixed rejection reason and its zero-based input byte offset. */
	@Immutable
	public static final class Rejected extends JsonParseResult {
		private final @NonNull Kind kind;
		private final int byteOffset;

		private Rejected(@NonNull Kind kind, int byteOffset) {
			this.kind = requireNonNull(kind);
			this.byteOffset = byteOffset;
		}

		/** @return the fixed rejection reason */
		public @NonNull Kind getKind() {
			return this.kind;
		}

		/** @return the zero-based input byte offset */
		public int getByteOffset() {
			return this.byteOffset;
		}

		@Override
		public @NonNull String toString() {
			return "JsonParseResult.Rejected{kind=" + this.kind + ", byteOffset=" + this.byteOffset + "}";
		}
	}
}
