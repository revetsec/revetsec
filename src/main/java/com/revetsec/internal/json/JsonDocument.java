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

import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.IdentityHashMap;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * One bounded, complete JSON parse and its number-token evidence. The private identity map neither hashes nor
 * compares public JSON values, and holds at most one entry per parsed number node under the parser's node bound.
 * Input bytes and raw number tokens are not retained. The map is copied before publication and never mutated.
 */
@Immutable
public final class JsonDocument {
	private final @NonNull JsonValue value;
	private final @NonNull IdentityHashMap<@NonNull JsonNumber, @NonNull JsonNumberSyntax> numberSyntax;

	JsonDocument(@NonNull JsonValue value,
			@NonNull IdentityHashMap<@NonNull JsonNumber, @NonNull JsonNumberSyntax> numberSyntax) {
		this.value = requireNonNull(value);
		this.numberSyntax = new IdentityHashMap<>(requireNonNull(numberSyntax));
	}

	/** @return the complete parsed value */
	public @NonNull JsonValue getValue() {
		return this.value;
	}

	/**
	 * Returns lexical evidence only for the exact number node parsed into this document. Equal-valued numbers created
	 * separately or parsed into another document have no evidence here.
	 *
	 * @param number the exact number node
	 * @return its token flags, or empty for a node outside this document
	 * @throws NullPointerException if {@code number} is {@code null}
	 */
	public @NonNull Optional<@NonNull JsonNumberSyntax> numberSyntax(@NonNull JsonNumber number) {
		return Optional.ofNullable(this.numberSyntax.get(requireNonNull(number)));
	}

	@Override
	public @NonNull String toString() {
		return "JsonDocument{value=<redacted>, numberTokens=" + this.numberSyntax.size() + "}";
	}
}
