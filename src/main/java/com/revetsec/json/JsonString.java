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

package com.revetsec.json;

import com.revetsec.internal.json.JsonWriter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;

/**
 * A JSON string.
 * <p>
 * Its value is well-formed UTF-16: an unpaired surrogate is rejected. It may hold any other character, including
 * NUL and Unicode noncharacters, and it compares exactly, with no case folding or normalization.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonString implements JsonValue {
	@NonNull
	private final String value;

	/**
	 * Returns a JSON string holding {@code value}.
	 *
	 * @param value the string's value
	 * @return the JSON string
	 * @throws NullPointerException     if {@code value} is {@code null}
	 * @throws IllegalArgumentException if {@code value} contains an unpaired surrogate
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonString fromValue(@NonNull String value) {
		return new JsonString(JsonInvariants.requireWellFormed(value));
	}

	private JsonString(@NonNull String value) {
		this.value = value;
	}

	/**
	 * Returns this string's value, which may be a secret or personal data.
	 *
	 * @return the value
	 * @since 1.0.0
	 */
	@NonNull
	public String getValue() {
		return this.value;
	}

	@Override
	@NonNull
	public String toJson() {
		return JsonWriter.toJson(this);
	}

	@Override
	public boolean equals(@Nullable Object other) {
		return this == other || (other instanceof JsonString string && this.value.equals(string.value));
	}

	@Override
	public int hashCode() {
		return this.value.hashCode();
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonString{value=<redacted>}";
	}
}
