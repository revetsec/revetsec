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

import static java.util.Objects.requireNonNull;

/**
 * A JSON {@code true} or {@code false}. There are exactly two instances.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonBoolean implements JsonValue {
	@NonNull
	private static final JsonBoolean TRUE = new JsonBoolean(true);
	@NonNull
	private static final JsonBoolean FALSE = new JsonBoolean(false);

	private final boolean value;

	/**
	 * Returns the JSON {@code true}.
	 *
	 * @return the shared instance for {@code true}
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonBoolean trueInstance() {
		return TRUE;
	}

	/**
	 * Returns the JSON {@code false}.
	 *
	 * @return the shared instance for {@code false}
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonBoolean falseInstance() {
		return FALSE;
	}

	/**
	 * Returns the JSON boolean for {@code value}.
	 *
	 * @param value the boolean
	 * @return {@link #trueInstance()} or {@link #falseInstance()}
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonBoolean fromValue(@NonNull Boolean value) {
		requireNonNull(value);
		return value.booleanValue() ? TRUE : FALSE;
	}

	private JsonBoolean(boolean value) {
		this.value = value;
	}

	/**
	 * Returns this boolean's value.
	 *
	 * @return {@code true} or {@code false}
	 * @since 1.0.0
	 */
	@NonNull
	public Boolean getValue() {
		return this.value;
	}

	@Override
	@NonNull
	public String toJson() {
		return JsonWriter.toJson(this);
	}

	@Override
	public boolean equals(@Nullable Object other) {
		// Exactly two instances exist, one per value, so identity is value equality.
		return this == other;
	}

	@Override
	public int hashCode() {
		return Boolean.hashCode(this.value);
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonBoolean{value=<redacted>}";
	}
}
