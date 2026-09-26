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
 * The JSON {@code null}. It is a value, distinct from an absent member: {@code {"a":null}} has a member {@code a},
 * and {@code {}} has none.
 * <p>
 * This is a final class with one shared instance, not an enum, so it has no {@code values()}, {@code ordinal()} or
 * {@code name()}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonNull implements JsonValue {
	@NonNull
	private static final JsonNull INSTANCE = new JsonNull();

	/**
	 * Returns the JSON {@code null}.
	 *
	 * @return the shared instance
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonNull defaultInstance() {
		return INSTANCE;
	}

	private JsonNull() {
	}

	@Override
	@NonNull
	public String toJson() {
		return JsonWriter.toJson(this);
	}

	@Override
	public boolean equals(@Nullable Object other) {
		return other instanceof JsonNull;
	}

	@Override
	public int hashCode() {
		return 0x6E756C6C;
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonNull{value=<redacted>}";
	}
}
