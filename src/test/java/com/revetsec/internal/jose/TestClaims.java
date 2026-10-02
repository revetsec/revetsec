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

package com.revetsec.internal.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.testing.JsonText;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * A JWT claims set under construction for the JOSE tests: each member is raw JSON text, a later {@code put} replaces an
 * earlier one in place, and {@link #remove(String)} drops one, so a test starts from valid claims and changes only
 * what it is about. {@link #toJson()} writes the members in order with no whitespace.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
public final class TestClaims {
	private final Map<String, String> members = new LinkedHashMap<>();

	private TestClaims() {
	}

	/**
	 * An empty claims set.
	 *
	 * @return a new builder
	 */
	public static @NonNull TestClaims empty() {
		return new TestClaims();
	}

	/**
	 * Sets a string member.
	 *
	 * @param name  the member name
	 * @param value the string
	 * @return this builder
	 */
	public @NonNull TestClaims put(@NonNull String name, @NonNull String value) {
		return raw(name, JsonText.string(requireNonNull(value)));
	}

	/**
	 * Sets a number member.
	 *
	 * @param name  the member name
	 * @param value the number
	 * @return this builder
	 */
	public @NonNull TestClaims put(@NonNull String name, long value) {
		return raw(name, Long.toString(value));
	}

	/**
	 * Sets a member to raw JSON text, such as {@code null}, {@code [1]} or {@code 1.5}.
	 *
	 * @param name        the member name
	 * @param rawJsonText the value's JSON text
	 * @return this builder
	 */
	public @NonNull TestClaims raw(@NonNull String name, @NonNull String rawJsonText) {
		this.members.put(requireNonNull(name), requireNonNull(rawJsonText));
		return this;
	}

	/**
	 * Removes a member, if present.
	 *
	 * @param name the member name
	 * @return this builder
	 */
	public @NonNull TestClaims remove(@NonNull String name) {
		this.members.remove(requireNonNull(name));
		return this;
	}

	/**
	 * A copy of this builder.
	 *
	 * @return a new builder with the same members
	 */
	public @NonNull TestClaims copy() {
		TestClaims copy = new TestClaims();
		copy.members.putAll(this.members);
		return copy;
	}

	/**
	 * The claims set's JSON text.
	 *
	 * @return a JSON object, members in order
	 */
	public @NonNull String toJson() {
		List<Map.Entry<String, String>> entries = new ArrayList<>(this.members.entrySet());
		return JsonText.object(entries);
	}

	@Override
	public @NonNull String toString() {
		return toJson();
	}
}
