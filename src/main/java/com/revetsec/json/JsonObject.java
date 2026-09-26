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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.json.JsonWriter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A JSON object: an unmodifiable map from member names to values that keeps the order in which members were added.
 * <p>
 * <strong>Names</strong> are unique and compared exactly, with no case folding or Unicode normalization. Two objects
 * are equal when they have the same names with equal values, whatever the order of their members.
 * <p>
 * <strong>Building.</strong> {@link #builder()} adds one member per {@code put} call, and a name that is already
 * present throws {@link IllegalArgumentException} instead of replacing the earlier value. {@link #fromMembers(Map)}
 * takes a complete map.
 * <p>
 * <strong>Convenience lookups.</strong> {@link #findString(String)}, {@link #findLong(String)},
 * {@link #findBoolean(String)} and {@link #findStringList(String)} return an empty {@link Optional} both when a
 * member is absent and when it holds a value of another type. They suit display and application code. Revetsec's own
 * protocol validation never uses them, because it must tell an absent member from a malformed one and reject the
 * malformed one.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonObject implements JsonValue {
	@NonNull
	private static final JsonObject EMPTY = new JsonObject(new LinkedHashMap<>(), 1);

	private static final String DUPLICATE_NAME_MESSAGE = "A JSON object must not contain two members with the same "
			+ "name.";

	/**
	 * A {@link LinkedHashMap}, so iteration follows insertion order. Never modified after construction and never
	 * exposed except through an unmodifiable view.
	 */
	@NonNull
	private final Map<@NonNull String, @NonNull JsonValue> members;
	private final int depth;
	private final int hashCode;

	/**
	 * Returns the empty JSON object.
	 *
	 * @return the shared empty object
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonObject emptyInstance() {
		return EMPTY;
	}

	/**
	 * Returns a new builder, which adds one member per {@code put} call.
	 *
	 * @return a builder with no members
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Returns a JSON object holding a snapshot of {@code members}, in the map's iteration order.
	 *
	 * @param members the members; later changes to the map do not affect the object
	 * @return the JSON object
	 * @throws NullPointerException     if {@code members}, or any name or value in it, is {@code null}
	 * @throws IllegalArgumentException if a name contains an unpaired surrogate, the map holds two equal names (as an
	 *                                  identity-based map can), or the object would nest more than 64 deep
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonObject fromMembers(@NonNull Map<@NonNull String, ? extends @NonNull JsonValue> members) {
		requireNonNull(members);
		LinkedHashMap<@NonNull String, @NonNull JsonValue> snapshot = new LinkedHashMap<>(capacityFor(members.size()));
		int deepestChild = 0;

		for (Map.Entry<@NonNull String, ? extends @NonNull JsonValue> member : members.entrySet()) {
			String name = JsonInvariants.requireWellFormed(member.getKey());
			JsonValue value = requireNonNull(member.getValue());

			if (snapshot.putIfAbsent(name, value) != null)
				throw new IllegalArgumentException(DUPLICATE_NAME_MESSAGE);

			deepestChild = Math.max(deepestChild, JsonInvariants.depthOf(value));
		}

		return fromSnapshot(snapshot, deepestChild);
	}

	/**
	 * Keeps a {@link LinkedHashMap} that no caller can reach any more.
	 */
	@NonNull
	private static JsonObject fromSnapshot(@NonNull Map<@NonNull String, @NonNull JsonValue> snapshot,
																				 int deepestChild) {
		if (snapshot.isEmpty())
			return EMPTY;

		return new JsonObject(snapshot, JsonInvariants.requireContainerDepth(deepestChild));
	}

	/**
	 * A hash-table capacity that holds {@code size} members without resizing, so a parsed document's many small
	 * objects do not each carry a 16-slot table.
	 */
	private static int capacityFor(int size) {
		return (int) Math.min(Integer.MAX_VALUE, size * 4L / 3 + 1);
	}

	private JsonObject(@NonNull Map<@NonNull String, @NonNull JsonValue> members, int depth) {
		this.members = members;
		this.depth = depth;
		// Order-independent: the sum of each member's name hash XOR value hash (Map.hashCode()).
		this.hashCode = members.hashCode();
	}

	/**
	 * Returns this object's members, in the order they were added.
	 *
	 * @return an unmodifiable map
	 * @since 1.0.0
	 */
	@NonNull
	public Map<@NonNull String, @NonNull JsonValue> getMembers() {
		return Collections.unmodifiableMap(this.members);
	}

	/**
	 * Returns the value of the member named {@code name}.
	 *
	 * @param name the member name, compared exactly
	 * @return the value, which may be {@link JsonNull}, or empty if there is no such member
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull JsonValue> find(@NonNull String name) {
		requireNonNull(name);
		return Optional.ofNullable(this.members.get(name));
	}

	/**
	 * Returns the value of the member named {@code name} if it is a JSON string. Never used by Revetsec for protocol
	 * validation: an absent member and a member of another type both give an empty result.
	 *
	 * @param name the member name, compared exactly
	 * @return the string, or empty if the member is absent or not a string
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> findString(@NonNull String name) {
		@Nullable JsonValue value = this.members.get(requireNonNull(name));
		return value instanceof JsonString string ? Optional.of(string.getValue()) : Optional.empty();
	}

	/**
	 * Returns the value of the member named {@code name} if it is a JSON number that is a whole number in the range
	 * of {@code long} (see {@link JsonNumber#getLongValueExact()}). Never used by Revetsec for protocol validation: an
	 * absent member and a member of another type or range both give an empty result.
	 *
	 * @param name the member name, compared exactly
	 * @return the number, or empty if the member is absent, not a number, not whole or out of range
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Long> findLong(@NonNull String name) {
		@Nullable JsonValue value = this.members.get(requireNonNull(name));
		return value instanceof JsonNumber number ? number.getLongValueExact() : Optional.empty();
	}

	/**
	 * Returns the value of the member named {@code name} if it is a JSON boolean. Never used by Revetsec for protocol
	 * validation: an absent member and a member of another type both give an empty result.
	 *
	 * @param name the member name, compared exactly
	 * @return the boolean, or empty if the member is absent or not a boolean
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Boolean> findBoolean(@NonNull String name) {
		@Nullable JsonValue value = this.members.get(requireNonNull(name));
		return value instanceof JsonBoolean bool ? Optional.of(bool.getValue()) : Optional.empty();
	}

	/**
	 * Returns the value of the member named {@code name} if it is a JSON array whose elements are all strings. A
	 * single string is not a list. Never used by Revetsec for protocol validation: an absent member and a member of
	 * another type both give an empty result.
	 *
	 * @param name the member name, compared exactly
	 * @return the strings in order (an empty array gives an empty list), or empty if the member is absent, not an
	 * array, or holds a value that is not a string
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull List<@NonNull String>> findStringList(@NonNull String name) {
		@Nullable JsonValue value = this.members.get(requireNonNull(name));

		if (!(value instanceof JsonArray array))
			return Optional.empty();

		List<@NonNull String> strings = new ArrayList<>(array.getElements().size());

		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString string))
				return Optional.empty();

			strings.add(string.getValue());
		}

		return Optional.of(Collections.unmodifiableList(strings));
	}

	/**
	 * The G7-6 depth: 1 if empty, otherwise 1 more than the deepest member value.
	 */
	int getDepth() {
		return this.depth;
	}

	@Override
	@NonNull
	public String toJson() {
		return JsonWriter.toJson(this);
	}

	@Override
	public boolean equals(@Nullable Object other) {
		return this == other || (other instanceof JsonObject object && this.hashCode == object.hashCode
				&& this.members.equals(object.members));
	}

	@Override
	public int hashCode() {
		return this.hashCode;
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonObject{members=<redacted>}";
	}

	/**
	 * Builds a {@link JsonObject} one member at a time, keeping the order in which members are added.
	 * <p>
	 * Each {@code put} adds exactly one member, and a name that is already present throws
	 * {@link IllegalArgumentException} rather than replacing the earlier value. Every check runs in {@code put}, so
	 * {@link #build()} never fails. A builder may be reused: each {@link #build()} returns a snapshot of the members
	 * added so far.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		@NonNull
		private final LinkedHashMap<@NonNull String, @NonNull JsonValue> members;
		private int deepestChild;

		private Builder() {
			this.members = new LinkedHashMap<>();
		}

		/**
		 * Adds a member.
		 *
		 * @param name  the member name
		 * @param value the member value
		 * @return this builder
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if {@code name} contains an unpaired surrogate or is already present, or
		 *                                  the object would nest more than 64 deep
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder put(@NonNull String name, @NonNull JsonValue value) {
			JsonInvariants.requireWellFormed(name);
			requireNonNull(value);

			if (this.members.containsKey(name))
				throw new IllegalArgumentException(DUPLICATE_NAME_MESSAGE);

			int valueDepth = JsonInvariants.depthOf(value);
			JsonInvariants.requireContainerDepth(valueDepth);
			this.members.put(name, value);
			this.deepestChild = Math.max(this.deepestChild, valueDepth);
			return this;
		}

		/**
		 * Adds a member whose value is a JSON string.
		 *
		 * @param name  the member name
		 * @param value the string
		 * @return this builder
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if {@code name} or {@code value} contains an unpaired surrogate, or
		 *                                  {@code name} is already present
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder put(@NonNull String name, @NonNull String value) {
			return put(name, JsonString.fromValue(value));
		}

		/**
		 * Adds a member whose value is a JSON number.
		 *
		 * @param name  the member name
		 * @param value the number
		 * @return this builder
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if {@code name} contains an unpaired surrogate or is already present
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder put(@NonNull String name, @NonNull Long value) {
			return put(name, JsonNumber.fromValue(value));
		}

		/**
		 * Adds a member whose value is a JSON number, held exactly (see {@link JsonNumber#fromValue(BigDecimal)}).
		 *
		 * @param name  the member name
		 * @param value the number
		 * @return this builder
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if {@code value} is outside the caps of {@link JsonNumber}, or
		 *                                  {@code name} contains an unpaired surrogate or is already present
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder put(@NonNull String name, @NonNull BigDecimal value) {
			return put(name, JsonNumber.fromValue(value));
		}

		/**
		 * Adds a member whose value is a JSON boolean.
		 *
		 * @param name  the member name
		 * @param value the boolean
		 * @return this builder
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if {@code name} contains an unpaired surrogate or is already present
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder put(@NonNull String name, @NonNull Boolean value) {
			return put(name, JsonBoolean.fromValue(value));
		}

		/**
		 * Adds a member whose value is the JSON {@code null}.
		 *
		 * @param name the member name
		 * @return this builder
		 * @throws NullPointerException     if {@code name} is {@code null}
		 * @throws IllegalArgumentException if {@code name} contains an unpaired surrogate or is already present
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder putNull(@NonNull String name) {
			return put(name, JsonNull.defaultInstance());
		}

		/**
		 * Returns an object holding the members added so far, in the order they were added.
		 *
		 * @return the JSON object; {@link JsonObject#emptyInstance()} if no member was added
		 * @since 1.0.0
		 */
		@NonNull
		public JsonObject build() {
			LinkedHashMap<@NonNull String, @NonNull JsonValue> snapshot = new LinkedHashMap<>(capacityFor(
					this.members.size()));
			snapshot.putAll(this.members);
			return fromSnapshot(snapshot, this.deepestChild);
		}

		@Override
		@NonNull
		public String toString() {
			return "JsonObject.Builder{members=<redacted>}";
		}
	}
}
