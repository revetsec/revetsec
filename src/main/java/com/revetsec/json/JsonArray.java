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
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * A JSON array: an ordered, unmodifiable list of values. Two arrays are equal when they hold equal elements in the
 * same order.
 * <p>
 * There is no array builder: assemble a {@link List} and pass it to {@link #fromElements(List)}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonArray implements JsonValue {
	@NonNull
	private static final JsonArray EMPTY = new JsonArray(List.of(), 1, List.of().hashCode());

	@NonNull
	private final List<@NonNull JsonValue> elements;
	private final int depth;
	private final int hashCode;

	/**
	 * Returns the empty JSON array.
	 *
	 * @return the shared empty array
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonArray emptyInstance() {
		return EMPTY;
	}

	/**
	 * Returns a JSON array holding a snapshot of {@code elements}, in order.
	 *
	 * @param elements the elements; later changes to the list do not affect the array
	 * @return the JSON array
	 * @throws NullPointerException     if {@code elements} or any element is {@code null}
	 * @throws IllegalArgumentException if the array would nest more than 64 deep
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonArray fromElements(@NonNull List<? extends @NonNull JsonValue> elements) {
		requireNonNull(elements);
		List<@NonNull JsonValue> snapshot = List.copyOf(elements);

		if (snapshot.isEmpty())
			return EMPTY;

		int deepestChild = 0;

		for (JsonValue element : snapshot)
			deepestChild = Math.max(deepestChild, JsonInvariants.depthOf(element));

		return new JsonArray(snapshot, JsonInvariants.requireContainerDepth(deepestChild), snapshot.hashCode());
	}

	private JsonArray(@NonNull List<@NonNull JsonValue> elements, int depth, int hashCode) {
		// Already an unmodifiable copy, which List.copyOf returns as it is; copying here documents that the field is
		// immutable.
		this.elements = List.copyOf(elements);
		this.depth = depth;
		this.hashCode = hashCode;
	}

	/**
	 * Returns this array's elements, in order.
	 *
	 * @return an unmodifiable list
	 * @since 1.0.0
	 */
	@NonNull
	public List<@NonNull JsonValue> getElements() {
		return this.elements;
	}

	/**
	 * The G7-6 depth: 1 if empty, otherwise 1 more than the deepest element.
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
		return this == other || (other instanceof JsonArray array && this.hashCode == array.hashCode
				&& this.elements.equals(array.elements));
	}

	@Override
	public int hashCode() {
		return this.hashCode;
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonArray{elements=<redacted>}";
	}
}
