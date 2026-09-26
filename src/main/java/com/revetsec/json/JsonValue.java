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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

/**
 * An immutable JSON value (RFC 8259): exactly one of {@link JsonObject}, {@link JsonArray}, {@link JsonString},
 * {@link JsonNumber}, {@link JsonBoolean} or {@link JsonNull}.
 * <p>
 * The permitted subtypes are frozen within a major version, so an exhaustive {@code instanceof} chain or, on newer
 * Java releases, a pattern {@code switch} over them stays exhaustive.
 * <p>
 * <strong>Invariants.</strong> Every value is immutable and holds no {@code null}. Its strings and member names are
 * well-formed UTF-16 (no unpaired surrogate). It nests at most 64 deep, where a scalar or an empty container has
 * depth 1 and any other container is 1 deeper than its deepest child (member names add nothing). A number has at most
 * 4,096 significant digits and an adjusted decimal exponent of magnitude at most 100,000. The factories reject a
 * {@code null} with {@link NullPointerException} and anything else outside these invariants with
 * {@link IllegalArgumentException}, so no content can make {@link #toJson()}, {@code equals} or {@code hashCode}
 * throw, and none of them recurses more than 64 levels deep.
 * <p>
 * <strong>Cost.</strong> {@code hashCode} never walks nested values: containers compute theirs once, at construction.
 * A value may hold the same instance in several places, and {@link #toJson()} and {@code equals} then visit it once
 * per occurrence, so their work, and the length of the JSON text, follow the value's expanded tree, not the number of
 * objects it holds. A value that nests one instance repeatedly can therefore be far larger than its objects: its
 * {@link #toJson()} can run out of memory, and {@code equals} against a copy built separately can take exponential
 * time. A value parsed from JSON text is always a tree, so its cost is proportional to that text.
 * <p>
 * <strong>Equality.</strong> Numbers compare by numeric value ({@code 1}, {@code 1.0} and {@code 1E0} are equal),
 * objects compare their members by name regardless of order, arrays compare element by element in order, and strings
 * and member names compare exactly, with no case folding or Unicode normalization. {@code hashCode} is consistent
 * with {@code equals} but not resistant to collisions: strings use {@link String#hashCode()}, containers combine
 * their contents' hashes, and no value type is {@link Comparable}. So a {@code HashMap} or {@code HashSet} keyed by
 * values that someone else chooses can degrade to quadratic time.
 * <p>
 * <strong>Rendering.</strong> {@code toString()} never shows content: it renders {@code SimpleName{...=<redacted>}},
 * so a value that holds a secret or personal data is safe to log. {@link #toJson()} is the method that emits
 * content.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public sealed interface JsonValue permits JsonObject, JsonArray, JsonString, JsonNumber, JsonBoolean, JsonNull {
	/**
	 * Serializes this value as compact JSON text: no insignificant whitespace, members in insertion order, and numbers
	 * in the canonical form of {@link java.math.BigDecimal#toString()} ({@code 1e2} becomes {@code 1E+2}).
	 * <p>
	 * Strings escape only what JSON requires: the quotation mark, the reverse solidus and the control characters
	 * U+0000 to U+001F, using the two-character escapes where they exist. Every other character, U+2028 and U+2029
	 * included, is written as itself.
	 * <p>
	 * Unlike {@code toString()}, the result contains every string and number this value holds. It is not the text a
	 * value was parsed from, so never verify a signature over it.
	 *
	 * @return the JSON text
	 * @since 1.0.0
	 */
	@NonNull String toJson();
}
