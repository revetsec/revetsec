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

package com.revetsec.internal.encoding;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * The parameters of a raw query string or {@code application/x-www-form-urlencoded} body, in their original order,
 * with every repetition kept (R7).
 * <p>
 * Protocol parsers need both: a repeated single-valued parameter must be rejected (RFC 6749 section 3.1), not
 * collapsed into one value or a set, and a parser that picks the first or the last value lets an attacker choose.
 * So nothing is merged, dropped or reordered here; the caller decides.
 * <p>
 * The input is split on {@code &} only ({@code ;} is an ordinary character). Empty pieces, as in {@code a=1&&b=2} or
 * a leading or trailing {@code &}, carry no parameter and are skipped. In each piece, the first {@code =} separates
 * the name from the value, and a piece without {@code =} is a name with the empty value. Names and values are then
 * decoded with {@link FormUrlEncoding#decode(String)} (RFC 6749 Appendix B), so one malformed escape or invalid
 * UTF-8 sequence anywhere rejects the whole input. Names are compared exactly, and case-sensitively.
 * <p>
 * The input is the raw query, without the {@code ?}. The caller bounds its length before parsing (R8); the parse is
 * linear in it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class QueryParameters {
	private final @NonNull List<@NonNull Parameter> parameters;

	/**
	 * One name and value, both decoded.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public static final class Parameter {
		private final @NonNull String name;
		private final @NonNull String value;

		private Parameter(@NonNull String name, @NonNull String value) {
			this.name = name;
			this.value = value;
		}

		/**
		 * The decoded name.
		 *
		 * @return the name, possibly empty
		 */
		public @NonNull String getName() {
			return this.name;
		}

		/**
		 * The decoded value.
		 *
		 * @return the value, empty when the piece had no {@code =} or nothing after it
		 */
		public @NonNull String getValue() {
			return this.value;
		}

		/**
		 * A redacted rendering: parameter values include authorization codes and state (R9).
		 *
		 * @return a string that holds no part of the name or value
		 */
		@Override
		public @NonNull String toString() {
			return "Parameter{name=<redacted>, value=<redacted>}";
		}
	}

	private QueryParameters(@NonNull List<@NonNull Parameter> parameters) {
		this.parameters = List.copyOf(parameters);
	}

	/**
	 * Parses a raw query string or form body.
	 *
	 * @param encoded the raw query or body, without a leading {@code ?}
	 * @return the parameters, in order
	 * @throws EncodingException   if any name or value is not valid {@code application/x-www-form-urlencoded} UTF-8
	 * @throws ArithmeticException if a name's or value's decoded octets would number more than
	 *                             {@link Integer#MAX_VALUE}, which takes an input of roughly 715 million characters or
	 *                             more
	 */
	public static @NonNull QueryParameters parse(@NonNull String encoded) throws EncodingException {
		requireNonNull(encoded);
		List<Parameter> parameters = new ArrayList<>();
		int length = encoded.length();
		int start = 0;
		while (start < length) {
			int end = encoded.indexOf('&', start);
			if (end < 0)
				end = length;
			if (end > start) {
				// Search for '=' only inside this piece, so the parse stays linear.
				int separator = start;
				while (separator < end && encoded.charAt(separator) != '=')
					++separator;
				String name = FormUrlEncoding.decode(encoded.substring(start, separator));
				String value = separator < end ? FormUrlEncoding.decode(encoded.substring(separator + 1, end)) : "";
				parameters.add(new Parameter(name, value));
			}
			start = end + 1;
		}
		return new QueryParameters(parameters);
	}

	/**
	 * Every parameter, in input order, repetitions included.
	 *
	 * @return an unmodifiable list
	 */
	public @NonNull List<@NonNull Parameter> getParameters() {
		return this.parameters;
	}

	/**
	 * The values of every parameter named exactly {@code name}, in input order.
	 *
	 * @param name the decoded name, compared case-sensitively
	 * @return an unmodifiable list, empty if the name does not occur
	 */
	public @NonNull List<@NonNull String> getValues(@NonNull String name) {
		requireNonNull(name);
		List<String> values = new ArrayList<>();
		for (Parameter parameter : this.parameters)
			if (parameter.getName().equals(name))
				values.add(parameter.getValue());
		return List.copyOf(values);
	}

	/**
	 * The values grouped by name. Names are in order of first occurrence, and each list keeps its values in input
	 * order.
	 *
	 * @return an unmodifiable map of unmodifiable lists
	 */
	public @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> getValuesByName() {
		Map<String, List<String>> grouped = new LinkedHashMap<>();
		for (Parameter parameter : this.parameters)
			grouped.computeIfAbsent(parameter.getName(), name -> new ArrayList<>()).add(parameter.getValue());
		Map<String, List<String>> result = new LinkedHashMap<>();
		for (Map.Entry<String, List<String>> entry : grouped.entrySet())
			result.put(entry.getKey(), List.copyOf(entry.getValue()));
		return Collections.unmodifiableMap(result);
	}

	/**
	 * A redacted rendering (R9).
	 *
	 * @return a string that holds no name or value
	 */
	@Override
	public @NonNull String toString() {
		return "QueryParameters{parameters=<redacted>}";
	}
}
