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

package com.revetsec;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Seeded violations: mutable static state in a branch of a conditional or switch expression (R4, G6-10). javac types
 * the whole expression by the least upper bound of its branches, which can hide the mutable type (AtomicLong and
 * AtomicInteger meet at Number), so each branch is checked. Every field on a reported line is named, and
 * ContractMetaTests allowlists LEFT, so its line names RIGHT alone. EnumSet.of is only named like an immutable
 * factory: its set is mutable. Nothing in Controls is reported.
 */
final class MutableStaticBranchesFixture {
	static final boolean FLAG = Boolean.parseBoolean("true");
	static final int MODE = Integer.parseInt("1");
	static final Object EITHER_ATOMIC = FLAG ? new AtomicLong() : new AtomicInteger();
	static final Object EITHER_BUILDER = FLAG ? new StringBuilder() : new StringBuffer();
	static final Object EITHER_COLLECTION = FLAG ? new ArrayList<String>() : new LinkedList<String>();
	static final Object SWITCHED_ARRAY = switch (MODE) {
		case 1 -> new byte[1];
		default -> "none";
	};
	static final Object YIELDED_ATOMIC = switch (MODE) {
		case 1 -> {
			yield new AtomicInteger();
		}
		default -> "none";
	};
	static final Object STATEMENT_GROUPS = switch (MODE) {
		case 1:
			yield FLAG ? "none" : new StringBuilder();
		default:
			yield "none";
	};
	static int first, second;
	static final int[] LEFT = {1}, RIGHT = {2};
	static final java.util.Set<java.time.DayOfWeek> DAYS = java.util.EnumSet.of(java.time.DayOfWeek.MONDAY);

	static final class Controls {
		static final List<String> CHOSEN = FLAG ? List.of() : List.of("a");
		static final int[] MAYBE_EMPTY = FLAG ? new int[0] : null;
		static final Object WIDENED = FLAG ? java.math.BigInteger.ONE : java.math.BigDecimal.ONE;
		static final Object NESTED = switch (MODE) {
			case 1 -> {
				Object inner = switch (MODE) {
					default -> new byte[1];
				};
				yield inner == null ? "none" : "some";
			}
			default -> "none";
		};
	}
}
