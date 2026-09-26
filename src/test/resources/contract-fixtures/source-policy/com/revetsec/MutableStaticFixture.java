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

/**
 * Seeded violations: mutable static state (R4, G6-10), each kind found through the declared type and through the
 * initializer's type, plus a blank final collection, an unmodifiable view, Stream.toList and an interface constant.
 * ContractMetaTests allowlists LookupTable.VALUES, so it is not reported, and supplies stale, duplicate and malformed
 * rows. Nothing in Controls is reported.
 */
final class MutableStaticFixture {
	static int counter;
	private static volatile Object accessor = new Object();
	static final int[] TABLE = {1, 2};
	static final Object HIDDEN_ARRAY = new byte[4];
	static final java.util.concurrent.atomic.AtomicLong COUNT = new java.util.concurrent.atomic.AtomicLong();
	static final Number ADDER = new java.util.concurrent.atomic.LongAdder();
	static final StringBuilder BUFFER = new StringBuilder();
	static final CharSequence LEGACY_BUFFER = new StringBuffer();
	static final java.util.List<String> NAMES = new java.util.ArrayList<>();
	static final Object HIDDEN_MAP = new java.util.HashMap<String, String>();
	static final java.util.Set<String> VIEW = java.util.Collections.unmodifiableSet(new java.util.HashSet<>());
	static final java.util.List<String> STREAMED = java.util.stream.Stream.of("a").toList();
	static final java.util.Map<String, String> ASSIGNED;

	static {
		ASSIGNED = java.util.Map.of();
	}

	interface Constants {
		int[] VALUES = {1};
	}

	static final class LookupTable {
		static final byte[] VALUES = {1, 2};
		static final byte[] UNLISTED = {3};
	}

	static final class Controls {
		static final int LIMIT = 4;
		static final String NAME = "name";
		static final Object LOCK = new Object();
		static final Object NOTHING = null;
		static final java.util.List<String> LIST = java.util.List.of("a");
		static final java.util.Set<String> COPY = java.util.Set.copyOf(LIST);
		static final java.util.Map<String, Integer> ENTRIES = java.util.Map.ofEntries(java.util.Map.entry("a", 1));
		static final java.util.Collection<String> CAST = (java.util.Collection<String>) (java.util.List.of("b"));
		static final byte[] EMPTY = new byte[0];
		static final String[] NONE = {};
		static final int[][] NO_ROWS = new int[0][4];
		private final int[] instanceTable = {1};

		enum Mode {
			ON,
			OFF
		}

		int[] local() {
			int[] local = {1};
			java.util.List<String> names = new java.util.ArrayList<>();
			return names.isEmpty() ? local : this.instanceTable;
		}
	}

	// A subclass of an atomic type is atomic. A field is reported on the line of its type and name, not on the line of
	// an annotation above it.
	static final class Counter extends java.util.concurrent.atomic.AtomicLong {
	}

	static final Counter COUNTER = new Counter();
	@Deprecated
	static final StringBuilder ANNOTATED = new StringBuilder();
}
