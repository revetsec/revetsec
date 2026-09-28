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

package com.revetsec.internal.http;

import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Control (for-tests-call): a class that declares test hooks, like HttpExchange and DefaultHttpClientHolder. The file
 * that declares a hook may call it: directly, through an instance, through method references, from a nested class
 * and from a second top-level class in the same file. Nothing here is reported. TestHookNeighborFixture.java (the
 * same package), internal/TestHookFixture.java (the same file and class name, in another package) and
 * jose/TestHookCallerFixture.java seed the calls from other files; the last also calls the methods here whose names
 * only resemble a hook's, as controls.
 */
public final class TestHookFixture {
	private final String state;

	public TestHookFixture(String state) {
		this.state = state;
	}

	public static String sharedStateForTests() {
		return "shared";
	}

	public String stateForTests() {
		return this.state;
	}

	// Not hooks: the names contain ForTests without ending in it, or end in ForTest or in Tests without For.

	public String stateForTestsOnly() {
		return "infix";
	}

	public String stateForTest() {
		return "singular";
	}

	public String countTests() {
		return "no For";
	}

	public String forTestsOnly() {
		return "prefix";
	}

	String controls() {
		Supplier<String> shared = TestHookFixture::sharedStateForTests;
		Function<TestHookFixture, String> instance = TestHookFixture::stateForTests;
		return sharedStateForTests() + this.stateForTests() + shared.get() + instance.apply(this)
				+ new Base().baseStateForTests();
	}

	/**
	 * A class other files may extend, with a hook they inherit.
	 */
	public static class Base {
		public String baseStateForTests() {
			return "base";
		}

		String read(TestHookFixture fixture) {
			return fixture.stateForTests() + TestHookFixture.sharedStateForTests() + baseStateForTests();
		}
	}
}

/**
 * A second top-level class: it is in the file that declares the hooks, so it may call them.
 */
final class TestHookCompanionFixture {
	String read(TestHookFixture fixture) {
		return fixture.stateForTests() + TestHookFixture.sharedStateForTests();
	}
}
