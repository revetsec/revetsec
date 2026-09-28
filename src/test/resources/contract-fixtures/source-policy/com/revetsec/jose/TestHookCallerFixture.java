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

package com.revetsec.jose;

import com.revetsec.internal.http.TestHookFixture;

import java.util.function.Function;
import java.util.function.Supplier;

import static com.revetsec.internal.http.TestHookFixture.sharedStateForTests;

/**
 * Seeded violations (for-tests-call): test hooks declared in another file, called through the class, through an
 * instance, through a static import (the import line itself names the hook without calling it), through method
 * references, as an argument, and unqualified from a subclass that inherits one. The controls are not reported: a
 * hook this file declares and calls itself; methods of TestHookFixture, another file, whose names contain ForTests
 * without ending in it, end in ForTest, or end in Tests without For; and the hooks' names in strings and comments.
 */
final class TestHookCallerFixture {
	String seeded(TestHookFixture fixture) {
		String state = TestHookFixture.sharedStateForTests();
		state += fixture.stateForTests();
		state += sharedStateForTests();
		Supplier<String> shared = TestHookFixture::sharedStateForTests;
		Function<TestHookFixture, String> instance = TestHookFixture::stateForTests;
		return state + shared.get() + instance.apply(fixture) + String.valueOf(
				fixture.stateForTests());
	}

	String controls(TestHookFixture fixture) {
		// TestHookFixture.sharedStateForTests() and fixture.stateForTests() in a comment are not calls.
		Supplier<String> local = this::localStateForTests;
		Supplier<String> infix = fixture::stateForTestsOnly;
		return localStateForTests() + local.get() + infix.get() + fixture.stateForTestsOnly() + fixture.stateForTest()
				+ fixture.countTests() + fixture.forTestsOnly() + "TestHookFixture.sharedStateForTests()";
	}

	String localStateForTests() {
		return "local";
	}

	static final class Derived extends TestHookFixture.Base {
		String read() {
			return baseStateForTests();
		}
	}
}
