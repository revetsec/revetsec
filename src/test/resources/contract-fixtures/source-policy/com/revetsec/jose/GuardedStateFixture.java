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

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Seeded violations: provided-scope annotations whose types have elements, in a package-private class of an exported
 * package (provided-annotation-with-element, M2-10). jsr305's GuardedBy by simple and qualified name, Error Prone's
 * own GuardedBy and InlineMe, and Error Prone's Immutable, whose one element has a default, so the use names none.
 * Controls: provided-scope annotations without elements (jsr305 ThreadSafe, Error Prone CheckReturnValue, JSpecify
 * Nullable), the JDK's SuppressWarnings and Deprecated, which have elements but ship with every JDK, and an annotation
 * type declared in the analyzed sources. The imports name annotations without using them, so they are not reported.
 */
@ThreadSafe
final class GuardedStateFixture {
	private final java.util.concurrent.locks.ReentrantLock lock = new java.util.concurrent.locks.ReentrantLock();
	@GuardedBy("lock")
	private int count;
	@javax.annotation.concurrent.GuardedBy("lock") private int total;
	@com.google.errorprone.annotations.concurrent.GuardedBy("lock")
	private int pending;

	@com.google.errorprone.annotations.InlineMe(replacement = "this.next()")
	@Deprecated(since = "1.0.0")
	int increment() {
		return next();
	}

	@com.google.errorprone.annotations.Immutable
	static final class Snapshot {
	}

	@com.google.errorprone.annotations.CheckReturnValue
	@SuppressWarnings("unused")
	@ReviewedFixture(reason = "an annotation type in the analyzed sources")
	int next() {
		this.lock.lock();
		try {
			return ++this.count + this.total + this.pending;
		} finally {
			this.lock.unlock();
		}
	}

	@org.jspecify.annotations.Nullable String name() {
		return null;
	}
}

/**
 * Control: an annotation type with an element, declared in the analyzed sources, so not from a provided-scope JAR.
 */
@interface ReviewedFixture {
	String reason();
}
