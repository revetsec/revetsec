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

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Holds exported exceptions whose serialVersionUID is a long with the wrong modifiers. The JDK ignores the field
 * unless it is static and final, and computes a version that changes with the class; a non-private one is API.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class SerialVersionFixtures {
	private SerialVersionFixtures() {
	}

	/**
	 * Seeded violation: the field is not final, so serialization ignores it.
	 *
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class UnfinalFixtureException extends RevetsecException {
		private static long serialVersionUID = 1L;

		private UnfinalFixtureException() {
			super("Unfinal.");
		}
	}

	/**
	 * Seeded violation: the field is an instance field, so serialization ignores it.
	 *
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class InstanceFixtureException extends RevetsecException {
		private final long serialVersionUID = 1L;

		private InstanceFixtureException() {
			super("Instance.");
		}
	}

	/**
	 * Seeded violation: the field is package-private, not private.
	 *
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class UnprivateFixtureException extends RevetsecException {
		static final long serialVersionUID = 1L;

		private UnprivateFixtureException() {
			super("Unprivate.");
		}
	}
}
