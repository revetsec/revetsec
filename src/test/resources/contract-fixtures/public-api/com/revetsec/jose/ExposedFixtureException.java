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

import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Seeded violations: an abstract sealed intermediate with a public and a protected constructor, which put
 * constructors no application can call into the API (G6-1, M2-10 item 6). Control: its permitted subclass is final.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class ExposedFixtureException extends RevetsecException permits ClosedFixtureException {
	private static final long serialVersionUID = 1L;

	/**
	 * A public constructor on an abstract sealed class.
	 *
	 * @since 1.0.0
	 */
	public ExposedFixtureException() {
		super("The exposed fixture failed.");
	}

	/**
	 * A protected constructor on an abstract sealed class.
	 *
	 * @param fixedMessage a fixed message
	 * @since 1.0.0
	 */
	protected ExposedFixtureException(@NonNull String fixedMessage) {
		super(fixedMessage);
	}
}

/**
 * Control: final and package-private.
 */
final class ClosedFixtureException extends ExposedFixtureException {
	private static final long serialVersionUID = 1L;

	ClosedFixtureException() {
		super("The closed fixture failed.");
	}
}
