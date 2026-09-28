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
 * An abstract sealed protocol intermediate, shaped like JoseException (G6-1, M2-2). Controls: its package-private
 * constructor, and its final exported leaf {@link MalformedFixtureException}. Seeded violations: two package-private
 * non-sealed subclasses, one permitted directly and one behind a sealed package-private intermediate. Neither is
 * exported, so only the walk of the permitted subclasses finds them (M2-10 item 6).
 *
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class JoseFixtureException extends RevetsecException
		permits MalformedFixtureException, LenientFixtureException, GroupedFixtureException {
	private static final long serialVersionUID = 1L;

	JoseFixtureException(@NonNull String fixedMessage) {
		super(fixedMessage);
	}
}

/**
 * Non-sealed: any class in the package, including one a split package on the class path adds, may extend it.
 */
non-sealed class LenientFixtureException extends JoseFixtureException {
	private static final long serialVersionUID = 1L;

	LenientFixtureException() {
		super("The lenient fixture failed.");
	}
}

/**
 * Sealed, so the walk continues to its permitted subclass.
 */
abstract sealed class GroupedFixtureException extends JoseFixtureException permits LooseFixtureException {
	private static final long serialVersionUID = 1L;

	GroupedFixtureException(@NonNull String fixedMessage) {
		super(fixedMessage);
	}
}

/**
 * Non-sealed, two levels below the exported class.
 */
non-sealed class LooseFixtureException extends GroupedFixtureException {
	private static final long serialVersionUID = 1L;

	LooseFixtureException() {
		super("The loose fixture failed.");
	}
}
