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

package com.revetsec.oauth;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;

/**
 * Seeded violations: an observer interface without a disabledInstance(), because the only method of that name takes
 * an argument, and which inherits an abstract hook from a package-private interface.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface SilentObserver extends HiddenHooks {
	/**
	 * Seeded violation: a disabledInstance() takes no arguments, so this is another static method, and the observer
	 * still has no disabledInstance().
	 *
	 * @param name a name
	 * @return never
	 * @since 1.0.0
	 */
	static @NonNull SilentObserver disabledInstance(@NonNull String name) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Control: a compliant hook.
	 *
	 * @param duration how long it waited
	 * @since 1.0.0
	 */
	default void didWait(@Nullable Duration duration) {
	}
}

/**
 * A package-private interface whose abstract hook callers reach through the exported {@link SilentObserver}.
 */
interface HiddenHooks {
	/**
	 * Documented and annotated; the problem is that it is abstract.
	 *
	 * @param name a name
	 * @since 1.0.0
	 */
	void didHide(@Nullable String name);
}
