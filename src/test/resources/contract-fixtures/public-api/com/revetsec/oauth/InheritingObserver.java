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

/**
 * Seeded violations: an observer that inherits abstract hooks from interfaces the observer rules check nowhere else,
 * so they are reported here: an exported interface that is not an observer ({@link ExportedHooks}), and a
 * package-private interface that is named like an observer but is not exported ({@code HiddenObserver}).
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface InheritingObserver extends ExportedHooks, HiddenObserver {
	/**
	 * The observer whose hooks do nothing.
	 *
	 * @return never
	 * @since 1.0.0
	 */
	static @NonNull InheritingObserver disabledInstance() {
		throw new UnsupportedOperationException();
	}
}

/**
 * A package-private interface named like an observer. It is not exported, so its members are checked on the exported
 * observers that extend it.
 */
interface HiddenObserver {
	/**
	 * Documented and annotated; the problem is that it is abstract.
	 *
	 * @param name a name
	 * @since 1.0.0
	 */
	void didConceal(@Nullable String name);
}
