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
 * Control: an observer that extends LeakyObserver, which is itself an exported observer. The members it inherits
 * from LeakyObserver (its field and its non-compliant hooks) are reported once, on LeakyObserver, and not again here.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface LeakyChildObserver extends LeakyObserver {
	/**
	 * The observer whose hooks do nothing.
	 *
	 * @return never
	 * @since 1.0.0
	 */
	static @NonNull LeakyChildObserver disabledInstance() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Called after a retry.
	 *
	 * @param delay how long it waited
	 * @since 1.0.0
	 */
	default void didRetry(@Nullable Duration delay) {
	}
}
