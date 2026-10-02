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

import com.google.errorprone.annotations.CheckReturnValue;
import java.time.Duration;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import static java.util.Objects.requireNonNull;

/**
 * Supplies one immutable key and header snapshot per assertion POST. Implementations must be thread-safe,
 * cooperate with the remaining budget and interruption, and return promptly. Execution is on the calling thread.
 * No key lookup occurs at client construction or on a cached token result.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface ClientAssertionKeyProvider {
	/**
	 * Selects the key for one outgoing assertion.
	 * @param remainingBudget the positive time left in the original operation
	 * @return one immutable signer and identifier snapshot
	 * @since 1.0.0
	 */
	@NonNull ClientAssertionSigningKey getSigningKey(@NonNull Duration remainingBudget);

	/**
	 * Uses one fixed immutable key snapshot.
	 * @param key the snapshot
	 * @return a thread-safe fixed provider
	 * @since 1.0.0
	 */
	@CheckReturnValue
	static @NonNull ClientAssertionKeyProvider fromKey(@NonNull ClientAssertionSigningKey key) {
		requireNonNull(key);
		return remainingBudget -> { requireNonNull(remainingBudget); return key; };
	}
}
