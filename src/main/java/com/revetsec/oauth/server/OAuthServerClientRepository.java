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

package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.util.Optional;

/**
 * Application-owned lookup of trusted, pre-registered client configuration.
 * Implementations must be thread safe and honor the remaining budget. Absence means a genuinely unknown client;
 * exceptions, null results and exhausted budgets are infrastructure faults, never an unknown-client decision.
 * A returned registration must retain the exact requested client identifier.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@FunctionalInterface
public interface OAuthServerClientRepository {
	/**
	 * Looks up trusted registration without interpreting the identifier as an outbound URL.
	 * @param clientId the exact client identifier
	 * @param remainingTime the cooperative remaining operation budget
	 * @return the registration, or genuine absence
	 * @since 1.0.0
	 */
	@NonNull Optional<@NonNull OAuthServerClientRegistration> findRegisteredClient(@NonNull String clientId,
			@NonNull Duration remainingTime);
}
