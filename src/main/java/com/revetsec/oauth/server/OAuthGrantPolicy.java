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

/**
 * Continuing application authorization policy, invoked outside store transactions at approval, code exchange
 * and refresh. Implementations must be thread safe and honor the remaining budget. Decisions must retain the
 * checked subject and may only narrow scope/resource/refresh authority. Denial terminates authorization; null,
 * exceptions, exhausted budgets, changed subjects and widening are infrastructure/configuration faults.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@FunctionalInterface
public interface OAuthGrantPolicy {
	/**
	 * Rechecks application permission against issuer-checked grant facts.
	 * @param context checked grant facts, with no raw authorization code or refresh credential
	 * @param remainingTime the cooperative remaining operation budget
	 * @return the application decision
	 * @since 1.0.0
	 */
	@NonNull OAuthAuthorizationDecision authorizeGrant(@NonNull OAuthGrantContext context, @NonNull Duration remainingTime);
}
