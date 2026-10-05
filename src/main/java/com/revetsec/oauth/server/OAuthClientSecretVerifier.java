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
 * Application-owned verification of a pre-registered confidential client's secret.
 * Implementations must be thread safe, honor the remaining budget and use constant-time secret verification.
 * The issuer owns Basic decoding and clears the temporary secret after the callback; do not retain its bytes.
 * A false result means invalid credentials; a null result, exception or exhausted budget is an infrastructure fault.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@FunctionalInterface
public interface OAuthClientSecretVerifier {
	/**
	 * Checks a temporary decoded secret against application-managed credentials.
	 * @param clientId the exact registered client identifier
	 * @param presentedSecret temporary secret bytes, valid only for this callback
	 * @param remainingTime the cooperative remaining operation budget
	 * @return whether the secret matches
	 * @since 1.0.0
	 */
	@NonNull Boolean verifiesClientSecret(@NonNull String clientId, byte @NonNull [] presentedSecret,
			@NonNull Duration remainingTime);
}
