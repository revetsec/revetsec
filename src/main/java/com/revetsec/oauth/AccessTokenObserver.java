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

import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;

/**
 * Caller-thread resource events and inherited OAuth/JOSE events, without credentials or claims.
 * Hooks must be fast and thread-safe; callers contain failures except VirtualMachineError.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface AccessTokenObserver extends OAuthObserver {

	/**
	 * Returns a silent observer.
	 * @return observer
	 * @since 1.0.0
	 */
	@NonNull
	static AccessTokenObserver disabledInstance() {
		return DisabledAccessTokenObserver.INSTANCE;
	}

	/**
	 * Reports successful build with the explicit mode.
	 * @param mode enabled mode
	 * @since 1.0.0
	 */
	default void didEnableCompatibilityMode(@NonNull AccessTokenCompatibilityMode mode) {
	}

	/**
	 * Reports actual mode use, including a later rejection.
	 * @param mode used mode
	 * @since 1.0.0
	 */
	default void didUseCompatibilityMode(@NonNull AccessTokenCompatibilityMode mode) {
	}

	/**
	 * Reports successful profile validation; releases no result or identity.
	 * @since 1.0.0
	 */
	default void didValidateAccessToken() {
	}

	/**
	 * Reports a fixed local rejection, never infrastructure failure.
	 * @param exception same fixed-message rejection the caller receives
	 * @since 1.0.0
	 */
	default void didRejectAccessToken(@NonNull AccessTokenValidationException exception) {
	}
}
