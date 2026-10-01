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
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;

/**
 * Validates bearer access tokens for explicitly configured audiences.
 * Infrastructure failures remain exceptions. This sealed hierarchy may gain implementations.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public sealed interface AccessTokenValidator permits JwtAccessTokenValidator, TokenIntrospectionClient {

	/**
	 * Validates the credential, throwing only for rejection or infrastructure failure.
	 * @param token unverified header credential
	 * @return fully checked access token
	 * @since 1.0.0
	 */
	@CheckReturnValue
	@NonNull
	VerifiedAccessToken validate(@NonNull BearerToken token);

	/**
	 * Returns a local credential verdict; infrastructure failures remain exceptions.
	 * @param token unverified header credential
	 * @return validation outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	@NonNull
	AccessTokenValidationResult validateResult(@NonNull BearerToken token);
}
