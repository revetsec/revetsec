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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

/**
 * A supported JWT protected-header {@code typ} value used when signing a token.
 * The token type describes its intended use; it is separate from the claims and signing algorithm.
 * <p>
 * This enum is not switch-stable: a later release may add constants, so a {@code switch} over it needs a default
 * branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum JwtType {
	/**
	 * A general-purpose JWT ({@code JWT}).
	 */
	JWT("JWT"),
	/**
	 * A JWT access token ({@code at+jwt}).
	 */
	ACCESS_TOKEN("at+jwt"),
	/**
	 * A JWT client authentication assertion ({@code client-authentication+jwt}).
	 */
	CLIENT_AUTHENTICATION("client-authentication+jwt");

	private final @NonNull String wireValue;

	JwtType(@NonNull String wireValue) {
		this.wireValue = wireValue;
	}

	/**
	 * Returns this type's exact protected-header {@code typ} value.
	 *
	 * @return the wire value
	 * @since 1.0.0
	 */
	public @NonNull String getWireValue() {
		return this.wireValue;
	}
}
