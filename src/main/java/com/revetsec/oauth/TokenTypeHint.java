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

import javax.annotation.concurrent.Immutable;

/**
 * RFC 7009 revocation token-type hint.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum TokenTypeHint {
	/** An access token. */
	ACCESS_TOKEN("access_token"),
	/** A refresh token. */
	REFRESH_TOKEN("refresh_token");

	private final String wireValue;

	TokenTypeHint(String wireValue) { this.wireValue = wireValue; }

	String wireValue() { return this.wireValue; }
}
