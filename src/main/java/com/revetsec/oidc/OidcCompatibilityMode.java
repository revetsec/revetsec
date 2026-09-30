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

package com.revetsec.oidc;

import javax.annotation.concurrent.Immutable;

/**
 * Explicit per-client OIDC relaxations. Modes are off by default and observed at build and every actual use.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum OidcCompatibilityMode {
	/**
	 * Permits explicitly allowlisted HS256/384/512 ID tokens for a confidential client. The key is the exact
	 * request-authentication client secret in UTF-8, at least 32/48/64 bytes respectively. Multi-valued audiences
	 * are rejected. This does not permit HMAC in the public JWT validator or in signed UserInfo.
	 */
	HMAC_ID_TOKENS
}
