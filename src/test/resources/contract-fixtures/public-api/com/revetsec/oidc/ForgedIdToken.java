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

import javax.annotation.concurrent.ThreadSafe;

/**
 * Seeded violation: a public subclass of a verified type, with a public constructor.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class ForgedIdToken extends IdToken {
	/**
	 * Anyone could create a "verified" token.
	 *
	 * @since 1.0.0
	 */
	public ForgedIdToken() {
	}
}
