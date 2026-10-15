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
 * Closed, value-free provider outcomes for saving a browser-bound pending authorization.
 * Only SAVED establishes that the caller may continue the authorization redirect. INDETERMINATE
 * requires reconciliation; it supplies no guarantee that retrying the save is safe.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum PendingAuthorizationSaveResult {
	/**
	 * A new record was saved.
	 * @since 1.0.0
	 */
	SAVED,
	/**
	 * A live record already uses this binding and state.
	 * @since 1.0.0
	 */
	ALREADY_PRESENT,
	/**
	 * Capacity refused the write without evicting a live record.
	 * @since 1.0.0
	 */
	CAPACITY_REFUSED,
	/**
	 * The write did not occur because the store or budget was unavailable.
	 * @since 1.0.0
	 */
	UNAVAILABLE,
	/**
	 * A write may have occurred; presence and safe retry are not established.
	 * @since 1.0.0
	 */
	INDETERMINATE
}
