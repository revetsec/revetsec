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

package com.revetsec;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * The fixture tree's stand-in for the real exception root: every exported Throwable must extend it, and hooks may
 * take it. ContractMetaTests lists it in OPEN_ABSTRACT_TYPES, so it may stay unsealed. Control: it declares its
 * serialVersionUID.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public abstract class RevetsecException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	/**
	 * For Revetsec's own subclasses.
	 *
	 * @param fixedMessage a fixed message
	 * @since 1.0.0
	 */
	protected RevetsecException(@NonNull String fixedMessage) {
		super(fixedMessage, null, false, true);
	}
}
