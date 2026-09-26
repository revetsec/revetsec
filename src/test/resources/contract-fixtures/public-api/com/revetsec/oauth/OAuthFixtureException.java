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

import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Control: a protocol's abstract sealed intermediate exception. ContractMetaTests lists it in OPEN_ABSTRACT_TYPES,
 * which is a stale entry because a sealed class needs no exemption.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class OAuthFixtureException extends RevetsecException
		permits TokenFixtureException, ReopenedFixtureException {
	private static final long serialVersionUID = 1L;

	OAuthFixtureException(@NonNull String fixedMessage) {
		super(fixedMessage);
	}
}
