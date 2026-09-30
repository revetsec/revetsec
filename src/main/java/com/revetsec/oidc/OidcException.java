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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * An OpenID Connect validation failure. Messages are fixed and contain no tokens, claims or other input.
 * Applications catch this family; only Revetsec constructs it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class OidcException extends RevetsecException permits OidcValidationException {
	private static final long serialVersionUID = 1L;

	OidcException(@NonNull String fixedMessage) {
		super(ErrorCategory.VALIDATION_FAILURE, false, fixedMessage, null);
	}
}
