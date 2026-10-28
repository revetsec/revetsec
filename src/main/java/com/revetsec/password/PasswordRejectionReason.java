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
package com.revetsec.password;

import javax.annotation.concurrent.Immutable;

/** Fixed internal reasons for a refused password-hashing or verification request. Applications
 * should present a generic login response, regardless of the reason.
 * @since 1.0.0 */
@Immutable
public enum PasswordRejectionReason {
    /** The submitted password exceeds a configured input ceiling. */
    PASSWORD_TOO_LONG,
    /** The submitted password contains malformed UTF-16. */
    INVALID_PASSWORD,
    /** The stored verifier is malformed or exceeds a configured verification ceiling. */
    INVALID_STORED_HASH,
    /** The stored verifier is a format not accepted for this operation. */
    UNSUPPORTED_STORED_HASH,
    /** A legacy bcrypt candidate would be truncated and cannot prove the complete password. */
    LEGACY_BCRYPT_INPUT_TOO_LONG
}
