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

package com.revetsec.totp;

import javax.annotation.concurrent.Immutable;

/** Fixed, redacted application-visible reasons for rejected TOTP operations.
 * @since 1.0.0 */
@Immutable
public enum TotpRejectionReason {
    /** The input, binding or requested transition was not accepted.
     * @since 1.0.0 */
    REJECTED,
    /** The submitted code was invalid, expired or already consumed.
     * @since 1.0.0 */
    INVALID_CODE,
    /** No active factor exists for this account.
     * @since 1.0.0 */
    NOT_ENROLLED,
    /** Initial enrollment cannot replace an active factor.
     * @since 1.0.0 */
    ALREADY_ENROLLED,
    /** The pending enrollment was absent or expired.
     * @since 1.0.0 */
    ENROLLMENT_NOT_FOUND,
    /** A pending enrollment already exists or its generation changed.
     * @since 1.0.0 */
    ENROLLMENT_CONFLICT,
    /** The approved factor generation is no longer current.
     * @since 1.0.0 */
    FACTOR_MISMATCH,
    /** The approved recovery batch is no longer current.
     * @since 1.0.0 */
    RECOVERY_BATCH_MISMATCH,
    /** The server-owned operation or browser binding did not match.
     * @since 1.0.0 */
    BINDING_MISMATCH,
    /** The observed time precedes authoritative stored time.
     * @since 1.0.0 */
    CLOCK_ROLLBACK
}
