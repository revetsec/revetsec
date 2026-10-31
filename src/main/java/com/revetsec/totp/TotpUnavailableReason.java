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

/** Fixed operational reasons without account or secret data.
 * @since 1.0.0 */
@Immutable
public enum TotpUnavailableReason {
    /** A store, clock, random source or other dependency was unavailable.
     * @since 1.0.0 */
    DEPENDENCY_UNAVAILABLE,
    /** Recovery admission was closed or could not be confirmed.
     * @since 1.0.0 */
    ADMISSION_CLOSED,
    /** The authority, admission, clock generation or recovery epoch was no longer authoritative.
     * @since 1.0.0 */
    FENCED,
    /** The backend refused capacity without changing state.
     * @since 1.0.0 */
    CAPACITY_REFUSED,
    /** An opaque record could not be authenticated or validated.
     * @since 1.0.0 */
    INVALID_STORED_STATE,
    /** An authenticated durable record format was unsupported.
     * @since 1.0.0 */
    UNSUPPORTED_STORED_FORMAT,
    /** A required durable-record sealing key was unavailable.
     * @since 1.0.0 */
    SEALING_KEY_UNAVAILABLE,
    /** The activated namespace record was missing or initialization was incomplete.
     * @since 1.0.0 */
    NAMESPACE_NOT_INITIALIZED,
    /** The original operation budget was exhausted.
     * @since 1.0.0 */
    DEADLINE_EXCEEDED,
    /** Repeated confirmed conflicts exhausted the bounded retry policy.
     * @since 1.0.0 */
    CONFLICT_LIMIT_REACHED,
    /** A charge reservation is confirmed, but verification or settlement is definitely incomplete.
     * No proof is released and the charge is not refunded or reserved again automatically.
     * @since 1.0.0 */
    ATTEMPT_INCOMPLETE,
    /** Healthy admitted authority time is unavailable or precedes a required minimum or entity floor.
     * No worker-time fallback is permitted.
     * @since 1.0.0 */
    TIME_AUTHORITY_UNAVAILABLE,
    /** The complete worker offset interval, elapsed continuity or release-rate bound could not establish health.
     * @since 1.0.0 */
    CLOCK_HEALTH_UNCONFIRMED
}
