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

package com.revetsec.webauthn;

/** Fixed, redacted reasons; no claimed account or browser detail is included.
 * @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public enum WebAuthnRejectionReason {
    /** Input or policy was not accepted.
     * @since 1.0.0 */ REJECTED,
    /** A non-increasing nonzero signature counter requires account review.
     * @since 1.0.0 */ COUNTER_RISK
}
