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

/** Method provenance for a successful second-factor operation.
 * @since 1.0.0 */
@Immutable
public enum TotpAuthenticationMethod {
    /** A fresh time-based one-time password was accepted.
     * @since 1.0.0 */
    TOTP,
    /** A single-use recovery code was consumed; application recovery policy applies.
     * @since 1.0.0 */
    RECOVERY_CODE
}
