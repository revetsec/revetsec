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

/** Operational reasons for password work that could not be completed.
 * @since 1.0.0 */
@Immutable
public enum PasswordUnavailableReason {
    /** The local shared work gate could not admit the KDF. */
    WORK_CAPACITY,
    /** Required pepper key material was unavailable. */
    PEPPER_UNAVAILABLE,
    /** The selected cryptographic primitive was unavailable. */
    CRYPTO_UNAVAILABLE,
    /** The caller was interrupted before expensive work started. */
    INTERRUPTED
}
