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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;

/** Supported verify-only PBKDF2 pseudorandom functions for trusted legacy records.
 * @since 1.0.0 */
@Immutable
public enum Pbkdf2Hmac {
    /** PBKDF2-HMAC-SHA-256. */
    SHA256("HmacSHA256"),
    /** PBKDF2-HMAC-SHA-512. */
    SHA512("HmacSHA512");

    private final @NonNull String jcaName;
    Pbkdf2Hmac(@NonNull String jcaName) { this.jcaName = jcaName; }
    @NonNull String jcaName() { return jcaName; }
}
