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

package com.revetsec.scim;

import javax.annotation.concurrent.Immutable;

/**
 * Schema-bound SCIM JSON attribute types.
 *
 * @since 1.0.0
 */
@Immutable
public enum ScimAttributeType {
    /** A Unicode string. */
    STRING,
    /** A Boolean. */
    BOOLEAN,
    /** A decimal JSON number. */
    DECIMAL,
    /** A JSON integer without fractional or exponent syntax. */
    INTEGER,
    /** An XML Schema date-time string. */
    DATE_TIME,
    /** A Base64-encoded binary string. */
    BINARY,
    /** An absolute or relative URI reference. */
    REFERENCE,
    /** An object with defined subattributes. */
    COMPLEX
}
