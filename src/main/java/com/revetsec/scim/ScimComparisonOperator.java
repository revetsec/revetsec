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
 * SCIM filter comparison operators (RFC 7644 section 3.4.2.2).
 *
 * @since 1.0.0
 */
@Immutable
public enum ScimComparisonOperator {
    /** Equal.
     * @since 1.0.0
     */ EQ,
    /** Not equal; multi-valued attributes use any-element semantics.
     * @since 1.0.0
     */ NE,
    /** Contains.
     * @since 1.0.0
     */ CO,
    /** Starts with.
     * @since 1.0.0
     */ SW,
    /** Ends with.
     * @since 1.0.0
     */ EW,
    /** Greater than.
     * @since 1.0.0
     */ GT,
    /** Less than.
     * @since 1.0.0
     */ LT,
    /** Greater than or equal.
     * @since 1.0.0
     */ GE,
    /** Less than or equal.
     * @since 1.0.0
     */ LE
}
