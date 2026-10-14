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

import com.google.errorprone.annotations.CheckReturnValue;

import org.jspecify.annotations.NonNull;

import java.util.*;

/** Application-owned attribute-aware matching; deterministic, bounded and non-I/O.
 * No Unicode or username preparation default is provided.
 * Unexpected ordinary failures, including a null return, become fixed internalError results.
 * The facade restores a thrown InterruptedException's thread flag; fatal VM errors escape.
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
public interface ScimStringMatching {
    /** Compares one assigned value under the authoritative backend's rules.
     * @param attributePath canonical attribute path
     * @param definition bound definition
     * @param operator requested operation
     * @param value stored value
     * @param literal comparison literal
     * @return match or unsupported
     * @since 1.0.0
     */
    @CheckReturnValue
    @NonNull ScimStringMatchResult match(
            @NonNull ScimAttributePath attributePath,
            @NonNull ScimAttributeDefinition definition,
            @NonNull ScimComparisonOperator operator,
            @NonNull String value,
            @NonNull String literal);
}
