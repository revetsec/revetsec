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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.NotThreadSafe;

/** Trusted resource construction exceeded its configured processing work budget.
 * @since 1.0.0
 */
@NotThreadSafe
public final class ScimResourceWorkLimitException extends RevetsecException {
    private static final long serialVersionUID = 1L;

    ScimResourceWorkLimitException() {
        super(ErrorCategory.MALFORMED_INPUT, false,
                "SCIM resource construction exceeded its processing work budget.", null);
    }

    /** Returns a fixed message with no resource data.
     * @return fixed description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimResourceWorkLimitException{budget exceeded}"; }
}
