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
 * SCIM response visibility attached to an attribute.
 *
 * @since 1.0.0
 */
@Immutable
public enum ScimReturned {
    /** Return irrespective of projection. */
    ALWAYS,
    /** Never return the value. */
    NEVER,
    /** Return unless projection excludes the value. */
    DEFAULT,
    /** Return only when explicitly requested or supplied in the write. */
    REQUEST
}
