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
 * Explicit SCIM compatibility relaxations; no feature is selected from request content.
 *
 * @since 1.0.0
 */
@Immutable
public enum ScimCompatibilityFeature {
    /** Accept ASCII case variants of PATCH operation names. */
    PATCH_OPERATION_NAME_CASE_INSENSITIVE,
    /** Accept true/false strings only in Boolean-bound positions. */
    BOOLEAN_STRINGS,
    /** Accept reviewed member-removal value shapes. */
    PATCH_REMOVE_WITH_VALUE,
    /** Accept reviewed email type-selector upsert shapes. */
    PATCH_VALUE_PATH_UPSERT,
    /** Accept dotted or qualified keys in reviewed PATCH objects. */
    PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS,
    /** Rewrite a filtered suffix to a same-element predicate. */
    FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON,
    /** Infer registered extension declarations from present values. */
    INFER_MISSING_EXTENSION_SCHEMAS,
    /** Ignore unknown schema declarations without admitting unknown attributes. */
    IGNORE_UNDECLARED_SCHEMA_URIS,
    /** Accept an Enterprise manager string as its value object. */
    COMPLEX_VALUE_AS_SCALAR,
    /** Drop unknown attributes while preserving known-attribute rules. */
    IGNORE_UNKNOWN_ATTRIBUTES,
    /** Ignore an identical current id in reviewed no-path PATCH objects. */
    PATCH_READ_ONLY_ID_ECHO,
    /** Accept an exact registered extension schema URI as a whole-extension PATCH object target.
     * This profile is opt-in and is absent from the strict, Microsoft Entra ID and Okta presets. */
    PATCH_EXTENSION_SCHEMA_ROOT
}
