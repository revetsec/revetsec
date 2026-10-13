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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

/**
 * Fixed SCIM error types and their wire spellings.
 *
 * @since 1.0.0
 */
@Immutable
public enum ScimErrorType {
    /** A filter is malformed or unsupported. */ INVALID_FILTER("invalidFilter"),
    /** A request would return too many results. */ TOO_MANY("tooMany"),
    /** An advertised uniqueness requirement was violated. */ UNIQUENESS("uniqueness"),
    /** An attribute's mutability restriction was violated. */ MUTABILITY("mutability"),
    /** A request's structure or syntax is invalid. */ INVALID_SYNTAX("invalidSyntax"),
    /** An attribute path is malformed or unsupported. */ INVALID_PATH("invalidPath"),
    /** A PATCH selector has no target. */ NO_TARGET("noTarget"),
    /** A supplied value is invalid. */ INVALID_VALUE("invalidValue"),
    /** A SCIM version is invalid. */ INVALID_VERSION("invalidVers"),
    /** A sensitive operation is forbidden. */ SENSITIVE("sensitive"),
    /** A pagination cursor is invalid. */ INVALID_CURSOR("invalidCursor"),
    /** A pagination cursor has expired. */ EXPIRED_CURSOR("expiredCursor"),
    /** A requested cursor page count is invalid. */ INVALID_COUNT("invalidCount");

    private final @NonNull String value;

    ScimErrorType(@NonNull String value) {
        this.value = value;
    }

    /**
     * Returns the fixed value of the SCIM {@code scimType} field.
     *
     * @return the wire spelling
     * @since 1.0.0
     */
    public @NonNull String getValue() {
        return value;
    }
}
