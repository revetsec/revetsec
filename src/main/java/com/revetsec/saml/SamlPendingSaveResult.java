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

package com.revetsec.saml;

import javax.annotation.concurrent.Immutable;

/**
 * Storage provider outcomes when saving a pending login.
 *
 * @since 1.0.0
 */
@Immutable
public enum SamlPendingSaveResult {
    /** A new record was saved. */ SAVED,
    /** A live record already uses this binding and handle. */ ALREADY_PRESENT,
    /** Capacity does not permit another live record. */ CAPACITY_REFUSED,
    /** The store was unavailable before a mutation could occur. */ UNAVAILABLE,
    /** A mutation may have occurred; do not assume the record is present. */ INDETERMINATE
}
