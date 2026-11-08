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


package com.revetsec.testing;

/** Test-only read failures delivered after an actual authoritative snapshot was obtained. */
public enum StoreReadFaults {
 UNAVAILABLE, NULL, THROW, OMIT_ROOT, OMIT_ENTITY, EXTRA_ABSENCE, FOREIGN_SCOPE,
 WRONG_KIND, AUTHENTICATED_BAD_AUTHORITY, AUTHENTICATED_NEGATIVE_FLOOR, CORRUPT_ROOT,
 CORRUPT_ENTITY;
 public boolean appliesToRootOnly(){return this!=OMIT_ROOT&&this!=OMIT_ENTITY&&this!=CORRUPT_ENTITY;}
}
