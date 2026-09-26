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

/**
 * Revetsec's public, immutable JSON value model (RFC 8259), shared by the JOSE, OAuth, OpenID Connect and SCIM
 * packages: {@link com.revetsec.json.JsonValue} and its six permitted types.
 * <p>
 * There is no public parser. Values come from Revetsec's protocol types, or are built with the types' factories and
 * {@link com.revetsec.json.JsonObject#builder()}. {@link com.revetsec.json.JsonValue#toJson()} serializes a value,
 * and every {@code toString()} is redacted, so logging a value never shows its content.
 * <p>
 * It depends only on the root package, apart from Revetsec's internal packages.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.json;

import org.jspecify.annotations.NullMarked;
