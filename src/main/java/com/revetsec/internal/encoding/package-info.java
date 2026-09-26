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
 * Internal codecs: strict Base64 (base64url, standard and SAML POST), percent-encoding,
 * {@code application/x-www-form-urlencoded} and query parameters, and strict UTF-8. Every decoder rejects malformed
 * input with a checked {@link com.revetsec.internal.encoding.EncodingException} and never repairs or replaces it.
 * Inputs of hundreds of millions of characters, far beyond every R8 bound, fail instead with
 * {@link java.lang.ArithmeticException} where a length would pass {@link java.lang.Integer#MAX_VALUE}; each method
 * that can do so documents it.
 * <p>
 * <strong>Not API.</strong> This package is public only because other Revetsec packages need access to it.
 * Its types may change or disappear in any release without notice, are not covered by semantic versioning,
 * are excluded from the published Javadoc, and never appear in a public or protected signature of an
 * exported package.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.internal.encoding;

import org.jspecify.annotations.NullMarked;
