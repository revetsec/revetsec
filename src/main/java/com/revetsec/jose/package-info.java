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
 * JSON Object Signing and Encryption: JWS signature verification, JSON Web Keys and key sets, and JWT claims
 * validation (RFC 7515, RFC 7517, RFC 7519).
 * <p>
 * {@link com.revetsec.jose.JwtValidator} validates tokens with keys from a
 * {@link com.revetsec.jose.StaticJsonWebKeySource} or a {@link com.revetsec.jose.RemoteJsonWebKeySource}.
 * <p>
 * It depends only on {@code com.revetsec.json} and the root package, apart from Revetsec's internal packages.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.jose;

import org.jspecify.annotations.NullMarked;
