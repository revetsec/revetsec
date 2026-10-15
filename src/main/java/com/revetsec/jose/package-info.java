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
 * JSON Object Signing and Encryption: JWS signature verification and bounded RSA signing, JSON Web Keys and key sets, and JWT claims
 * validation (RFC 7515, RFC 7517, RFC 7519).
 * <p>
 * {@link com.revetsec.jose.JwtValidator} validates tokens with keys from a
 * {@link com.revetsec.jose.StaticJwksSource} or a {@link com.revetsec.jose.RemoteJwksSource}.
 * <p>
 * {@link com.revetsec.jose.JwsSigner} signs a typed {@link com.revetsec.jose.JwtSigningHeader} and
 * {@link com.revetsec.jose.JwtClaimsSet} with an application-owned RSA private key. Its
 * {@code fromHeaderAndClaims} method immediately releases a signed compact JWT with the default two-second
 * operation budget; {@code withHeaderAndClaims} provides optional configuration and signs only when its
 * builder's {@code build()} is called. The signer selects the algorithm and verifies every output against its
 * checked public projection before releasing a credential. The exact-byte signing API remains available.
 * Issuance claims are separate from validated {@link com.revetsec.jose.JwtClaims}; signing does not validate
 * claim meaning or grant permission.
 * <p>
 * Standalone public-key publication uses {@link com.revetsec.jose.PublishedJwk} and
 * {@link com.revetsec.jose.JwksPublisher}. It supports RSA, EC and Ed25519 verification keys, optional
 * certificate chains, and prepared GET/HEAD responses without configuring an OAuth authorization server.
 * <p>
 * It depends only on {@code com.revetsec.json} and the root package, apart from Revetsec's internal packages.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.jose;

import org.jspecify.annotations.NullMarked;
