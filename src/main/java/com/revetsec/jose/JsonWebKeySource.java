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

package com.revetsec.jose;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Where a validator gets the public keys that verify token signatures: a fixed key set
 * ({@link StaticJsonWebKeySource}) or one fetched from a URI and kept up to date ({@link RemoteJsonWebKeySource}).
 * <p>
 * A source holds no issuer. Share one only among validators that expect the same issuer, because every key in it is
 * trusted for any token those validators check.
 * <p>
 * The list of permitted implementations is not switch-stable: a later release may add one, so a {@code switch} over
 * a source needs a default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public sealed interface JsonWebKeySource permits StaticJsonWebKeySource, RemoteJsonWebKeySource {
}
