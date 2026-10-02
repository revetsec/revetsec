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

import java.security.Provider;
import java.security.Signature;
import java.security.GeneralSecurityException;
import org.jspecify.annotations.NonNull;

// Exact public signer path: reject both provider selection overloads, accept algorithm-only selection.
final class JwsSigner {
    private JwsSigner() {}
    static @NonNull Signature forbiddenName() throws GeneralSecurityException {
        return Signature.getInstance("SHA256withRSA", "SUN");
    }
    static @NonNull Signature forbiddenObject(@NonNull Provider provider) throws GeneralSecurityException {
        return Signature.getInstance("SHA256withRSA", provider);
    }
    static @NonNull Signature accepted() throws GeneralSecurityException {
        return Signature.getInstance("SHA256withRSA");
    }
}
