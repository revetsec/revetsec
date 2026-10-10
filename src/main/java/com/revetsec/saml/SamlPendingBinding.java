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

import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Binds one sealed pending record to a browser secret and store mode. */
final class SamlPendingBinding {
    private SamlPendingBinding() { }

    static @NonNull String context(@NonNull String applicationContext, @NonNull String browserBinding) {
        if (applicationContext.isEmpty() || browserBinding.isEmpty() || browserBinding.length() > 4096)
            throw new IllegalArgumentException("Invalid SAML pending context or browser binding");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(browserBinding.getBytes(StandardCharsets.UTF_8));
            return applicationContext + "|saml-store-v1|"
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
