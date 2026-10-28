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

package com.revetsec.internal.password;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class BcryptVendoredSourceTests {
    private static final String ORIGINAL_SHA256 =
            "c05d267ceef5faa04380006075b9067939e03d526a2d9f4987bbf22a7a6ff7be";

    @Test void onlyPackageDeclarationDiffersFromPinnedSpringSecurity6511Source() throws Exception {
        String vendor = Files.readString(Path.of(
                "src/main/java/com/revetsec/internal/password/vendor/spring/BCrypt.java"));
        String upstream = vendor.replace("package com.revetsec.internal.password.vendor.spring;",
                "package org.springframework.security.crypto.bcrypt;");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(upstream.getBytes(StandardCharsets.UTF_8));
        assertEquals(ORIGINAL_SHA256, HexFormat.of().formatHex(digest));
    }
}
