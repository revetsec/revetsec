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
package example.playground;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.jspecify.annotations.NonNull;

/** Local secret indirection. References are configuration; resolved values never reach views. */
final class LocalSecrets {
    private LocalSecrets() {}

    static @NonNull String resolve(@NonNull String reference) {
        return resolve(reference, System.getenv());
    }

    static @NonNull String resolve(@NonNull String reference,
            @NonNull Map<@NonNull String, @NonNull String> environment) {
        if (reference.length() > 512) throw new IllegalArgumentException("Secret reference is invalid.");
        String value;
        if (reference.startsWith("env:") && reference.substring(4).matches("[A-Z_][A-Z0-9_]{0,63}")) {
            value = environment.get(reference.substring(4));
        } else if (reference.startsWith("file:")) {
            try {
                Path path = Path.of(reference.substring(5));
                if (!path.isAbsolute() || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                        || Files.size(path) > 4096) throw new IllegalArgumentException("Secret file is invalid.");
                byte[] bytes;
                try (var input = Files.newInputStream(path)) { bytes = input.readNBytes(4097); }
                if (bytes.length > 4096) throw new IllegalArgumentException("Secret file is invalid.");
                value = new String(bytes, StandardCharsets.UTF_8).stripTrailing();
            } catch (IOException failure) {
                throw new IllegalArgumentException("Secret file is unavailable.");
            }
        } else {
            throw new IllegalArgumentException("Use an environment or absolute local file reference.");
        }
        if (value == null || value.isEmpty() || value.length() > 4096 || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Secret reference could not be resolved.");
        return value;
    }

    static byte @NonNull [] randomBytes() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    static @NonNull String randomId() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes());
    }
}
