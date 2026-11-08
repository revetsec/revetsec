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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Verification-only actual origin check; loads without class initialization or private access. */
public final class RuntimeOrigins {
    private RuntimeOrigins() { }
    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args.length % 4 != 0) throw new IllegalArgumentException("Origin arguments");
        for (int i = 0; i < args.length; i += 4) {
            Class<?> type = Class.forName(args[i + 1], false, ClassLoader.getSystemClassLoader());
            Path actual = Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
            Path expected = Path.of(args[i + 2]).toRealPath();
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)));
            if (!actual.equals(expected) || !hash.equals(args[i + 3])) throw new AssertionError("Selected origin mismatch");
            System.out.println(args[i] + "\t" + type.getName() + "\t" + hash);
        }
    }
}
