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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Source identity and Java-method mapping for the pinned Argon2 C reference translation. */
final class Argon2VendoredSourceTests {
    private static final String RESOURCE_ROOT = "/vectors/argon2-reference-20190702/";
    private static final Map<String, String> FILE_HASHES = Map.of(
        "src/argon2.c", "72a93deebc5fd76bec0c6d300a2d92b500fb354b26babbddbc6d8b88681e663d",
        "src/ref.c", "4ec47b080c22f4ee416b9dbcfae70ee6007fcfba427f870d7b84395846fa1bc7",
        "src/core.c", "0f53eb2370f8971f04fcf043b8083bf81d1530c48b2ead71c0b6c4e22a01aeec",
        "src/core.h", "c9665623cb3d306f63b6a3effd87bcfab971c28253c77e111445e42c1523235e",
        "src/blake2/blake2b.c", "52519ccbc1e48f489ff444091f630d05dadcc8f1ee61c5b7361e3a9618299c9a",
        "src/blake2/blamka-round-ref.h", "bcfdcf785218cf897f05b144e80b659e611188fee3887d533bdcb7a6aa4c336b",
        "src/blake2/blake2-impl.h", "8ac91f1f57d94235f8de0069b7809be1deb365c3b37adb8e30423cd364aff09a",
        "include/argon2.h", "df20cb726a2fe6bccc736b81ea0d86219766a0d17f1794c19e048a34830ca1cc",
        "LICENSE", "220f8736a89ff51c92ef3d497f413b48e6cf1df3d6278bc909c6308c78e1718e");

    @Test
    void referenceFilesAndManifestAreExactlyPinned() throws IOException, NoSuchAlgorithmException {
        String sourceManifest = readResource("SOURCE.txt");
        Assertions.assertTrue(sourceManifest.contains("62358ba2123abd17fccf2a108a301d4b52c01a7c"));
        Assertions.assertTrue(sourceManifest.contains("daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c"));
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (Map.Entry<String, String> file : FILE_HASHES.entrySet()) {
            byte[] original = readResourceBytes(file.getKey());
            Assertions.assertEquals(file.getValue(), HexFormat.of().formatHex(sha256.digest(original)), file.getKey());
            Assertions.assertTrue(sourceManifest.contains(file.getValue() + "  " + file.getKey()));
        }
    }

    @Test
    void provenanceMapsEveryTranslatedPrimitiveToPinnedSource() throws IOException {
        String provenance = Files.readString(Path.of("docs/password-vendored-source.md"), StandardCharsets.UTF_8);
        for (String file : FILE_HASHES.keySet())
            if (!file.equals("LICENSE")) Assertions.assertTrue(provenance.contains(file), file);
        Assertions.assertTrue(provenance.contains("JAVA-MAP.tsv"));
        Map<String, String> mapping = new HashMap<>();
        for (String line : readResource("JAVA-MAP.tsv").lines().toList()) {
            if (line.startsWith("#") || line.isBlank()) continue;
            String[] columns = line.split("\\t", -1);
            Assertions.assertEquals(2, columns.length, line);
            Assertions.assertNull(mapping.putIfAbsent(columns[0], columns[1]), columns[0]);
            String[] source = columns[1].split("#", -1);
            Assertions.assertEquals(2, source.length, columns[1]);
            Assertions.assertTrue(FILE_HASHES.containsKey(source[0]), columns[1]);
            Assertions.assertTrue(readResource(source[0]).contains(source[1]), columns[1]);
        }
        Set<String> methods = new HashSet<>();
        collectMethods(Argon2id.class, methods);
        collectMethods(Blake2b.class, methods);
        Assertions.assertEquals(methods, mapping.keySet(),
            "Every Java method, including nested block/state adaptations, must map to a pinned C operation");
    }

    private static void collectMethods(@NonNull Class<?> type, @NonNull Set<@NonNull String> methods) {
        String name = type.getName().substring(type.getName().lastIndexOf('.') + 1).replace('$', '.');
        for (Method method : type.getDeclaredMethods()) {
            if (!method.isSynthetic())
                methods.add(name + "." + method.getName() + "/" + method.getParameterCount());
        }
        for (Class<?> nested : type.getDeclaredClasses()) collectMethods(nested, methods);
    }

    private static @NonNull String readResource(@NonNull String path) throws IOException {
        return new String(readResourceBytes(path), StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] readResourceBytes(@NonNull String path) throws IOException {
        try (InputStream in = Argon2VendoredSourceTests.class.getResourceAsStream(RESOURCE_ROOT + path)) {
            Assertions.assertNotNull(in, path);
            return in.readAllBytes();
        }
    }
}
