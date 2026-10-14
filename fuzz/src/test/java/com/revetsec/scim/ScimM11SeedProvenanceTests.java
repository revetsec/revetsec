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
package com.revetsec.scim;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** The complete hand-authored SCIM corpus must match its explicit provenance and checksum manifest. */
final class ScimM11SeedProvenanceTests {
    @Test void everyScimSeedIsInventoriedWithItsExactBytes() throws Exception {
        Path root = Path.of(Objects.requireNonNull(System.getProperty("revetsec.core.basedir")))
                .resolve("fuzz/src/test/resources/com/revetsec/scim").toAbsolutePath().normalize();
        Assertions.assertTrue(Files.readString(root.resolve("SCIM-M11-SEEDS.md"), StandardCharsets.UTF_8)
                .contains("https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2"));
        Set<String> expected = new TreeSet<>();
        for (String line : Files.readAllLines(root.resolve("scim-m11-seeds.sha256"), StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] fields = line.split("  ", 2);
            Assertions.assertEquals(2, fields.length);
            String name = fields[1];
            Assertions.assertTrue(expected.add(name), "Duplicate seed manifest entry");
            Path file = root.resolve(name).normalize();
            Assertions.assertTrue(file.startsWith(root.resolve("ScimM11FuzzTestsInputs")));
            Assertions.assertEquals(fields[0], HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(Files.readAllBytes(file))), name);
        }
        Set<String> actual;
        try (Stream<Path> files = Files.walk(root.resolve("ScimM11FuzzTestsInputs"))) {
            actual = files.filter(Files::isRegularFile).map(root::relativize).map(Path::toString)
                    .collect(Collectors.toCollection(TreeSet::new));
        }
        Assertions.assertEquals(expected, actual);
        Assertions.assertTrue(actual.size() >= 29, "Primary examples and authored boundary cases remain represented");
    }
}
