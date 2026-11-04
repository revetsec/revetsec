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
package example.tools;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

final class DemoAccessKeysTests {
  @Test void createsPrivateRandomKeysAndRefusesOverwrite(@TempDir @NonNull Path directory) throws Exception {
    var first = directory.resolve("first");
    var second = directory.resolve("second");
    DemoAccessKeys.main(new String[] {first.toString(), second.toString()});
    String value = Files.readString(first);
    assertTrue(value.matches("[A-Za-z0-9_-]{43}"));
    assertEquals(32, Base64.getUrlDecoder().decode(value).length);
    assertNotEquals(value, Files.readString(second));
    assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(first));
    assertThrows(FileAlreadyExistsException.class,
      () -> DemoAccessKeys.main(new String[] {first.toString()}));
    assertEquals(value, Files.readString(first));
  }

  @Test void rejectsMissingAndRelativePaths() {
    assertThrows(IllegalArgumentException.class, () -> DemoAccessKeys.main(new String[0]));
    assertThrows(IllegalArgumentException.class,
      () -> DemoAccessKeys.main(new String[] {"relative-key"}));
  }
}
