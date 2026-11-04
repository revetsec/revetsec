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
import javax.annotation.concurrent.ThreadSafe;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/**
 * Creates new private POSIX files for the applications' disposable demo access keys.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class DemoAccessKeys {
  private DemoAccessKeys() { }

  /**
   * Writes one fresh demo key to each new absolute file without printing its contents.
   *
   * @param filenames new absolute paths with existing private POSIX parent directories
   * @throws Exception if a path cannot be created with private permissions
   * @since 1.0.0
   */
  public static void main(@NonNull String @NonNull [] filenames) throws Exception {
    if (filenames.length == 0) throw new IllegalArgumentException("Supply new absolute key-file paths");
    var random = new SecureRandom();
    for (String filename : filenames) {
      Path path = Path.of(filename);
      if (!path.isAbsolute()) throw new IllegalArgumentException("Key-file paths must be absolute");
      byte[] secret = new byte[32];
      random.nextBytes(secret);
      byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(secret);
      try (var file = Files.newByteChannel(path,
          Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
        var buffer = ByteBuffer.wrap(encoded);
        while (buffer.hasRemaining()) file.write(buffer);
      } finally {
        Arrays.fill(secret, (byte) 0);
        Arrays.fill(encoded, (byte) 0);
      }
    }
    System.out.println("Created private demo access-key files; contents are not printed.");
  }
}
