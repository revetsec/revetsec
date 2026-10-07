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

package verification.store;

import org.jspecify.annotations.NonNull;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Application-owned one-host admission demonstration. The trusted operator keeps this file outside restore.
 * This check does not drain in-flight requests or implement a distributed lease/network fence. */
final class DeploymentGate {
    private final @NonNull Path path;
    private final @NonNull String generation;
    DeploymentGate(@NonNull Path path,@NonNull String generation) {
        this.path=path;this.generation=generation;
        if (!generation.matches("[A-Za-z0-9_-]{43}") || !Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Base64.getUrlDecoder().decode(generation)).equals(generation))
            throw new IllegalArgumentException("Invalid deployment generation");
    }
    boolean isOpen() {
        try {
            if(Files.isSymbolicLink(this.path))return false;
            byte[] bytes;
            try(var in=Files.newInputStream(this.path)){bytes=in.readNBytes(129);}
            return bytes.length<=128 && new String(bytes,StandardCharsets.US_ASCII).equals("LIVE "+this.generation+"\n");
        } catch(java.io.IOException | SecurityException e){return false;}
    }
}
