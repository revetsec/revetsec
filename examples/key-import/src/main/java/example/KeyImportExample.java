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

package example;

import com.revetsec.KeyImports;
import org.jspecify.annotations.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Arrays;

/** Java 17 public-API recipe: bounded application file loading and an explicit noncredential pair check. */
public final class KeyImportExample {
	private KeyImportExample() { }
	/**
	 * Checks an application-owned PKCS#8 private DER file against a separately supplied public SPKI DER file.
	 * @param arguments the two application-owned local file paths
	 * @throws IOException if a file cannot be read or exceeds the fixed import ceiling
	 */
	public static void main(@NonNull String @NonNull [] arguments) throws IOException {
		if (arguments.length != 2) throw new IllegalArgumentException("Supply private PKCS8 DER and public SPKI DER paths.");
		byte[] privateDer = readBounded(Path.of(arguments[0]));
		try {
			PrivateKey privateKey = KeyImports.privateKeyFromPkcs8Der(privateDer);
			PublicKey publicKey = KeyImports.publicKeyFromSpkiDer(readBounded(Path.of(arguments[1])));
			KeyImports.checkKeyPair(privateKey, publicKey, Duration.ofSeconds(2));
			System.out.println("Key pair checked.");
		} finally { Arrays.fill(privateDer, (byte) 0); }
	}
	private static byte @NonNull [] readBounded(@NonNull Path path) throws IOException {
		try (InputStream input = Files.newInputStream(path)) {
			byte[] bytes = input.readNBytes(65_537);
			if (bytes.length > 65_536) { Arrays.fill(bytes, (byte) 0); throw new IOException("Key import file exceeds its size limit."); }
			return bytes;
		}
	}
}
