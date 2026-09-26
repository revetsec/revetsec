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

package com.revetsec.internal.json;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/**
 * The core JSON corpus under {@code src/test/resources/com/revetsec/internal/json/corpus/}: the 25 files ported from
 * Soklet at {@code 38786326} plus Revetsec's protocol-shaped seeds, with a SHA-256 manifest.
 * <p>
 * Tests read the source directory when they run from a checkout (so the manifest test checks exactly what is
 * committed, not a build copy), and otherwise the copy on the test class path.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class JsonCorpus {
	static final String MANIFEST = "manifest.sha256";

	private static final String RELATIVE_SOURCE = "src/test/resources/com/revetsec/internal/json/corpus";

	private JsonCorpus() {
	}

	/**
	 * The corpus directory.
	 */
	static Path root() {
		try {
			// target/test-classes -> target -> the module root.
			Path testClasses = Path.of(JsonCorpus.class.getProtectionDomain().getCodeSource().getLocation().toURI());
			Path moduleRoot = testClasses.getParent() == null ? null : testClasses.getParent().getParent();

			if (moduleRoot != null && Files.isDirectory(moduleRoot.resolve(RELATIVE_SOURCE)))
				return moduleRoot.resolve(RELATIVE_SOURCE);

			URL resource = JsonCorpus.class.getResource("corpus");

			if (resource == null)
				throw new IllegalStateException("The JSON corpus is not on the test class path");

			return Path.of(resource.toURI());
		} catch (URISyntaxException exception) {
			throw new IllegalStateException(exception);
		}
	}

	/**
	 * The bytes of a corpus file, by its path relative to the corpus root (such as {@code parse/array.json}).
	 */
	static byte[] read(String relativePath) {
		try {
			return Files.readAllBytes(root().resolve(relativePath));
		} catch (IOException exception) {
			throw new UncheckedIOException(exception);
		}
	}

	/**
	 * Every corpus file except the manifest, as sorted paths relative to the root with {@code /} separators.
	 */
	static List<String> files() {
		Path root = root();

		try (Stream<Path> paths = Files.walk(root)) {
			return paths.filter(Files::isRegularFile)
					.map(path -> root.relativize(path).toString().replace('\\', '/'))
					.filter(path -> !path.equals(MANIFEST))
					.sorted()
					.toList();
		} catch (IOException exception) {
			throw new UncheckedIOException(exception);
		}
	}
}
