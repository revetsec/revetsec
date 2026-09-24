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

import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Path;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * A minimal application that consumes the packaged RevetSec JAR.
 * <p>
 * Until M1 the JAR holds only {@code package-info} classes, so there is no public type to call yet. This class
 * checks what any consumer can observe: the root package is on the class path and comes from a JAR, that JAR
 * declares {@code Automatic-Module-Name: com.revetsec}, and the module system resolves it under that name. From M1
 * this class also calls the public API, so the build proves a consumer compiles against the packaged artifact.
 * <p>
 * The first argument, if present, is the path of the JAR the caller expects the root package to come from.
 */
public final class PackagedConsumer {
	private static final String MODULE_NAME = "com.revetsec";
	private static final String ROOT_PACKAGE_INFO_CLASS = "com.revetsec.package-info";
	private static final String ROOT_PACKAGE_INFO_RESOURCE = "com/revetsec/package-info.class";

	private PackagedConsumer() {
		// Entry point only.
	}

	public static void main(String[] arguments) throws Exception {
		ClassLoader classLoader = PackagedConsumer.class.getClassLoader();
		URL resource = classLoader.getResource(ROOT_PACKAGE_INFO_RESOURCE);

		if (resource == null)
			throw new IllegalStateException(ROOT_PACKAGE_INFO_RESOURCE + " is not on the class path");

		URLConnection connection = resource.openConnection();

		if (!(connection instanceof JarURLConnection))
			throw new IllegalStateException(ROOT_PACKAGE_INFO_RESOURCE + " must come from a JAR, found " + resource);

		connection.setUseCaches(false);
		Path jar = Path.of(((JarURLConnection) connection).getJarFileURL().toURI()).toRealPath();

		if (arguments.length > 0) {
			Path expectedJar = Path.of(arguments[0]).toRealPath();

			if (!expectedJar.equals(jar))
				throw new IllegalStateException("Root package came from " + jar + ", expected " + expectedJar);
		}

		String automaticModuleName;

		try (JarFile jarFile = new JarFile(jar.toFile())) {
			Manifest manifest = jarFile.getManifest();
			automaticModuleName = manifest == null ? null : manifest.getMainAttributes().getValue("Automatic-Module-Name");
		}

		if (!MODULE_NAME.equals(automaticModuleName))
			throw new IllegalStateException("Automatic-Module-Name is " + automaticModuleName + ", expected " + MODULE_NAME);

		ModuleReference moduleReference = ModuleFinder.of(jar).find(MODULE_NAME)
				.orElseThrow(() -> new IllegalStateException("The module system does not resolve " + MODULE_NAME + " from " + jar));
		ModuleDescriptor descriptor = moduleReference.descriptor();

		if (!descriptor.isAutomatic())
			throw new IllegalStateException(MODULE_NAME + " must be an automatic module; the plan uses Automatic-Module-Name");

		// Load, without initializing, the root package-info class to prove this runtime accepts the class file.
		Class<?> packageInfo = Class.forName(ROOT_PACKAGE_INFO_CLASS, false, classLoader);

		System.out.println("jar=" + jar);
		System.out.println("automatic-module-name=" + automaticModuleName);
		System.out.println("root-package-info=" + packageInfo.getName());
		System.out.println("packages=" + String.join(",", new TreeSet<>(descriptor.packages())));
		System.out.println("runtime=" + Runtime.version());
	}
}
