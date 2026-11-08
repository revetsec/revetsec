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

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;

import javax.lang.model.element.Modifier;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Prints the exported public-type inventory used by the packaged-consumer guard.
 *
 * <p>The traversal intentionally mirrors {@code ContractSupport.exportedTypes}: every public top-level type in an
 * exported package, followed recursively by every public or protected member type. It uses javac's parsed source
 * model, so annotations, indentation and declaration line breaks cannot hide a type from the guard.</p>
 */
public final class ExportedTypeInventory {
	private static final Set<String> EXPORTED_PACKAGES = Set.of(
			"com.revetsec",
			"com.revetsec.json",
			"com.revetsec.jose",
			"com.revetsec.oauth",
			"com.revetsec.oauth.server",
			"com.revetsec.oidc",
			"com.revetsec.saml",
			"com.revetsec.scim",
			"com.revetsec.password",
			"com.revetsec.totp",
			"com.revetsec.webauthn");

	private ExportedTypeInventory() {
		// Entry point only.
	}

	public static void main(String[] arguments) throws IOException {
		if (arguments.length != 1)
			throw new IllegalArgumentException("usage: ExportedTypeInventory <source-root>");
		for (String type : inventory(Path.of(arguments[0])))
			System.out.println(type);
	}

	private static List<String> inventory(Path sourceRoot) throws IOException {
		List<Path> sources;
		try (Stream<Path> paths = Files.walk(sourceRoot)) {
			sources = paths.filter(path -> path.getFileName().toString().endsWith(".java"))
					.sorted().toList();
		}
		if (sources.isEmpty())
			throw new IllegalArgumentException("No Java sources under " + sourceRoot);

		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		if (compiler == null)
			throw new IllegalStateException("A full JDK is required (javax.tools.JavaCompiler is unavailable)");

		List<String> inventory = new ArrayList<>();
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
		try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT,
				StandardCharsets.UTF_8)) {
			JavacTask task = (JavacTask) compiler.getTask(null, fileManager, diagnostics,
					List.of("--release", "17", "-proc:none", "-implicit:none", "-Xlint:none"), null,
					fileManager.getJavaFileObjectsFromPaths(sources));
			for (CompilationUnitTree unit : task.parse()) {
				String packageName = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
				if (!EXPORTED_PACKAGES.contains(packageName))
					continue;
				for (Tree declaration : unit.getTypeDecls())
					if (declaration instanceof ClassTree type
							&& type.getModifiers().getFlags().contains(Modifier.PUBLIC))
						appendType(packageName, type, type.getSimpleName().toString(), inventory);
			}
		}
		List<String> errors = diagnostics.getDiagnostics().stream()
				.filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
				.map(Object::toString).toList();
		if (!errors.isEmpty())
			throw new IllegalArgumentException("Unable to parse sources under " + sourceRoot + ":\n"
					+ String.join("\n", errors));

		inventory.sort(Comparator.naturalOrder());
		return List.copyOf(inventory);
	}

	private static void appendType(String packageName, ClassTree type, String relativeName, List<String> inventory) {
		inventory.add(packageName + "\t" + relativeName);
		boolean membersAreImplicitlyPublic = type.getKind() == Tree.Kind.INTERFACE
				|| type.getKind() == Tree.Kind.ANNOTATION_TYPE;
		for (Tree member : type.getMembers()) {
			if (!(member instanceof ClassTree nested))
				continue;
			EnumSet<Modifier> accessibility = EnumSet.of(Modifier.PUBLIC, Modifier.PROTECTED);
			if (!membersAreImplicitlyPublic
					&& nested.getModifiers().getFlags().stream().noneMatch(accessibility::contains))
				continue;
			appendType(packageName, nested, relativeName + "." + nested.getSimpleName(), inventory);
		}
	}
}
