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

package com.revetsec;

import org.jspecify.annotations.NonNull;

import com.revetsec.ContractSupport.SourceAnalysis;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.ImportTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePathScanner;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.TypeParameterElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.IntersectionType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.WildcardType;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Enforces Revetsec's package dependency graph (plan 6 and the M0 plan).
 * <p>
 * Dependencies come from import declarations and from every resolved type or member reference in the code, so
 * fully qualified names count too. The rules:
 * <ul>
 *   <li>Each exported package depends only on the packages {@link #ALLOWED_DEPENDENCIES} lists for it.</li>
 *   <li>Each internal package belongs to the exported package it serves ({@link #INTERNAL_PACKAGE_LAYERS}), and
 *   is held to that package's rules in both directions: {@code saml} cannot reach {@code internal.jose}, and
 *   {@code internal.json} cannot reach {@code jose}. Extracting a protocol later stays mechanical.</li>
 *   <li>{@code internal.xml} is used only by {@code saml}, {@code internal.oauth} only by {@code oauth} and
 *   {@code oidc}, and {@code internal.http} only by {@code jose}, {@code oauth}, {@code oidc} and
 *   {@code internal.oauth} ({@link #RESTRICTED_INTERNAL_PACKAGES}), so the HTTP helper stays out of {@code saml},
 *   {@code scim}, {@code json}, the root package and every other internal package, {@code internal.jose}
 *   included.</li>
 *   <li>Every package is in the graph and has a {@code package-info.java} annotated {@code @NullMarked}.</li>
 *   <li>No public or protected signature of an exported type mentions a {@code com.revetsec.internal} type: not
 *   a supertype at any depth (reached through a package-private class, say), not a member it declares or inherits
 *   from a non-exported Revetsec class, and not an internal annotation that is {@code @Documented} or
 *   runtime-retained on the type, its members or their parameters.</li>
 * </ul>
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PackageDependencyTests {
	private static final String ROOT = "com.revetsec";
	private static final String JSON = "com.revetsec.json";
	private static final String JOSE = "com.revetsec.jose";
	private static final String OAUTH = "com.revetsec.oauth";
	private static final String SERVER = "com.revetsec.oauth.server";
	private static final String OIDC = "com.revetsec.oidc";
	private static final String SAML = "com.revetsec.saml";
	private static final String SCIM = "com.revetsec.scim";
	private static final String INTERNAL = "com.revetsec.internal";
	private static final String NULL_MARKED = "org.jspecify.annotations.NullMarked";

	/**
	 * The allowed dependency DAG among exported packages (plan 6). A package may always use itself.
	 */
	static final Map<String, Set<String>> ALLOWED_DEPENDENCIES = Map.of(
			ROOT, Set.of(),
			JSON, Set.of(ROOT),
			JOSE, Set.of(JSON, ROOT),
			OAUTH, Set.of(JOSE, JSON, ROOT),
			SERVER, Set.of(OAUTH, JOSE, JSON, ROOT),
			OIDC, Set.of(OAUTH, JOSE, JSON, ROOT),
			SAML, Set.of(ROOT),
			SCIM, Set.of(JSON, ROOT));

	/**
	 * The exported package each internal package serves. An internal package follows its owner's rules.
	 */
	static final Map<String, String> INTERNAL_PACKAGE_LAYERS = Map.of(
			INTERNAL, ROOT,
			INTERNAL + ".encoding", ROOT,
			INTERNAL + ".crypto", ROOT,
			INTERNAL + ".pem", ROOT,
			INTERNAL + ".http", ROOT,
			INTERNAL + ".json", JSON,
			INTERNAL + ".jose", JOSE,
			INTERNAL + ".oauth", OAUTH,
			INTERNAL + ".xml", SAML);

	/**
	 * Internal packages that only the listed packages may use (besides themselves). The check matches the importing
	 * package by name, not by layer, so an internal package that may use a restricted one is listed in its own right.
	 * <p>
	 * {@code internal.http} is for the protocols that fetch over the network: JWKS (jose), token, introspection and
	 * revocation endpoints (oauth), and discovery and UserInfo (oidc), and issuer ingress/deadline checks ({@code oauth.server}), and for {@code internal.oauth}, where that
	 * fetching code may live (M1 plan, "Contract-list changes" item 3). Its layer is the root package, which every
	 * package may use, so without this row {@code saml}, {@code scim} and {@code json} could reach it too.
	 * {@code internal.jose} is not listed: it holds only pure, I/O-free JOSE code, and the JWKS fetch and its cache
	 * live in {@code jose}, next to {@code RemoteJsonWebKeySource} (G8-11). The row bans only this package; other I/O is
	 * left to review.
	 */
	static final Map<String, Set<String>> RESTRICTED_INTERNAL_PACKAGES = Map.of(
			INTERNAL + ".xml", Set.of(SAML),
			INTERNAL + ".oauth", Set.of(OAUTH, OIDC),
			INTERNAL + ".http", Set.of(JOSE, OAUTH, OIDC, SERVER, INTERNAL + ".oauth"));

	@Test
	void mainSourcesRespectPackageDependencyRules() throws IOException {
		ContractSupport.assertNoViolations("Package dependency violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java")));
	}

	@Test
	void allowedDependencyGraphIsAcyclicAndClosed() {
		for (Map.Entry<String, Set<String>> entry : ALLOWED_DEPENDENCIES.entrySet())
			for (String dependency : entry.getValue())
				Assertions.assertTrue(ALLOWED_DEPENDENCIES.containsKey(dependency),
						() -> entry.getKey() + " depends on unknown package " + dependency);
		for (String layer : INTERNAL_PACKAGE_LAYERS.values())
			Assertions.assertTrue(ALLOWED_DEPENDENCIES.containsKey(layer), () -> "Unknown layer " + layer);

		for (String packageName : ALLOWED_DEPENDENCIES.keySet())
			assertAcyclic(packageName, new ArrayList<>());
	}

	private static void assertAcyclic(@NonNull String packageName, @NonNull List<@NonNull String> path) {
		Assertions.assertFalse(path.contains(packageName), () -> "Dependency cycle: " + path + " -> " + packageName);
		path.add(packageName);
		for (String dependency : ALLOWED_DEPENDENCIES.getOrDefault(packageName, Set.of()))
			assertAcyclic(dependency, path);
		path.remove(path.size() - 1);
	}

	/**
	 * Checks the Java sources under {@code sourceRoot} and returns one message per violation (empty if none).
	 */
	static @NonNull List<@NonNull String> findViolations(@NonNull Path sourceRoot) throws IOException {
		if (ContractSupport.javaSources(sourceRoot).isEmpty())
			return List.of();
		return ContractSupport.analyze(sourceRoot, PackageDependencyTests::findViolations);
	}

	private static @NonNull List<@NonNull String> findViolations(@NonNull SourceAnalysis analysis) {
		Set<String> violations = new TreeSet<>();
		Set<String> declaredPackages = new TreeSet<>();
		Set<String> packagesWithPackageInfo = new HashSet<>();

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			String packageName = ContractSupport.packageName(compilationUnit);
			declaredPackages.add(packageName);
			if (ContractSupport.fileName(Path.of(compilationUnit.getSourceFile().toUri())).equals("package-info.java"))
				packagesWithPackageInfo.add(packageName);
		}

		for (String packageName : declaredPackages) {
			if (layerOf(packageName) == null)
				violations.add(packageName + ": package is not in the package dependency graph; add it to "
						+ "PackageDependencyTests deliberately");
			if (!packagesWithPackageInfo.contains(packageName)) {
				violations.add(packageName + ": package has no package-info.java (R20)");
			} else {
				@Nullable PackageElement packageElement = analysis.getElements().getPackageElement(packageName);
				boolean nullMarked = packageElement != null && packageElement.getAnnotationMirrors().stream()
						.anyMatch(annotation -> annotation.getAnnotationType().toString().equals(NULL_MARKED));
				if (!nullMarked)
					violations.add(packageName + ": package-info.java is not annotated @NullMarked (R2)");
			}
		}

		Set<String> knownPackages = new HashSet<>(declaredPackages);
		knownPackages.addAll(ALLOWED_DEPENDENCIES.keySet());
		knownPackages.addAll(INTERNAL_PACKAGE_LAYERS.keySet());

		for (Map.Entry<String, Map<String, String>> source : dependencies(analysis, knownPackages).entrySet())
			for (Map.Entry<String, String> target : source.getValue().entrySet())
				checkDependency(source.getKey(), target.getKey(), target.getValue(), violations);

		List<TypeElement> exportedTypes = ContractSupport.exportedTypes(analysis);
		Set<TypeElement> exported = new HashSet<>(exportedTypes);
		for (TypeElement type : exportedTypes)
			checkSignatures(type, exported, analysis, violations);

		return List.copyOf(violations);
	}

	private static void checkDependency(@NonNull String source, @NonNull String target, @NonNull String location, @NonNull Set<@NonNull String> violations) {
		@Nullable Set<String> restrictedTo = RESTRICTED_INTERNAL_PACKAGES.get(target);
		if (restrictedTo != null && !restrictedTo.contains(source))
			violations.add(source + " uses " + target + " (" + location + "): " + target + " may be used only by "
					+ new TreeSet<>(restrictedTo));

		@Nullable String sourceLayer = layerOf(source);
		@Nullable String targetLayer = layerOf(target);
		if (sourceLayer == null || targetLayer == null || sourceLayer.equals(targetLayer))
			return;
		Set<String> allowed = ALLOWED_DEPENDENCIES.getOrDefault(sourceLayer, Set.of());
		if (!allowed.contains(targetLayer))
			violations.add(source + " uses " + target + " (" + location + "): " + describe(source, sourceLayer)
					+ " may depend only on " + (allowed.isEmpty() ? "nothing else" : new TreeSet<>(allowed))
					+ ", not on " + describe(target, targetLayer));
	}

	private static @NonNull String describe(@NonNull String packageName, @NonNull String layer) {
		return packageName.equals(layer) ? packageName : packageName + " (part of " + layer + ")";
	}

	private static @Nullable String layerOf(@NonNull String packageName) {
		if (ALLOWED_DEPENDENCIES.containsKey(packageName))
			return packageName;
		return INTERNAL_PACKAGE_LAYERS.get(packageName);
	}

	/**
	 * Source package to target package to the first location (file:line) of that dependency.
	 */
	private static @NonNull Map<@NonNull String, @NonNull Map<@NonNull String, @NonNull String>> dependencies(@NonNull SourceAnalysis analysis, @NonNull Set<@NonNull String> knownPackages) {
		Map<String, Map<String, String>> dependencies = new TreeMap<>();

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			String source = ContractSupport.packageName(compilationUnit);
			Map<String, String> targets = dependencies.computeIfAbsent(source, ignored -> new TreeMap<>());

			new TreePathScanner<Void, Void>() {
				@Override
				public @Nullable Void visitImport(@NonNull ImportTree node, @Nullable Void unused) {
					String name = node.getQualifiedIdentifier().toString();
					if (name.endsWith(".*"))
						name = name.substring(0, name.length() - 2);
					record(owningPackage(name, knownPackages), node);
					return null;
				}

				@Override
				public @Nullable Void visitIdentifier(@NonNull IdentifierTree node, @Nullable Void unused) {
					recordReference(node);
					return super.visitIdentifier(node, null);
				}

				@Override
				public @Nullable Void visitMemberSelect(@NonNull MemberSelectTree node, @Nullable Void unused) {
					recordReference(node);
					return super.visitMemberSelect(node, null);
				}

				private void recordReference(@NonNull Tree node) {
					@Nullable Element element = analysis.getTrees().getElement(getCurrentPath());
					if (element == null || element.getKind() == ElementKind.PACKAGE)
						return;
					record(analysis.getElements().getPackageOf(element).getQualifiedName().toString(), node);
				}

				private void record(@Nullable String target, @NonNull Tree node) {
					if (target == null || target.equals(source) || !isRevetsecPackage(target))
						return;
					targets.putIfAbsent(target, analysis.location(compilationUnit, node));
				}
			}.scan(compilationUnit, null);
		}

		return dependencies;
	}

	private static boolean isRevetsecPackage(@NonNull String packageName) {
		return packageName.equals(ROOT) || packageName.startsWith(ROOT + ".");
	}

	private static @Nullable String owningPackage(@NonNull String qualifiedName, @NonNull Set<@NonNull String> knownPackages) {
		@Nullable String best = null;
		for (String candidate : knownPackages)
			if ((qualifiedName.equals(candidate) || qualifiedName.startsWith(candidate + "."))
					&& (best == null || candidate.length() > best.length()))
				best = candidate;
		return best;
	}

	/**
	 * No public or protected signature of an exported type may mention an internal type.
	 */
	private static void checkSignatures(@NonNull TypeElement type, @NonNull Set<@NonNull TypeElement> exported, @NonNull SourceAnalysis analysis,
			@NonNull Set<@NonNull String> violations) {
		String typeName = analysis.getElements().getBinaryName(type).toString();
		Map<String, TypeMirror> signatureTypes = new LinkedHashMap<>();
		Map<String, Element> annotatedElements = new LinkedHashMap<>();
		annotatedElements.put("", type);

		for (TypeMirror supertype : allSupertypes(type, analysis))
			signatureTypes.put("supertype " + analysis.erasedName(supertype), supertype);
		for (TypeParameterElement typeParameter : type.getTypeParameters())
			for (TypeMirror bound : typeParameter.getBounds())
				signatureTypes.put("type parameter " + typeParameter + " bound", bound);
		for (TypeMirror permitted : type.getPermittedSubclasses())
			signatureTypes.put("permitted subclass " + analysis.erasedName(permitted), permitted);

		for (Element member : analysis.getElements().getAllMembers(type)) {
			if (member instanceof TypeElement || !ContractSupport.isPublicOrProtected(member)
					|| !(member.getEnclosingElement() instanceof TypeElement declaringType))
				continue;
			boolean inherited = !declaringType.equals(type);
			if (inherited && (exported.contains(declaringType) || !analysis.isAnalyzed(declaringType)))
				continue;
			String name = "#" + analysis.describe(member) + (inherited ? " (inherited from "
					+ analysis.getElements().getBinaryName(declaringType) + ")" : "");
			annotatedElements.put(name, member);
			if (member.getKind() == ElementKind.FIELD || member.getKind() == ElementKind.ENUM_CONSTANT)
				signatureTypes.put(name + " type", member.asType());
			if (member instanceof ExecutableElement executable) {
				signatureTypes.put(name + " return type", executable.getReturnType());
				for (int index = 0; index < executable.getParameters().size(); ++index) {
					signatureTypes.put(name + " parameter " + index, executable.getParameters().get(index).asType());
					annotatedElements.put(name + " parameter " + index, executable.getParameters().get(index));
				}
				for (TypeMirror thrown : executable.getThrownTypes())
					signatureTypes.put(name + " throws " + analysis.erasedName(thrown), thrown);
				for (TypeParameterElement typeParameter : executable.getTypeParameters())
					for (TypeMirror bound : typeParameter.getBounds())
						signatureTypes.put(name + " type parameter " + typeParameter + " bound", bound);
			}
		}

		for (Map.Entry<String, TypeMirror> entry : signatureTypes.entrySet()) {
			Set<String> internalTypes = new TreeSet<>();
			collectInternalTypes(entry.getValue(), analysis, internalTypes);
			for (String internalType : internalTypes)
				violations.add(typeName + " " + entry.getKey() + ": exported signature mentions internal type "
						+ internalType + " (plan 6)");
		}

		for (Map.Entry<String, Element> entry : annotatedElements.entrySet())
			for (AnnotationMirror annotation : entry.getValue().getAnnotationMirrors()) {
				TypeElement annotationType = (TypeElement) annotation.getAnnotationType().asElement();
				if (isInternal(analysis.getElements().getPackageOf(annotationType).getQualifiedName().toString())
						&& isPublishedAnnotation(annotationType))
					violations.add(typeName + (entry.getKey().isEmpty() ? "" : " " + entry.getKey())
							+ ": exported API carries the internal annotation @" + annotationType.getQualifiedName()
							+ ", which is @Documented or runtime-retained (plan 6)");
			}
	}

	/**
	 * Every supertype of {@code type}, direct or indirect, with type arguments as {@code type} sees them.
	 */
	private static @NonNull List<@NonNull TypeMirror> allSupertypes(@NonNull TypeElement type, @NonNull SourceAnalysis analysis) {
		Map<String, TypeMirror> supertypes = new LinkedHashMap<>();
		Deque<TypeMirror> pending = new ArrayDeque<>(analysis.getTypes().directSupertypes(type.asType()));
		while (!pending.isEmpty()) {
			TypeMirror supertype = pending.removeFirst();
			if (supertypes.putIfAbsent(analysis.erasedName(supertype), supertype) == null)
				pending.addAll(analysis.getTypes().directSupertypes(supertype));
		}
		return List.copyOf(supertypes.values());
	}

	/**
	 * An annotation appears in the published API when javadoc shows it ({@code @Documented}) or reflection sees it
	 * ({@code @Retention(RUNTIME)}).
	 */
	private static boolean isPublishedAnnotation(@NonNull TypeElement annotationType) {
		for (AnnotationMirror metaAnnotation : annotationType.getAnnotationMirrors()) {
			String name = ((TypeElement) metaAnnotation.getAnnotationType().asElement()).getQualifiedName().toString();
			if (name.equals("java.lang.annotation.Documented"))
				return true;
			if (name.equals("java.lang.annotation.Retention"))
				for (AnnotationValue value : metaAnnotation.getElementValues().values())
					if (value.getValue() instanceof VariableElement constant
							&& constant.getSimpleName().contentEquals("RUNTIME"))
						return true;
		}
		return false;
	}

	private static boolean isInternal(@NonNull String packageName) {
		return packageName.equals(INTERNAL) || packageName.startsWith(INTERNAL + ".");
	}

	private static void collectInternalTypes(@NonNull TypeMirror type, @NonNull SourceAnalysis analysis, @NonNull Set<@NonNull String> internalTypes) {
		if (type instanceof DeclaredType declaredType) {
			Element element = declaredType.asElement();
			String packageName = analysis.getElements().getPackageOf(element).getQualifiedName().toString();
			if (isInternal(packageName))
				internalTypes.add(((TypeElement) element).getQualifiedName().toString());
			TypeMirror enclosingType = declaredType.getEnclosingType();
			if (enclosingType.getKind() == TypeKind.DECLARED)
				collectInternalTypes(enclosingType, analysis, internalTypes);
			for (TypeMirror argument : declaredType.getTypeArguments())
				collectInternalTypes(argument, analysis, internalTypes);
		} else if (type instanceof ArrayType arrayType) {
			collectInternalTypes(arrayType.getComponentType(), analysis, internalTypes);
		} else if (type instanceof WildcardType wildcardType) {
			@Nullable TypeMirror extendsBound = wildcardType.getExtendsBound();
			if (extendsBound != null)
				collectInternalTypes(extendsBound, analysis, internalTypes);
			@Nullable TypeMirror superBound = wildcardType.getSuperBound();
			if (superBound != null)
				collectInternalTypes(superBound, analysis, internalTypes);
		} else if (type instanceof IntersectionType intersectionType) {
			for (TypeMirror bound : intersectionType.getBounds())
				collectInternalTypes(bound, analysis, internalTypes);
		}
	}
}
