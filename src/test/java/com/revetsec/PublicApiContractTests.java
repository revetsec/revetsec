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
import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePath;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.TypeParameterElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.ExecutableType;
import javax.lang.model.type.IntersectionType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.TypeVariable;
import javax.lang.model.type.WildcardType;
import javax.lang.model.util.ElementFilter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Source-inventory contracts for Revetsec's exported API (plan R1, R2, R17, R20, 14.6), adapted from Soklet.
 * <p>
 * For every exported type (public top-level types in the eight exported packages, and their public or protected
 * nested types):
 * <ul>
 *   <li>it is not a record;</li>
 *   <li>it carries exactly one jsr305 thread-safety marker ({@code @ThreadSafe}, {@code @NotThreadSafe} or
 *   {@code @Immutable}), enums, interfaces and annotation types included;</li>
 *   <li>a concrete class is final, or sealed with every permitted subclass final or sealed in turn, unless it is in
 *   {@link #R1_EXCEPTIONS}; and it has no public or protected constructor, listed or not (R1);</li>
 *   <li>it has Javadoc with {@code @since}, and so does every public or protected member it declares or inherits
 *   from a non-exported Revetsec class (such as a package-private base class), since callers can reach those
 *   members too. Two exemptions: {@code @Override} methods inherit their documentation, and enum constants need
 *   Javadoc but take their {@code @since} from the enum (Pyranid precedent);</li>
 *   <li>it has no implicit public or protected constructor (declare constructors explicitly);</li>
 *   <li>no public or protected static method is named {@code of*}, {@code create*} or {@code new*} (R1);</li>
 *   <li>every non-primitive type in a public or protected field, parameter or return type carries exactly one
 *   JSpecify nullness annotation, in type-argument, array-component and wildcard-bound positions too
 *   ({@code Optional}'s type argument must be {@code @NonNull});</li>
 *   <li>an abstract class is sealed, unless it is in {@link #OPEN_ABSTRACT_TYPES} (G6-1); a sealed abstract class
 *   declares no public or protected constructor, because only its permitted subclasses, in its own package, call
 *   one (G6-1, M2-10);</li>
 *   <li>a sealed abstract class or sealed interface permits only final or sealed subtypes, recursively, whether they
 *   are exported or not (G6-1, M2-10): a {@code non-sealed} one, such as a package-private leaf of an exception
 *   family, reopens the hierarchy to any class in its package, which a split package on the class path can add. A
 *   sealed concrete class is held to the same rule by R1's finality check.</li>
 * </ul>
 * Every exported {@link Throwable} extends {@code com.revetsec.RevetsecException}, declares its own
 * {@code private static final long serialVersionUID}, and has no public or protected static method, declared or
 * inherited from a non-exported Revetsec class, unless {@link #APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES} lists it:
 * Revetsec creates its exceptions itself (G6-1).
 * <p>
 * Every exported interface named {@code *Observer} declares a static {@code disabledInstance()} that takes no
 * arguments and returns the observer, and otherwise only {@code default void} hooks, which applications override
 * one by one. Hook parameters are enums, boxed numbers or {@code Boolean}, {@code Duration}, {@code Instant},
 * {@code URI}, {@code String} or Revetsec exceptions (G6-4). A member inherited from another interface is held to the
 * same rules, unless that interface is an exported observer, which is checked on its own. Fields and every other
 * static method are reported; private methods are not API and are not checked.
 * <p>
 * Verified identity types (R17) and their subtypes have no public or protected constructor and no public or
 * protected nested {@code Builder} or {@code Copier}; each is final, or sealed with only non-public permitted
 * subclasses. No public or protected method or field of an accessible type, in any package, declared or inherited,
 * returns or holds a type that mentions one (a subtype, a type argument or a type-variable bound included). A class
 * in {@link #VERIFIED_TYPE_SOURCES} is exempt for its instance members only; its static methods and fields are
 * checked like any other.
 * <p>
 * Entries in {@link #VERIFIED_TYPE_SOURCES}, {@link #R1_EXCEPTIONS} and {@link #OPEN_ABSTRACT_TYPES} are binary names
 * ({@code Outer$Nested}), and entries in {@link #APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES} are
 * {@code Outer$Nested#method(erased parameter types)}: the forms every violation message prints. An entry that names
 * nothing its rule examines is reported as stale or misspelled.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PublicApiContractTests {
	/**
	 * Verified identity types (plan R17, INV-G5). They exist only after every check passed, so they are created
	 * only by validators.
	 */
	static final Set<String> VERIFIED_TYPES = Set.of(
			"com.revetsec.jose.Jwt",
			"com.revetsec.jose.JwtClaims",
			"com.revetsec.jose.JwtValidationResult$Succeeded",
			"com.revetsec.oauth.VerifiedAccessToken",
			"com.revetsec.oauth.AccessTokenValidationResult$Succeeded",
            "com.revetsec.oauth.server.OAuthIssuerAccessTokenResult$Succeeded",
			"com.revetsec.oidc.IdToken",
			"com.revetsec.oidc.OidcAuthentication",
			"com.revetsec.oidc.OidcAuthenticationResult$Succeeded",
			"com.revetsec.oidc.OidcUserInfo",
			"com.revetsec.oidc.OidcRefreshResult",
			"com.revetsec.saml.SamlAuthentication",
			"com.revetsec.scim.ScimPatchResult");

	/**
	 * Binary names of the accessible classes whose public or protected instance methods and fields may return or hold
	 * a verified type: the validators that create them, and results or verified types whose accessors hand one out.
	 * Static members are never exempt, because a static factory or field would give any caller a verified type without
	 * validation. Each entry is a reviewed decision.
	 */
	static final Set<String> VERIFIED_TYPE_SOURCES = Set.of(
            "com.revetsec.oauth.AccessTokenValidator",
            "com.revetsec.oauth.JwtAccessTokenValidator",
            "com.revetsec.oauth.TokenIntrospectionClient",
            "com.revetsec.oauth.AccessTokenValidationResult$Succeeded",
            "com.revetsec.oauth.server.OAuthIssuerAccessTokenResult$Succeeded",
			"com.revetsec.jose.JwtValidator",
			"com.revetsec.jose.JwtValidationResult$Succeeded",
			"com.revetsec.jose.Jwt",
			"com.revetsec.oidc.IdToken",
			"com.revetsec.oidc.OidcAuthentication",
			"com.revetsec.oidc.OidcAuthenticationResult$Succeeded",
			"com.revetsec.oidc.OidcRefreshResult",
			"com.revetsec.oidc.OidcClient",
			"com.revetsec.internal.jose.JwtValidationAccess$Operations");

	/**
	 * Binary names of the exported concrete classes approved to be neither final nor sealed (R1). The exemption covers
	 * finality only: a listed class still may not have a public or protected constructor. Each entry is a reviewed
	 * decision; there are none.
	 */
	static final Set<String> R1_EXCEPTIONS = Set.of();

	/**
	 * Binary names of the exported abstract classes approved to be neither final nor sealed (M1 plan, "Contract-list
	 * changes" item 2; G6-1). Every other exported abstract class is sealed, so no application can extend it. The
	 * exception root stays open because each protocol's {@code abstract sealed} intermediate extends it from its own
	 * package, and a sealed class outside a named module permits subclasses only in its own package. Each entry is a
	 * reviewed decision.
	 */
	static final Set<String> OPEN_ABSTRACT_TYPES = Set.of("com.revetsec.RevetsecException");

	/**
	 * Public or protected static methods of exported exceptions that applications may call to create one, as
	 * {@code Outer$Nested#method(erased parameter types)} (M1 plan, "Contract-list changes" item 2; G6-1). Revetsec
	 * creates its exceptions through package-private factories, so any other public or protected static method on an
	 * exported exception is reported. The metadata-cache provider factory accepts a fixed reason only,
	 * without backend messages or causes.
	 */
	static final Set<String> APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES = Set.of(
			"com.revetsec.oauth.server.OAuthClientMetadataCacheException#fromReason(com.revetsec.oauth.server.OAuthClientMetadataCacheException.Reason)");

	private static final Set<String> THREAD_SAFETY_MARKERS = Set.of(
			"javax.annotation.concurrent.ThreadSafe",
			"javax.annotation.concurrent.NotThreadSafe",
			"javax.annotation.concurrent.Immutable");
	private static final String NON_NULL = "org.jspecify.annotations.NonNull";
	private static final String NULLABLE = "org.jspecify.annotations.Nullable";
	private static final String OVERRIDE = "java.lang.Override";
	private static final Set<String> FORBIDDEN_VERIFIED_TYPE_NESTED_NAMES = Set.of("Builder", "Copier");
	private static final Pattern FORBIDDEN_FACTORY_NAME = Pattern.compile("(?:of|create|new)(?:\\p{Lu}.*)?");
	private static final String REVETSEC_EXCEPTION = "com.revetsec.RevetsecException";
	private static final String THROWABLE = "java.lang.Throwable";
	private static final String OBJECT = "java.lang.Object";
	private static final String SERIAL_VERSION_UID = "serialVersionUID";
	private static final String DISABLED_INSTANCE = "disabledInstance";
	private static final String OBSERVER_SUFFIX = "Observer";
	/**
	 * Observer hook parameter types besides enums and Revetsec exceptions (G6-4): the boxed numbers and
	 * {@code Boolean}, and the value types hooks report with.
	 */
	private static final Set<String> OBSERVER_HOOK_PARAMETER_TYPES = Set.of(
			"java.lang.Byte",
			"java.lang.Short",
			"java.lang.Integer",
			"java.lang.Long",
			"java.lang.Float",
			"java.lang.Double",
			"java.lang.Boolean",
			"java.time.Duration",
			"java.time.Instant",
			"java.net.URI",
			"java.lang.String");

	@Test
	void exportedApiMeetsSourceContracts() throws IOException {
		ContractSupport.assertNoViolations("Public API contract violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java")));
	}

	/**
	 * Checks the Java sources under {@code sourceRoot} and returns one message per violation (empty if none).
	 */
	static @NonNull List<@NonNull String> findViolations(@NonNull Path sourceRoot) throws IOException {
		return findViolations(sourceRoot, VERIFIED_TYPE_SOURCES, R1_EXCEPTIONS, OPEN_ABSTRACT_TYPES,
				APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES);
	}

	/**
	 * {@link #findViolations(Path)} with the given lists in place of {@link #VERIFIED_TYPE_SOURCES},
	 * {@link #R1_EXCEPTIONS}, {@link #OPEN_ABSTRACT_TYPES} and {@link #APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES}, so
	 * {@link ContractMetaTests} can exercise entries against the fixtures.
	 */
	static @NonNull List<@NonNull String> findViolations(@NonNull Path sourceRoot, @NonNull Set<@NonNull String> verifiedTypeSources, @NonNull Set<@NonNull String> r1Exceptions,
			@NonNull Set<@NonNull String> openAbstractTypes, @NonNull Set<@NonNull String> appConstructibleExceptionFactories) throws IOException {
		if (ContractSupport.javaSources(sourceRoot).isEmpty())
			return List.of();
		return ContractSupport.analyze(sourceRoot, analysis -> findViolations(analysis, verifiedTypeSources,
				r1Exceptions, openAbstractTypes, appConstructibleExceptionFactories));
	}

	private static @NonNull List<@NonNull String> findViolations(@NonNull SourceAnalysis analysis, @NonNull Set<@NonNull String> verifiedTypeSources,
			@NonNull Set<@NonNull String> r1Exceptions, @NonNull Set<@NonNull String> openAbstractTypes, @NonNull Set<@NonNull String> appConstructibleExceptionFactories) {
		List<String> violations = new ArrayList<>();
		List<TypeElement> exportedTypes = ContractSupport.exportedTypes(analysis);
		Set<TypeElement> exported = new HashSet<>(exportedTypes);
		for (TypeElement type : exportedTypes)
			checkExportedType(type, exported, r1Exceptions, analysis, violations);
		Set<TypeElement> accessibleTypes = accessibleTypes(analysis);
		checkVerifiedTypes(accessibleTypes, verifiedTypeSources, analysis, violations);
		checkOpenAbstractTypes(exportedTypes, openAbstractTypes, analysis, violations);
		checkExceptions(exportedTypes, exported, appConstructibleExceptionFactories, analysis, violations);
		checkObservers(exportedTypes, exported, analysis, violations);
		checkReviewedEntries("R1_EXCEPTIONS", r1Exceptions, exported, "exported type", analysis, violations);
		checkReviewedEntries("VERIFIED_TYPE_SOURCES", verifiedTypeSources, accessibleTypes, "accessible type",
				analysis, violations);
		violations.sort(null);
		return List.copyOf(violations);
	}

	/**
	 * Every entry in a reviewed-exception list must be the binary name of a type its rule examines. Anything else,
	 * such as a canonical {@code Outer.Nested} spelling or a name left behind by a rename, exempts nothing.
	 */
	private static void checkReviewedEntries(@NonNull String listName, @NonNull Set<@NonNull String> entries, @NonNull Set<@NonNull TypeElement> examinedTypes,
			@NonNull String typeDescription, @NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		Set<String> binaryNames = examinedTypes.stream()
				.map(type -> analysis.getElements().getBinaryName(type).toString())
				.collect(Collectors.toUnmodifiableSet());
		for (String entry : entries)
			if (!binaryNames.contains(entry))
				violations.add("PublicApiContractTests." + listName + " entry \"" + entry + "\": stale or misspelled "
						+ "entry; use the binary name (Outer$Nested, as violation messages print it) of an "
						+ typeDescription + " in the analyzed sources");
	}

	/**
	 * G6-1: an exported abstract class is sealed, so every subclass is Revetsec's, unless {@code openAbstractTypes}
	 * lists it. A sealed one declares no public or protected constructor (the protocol intermediates' constructors
	 * are package-private), and it and every exported sealed interface permit only final or sealed subtypes, all the
	 * way down, so the sealing cannot be undone by a {@code non-sealed} subtype, exported or not (M2-10 item 6).
	 * Concrete classes are held to R1's finality rule instead ({@link #checkFinal}), which walks their permitted
	 * subclasses the same way.
	 */
	private static void checkOpenAbstractTypes(@NonNull List<@NonNull TypeElement> exportedTypes, @NonNull Set<@NonNull String> openAbstractTypes,
			@NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		Set<TypeElement> openAbstractClasses = new LinkedHashSet<>();
		for (TypeElement type : exportedTypes) {
			Set<Modifier> modifiers = type.getModifiers();
			boolean abstractClass = type.getKind() == ElementKind.CLASS && modifiers.contains(Modifier.ABSTRACT);
			boolean sealed = modifiers.contains(Modifier.SEALED);
			String typeName = binaryName(type, analysis);

			if (sealed && (abstractClass || type.getKind() == ElementKind.INTERFACE)) {
				List<TypeElement> openSubtypes = new ArrayList<>();
				collectNonSealedSubclasses(type, analysis, openSubtypes, new HashSet<>());
				for (TypeElement openSubtype : openSubtypes)
					violations.add(typeName + ": exported sealed " + (abstractClass ? "abstract class" : "interface")
							+ " permits the non-sealed subtype " + binaryName(openSubtype, analysis) + ", which reopens "
							+ "its hierarchy; every permitted subtype must be final or sealed (G6-1)");
			}
			if (abstractClass && sealed)
				for (ExecutableElement constructor : ElementFilter.constructorsIn(type.getEnclosedElements()))
					if (ContractSupport.isPublicOrProtected(constructor) && analysis.isSourceAuthored(constructor))
						violations.add(typeName + "#" + analysis.describe(constructor) + ": exported abstract sealed "
								+ "classes have package-private constructors, because only their permitted subclasses "
								+ "call them (G6-1)");
			if (!abstractClass || sealed)
				continue;
			openAbstractClasses.add(type);
			if (!openAbstractTypes.contains(typeName))
				violations.add(typeName + ": exported abstract classes are sealed, so only Revetsec extends them; an "
						+ "open one needs a reviewed entry in OPEN_ABSTRACT_TYPES (G6-1)");
		}
		checkReviewedEntries("OPEN_ABSTRACT_TYPES", openAbstractTypes, openAbstractClasses,
				"unsealed exported abstract class", analysis, violations);
	}

	/**
	 * G6-1: every exported {@link Throwable} extends RevetsecException and declares its own serialVersionUID, and
	 * applications never create one through a public or protected static method, declared or inherited from a
	 * non-exported Revetsec class, unless {@code appConstructibleExceptionFactories} lists it. An inherited method of
	 * an exported class is checked on that class.
	 */
	private static void checkExceptions(@NonNull List<@NonNull TypeElement> exportedTypes, @NonNull Set<@NonNull TypeElement> exported,
			@NonNull Set<@NonNull String> appConstructibleExceptionFactories, @NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		TypeElement throwable = analysis.getElements().getTypeElement(THROWABLE);
		@Nullable TypeElement revetsecException = analysis.getElements().getTypeElement(REVETSEC_EXCEPTION);
		Set<String> staticMethods = new HashSet<>();

		for (TypeElement type : exportedTypes) {
			if (!analysis.isSubtype(type, throwable))
				continue;
			String typeName = binaryName(type, analysis);
			if (revetsecException == null || !analysis.isSubtype(type, revetsecException))
				violations.add(typeName + ": every exported Throwable extends " + REVETSEC_EXCEPTION + " (G6-1)");
			checkSerialVersionUid(type, typeName, violations);

			for (Element member : analysis.getElements().getAllMembers(type)) {
				if (member.getKind() != ElementKind.METHOD || !member.getModifiers().contains(Modifier.STATIC)
						|| !ContractSupport.isPublicOrProtected(member)
						|| !(member.getEnclosingElement() instanceof TypeElement declaringType))
					continue;
				boolean inherited = !declaringType.equals(type);
				if (inherited && (exported.contains(declaringType) || !analysis.isAnalyzed(declaringType)))
					continue;
				String factory = typeName + "#" + analysis.describe(member);
				staticMethods.add(factory);
				if (!appConstructibleExceptionFactories.contains(factory))
					violations.add(factory + (inherited ? " (inherited from " + binaryName(declaringType, analysis) + ")"
							: "") + ": exported exceptions have no public or protected static methods, because Revetsec "
							+ "creates them; a factory applications need is a reviewed entry in "
							+ "APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES (G6-1)");
			}
		}

		for (String entry : appConstructibleExceptionFactories)
			if (!staticMethods.contains(entry))
				violations.add("PublicApiContractTests.APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES entry \"" + entry + "\": "
						+ "stale or misspelled entry; name a public or protected static method of an exported exception "
						+ "as violation messages print it (Outer$Nested#method(erased parameter types))");
	}

	/**
	 * The serialization specification requires a {@code static final long serialVersionUID}; declared
	 * {@code private}, it stays out of the API. The JDK ignores the field unless it is both {@code static} and
	 * {@code final}, and then computes the version from the class's members, so it changes with them. (It widens a
	 * narrower integral type, but the specification does not allow one.)
	 */
	private static void checkSerialVersionUid(@NonNull TypeElement type, @NonNull String typeName, @NonNull List<@NonNull String> violations) {
		@Nullable VariableElement serialVersionUid = ElementFilter.fieldsIn(type.getEnclosedElements()).stream()
				.filter(field -> field.getSimpleName().contentEquals(SERIAL_VERSION_UID))
				.findFirst()
				.orElse(null);
		if (serialVersionUid == null)
			violations.add(typeName + ": exported Throwable declares no serialVersionUID; declare private static final "
					+ "long " + SERIAL_VERSION_UID + " (G6-1)");
		else if (serialVersionUid.asType().getKind() != TypeKind.LONG || !serialVersionUid.getModifiers()
				.containsAll(Set.of(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)))
			violations.add(typeName + "#" + SERIAL_VERSION_UID + ": declare it private static final long; "
					+ "serialization ignores one that is not static and final, the specification requires a long, and "
					+ "private keeps it out of the API (G6-1)");
	}

	/**
	 * G6-4: the rules for exported interfaces named {@code *Observer} (see the class description).
	 */
	private static void checkObservers(@NonNull List<@NonNull TypeElement> exportedTypes, @NonNull Set<@NonNull TypeElement> exported,
			@NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		@Nullable TypeElement revetsecException = analysis.getElements().getTypeElement(REVETSEC_EXCEPTION);

		for (TypeElement type : exportedTypes) {
			if (!isObserver(type))
				continue;
			String typeName = binaryName(type, analysis);
			DeclaredType observerType = (DeclaredType) type.asType();
			boolean hasDisabledInstance = false;

			for (Element member : analysis.getElements().getAllMembers(type)) {
				if (member instanceof TypeElement || member.getModifiers().contains(Modifier.PRIVATE)
						|| !(member.getEnclosingElement() instanceof TypeElement declaringType)
						|| declaringType.getQualifiedName().contentEquals(OBJECT))
					continue;
				boolean inherited = !declaringType.equals(type);
				if (inherited && isObserver(declaringType) && exported.contains(declaringType))
					continue;
				String memberName = typeName + "#" + analysis.describe(member) + (inherited ? " (inherited from "
						+ binaryName(declaringType, analysis) + ")" : "");

				if (member.getKind() == ElementKind.FIELD) {
					violations.add(memberName + ": observer interfaces declare no fields, only default void hooks and a "
							+ "static disabledInstance() (G6-4)");
					continue;
				}
				if (!(member instanceof ExecutableElement method) || method.getKind() != ElementKind.METHOD)
					continue;

				if (method.getModifiers().contains(Modifier.STATIC)) {
					// Static interface methods are not inherited, so this one is the observer's own.
					boolean disabledInstance = method.getSimpleName().contentEquals(DISABLED_INSTANCE)
							&& method.getParameters().isEmpty();
					hasDisabledInstance = hasDisabledInstance || disabledInstance;
					if (!disabledInstance || !analysis.getTypes().isSameType(
							analysis.getTypes().erasure(method.getReturnType()), analysis.getTypes().erasure(observerType)))
						violations.add(memberName + ": an observer's only static method is disabledInstance(), which takes "
								+ "no arguments and returns the observer (G6-4)");
					continue;
				}

				if (!method.isDefault())
					violations.add(memberName + ": observer hooks are default methods that do nothing, so an application "
							+ "overrides only the hooks it needs (G6-4)");
				if (method.getReturnType().getKind() != TypeKind.VOID)
					violations.add(memberName + ": observer hooks return void (G6-4)");
				List<? extends TypeMirror> parameterTypes = ((ExecutableType) analysis.getTypes()
						.asMemberOf(observerType, method)).getParameterTypes();
				for (int index = 0; index < parameterTypes.size(); ++index)
					if (!isObserverHookParameterType(parameterTypes.get(index), revetsecException, analysis))
						violations.add(memberName + " parameter " + index + ": observer hook parameters are enums, boxed "
								+ "numbers or Boolean, Duration, Instant, URI, String or Revetsec exceptions, not "
								+ describeHookParameterType(parameterTypes.get(index), analysis) + " (G6-4)");
			}

			if (!hasDisabledInstance)
				violations.add(typeName + ": observer interfaces declare a static disabledInstance() (G6-4)");
		}
	}

	private static boolean isObserver(@NonNull TypeElement type) {
		return type.getKind() == ElementKind.INTERFACE && type.getSimpleName().toString().endsWith(OBSERVER_SUFFIX);
	}

	private static boolean isObserverHookParameterType(@NonNull TypeMirror type, @Nullable TypeElement revetsecException,
			@NonNull SourceAnalysis analysis) {
		if (!(type instanceof DeclaredType declaredType) || !(declaredType.asElement() instanceof TypeElement element))
			return false;
		return element.getKind() == ElementKind.ENUM
				|| OBSERVER_HOOK_PARAMETER_TYPES.contains(element.getQualifiedName().toString())
				|| (revetsecException != null && analysis.isSubtype(element, revetsecException));
	}

	private static @NonNull String describeHookParameterType(@NonNull TypeMirror type, @NonNull SourceAnalysis analysis) {
		if (type instanceof TypeVariable typeVariable)
			return "type variable " + typeVariable.asElement().getSimpleName();
		return analysis.erasedName(type);
	}

	private static @NonNull String binaryName(@NonNull TypeElement type, @NonNull SourceAnalysis analysis) {
		return analysis.getElements().getBinaryName(type).toString();
	}

	private static void checkExportedType(@NonNull TypeElement type, @NonNull Set<@NonNull TypeElement> exported, @NonNull Set<@NonNull String> r1Exceptions,
			@NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		String typeName = analysis.getElements().getBinaryName(type).toString();

		if (type.getKind() == ElementKind.RECORD)
			violations.add(typeName + ": exported types must not be records; use a final class with getX() "
					+ "accessors (R1)");

		List<String> markers = type.getAnnotationMirrors().stream()
				.map(annotation -> annotation.getAnnotationType().toString())
				.filter(THREAD_SAFETY_MARKERS::contains)
				.sorted()
				.toList();
		if (markers.size() != 1)
			violations.add(typeName + ": must declare exactly one jsr305 thread-safety marker "
					+ "(@ThreadSafe, @NotThreadSafe or @Immutable); found " + markers);

		checkDocumentation(typeName + " (type)", type, true, analysis, violations);

		boolean concreteClass = type.getKind() == ElementKind.CLASS && !type.getModifiers().contains(Modifier.ABSTRACT);
		if (concreteClass && !r1Exceptions.contains(typeName))
			checkFinal(type, typeName, analysis, violations);

		for (Element enclosed : type.getEnclosedElements()) {
			if (enclosed instanceof TypeElement || enclosed.getKind() == ElementKind.RECORD_COMPONENT
					|| !ContractSupport.isPublicOrProtected(enclosed))
				continue;

			String memberName = typeName + "#" + analysis.describe(enclosed);
			boolean explicit = analysis.isSourceAuthored(enclosed);

			if (enclosed.getKind() == ElementKind.CONSTRUCTOR && !explicit) {
				violations.add(memberName + ": implicit public or protected constructor; declare every "
						+ "constructor explicitly (R1: public concrete types have private constructors)");
				continue;
			}
			if (!explicit)
				continue;
			if (enclosed.getKind() == ElementKind.CONSTRUCTOR && concreteClass)
				violations.add(memberName + ": public concrete types have private constructors (R1)");

			checkMember(memberName, enclosed, analysis, violations);
		}

		// Members inherited from non-exported Revetsec classes (a package-private base class, say) are callable
		// through this type but are checked nowhere else.
		for (Element member : analysis.getElements().getAllMembers(type)) {
			if (member instanceof TypeElement || !ContractSupport.isPublicOrProtected(member)
					|| !(member.getEnclosingElement() instanceof TypeElement declaringType)
					|| declaringType.equals(type) || exported.contains(declaringType)
					|| !analysis.isAnalyzed(declaringType) || !analysis.isSourceAuthored(member))
				continue;
			checkMember(typeName + "#" + analysis.describe(member) + " (inherited from "
					+ analysis.getElements().getBinaryName(declaringType) + ")", member, analysis, violations);
		}
	}

	/**
	 * R1 finality: a concrete exported class is final, or sealed with every permitted subclass final or sealed in
	 * turn (a concrete exception with a subclass, say), so the hierarchy stays closed. A non-sealed subclass anywhere
	 * below reopens it.
	 */
	private static void checkFinal(@NonNull TypeElement type, @NonNull String typeName, @NonNull SourceAnalysis analysis,
			@NonNull List<@NonNull String> violations) {
		Set<Modifier> modifiers = type.getModifiers();
		if (modifiers.contains(Modifier.FINAL))
			return;
		if (!modifiers.contains(Modifier.SEALED)) {
			violations.add(typeName + ": public concrete types are final, or sealed with only final or sealed "
					+ "permitted subclasses (R1)");
			return;
		}
		List<TypeElement> openSubclasses = new ArrayList<>();
		collectNonSealedSubclasses(type, analysis, openSubclasses, new HashSet<>());
		for (TypeElement openSubclass : openSubclasses)
			violations.add(typeName + ": sealed public concrete type permits the non-sealed subclass "
					+ analysis.getElements().getBinaryName(openSubclass) + "; every permitted subclass must be final or "
					+ "sealed (R1)");
	}

	private static void collectNonSealedSubclasses(@NonNull TypeElement type, @NonNull SourceAnalysis analysis,
			@NonNull List<@NonNull TypeElement> openSubclasses, @NonNull Set<@NonNull TypeElement> visited) {
		for (TypeMirror permitted : type.getPermittedSubclasses()) {
			if (!(analysis.getTypes().asElement(permitted) instanceof TypeElement permittedType)
					|| !visited.add(permittedType))
				continue;
			Set<Modifier> modifiers = permittedType.getModifiers();
			if (modifiers.contains(Modifier.SEALED))
				collectNonSealedSubclasses(permittedType, analysis, openSubclasses, visited);
			else if (!modifiers.contains(Modifier.FINAL))
				openSubclasses.add(permittedType);
		}
	}

	/**
	 * The per-member checks: documentation, nullness and factory names.
	 */
	private static void checkMember(@NonNull String memberName, @NonNull Element member, @NonNull SourceAnalysis analysis,
			@NonNull List<@NonNull String> violations) {
		if (!isOverride(member))
			checkDocumentation(memberName, member, member.getKind() != ElementKind.ENUM_CONSTANT, analysis, violations);

		if (member.getKind() == ElementKind.FIELD && !member.asType().getKind().isPrimitive())
			inspectNullness(memberName + " field type", member.asType(), true, false, violations);

		if (member.getKind() == ElementKind.METHOD && member.getModifiers().contains(Modifier.STATIC)
				&& FORBIDDEN_FACTORY_NAME.matcher(member.getSimpleName()).matches())
			violations.add(memberName + ": static factories are named builder(), withX(), fromX(), *Instance() or "
					+ "fromDefaults(), never of*, create* or new* (R1, NAMING_CONVENTIONS.md)");

		if (member instanceof ExecutableElement executable) {
			for (int index = 0; index < executable.getParameters().size(); ++index) {
				TypeMirror parameterType = executable.getParameters().get(index).asType();
				if (!parameterType.getKind().isPrimitive())
					inspectNullness(memberName + " parameter " + index, parameterType, true, false, violations);
			}
			TypeMirror returnType = executable.getReturnType();
			if (returnType.getKind() != TypeKind.VOID && !returnType.getKind().isPrimitive())
				inspectNullness(memberName + " return type", returnType, true, false, violations);
		}
	}

	private static void checkDocumentation(@NonNull String owner, @NonNull Element element, boolean requireSince,
			@NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		// javac 23 and later also return Markdown (///) doc comments here, and javac 17 and 21 do not.
		// SourcePolicyTests bans /// in main sources, so the build's outcome does not depend on the JDK.
		@Nullable DocCommentTree docComment = analysis.getTrees().getDocCommentTree(element);
		if (docComment == null) {
			violations.add(owner + ": missing Javadoc (R20)");
			return;
		}
		if (requireSince && docComment.getBlockTags().stream().noneMatch(tag -> tag.getKind() == DocTree.Kind.SINCE))
			violations.add(owner + ": Javadoc has no @since tag (D28)");
	}

	private static boolean isOverride(@NonNull Element element) {
		return element.getAnnotationMirrors().stream()
				.anyMatch(annotation -> annotation.getAnnotationType().toString().equals(OVERRIDE));
	}

	private static void inspectNullness(@NonNull String owner, @NonNull TypeMirror type, boolean root, boolean requireNonNull,
			@NonNull List<@NonNull String> violations) {
		boolean checked = root || (type.getKind() != TypeKind.WILDCARD && !type.getKind().isPrimitive());
		if (checked && !(requireNonNull ? hasExactNullness(type, NON_NULL) : hasAnyExactNullness(type)))
			violations.add(owner + (root ? "" : " (nested)") + ": lacks "
					+ (requireNonNull ? "@NonNull" : "exactly one JSpecify @NonNull/@Nullable") + " at " + type + " (R2)");

		if (type instanceof DeclaredType declaredType) {
			boolean optional = ((TypeElement) declaredType.asElement()).getQualifiedName()
					.contentEquals("java.util.Optional");
			List<? extends TypeMirror> arguments = declaredType.getTypeArguments();
			for (int index = 0; index < arguments.size(); ++index)
				inspectNullness(owner + " type argument " + index, arguments.get(index), false, optional, violations);
		} else if (type instanceof ArrayType arrayType) {
			TypeMirror componentType = arrayType.getComponentType();
			if (!componentType.getKind().isPrimitive())
				inspectNullness(owner + " array component", componentType, false, false, violations);
		} else if (type instanceof WildcardType wildcardType) {
			@Nullable TypeMirror extendsBound = wildcardType.getExtendsBound();
			if (extendsBound != null)
				inspectNullness(owner + " wildcard upper bound", extendsBound, false, requireNonNull, violations);
			@Nullable TypeMirror superBound = wildcardType.getSuperBound();
			if (superBound != null)
				inspectNullness(owner + " wildcard lower bound", superBound, false, requireNonNull, violations);
		}
	}

	private static boolean hasAnyExactNullness(@NonNull TypeMirror type) {
		return hasExactNullness(type, NON_NULL) || hasExactNullness(type, NULLABLE);
	}

	private static boolean hasExactNullness(@NonNull TypeMirror type, @NonNull String annotation) {
		String opposite = annotation.equals(NON_NULL) ? NULLABLE : NON_NULL;
		Set<String> annotations = type.getAnnotationMirrors().stream()
				.map(value -> value.getAnnotationType().toString())
				.collect(Collectors.toUnmodifiableSet());
		return annotations.contains(annotation) && !annotations.contains(opposite);
	}

	/**
	 * The analyzed types a caller in another package can name: public top-level types in any package, and their
	 * public or protected nested types, recursively.
	 */
	private static @NonNull Set<@NonNull TypeElement> accessibleTypes(@NonNull SourceAnalysis analysis) {
		Set<TypeElement> accessibleTypes = new LinkedHashSet<>();
		for (TypeElement type : topLevelTypes(analysis))
			collectAccessibleTypes(type, type.getModifiers().contains(Modifier.PUBLIC), accessibleTypes);
		return accessibleTypes;
	}

	private static @NonNull List<@NonNull TypeElement> topLevelTypes(@NonNull SourceAnalysis analysis) {
		List<TypeElement> topLevelTypes = new ArrayList<>();
		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits())
			for (Tree declaration : compilationUnit.getTypeDecls())
				if (analysis.getTrees().getElement(TreePath.getPath(compilationUnit, declaration))
						instanceof TypeElement type)
					topLevelTypes.add(type);
		return topLevelTypes;
	}

	/**
	 * R17: verified identity types come only from validators.
	 */
	private static void checkVerifiedTypes(@NonNull Set<@NonNull TypeElement> accessibleTypes, @NonNull Set<@NonNull String> verifiedTypeSources,
			@NonNull SourceAnalysis analysis, @NonNull List<@NonNull String> violations) {
		List<TypeElement> verifiedTypes = VERIFIED_TYPES.stream()
				.map(name -> analysis.getElements().getTypeElement(name))
				.filter(Objects::nonNull)
				.toList();
		for (TypeElement type : topLevelTypes(analysis))
			checkVerifiedTypes(type, verifiedTypes, accessibleTypes, verifiedTypeSources, analysis, violations);
	}

	private static void collectAccessibleTypes(@NonNull TypeElement type, boolean accessible, @NonNull Set<@NonNull TypeElement> accessibleTypes) {
		if (accessible)
			accessibleTypes.add(type);
		for (TypeElement nested : ElementFilter.typesIn(type.getEnclosedElements()))
			collectAccessibleTypes(nested, accessible && ContractSupport.isPublicOrProtected(nested), accessibleTypes);
	}

	private static void checkVerifiedTypes(@NonNull TypeElement type, @NonNull List<@NonNull TypeElement> verifiedTypes,
			@NonNull Set<@NonNull TypeElement> accessibleTypes, @NonNull Set<@NonNull String> verifiedTypeSources, @NonNull SourceAnalysis analysis,
			@NonNull List<@NonNull String> violations) {
		String typeName = analysis.getElements().getBinaryName(type).toString();

		if (isVerifiedType(type, verifiedTypes, analysis)) {
			for (ExecutableElement constructor : ElementFilter.constructorsIn(type.getEnclosedElements()))
				if (ContractSupport.isPublicOrProtected(constructor))
					violations.add(typeName + "#" + analysis.describe(constructor) + ": verified type has a public or "
							+ "protected constructor (R17)");
			for (TypeElement nested : ElementFilter.typesIn(type.getEnclosedElements()))
				if (ContractSupport.isPublicOrProtected(nested)
						&& FORBIDDEN_VERIFIED_TYPE_NESTED_NAMES.contains(nested.getSimpleName().toString()))
					violations.add(analysis.getElements().getBinaryName(nested) + ": verified type exposes a "
							+ nested.getSimpleName() + " (R17)");
			checkClosed(type, typeName, analysis, violations);
		}

		if (accessibleTypes.contains(type)) {
			// A listed source hands verified types out through instance members only. A static method or field would
			// give one to any caller without validation, so statics are checked even here.
			boolean source = verifiedTypeSources.contains(typeName);
			String sourceNote = source ? "; VERIFIED_TYPE_SOURCES exempts instance members only" : "";
			for (Element member : analysis.getElements().getAllMembers(type)) {
				if (!ContractSupport.isPublicOrProtected(member)
						|| !(member.getEnclosingElement() instanceof TypeElement declaringType)
						|| (source && !member.getModifiers().contains(Modifier.STATIC)))
					continue;
				boolean inherited = !declaringType.equals(type);
				if (inherited && (accessibleTypes.contains(declaringType) || !analysis.isAnalyzed(declaringType)))
					continue;
				String memberName = typeName + "#" + analysis.describe(member) + (inherited ? " (inherited from "
						+ analysis.getElements().getBinaryName(declaringType) + ")" : "");
				if (member instanceof ExecutableElement method && method.getKind() == ElementKind.METHOD
						&& mentionsVerifiedType(method.getReturnType(), verifiedTypes, analysis, new HashSet<>()))
					violations.add(memberName + ": public or protected method returns a verified type; only validators "
							+ "may create one" + sourceNote + " (R17)");
				if (member.getKind() == ElementKind.FIELD
						&& mentionsVerifiedType(member.asType(), verifiedTypes, analysis, new HashSet<>()))
					violations.add(memberName + ": public or protected field holds a verified type; only validators "
							+ "may create one" + sourceNote + " (R17)");
			}
		}

		for (TypeElement nested : ElementFilter.typesIn(type.getEnclosedElements()))
			checkVerifiedTypes(nested, verifiedTypes, accessibleTypes, verifiedTypeSources, analysis, violations);
	}

	/**
	 * A verified type must be final, or sealed with only non-public, non-protected permitted subclasses, so no caller
	 * can subclass it.
	 */
	private static void checkClosed(@NonNull TypeElement type, @NonNull String typeName, @NonNull SourceAnalysis analysis,
			@NonNull List<@NonNull String> violations) {
		Set<Modifier> modifiers = type.getModifiers();
		if (type.getKind() == ElementKind.ENUM || type.getKind() == ElementKind.RECORD
				|| modifiers.contains(Modifier.FINAL))
			return;
		if (!modifiers.contains(Modifier.SEALED)) {
			violations.add(typeName + ": verified types are final, or sealed with only non-public permitted "
					+ "subclasses (R17)");
			return;
		}
		for (TypeMirror permitted : type.getPermittedSubclasses())
			if (analysis.getTypes().asElement(permitted) instanceof TypeElement permittedType
					&& ContractSupport.isPublicOrProtected(permittedType))
				violations.add(typeName + ": verified type permits the public or protected subclass "
						+ permittedType.getQualifiedName() + " (R17)");
	}

	private static boolean isVerifiedType(@NonNull TypeElement type, @NonNull List<@NonNull TypeElement> verifiedTypes, @NonNull SourceAnalysis analysis) {
		return verifiedTypes.stream().anyMatch(verifiedType -> analysis.isSubtype(type, verifiedType));
	}

	/**
	 * Returns whether {@code type} is, contains or is bounded by a verified type or a subtype of one (a nested type of
	 * a verified type counts too).
	 */
	private static boolean mentionsVerifiedType(@NonNull TypeMirror type, @NonNull List<@NonNull TypeElement> verifiedTypes,
			@NonNull SourceAnalysis analysis, @NonNull Set<@NonNull TypeParameterElement> visitedTypeVariables) {
		if (type instanceof DeclaredType declaredType) {
			for (@Nullable Element element = declaredType.asElement(); element instanceof TypeElement typeElement;
					element = typeElement.getEnclosingElement())
				if (isVerifiedType(typeElement, verifiedTypes, analysis))
					return true;
			return declaredType.getTypeArguments().stream().anyMatch(argument ->
					mentionsVerifiedType(argument, verifiedTypes, analysis, visitedTypeVariables));
		}
		if (type instanceof ArrayType arrayType)
			return mentionsVerifiedType(arrayType.getComponentType(), verifiedTypes, analysis, visitedTypeVariables);
		if (type instanceof WildcardType wildcardType) {
			@Nullable TypeMirror extendsBound = wildcardType.getExtendsBound();
			@Nullable TypeMirror superBound = wildcardType.getSuperBound();
			return (extendsBound != null && mentionsVerifiedType(extendsBound, verifiedTypes, analysis,
					visitedTypeVariables))
					|| (superBound != null && mentionsVerifiedType(superBound, verifiedTypes, analysis,
					visitedTypeVariables));
		}
		if (type instanceof TypeVariable typeVariable
				&& typeVariable.asElement() instanceof TypeParameterElement typeParameter
				&& visitedTypeVariables.add(typeParameter))
			return mentionsVerifiedType(typeVariable.getUpperBound(), verifiedTypes, analysis, visitedTypeVariables);
		if (type instanceof IntersectionType intersectionType)
			return intersectionType.getBounds().stream()
					.anyMatch(bound -> mentionsVerifiedType(bound, verifiedTypes, analysis, visitedTypeVariables));
		return false;
	}
}
