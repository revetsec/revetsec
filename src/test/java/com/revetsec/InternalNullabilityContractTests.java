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

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.TreePathScanner;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.RecordComponentElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.WildcardType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Every source-declared production signature states its reference nullability, including internal declarations.
 * This supplements the public API contract; implicit generic bounds and compiler-generated methods are not source
 * signatures. There is no production vendor exclusion: the current production inventory is Revetsec-authored.
 */
final class InternalNullabilityContractTests {

	private static final @NonNull String NON_NULL = "org.jspecify.annotations.NonNull";
	private static final @NonNull String NULLABLE = "org.jspecify.annotations.Nullable";

	@Test
	void allProductionReferenceSignaturesHaveExplicitNullability() throws IOException {
		List<String> violations = findViolations(ContractSupport.repositoryRoot().resolve("src/main/java"));
		Assertions.assertEquals(List.of(), violations, () -> String.join("\n", violations));
	}

	@Test
	void privateNestedInterfaceAnonymousAndRecordDeclarationsAreChecked(@TempDir @NonNull Path root)
			throws IOException {
		writeFixture(root, """
				package sample;
				import java.util.List;
				class Fixture {
				  Fixture(String value) { }
				  private String method(List<String> values) { return ""; }
				  static class Nested { protected String helper(String value) { return ""; } }
				  interface Internal { String apply(String value); }
				  Object anonymous() { return new Object() { String value(String input) { return input; } }; }
				  record Handle(String text) { }
				}
				""");
		List<String> violations = findViolations(root);
		Assertions.assertEquals(12, violations.size(), () -> String.join("\n", violations));
		for (String declaration : List.of("<init> parameter value", "method return", "method parameter values argument 0",
				"helper return", "apply return", "anonymous return", "value parameter input", "record component text"))
			Assertions.assertTrue(violations.stream().anyMatch(value -> value.contains(declaration)), declaration);
	}

	@Test
	void nullableArraysWildcardsTypeVariablesAndPrimitiveSignaturesAreAccepted(@TempDir @NonNull Path root)
			throws IOException {
		writeFixture(root, """
				package sample;
				import java.util.List;
				import org.jspecify.annotations.NonNull;
				import org.jspecify.annotations.Nullable;
				class Fixture<T> {
				  Fixture(@Nullable String value) { }
				  private @Nullable String optional(@Nullable String value) { return value; }
				  private @NonNull T generic(@NonNull T value) { return value; }
				  private @NonNull List<?> unbounded(@NonNull List<?> values) { return values; }
				  private @NonNull List<? extends @NonNull String> bounded(
				      @NonNull List<? extends @NonNull String> values) { return values; }
				  private @NonNull String @NonNull [] @Nullable [] arrays(
				      @NonNull String @NonNull [] @Nullable [] values) { return values; }
				  private int @NonNull [] primitives(int @NonNull ... values) { return values; }
				  private void nothing(int value, boolean flag) { }
				  record Handle(@NonNull String text) { }
				}
				""");
		Assertions.assertEquals(List.of(), findViolations(root));
	}

	@Test
	void arrayDimensionsComponentsVarargsAndWildcardBoundsAreChecked(@TempDir @NonNull Path root)
			throws IOException {
		writeFixture(root, """
				package sample;
				import java.util.List;
				import org.jspecify.annotations.NonNull;
				class Fixture {
				  private String[] array(String[] values) { return values; }
				  private int[] primitiveArray(int... values) { return values; }
				  private @NonNull List<? extends String> bounded(@NonNull List<? extends String> values) { return values; }
				}
				""");
		List<String> violations = findViolations(root);
		Assertions.assertEquals(8, violations.size(), () -> String.join("\n", violations));
		Assertions.assertTrue(violations.stream().anyMatch(value -> value.contains("array return component")));
		Assertions.assertTrue(violations.stream().anyMatch(value -> value.contains("primitiveArray parameter values")));
		Assertions.assertTrue(violations.stream().anyMatch(value -> value.contains("bounded return argument 0 upper bound")));
	}

	@Test
	void defaultsAndSameNamedAnnotationsCannotStandInForExplicitJSpecify(@TempDir @NonNull Path root)
			throws IOException {
		writeFixture(root, """
				package sample;
				import java.lang.annotation.ElementType;
				import java.lang.annotation.Target;
				import org.jspecify.annotations.NullMarked;
				@Target(ElementType.TYPE_USE) @interface NonNull { }
				@NullMarked class Fixture {
				  private String implicit(String value) { return value; }
				  private @NonNull String shadowed(@NonNull String value) { return value; }
				}
				""");
		Assertions.assertEquals(4, findViolations(root).size());
	}

	private static void writeFixture(@NonNull Path root, @NonNull String source) throws IOException {
		Path path = root.resolve("sample/Fixture.java");
		Files.createDirectories(path.getParent());
		Files.writeString(path, source, StandardCharsets.UTF_8);
	}

	static @NonNull List<@NonNull String> findViolations(@NonNull Path sourceRoot) throws IOException {
		return ContractSupport.analyze(sourceRoot, analysis -> {
			List<String> violations = new ArrayList<>();
			for (CompilationUnitTree unit : analysis.getCompilationUnits()) {
				new TreePathScanner<Void, Void>() {
					private @NonNull String owner(@NonNull Tree tree, @NonNull String member) {
						long position = analysis.getTrees().getSourcePositions().getStartPosition(unit, tree);
						return analysis.relativePath(unit) + ":" + unit.getLineMap().getLineNumber(position) + " " + member;
					}

					@Override
					public @Nullable Void visitMethod(@NonNull MethodTree method, @Nullable Void unused) {
						// Attribution synthesizes implicit constructors. Only source-declared signatures have an end position.
						if (analysis.getTrees().getSourcePositions().getEndPosition(unit, method) >= 0
								&& analysis.getTrees().getElement(getCurrentPath()) instanceof ExecutableElement executable) {
							String owner = owner(method, method.getName().toString());
							inspect(owner + " return", executable.getReturnType(), violations);
							for (VariableElement parameter : executable.getParameters())
								inspect(owner + " parameter " + parameter.getSimpleName(), parameter.asType(), violations);
						}
						return super.visitMethod(method, unused);
					}

					@Override
					public @Nullable Void visitVariable(@NonNull VariableTree variable, @Nullable Void unused) {
						if (getCurrentPath().getParentPath().getLeaf() instanceof ClassTree declaration
								&& declaration.getKind() == Tree.Kind.RECORD
								&& analysis.getTrees().getElement(getCurrentPath().getParentPath()) instanceof TypeElement record) {
							for (RecordComponentElement component : record.getRecordComponents())
								if (component.getSimpleName().contentEquals(variable.getName()))
									inspect(owner(variable, "record component " + component.getSimpleName()), component.asType(), violations);
						}
						return super.visitVariable(variable, unused);
					}
					}.scan(unit, null);
			}
			return List.copyOf(violations);
		});
	}

	private static void inspect(@NonNull String owner, @NonNull TypeMirror type,
			@NonNull List<@NonNull String> violations) {
		if (type.getKind().isPrimitive() || type.getKind() == TypeKind.VOID || type.getKind() == TypeKind.NONE)
			return;
		if (type instanceof WildcardType wildcard) {
			if (wildcard.getExtendsBound() != null)
				inspect(owner + " upper bound", wildcard.getExtendsBound(), violations);
			if (wildcard.getSuperBound() != null)
				inspect(owner + " lower bound", wildcard.getSuperBound(), violations);
			return;
		}
		Set<String> annotations = type.getAnnotationMirrors().stream()
				.map(annotation -> annotation.getAnnotationType().toString()).collect(Collectors.toSet());
		if (annotations.contains(NON_NULL) == annotations.contains(NULLABLE))
			violations.add(owner + ": expected exactly one JSpecify @NonNull/@Nullable");
		if (type instanceof DeclaredType declared) {
			for (int index = 0; index < declared.getTypeArguments().size(); index++)
				inspect(owner + " argument " + index, declared.getTypeArguments().get(index), violations);
		} else if (type instanceof ArrayType array)
			inspect(owner + " component", array.getComponentType(), violations);
	}
}
