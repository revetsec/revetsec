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

import com.revetsec.ContractSupport.SourceAnalysis;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.util.ElementFilter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Source-attributed builder/value conventions, including calibrated negative fixtures. */
final class BuilderConventionsContractTests {
	@Test
	void exportedBuildersAndValueAccessorsFollowApprovedConventions() throws IOException {
		assertEquals(List.of(), findViolations(ContractSupport.repositoryRoot().resolve("src/main/java")));
	}

	@Test
	void rejectsMissingCrvOuterNonnullableAndPrimitiveDeclarations() throws IOException {
		List<String> violations = findViolations(ContractSupport.repositoryRoot()
				.resolve("src/test/resources/contract-fixtures/builder-conventions"));
		assertEquals(List.of(
				"com.revetsec.BuilderConventionsFixture#isReady(): primitive value return",
				"com.revetsec.BuilderConventionsFixture$Builder: missing CheckReturnValue",
				"com.revetsec.BuilderConventionsFixture$Builder#attempts(int): property argument must be nullable and boxed",
				"com.revetsec.BuilderConventionsFixture$Builder#put(java.lang.String): property argument must be nullable and boxed",
				"com.revetsec.BuilderConventionsFixture$Builder#token(java.lang.String): property argument must be nullable and boxed",
				"com.revetsec.BuilderConventionsFixture$Builder#values(java.util.List): property argument must be nullable and boxed").stream().sorted().toList(), violations);
	}

	static List<String> findViolations(Path sourceRoot) throws IOException {
		return ContractSupport.analyze(sourceRoot, BuilderConventionsContractTests::findViolations);
	}

	private static List<String> findViolations(SourceAnalysis analysis) {
		List<String> violations = new ArrayList<>();
		for (TypeElement type : ContractSupport.exportedTypes(analysis)) {
			String name = analysis.getElements().getBinaryName(type).toString();
			boolean builder = type.getSimpleName().contentEquals("Builder");
			if (builder && type.getAnnotationMirrors().stream().noneMatch(annotation ->
					annotation.getAnnotationType().toString().equals("com.google.errorprone.annotations.CheckReturnValue")))
				violations.add(name + ": missing CheckReturnValue");
			for (ExecutableElement method : ElementFilter.methodsIn(analysis.getElements().getAllMembers(type))) {
				if (!ContractSupport.isPublicOrProtected(method) || !analysis.isSourceAuthored(method)) continue;
				String description = name + "#" + analysis.describe(method);
				if (builder && method.getParameters().size() == 1
						&& analysis.getTypes().isSameType(analysis.getTypes().erasure(method.getReturnType()),
								analysis.getTypes().erasure(type.asType()))
						&& !(name.equals("com.revetsec.json.JsonObject$Builder")
								&& method.getSimpleName().contentEquals("putNull"))) {
					var parameter = method.getParameters().get(0).asType();
					boolean nullable = parameter.getAnnotationMirrors().stream().anyMatch(annotation ->
							annotation.getAnnotationType().toString().equals("org.jspecify.annotations.Nullable"));
					if (parameter.getKind().isPrimitive() || !nullable)
						violations.add(description + ": property argument must be nullable and boxed");
				}
				if (!method.getModifiers().contains(Modifier.STATIC) && method.getReturnType().getKind().isPrimitive()
						&& method.getReturnType().getKind() != TypeKind.VOID && !objectPrimitiveOverride(method, analysis))
					violations.add(description + ": primitive value return");
			}
		}
		violations.sort(null);
		return List.copyOf(violations);
	}

	private static boolean objectPrimitiveOverride(ExecutableElement method, SourceAnalysis analysis) {
		return method.getSimpleName().contentEquals("hashCode") && method.getParameters().isEmpty()
				|| method.getSimpleName().contentEquals("equals") && method.getParameters().size() == 1
				&& analysis.getTypes().isSameType(analysis.getTypes().erasure(method.getParameters().get(0).asType()),
						analysis.getElements().getTypeElement("java.lang.Object").asType());
	}
}
