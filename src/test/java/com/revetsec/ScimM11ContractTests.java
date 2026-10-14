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

import com.revetsec.scim.ScimPatchRequest;
import com.revetsec.scim.ScimPatchResult;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.CatchTree;
import com.sun.source.tree.ThrowTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import static org.junit.jupiter.api.Assertions.*;

/** Calibrated PATCH guards for direct outcomes, one passed budget, closed proof and pure construction. */
final class ScimM11ContractTests {
    @Test void patchHelpersNeverThrowCatchExpectedInputsOrRestartWorkBudgets() throws IOException {
        for(String file:List.of("ScimPatchParsing","ScimPatchEngine","ScimMembershipReduction"))
            assertDirect(parse(Files.readString(Path.of("src/main/java/com/revetsec/scim/"+file+".java"))));
    }
    @Test void parsedAndAppliedCarriersKeepTheirRegistrationProofPrivate() throws ReflectiveOperationException {
        assertPrivateProof(ScimPatchRequest.class);
        assertPrivateProof(ScimPatchResult.class);
    }
    @Test void patchCarrierConstructionCannotCallAnApplicationOrPerformIo() throws IOException {
        for(String file:List.of("ScimPatchOperationType","ScimPatchOperation","ScimPatchRequest","ScimPatchParseResult",
                "ScimPatchResult","ScimPatchApplicationResult","ScimMembershipPatch","ScimMembershipPatchResult"))
            assertPureConstructors(parse(Files.readString(Path.of("src/main/java/com/revetsec/scim/"+file+".java"))));
    }
    @Test void guardsRejectPlantedExceptionBudgetCallbackAndProofDefects() {
        assertThrows(AssertionError.class,()->assertDirect(parse("class Engine { void apply() { throw new IllegalArgumentException(); } }")));
        assertThrows(AssertionError.class,()->assertDirect(parse("class Engine { void apply() { try {} catch (RuntimeException e) {} } }")));
        assertThrows(AssertionError.class,()->assertDirect(parse("class Engine { Object apply() { return new ScimWork(10000); } }")));
        assertThrows(AssertionError.class,()->assertPureConstructors(parse("class Carrier { Carrier() { callback.apply(); } }")));
        assertThrows(AssertionError.class,()->assertPureConstructors(parse("class Carrier { Carrier() { reader.read(); } }")));
        UnsafeProof unsafe=new UnsafeProof();
        assertSame(unsafe.semanticContext,unsafe.getSemanticContext(),"The planted public accessor actually exposes its proof");
        assertThrows(AssertionError.class,()->assertPrivateProof(UnsafeProof.class));
    }
    private static void assertPrivateProof(@NonNull Class<?> type) throws ReflectiveOperationException {
        var proof=type.getDeclaredField("semanticContext");
        assertTrue(Modifier.isPrivate(proof.getModifiers()) && Modifier.isFinal(proof.getModifiers()));
        assertEquals(Object.class,proof.getType());
        var accessor=type.getDeclaredMethod("getSemanticContext");
        assertFalse(Modifier.isPublic(accessor.getModifiers()) || Modifier.isProtected(accessor.getModifiers()));
        for(var method:type.getDeclaredMethods())
            if(Modifier.isPublic(method.getModifiers())) assertNotEquals(Object.class,method.getReturnType(),"No public accessor exposes the proof");
    }
    private static @NonNull CompilationUnitTree parse(@NonNull String source) throws IOException {
        var input=new SimpleJavaFileObject(URI.create("string:///GuardInput.java"),JavaFileObject.Kind.SOURCE) {
            @Override public @NonNull CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
        };
        JavacTask task=(JavacTask)ToolProvider.getSystemJavaCompiler().getTask(null,null,null,List.of("-proc:none"),null,List.of(input));
        return task.parse().iterator().next();
    }
    private static void assertDirect(@NonNull Tree tree) {
        List<Tree> defects=new ArrayList<>();
        new TreeScanner<@Nullable Void,@Nullable Void>() {
            @Override public @Nullable Void visitThrow(@NonNull ThrowTree node,@Nullable Void ignored) { defects.add(node); return super.visitThrow(node,ignored); }
            @Override public @Nullable Void visitCatch(@NonNull CatchTree node,@Nullable Void ignored) { defects.add(node); return super.visitCatch(node,ignored); }
            @Override public @Nullable Void visitNewClass(@NonNull NewClassTree node,@Nullable Void ignored) {
                String type=node.getIdentifier().toString();
                if(type.equals("ScimWork") || type.equals("com.revetsec.scim.ScimWork")) defects.add(node);
                return super.visitNewClass(node,ignored);
            }
        }.scan(tree,null);
        assertTrue(defects.isEmpty(),"Pure PATCH helpers use direct rejection outcomes and the caller's original work budget");
    }
    private static void assertPureConstructors(@NonNull Tree tree) {
        Set<String> snapshots=Set.of("requireNonNull","Objects.requireNonNull","List.copyOf","Set.copyOf","Collections.unmodifiableSet");
        List<Tree> defects=new ArrayList<>();
        new TreeScanner<@Nullable Void,@Nullable Void>() {
            @Override public @Nullable Void visitMethod(@NonNull MethodTree node,@Nullable Void ignored) {
                if(node.getName().contentEquals("<init>")) {
                    new TreeScanner<@Nullable Void,@Nullable Void>() {
                        @Override public @Nullable Void visitMethodInvocation(@NonNull MethodInvocationTree call,@Nullable Void unused) {
                            if(!snapshots.contains(call.getMethodSelect().toString())) defects.add(call);
                            return super.visitMethodInvocation(call,unused);
                        }
                        @Override public @Nullable Void visitNewClass(@NonNull NewClassTree allocation,@Nullable Void unused) {
                            if(!allocation.getIdentifier().toString().startsWith("LinkedHashSet<")) defects.add(allocation);
                            return super.visitNewClass(allocation,unused);
                        }
                    }.scan(node.getBody(),null);
                    return null;
                }
                return super.visitMethod(node,ignored);
            }
        }.scan(tree,null);
        assertTrue(defects.isEmpty(),"Carrier construction contains only reviewed defensive snapshots and null checks");
    }
    private static final class UnsafeProof {
        private final @NonNull Object semanticContext=new Object();
        public @NonNull Object getSemanticContext() { return semanticContext; }
    }
}
