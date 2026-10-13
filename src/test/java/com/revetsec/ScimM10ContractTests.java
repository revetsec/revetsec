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

import static org.junit.jupiter.api.Assertions.*;

import com.sun.source.tree.CatchTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ThrowTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/** Calibrated guard: expected JSON input failures are direct outcomes before protocol handling. */
class ScimM10ContractTests {
    @Test
    void sharedJsonDirectParserNeverUsesThrowCatchForMalformedInput() throws IOException {
        var unit =
                parse(
                        Files.readString(
                                Path.of(
                                        "src/main/java/com/revetsec/internal/json/JsonCodec.java")));
        ClassTree codec = (ClassTree) unit.getTypeDecls().get(0);
        MethodTree direct =
                codec.getMembers().stream()
                        .filter(
                                t ->
                                        t instanceof MethodTree method
                                                && method.getName().contentEquals("parseResult"))
                        .map(t -> (MethodTree) t)
                        .findFirst()
                        .orElseThrow();
        assertDirect(direct);
        ClassTree parser =
                codec.getMembers().stream()
                        .filter(
                                t ->
                                        t instanceof ClassTree type
                                                && type.getSimpleName().contentEquals("Parser"))
                        .map(t -> (ClassTree) t)
                        .findFirst()
                        .orElseThrow();
        assertDirect(parser);
        MethodTree wrapper =
                codec.getMembers().stream()
                        .filter(
                                t ->
                                        t instanceof MethodTree method
                                                && method.getName().contentEquals("parse"))
                        .map(t -> (MethodTree) t)
                        .findFirst()
                        .orElseThrow();
        assertEquals(1, forbidden(wrapper).size());
        assertTrue(wrapper.toString().contains("parseResult(input, limits)"));
    }

    @Test
    void directParserGuardDetectsThrowAndCatchRegressions() {
        assertThrows(
                AssertionError.class,
                () ->
                        assertDirect(
                                parse(
                                        "class Parser { void parse() { throw new IllegalArgumentException(); } }")));
        assertThrows(
                AssertionError.class,
                () ->
                        assertDirect(
                                parse(
                                        "class Parser { void parse() { try {} catch (RuntimeException e) {} } }")));
    }

    private static com.sun.source.tree.@NonNull CompilationUnitTree parse(@NonNull String source)
            throws IOException {
        var file =
                new SimpleJavaFileObject(
                        URI.create("string:///Input.java"), JavaFileObject.Kind.SOURCE) {
                    @Override
                    public @NonNull CharSequence getCharContent(boolean ignoreEncodingErrors) {
                        return source;
                    }
                };
        JavacTask task =
                (JavacTask)
                        ToolProvider.getSystemJavaCompiler()
                                .getTask(
                                        null,
                                        null,
                                        null,
                                        List.of("-proc:none"),
                                        null,
                                        List.of(file));
        return task.parse().iterator().next();
    }

    private static void assertDirect(@NonNull Tree tree) {
        assertTrue(forbidden(tree).isEmpty());
    }

    private static @NonNull List<@NonNull Tree> forbidden(@NonNull Tree tree) {
        List<Tree> found = new ArrayList<>();
        new TreeScanner<@Nullable Void, @Nullable Void>() {
            @Override
            public @Nullable Void visitThrow(@NonNull ThrowTree node, @Nullable Void ignored) {
                found.add(node);
                return super.visitThrow(node, ignored);
            }

            @Override
            public @Nullable Void visitCatch(@NonNull CatchTree node, @Nullable Void ignored) {
                found.add(node);
                return super.visitCatch(node, ignored);
            }
        }.scan(tree, null);
        return found;
    }
}
