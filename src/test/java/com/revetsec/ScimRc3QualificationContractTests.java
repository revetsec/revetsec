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

import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import javax.tools.SimpleJavaFileObject;
import javax.tools.JavaFileObject;
import javax.tools.ToolProvider;
import java.net.URI;
import java.io.IOException;
import java.util.Locale;
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** CI checks the active SCIM invariant map; calibrated fixtures detect stale/empty mappings. */
class ScimRc3QualificationContractTests {
    private static @NonNull List<@NonNull String> violations(@NonNull List<@NonNull String> rows,@NonNull Map<@NonNull String,@NonNull String> sources) throws IOException {
        Set<String> ids=new HashSet<>(); List<String> errors=new ArrayList<>();
        for (String row:rows) {
            String[] columns=row.split("\\|",-1);
            if (columns.length!=5) { errors.add("Malformed invariant row"); continue; }
            String id=columns[1].trim();
            if (!ids.add(id)) errors.add("Duplicate invariant: "+id);
            String ref=columns[3].trim().replace("`",""); int marker=ref.lastIndexOf('.');
            if (marker<0) { errors.add("Missing method reference: "+id); continue; }
            String owner=ref.substring(0,marker), method=ref.substring(marker+1);
            if (owner.startsWith("scim.")) owner="com.revetsec."+owner;
            String source=sources.get(owner);
            if (source==null) { errors.add("Missing test source: "+id); continue; }
            boolean assertionTest=assertionTest(source,method);
            if (!assertionTest) errors.add("Missing assertion test: "+id);
        }
        Set<String> expected=new HashSet<>(); for (int index=1;index<=10;index++) expected.add("INV-M"+index);
        if (!ids.equals(expected)) errors.add("Active SCIM invariant set is incomplete or unexpected");
        return errors;
    }
    private static boolean assertionTest(@NonNull String source,@NonNull String method) throws IOException {
        var compiler=ToolProvider.getSystemJavaCompiler();
        if (compiler==null) throw new IllegalStateException("A JDK is required for source qualification");
        var file=new SimpleJavaFileObject(URI.create("string:///Fixture.java"),JavaFileObject.Kind.SOURCE) {
            @Override public @NonNull CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
        };
        boolean[] found={false};
        try (var manager=compiler.getStandardFileManager(null,Locale.ROOT,StandardCharsets.UTF_8)) {
            var task=(JavacTask)compiler.getTask(null,manager,null,List.of("-proc:none"),null,List.of(file));
            for (var unit:task.parse()) new TreeScanner<@Nullable Void,@Nullable Void>() {
                @Override public @Nullable Void visitMethod(@NonNull MethodTree node,@Nullable Void ignored) {
                    if (node.getName().contentEquals(method) && node.getModifiers().getAnnotations().stream()
                            .anyMatch(a -> a.getAnnotationType().toString().equals("Test"))) {
                        new TreeScanner<@Nullable Void,@Nullable Void>() {
                            @Override public @Nullable Void visitMethodInvocation(@NonNull MethodInvocationTree call,@Nullable Void value) {
                                var select=call.getMethodSelect();
                                String name=select instanceof IdentifierTree id ? id.getName().toString()
                                        : select instanceof MemberSelectTree member ? member.getIdentifier().toString() : "";
                                if (name.startsWith("assert")) found[0]=true;
                                return super.visitMethodInvocation(call,value);
                            }
                        }.scan(node.getBody(),null);
                    }
                    return super.visitMethod(node,ignored);
                }
            }.scan(unit,null);
        }
        return found[0];
    }
    @Test void everyActiveScimInvariantNamesARealAssertionBearingTest() throws Exception {
        var root=ContractSupport.repositoryRoot();
        String document=Files.readString(root.resolve("docs/threat-model.md"),StandardCharsets.UTF_8);
        List<String> rows=document.lines().filter(line -> line.startsWith("| INV-M")).toList();
        Map<String,String> sources=new HashMap<>();
        for (String row:rows) {
            String reference=row.split("\\|",-1)[3].trim().replace("`","");
            String owner="com.revetsec."+reference.substring(0,reference.lastIndexOf('.'));
            sources.put(owner,Files.readString(root.resolve("src/test/java/"+owner.replace('.','/')+".java"),StandardCharsets.UTF_8));
        }
        assertEquals(List.of(),violations(rows,sources));
    }
    private static @NonNull List<@NonNull String> fixtureRows() {
        List<String> rows=new ArrayList<>();
        for (int index=1;index<=10;index++) rows.add("| INV-M"+index+" | contract | `Fixture.checks` |");
        return rows;
    }
    @Test void missingDuplicateAndStaleRowsCannotPassTheMappingGuard() throws Exception {
        Map<String,String> sources=Map.of("Fixture","class Fixture { @Test void checks() { assertTrue(true); } }");
        List<String> complete=fixtureRows(); assertEquals(List.of(),violations(complete,sources));
        List<String> missing=new ArrayList<>(complete); missing.remove(0); assertFalse(violations(missing,sources).isEmpty());
        List<String> duplicate=new ArrayList<>(complete); duplicate.add(complete.get(0)); assertFalse(violations(duplicate,sources).isEmpty());
        List<String> stale=new ArrayList<>(complete); stale.set(0,stale.get(0).replace(".checks",".retired"));
        assertFalse(violations(stale,sources).isEmpty());
    }
    @Test void emptyOrUnannotatedMethodsAreNotAssertionEvidence() throws Exception {
        assertFalse(violations(fixtureRows(),Map.of("Fixture","class Fixture { @Test void checks() {} }")).isEmpty());
        assertFalse(violations(fixtureRows(),Map.of("Fixture","class Fixture { void checks() { assertTrue(true); } }")).isEmpty());
    }
}
