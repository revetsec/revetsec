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
package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Separate JVM/restart rehearsal of an application-owned, single-writer public-fact file fixture. */
final class OAuthIssuerPublicationHistoryTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-11-01T12:00:00Z");
 private static @NonNull Instant at(long seconds){return NOW.plusSeconds(seconds);}
 private static final class Worker implements AutoCloseable {
  final @NonNull Process process;final @NonNull PrintWriter commands;final @NonNull BufferedReader replies;final @NonNull ExecutorService reads=Executors.newSingleThreadExecutor();final @NonNull Path transcript;
  Worker(@NonNull Path root,@NonNull String name,boolean admitted) throws Exception {
   this.transcript=root.resolve(name+".transcript");List<String> command=new ArrayList<>();command.add(Path.of(System.getProperty("java.home"),"bin","java").toString());
   command.addAll(ManagementFactory.getRuntimeMXBean().getInputArguments().stream().filter(a->a.startsWith("-javaagent:")&&a.contains("org.jacoco.agent")).toList());
   command.addAll(List.of("-cp",System.getProperty("java.class.path"),OAuthIssuerPublicationCase.class.getName(),root.resolve("provider").toAbsolutePath().toString(),Boolean.toString(admitted)));
   this.process=new ProcessBuilder(command).redirectError(root.resolve(name+".stderr").toFile()).start();this.commands=new PrintWriter(this.process.getOutputStream(),true,StandardCharsets.UTF_8);this.replies=new BufferedReader(new InputStreamReader(this.process.getInputStream(),StandardCharsets.UTF_8));
   Files.writeString(this.transcript,"pid="+this.process.pid()+" admitted="+admitted+"\n");
  }
  @NonNull String call(@NonNull String action,@NonNull Instant now,@NonNull Instant expiry) throws Exception {
   String command=action+" "+now+" "+expiry;this.commands.println(command);assertFalse(this.commands.checkError());String reply=requireNonNull(this.reads.submit(this.replies::readLine).get(10,TimeUnit.SECONDS));Files.writeString(this.transcript,command+" -> "+reply+"\n",java.nio.file.StandardOpenOption.APPEND);return reply;
  }
  @NonNull String sign(@NonNull Instant now) throws Exception{return call("SIGN",now,now.plusSeconds(300));}
  @NonNull String snapshot(@NonNull Instant now) throws Exception{return call("SNAP",now,now.plusSeconds(300));}
  @Override public void close(){try{this.commands.println("EXIT");if(!this.process.waitFor(10,TimeUnit.SECONDS)){this.process.destroyForcibly();assertTrue(this.process.waitFor(10,TimeUnit.SECONDS));}assertEquals(0,this.process.exitValue());}catch(InterruptedException failure){this.process.destroyForcibly();Thread.currentThread().interrupt();throw new AssertionError(failure);}finally{this.commands.close();this.reads.shutdownNow();}}
 }
 private static @NonNull Path directory(@NonNull String name) throws Exception{return Files.createTempDirectory(Path.of("target"),"issuer-publication-"+name+"-");}
 private static @NonNull OAuthIssuerPublicationFixture initial(@NonNull Path directory) throws Exception {var provider=new OAuthIssuerPublicationFixture(directory.resolve("provider"));provider.publish("a",Set.of("a"),at(-120),Map.of("a",at(1000)));return provider;}
 private static void staged(@NonNull OAuthIssuerPublicationFixture p) throws Exception {p.publish("a",Set.of("a","b"),at(40),Map.of("a",at(1000),"b",at(2000)));}
 private static void activated(@NonNull OAuthIssuerPublicationFixture p) throws Exception {p.publish("b",Set.of("a","b"),at(100),Map.of("a",at(1000),"b",at(2000)));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> independentProcessesAndRestartKeepPublicationAndRetentionObligations(){return Stream.of(false,true).map(admitted->DynamicTest.dynamicTest("authority-history="+admitted,()->{
  Path root=directory("rollover");var publisher=initial(root);
  try(Worker a=new Worker(root,"node-a",admitted);Worker b=new Worker(root,"node-b",admitted)){
   assertNotEquals(a.process.pid(),b.process.pid());assertEquals("SIGNED a verified",a.sign(at(0)));assertEquals("SIGNED a verified",b.sign(at(30)));
   staged(publisher);assertEquals("KEYS a,b",a.snapshot(at(40)));activated(new OAuthIssuerPublicationFixture(root.resolve("provider")));
   assertEquals("SIGNED b verified",a.sign(at(100)));assertEquals("UNAVAILABLE INFRASTRUCTURE",b.sign(at(100)));
   try(Worker restart=new Worker(root,"restarted-node",admitted)){
    assertNotEquals(a.process.pid(),restart.process.pid());assertEquals("UNAVAILABLE INFRASTRUCTURE",restart.sign(at(160).minusNanos(1)));assertEquals("SIGNED b verified",restart.sign(at(160)));assertEquals("KEYS a,b",restart.snapshot(at(160)));
   }
   var controller=new OAuthIssuerPublicationFixture(root.resolve("provider"));byte[] before=Files.readAllBytes(root.resolve("provider/current.properties"));
   assertThrows(IllegalArgumentException.class,()->controller.publish("b",Set.of("b"),at(1000).minusNanos(1),Map.of("b",at(2000))));assertArrayEquals(before,Files.readAllBytes(root.resolve("provider/current.properties")));
   controller.publish("b",Set.of("b"),at(1000),Map.of("b",at(2000)));assertEquals("KEYS b",a.snapshot(at(1000)));assertEquals("KEYS b",b.snapshot(at(1000)));
   try(Worker fresh=new Worker(root,"after-retirement",admitted)){assertEquals("KEYS b",fresh.snapshot(at(1000)));}
  }
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> restartedControllerRejectsHistoryLossAndShortening(){return Stream.of("shorten","omit","reuse","same-time","artifact").map(mode->DynamicTest.dynamicTest(mode,()->{
  Path root=directory(mode);var publisher=initial(root);staged(publisher);var controller=new OAuthIssuerPublicationFixture(root.resolve("provider"));byte[] before=Files.readAllBytes(root.resolve("provider/current.properties"));
  switch(mode){
   case "shorten"->assertThrows(IllegalArgumentException.class,()->controller.publish("b",Set.of("a","b"),at(100),Map.of("a",at(999),"b",at(2000))));
   case "omit"->assertThrows(IllegalArgumentException.class,()->controller.publish("b",Set.of("b"),at(100),Map.of("b",at(2000))));
   case "same-time"->assertThrows(IllegalArgumentException.class,()->controller.publish("a",Set.of("a","b"),at(40),Map.of("a",at(1000),"b",at(2000))));
   case "reuse"->{var state=controller.state();state.setProperty("material.a","different-material");try(var out=Files.newBufferedWriter(root.resolve("provider/current.properties"))){state.store(out,"deliberate material conflict");}assertThrows(IllegalArgumentException.class,()->controller.publish("a",Set.of("a","b"),at(100),Map.of("a",at(1000),"b",at(2000))));return;}
   default->{Files.writeString(root.resolve("provider/g2.jwks.json"),"{}");try(Worker fresh=new Worker(root,"missing-publication",true)){assertEquals("UNAVAILABLE INFRASTRUCTURE",fresh.sign(at(100)));}return;}
  }
  assertArrayEquals(before,Files.readAllBytes(root.resolve("provider/current.properties")));
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unavailableOrDamagedDurableFactsNeverInventAnInitialSnapshot(){return Stream.of("manifest","artifact","material","malformed").map(mode->DynamicTest.dynamicTest(mode,()->{
  Path root=directory("lost-"+mode);var publisher=initial(root);
  switch(mode){
   case "manifest"->Files.delete(root.resolve("provider/current.properties"));case "artifact"->Files.delete(root.resolve("provider/g1.jwks.json"));
   case "material"->{var state=publisher.state();state.setProperty("material.a","wrong-material");try(var out=Files.newBufferedWriter(root.resolve("provider/current.properties"))){state.store(out,"deliberate invalid material");}}
   default->Files.writeString(root.resolve("provider/current.properties"),"invalid=true");
  }
  try(Worker fresh=new Worker(root,"lost-facts",true)){assertEquals("UNAVAILABLE INFRASTRUCTURE",fresh.sign(at(0)));}
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> firstSnapshotCannotRecoverHistoryOmittedByAnUnsupportedProvider(){return Stream.of(false,true).map(admitted->DynamicTest.dynamicTest("unsupported-provider authority-history="+admitted,()->{
  Path root=directory("unsupported");var publisher=initial(root);
  try(Worker warm=new Worker(root,"observed-history",admitted)){
   assertEquals("SIGNED a verified",warm.sign(at(0)));staged(publisher);assertEquals("KEYS a,b",warm.snapshot(at(40)));activated(publisher);assertEquals("SIGNED b verified",warm.sign(at(100)));
   publisher.unsupportedOmission(at(200),at(2000));assertEquals("UNAVAILABLE INFRASTRUCTURE",warm.snapshot(at(260)));
   try(Worker fresh=new Worker(root,"no-inherited-history",admitted)){
    assertEquals("KEYS b",fresh.snapshot(at(260)));assertEquals("SIGNED b verified",fresh.sign(at(260)));
    // a's earlier candidate expires at +300 and its promised retention is +1000: omission violates the provider contract.
    assertTrue(at(260).isBefore(at(300)));assertTrue(at(260).isBefore(at(1000)));
   }
  }
 }));}
}
