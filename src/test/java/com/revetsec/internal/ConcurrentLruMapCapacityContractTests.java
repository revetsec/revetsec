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
package com.revetsec.internal;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** The reused map is approximate in capacity; its sole production owner supplies strict admission. */
final class ConcurrentLruMapCapacityContractTests {
 @TestFactory @NonNull Stream<@NonNull DynamicTest> pausedMaintenanceAllowsPublicationBeyondTheRawCapacityTarget(){return Stream.of("put","putIfAbsent","computeIfAbsent").map(operation->DynamicTest.dynamicTest(operation,()->{
  List<Integer> evictions=new ArrayList<>();var map=new ConcurrentLruMap<Integer,String>(1,(key,value)->evictions.add(key));var field=ConcurrentLruMap.class.getDeclaredField("maintenanceLock");field.setAccessible(true);ReentrantLock lock=(ReentrantLock)field.get(map);CountDownLatch held=new CountDownLatch(1),release=new CountDownLatch(1);Thread owner=new Thread(()->{lock.lock();try{held.countDown();assertTrue(await(release));}finally{lock.unlock();}});owner.setDaemon(true);owner.start();
  try{
   assertTrue(held.await(5,TimeUnit.SECONDS));for(int i=0;i<32;i++){int key=i;switch(operation){case "put"->assertNull(map.put(key,"value"));case "putIfAbsent"->assertNull(map.putIfAbsent(key,"value"));default->assertEquals("value",map.computeIfAbsent(key,k->"value"));}}
   assertEquals(32,map.size());assertTrue(map.size()>map.capacity());var pending=ConcurrentLruMap.class.getDeclaredField("writeBufferSize");pending.setAccessible(true);assertEquals(32,((AtomicInteger)pending.get(map)).get());assertTrue(evictions.isEmpty());
  }finally{release.countDown();owner.join(5000);assertFalse(owner.isAlive());}
  map.drain();assertEquals(1,map.size());assertEquals(31,evictions.size());assertEquals(31,map.keysInAccessOrder().get(0));map.drain();assertEquals(31,evictions.size());
 }));}
 private static boolean await(@NonNull CountDownLatch latch){try{return latch.await(10,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();return false;}}
 @Test void productionUseIsRestrictedToTheSerializedCache() throws Exception {
  Path root=Path.of("src/main/java");List<String> users;
  try(var files=Files.walk(root)){users=files.filter(f->f.toString().endsWith(".java")).filter(f->{try{return Files.readString(f).contains("ConcurrentLruMap");}catch(java.io.IOException e){throw new java.io.UncheckedIOException(e);}}).map(f->root.relativize(f).toString().replace(java.io.File.separatorChar, '/')).sorted().toList();}
  assertEquals(List.of("com/revetsec/internal/ConcurrentLruMap.java","com/revetsec/oauth/server/InMemoryOAuthClientMetadataCache.java"),users);
  var owner=com.revetsec.oauth.server.InMemoryOAuthClientMetadataCache.class;assertTrue(Modifier.isFinal(owner.getModifiers()));var field=owner.getDeclaredField("entries");assertEquals(ConcurrentLruMap.class,field.getType());assertTrue(Modifier.isPrivate(field.getModifiers()));assertTrue(Modifier.isFinal(field.getModifiers()));
  for(var method:owner.getMethods())assertFalse(java.util.Map.class.isAssignableFrom(method.getReturnType()),"The raw map must not escape its owner");
 }
}
