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
package com.revetsec.testing;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/** Private instrumentation of the existing post-validation backing-map copy, never a clock seam. */
@ThreadSafe
public final class StoreCommitPause implements AutoCloseable {
 private final @NonNull CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
 private final @NonNull AtomicBoolean paused=new AtomicBoolean(),protectedAtPause=new AtomicBoolean();
 private final @NonNull AtomicReference<@Nullable Thread> writer=new AtomicReference<>();
 private final @NonNull AtomicReference<@Nullable StackTraceElement> callSite=new AtomicReference<>();
 private final @NonNull List<@NonNull String> trace;
 private final @NonNull BooleanSupplier ownsProtection;
 private final @NonNull Object installedMap;
 private StoreCommitPause(@NonNull Object receiver,@NonNull String fieldName,@NonNull List<@NonNull String> trace,@NonNull BooleanSupplier ownsProtection)throws ReflectiveOperationException{
  this.trace=trace;this.ownsProtection=ownsProtection;var field=receiver.getClass().getDeclaredField(fieldName);field.setAccessible(true);Object original=Objects.requireNonNull(field.get(receiver));if(!(original instanceof Map<?,?> map)||map.isEmpty())throw new IllegalArgumentException("Expected nonempty isolated fixture backing map");Map<Object,Object> copy=new HashMap<>();for(var entry:map.entrySet())copy.put(Objects.requireNonNull(entry.getKey()),Objects.requireNonNull(entry.getValue()));this.installedMap=new PausingMap(copy,this);field.set(receiver,this.installedMap);
 }
 public static @NonNull StoreCommitPause install(@NonNull Object receiver,@NonNull String fieldName,@NonNull List<@NonNull String> trace,@NonNull BooleanSupplier ownsProtection)throws ReflectiveOperationException{return new StoreCommitPause(receiver,fieldName,trace,ownsProtection);}
 public void selectCurrentWriter(){if(!this.writer.compareAndSet(null,Thread.currentThread()))throw new IllegalStateException("Pause writer already selected");}
 public boolean awaitEntered()throws InterruptedException{return this.entered.await(3,TimeUnit.SECONDS);}
 public boolean wasProtected(){return this.protectedAtPause.get();}
 public @NonNull StackTraceElement getCallSite(){return Objects.requireNonNull(this.callSite.get());}
 public @NonNull Object installedMap(){return this.installedMap;}
 public void resume(){this.trace.add("release-copy");this.release.countDown();}
 @Override public void close(){this.release.countDown();}
 private void copy(){
  if(!Thread.currentThread().equals(this.writer.get())||!this.paused.compareAndSet(false,true))return;
  this.protectedAtPause.set(this.ownsProtection.getAsBoolean());for(StackTraceElement frame:Thread.currentThread().getStackTrace())if(frame.getMethodName().equals("compareAndCommit")||frame.getMethodName().equals("commit")){this.callSite.set(frame);break;}
  this.trace.add("validated-copy-paused");this.entered.countDown();try{if(!this.release.await(8,TimeUnit.SECONDS))throw new AssertionError("Post-validation pause was not released");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new AssertionError("Post-validation pause interrupted",interrupted);}this.trace.add("copy-resumed");
 }
 @ThreadSafe private static final class PausingMap extends AbstractMap<@NonNull Object,@NonNull Object> {
  private final @NonNull Map<@NonNull Object,@NonNull Object> data;
  private final @NonNull StoreCommitPause owner;
  PausingMap(@NonNull Map<@NonNull Object,@NonNull Object> data,@NonNull StoreCommitPause owner){this.data=data;this.owner=owner;}
  @Override public @NonNull Set<Map.@NonNull Entry<@NonNull Object,@NonNull Object>> entrySet(){this.owner.copy();return this.data.entrySet();}
  @Override public @NonNull Set<@NonNull Object> keySet(){return this.data.keySet();}
  @Override public int size(){return this.data.size();}
  @Override public boolean containsKey(@Nullable Object key){return this.data.containsKey(key);}
  @Override public @Nullable Object get(@Nullable Object key){return this.data.get(key);}
  @Override public @Nullable Object put(@NonNull Object key,@NonNull Object value){return this.data.put(key,value);}
  @Override public @Nullable Object remove(@Nullable Object key){return this.data.remove(key);}
  @Override public void clear(){this.data.clear();}
 }
}
