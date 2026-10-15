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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.InetAddress;
import java.time.Duration;
import java.util.AbstractList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import static org.junit.jupiter.api.Assertions.*;

/** Cooperative interruption at the two caller-owned iterator boundaries; no resolver or network is used. */
final class PinnedHttpsAddressesRc1MutationTests {
 @Test void interruptionAfterNextWinsBeforeTheExplicitNullAnswerRejection() throws Exception {
  try {
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsAddresses.checked(interruptingAnswers(true),16,Deadline.fromNow(Duration.ofSeconds(1))));
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,failure.getKind());assertTrue(Thread.currentThread().isInterrupted());
  } finally {Thread.interrupted();}
 }
 @Test void interruptionAtTheEndOfTheIteratorCannotPublishAdmittedAnswers() throws Exception {
  try {
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsAddresses.checked(interruptingAnswers(false),16,Deadline.fromNow(Duration.ofSeconds(1))));
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,failure.getKind());assertTrue(Thread.currentThread().isInterrupted());
  } finally {Thread.interrupted();}
 }
 @SuppressWarnings("unchecked")
 private static @NonNull List<@NonNull InetAddress> interruptingAnswers(boolean nullAnswer) throws Exception {
  InetAddress numeric=InetAddress.getByAddress(new byte[]{8,8,8,8});
  List<@Nullable InetAddress> answers=new AbstractList<>(){
   @Override public int size(){return 1;}
   @Override public @Nullable InetAddress get(int index){if(index!=0)throw new IndexOutOfBoundsException();return nullAnswer?null:numeric;}
   @Override public @NonNull Iterator<@Nullable InetAddress> iterator(){return new Iterator<>(){
    private boolean returned;
    @Override public boolean hasNext(){if(this.returned&&!nullAnswer)Thread.currentThread().interrupt();return !this.returned;}
    @Override public @Nullable InetAddress next(){if(this.returned)throw new NoSuchElementException();this.returned=true;if(nullAnswer)Thread.currentThread().interrupt();return nullAnswer?null:numeric;}
   };}
  };
  // An intentionally null element exercises the implementation's explicit defensive null-answer check.
  return (List<@NonNull InetAddress>)(List<?>)answers;
 }
}
