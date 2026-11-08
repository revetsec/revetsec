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
package com.revetsec.jose;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.lang.management.ManagementFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Corretto/HotSpot allocation-profile qualification of the typed preflight before expanded JSON writing. */
final class JwsSignerPreflightResourceTests {
 @Test void sharedStringTreeIsRefusedBeforeWriterAllocationOnTheRequiredHotSpotProfile(){
  var allocations=assertInstanceOf(com.sun.management.ThreadMXBean.class,ManagementFactory.getThreadMXBean(),"Required current-thread allocation profile unavailable");
  assertTrue(allocations.isThreadAllocatedMemorySupported());assertTrue(allocations.isThreadAllocatedMemoryEnabled());
  var fixture=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
  var signer=JwsSigner.fromRsaKeyPair(fixture.getPrivateKey(),fixture.getPublicKey(),JwsAlgorithm.RS256);
  var header=JwtSigningHeader.fromType(JwtType.JWT);
  String control=signer.withHeaderAndClaims(header,JwtClaimsSet.builder().claim("control",true).build()).remainingBudget(Duration.ofSeconds(5)).build();
  assertEquals(3,control.split("\\.",-1).length);
  JsonValue tree=JsonString.fromValue("a".repeat(1024));int expanded=1026;
  for(int n=0;n<12;n++){tree=JsonArray.fromElements(List.of(tree,tree));expanded=2+2*expanded+1;}
  var claims=JwtClaimsSet.builder().claim("data",tree).build();expanded+=9;
  assertEquals(4_214_790,expanded); // Scalar depth1 + twelve arrays + the claims object: depth14.
  for(int n=0;n<10;n++)refuse(signer,header,claims);
  List<Long> samples=new ArrayList<>(7);
  for(int n=0;n<7;n++){
   long before=allocations.getCurrentThreadAllocatedBytes();refuse(signer,header,claims);long after=allocations.getCurrentThreadAllocatedBytes();
   assertTrue(before>=0&&after>=before,"Required current-thread allocation counter must be available and monotonic");
   samples.add(after-before);
  }
  System.out.println("SIGNING_PREFLIGHT expandedUtf8Bytes="+expanded+" depth=14 allocatedBytes="+samples);
  for(long sample:samples)assertTrue(sample<1_048_576L,()->"Typed preflight allocated "+sample+" bytes before refusing the prebuilt shared tree");
 }
 private static void refuse(@NonNull JwsSigner signer,@NonNull JwtSigningHeader header,@NonNull JwtClaimsSet claims){
  try{String unexpected=signer.withHeaderAndClaims(header,claims).remainingBudget(Duration.ofSeconds(5)).build();throw new AssertionError("Oversized shared input emitted "+unexpected.length()+" credential characters");}
  catch(IllegalArgumentException expected){/* Direct input refusal is required before writer allocation. */}
 }
}
