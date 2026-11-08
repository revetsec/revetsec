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


package com.revetsec.internal.crypto;

import org.junit.jupiter.api.DynamicTest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.TestFactory;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class EcdsaSignaturesDerTests {
 @TestFactory @NonNull List<@NonNull DynamicTest> canonicalDerRoundTripsEveryExistingCurveAndRetainsHighS() {
  List<DynamicTest> tests=new ArrayList<>();
  for(EcCurve curve:EcCurve.values()) for(BigInteger r:List.of(BigInteger.ONE,curve.getOrder().subtract(BigInteger.ONE))) for(BigInteger s:List.of(BigInteger.ONE,curve.getOrder().subtract(BigInteger.ONE))) tests.add(DynamicTest.dynamicTest(curve+" r="+r.bitLength()+" s="+s.bitLength(),()->{
   byte[] raw=new byte[curve.getSignatureLength()];put(r,raw,0,curve.getCoordinateLength());put(s,raw,curve.getCoordinateLength(),curve.getCoordinateLength());byte[] der=EcdsaSignatures.toDer(curve,raw),before=der.clone();assertArrayEquals(raw,EcdsaSignatures.toJose(curve,der));assertArrayEquals(before,der);assertEquals(s,new BigInteger(1,Arrays.copyOfRange(EcdsaSignatures.toJose(curve,der),curve.getCoordinateLength(),raw.length)));
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> refusesMalformedGrammarZeroAndOrderBeforeOutput() {
  List<DynamicTest> tests=new ArrayList<>();
  for(EcCurve curve:EcCurve.values()) {
   List<byte[]> cases=new ArrayList<>(List.of(new byte[0],new byte[]{0x30,6,2,1,0,2,1,1},new byte[]{0x30,6,2,1,1,2,1,0},new byte[]{0x30,7,2,2,0,1,2,1,1},new byte[]{0x30,6,2,1,(byte)0x80,2,1,1},new byte[]{0x30,6,2,1,1,2,1,1,0},new byte[]{0x30,9,2,1,1,2,1,1,2,1,1},new byte[]{0x30,(byte)0x81,6,2,1,1,2,1,1},new byte[]{0x30,(byte)0x80,2,1,1,2,1,1},new byte[]{0x31,6,2,1,1,2,1,1},new byte[]{0x30,6,3,1,1,2,1,1},new byte[4096]));
   byte[] raw=new byte[curve.getSignatureLength()];put(curve.getOrder(),raw,0,curve.getCoordinateLength());put(BigInteger.ONE,raw,curve.getCoordinateLength(),curve.getCoordinateLength());cases.add(EcdsaSignatures.toDer(curve,raw));
   put(BigInteger.ONE,raw,0,curve.getCoordinateLength());put(curve.getOrder(),raw,curve.getCoordinateLength(),curve.getCoordinateLength());cases.add(EcdsaSignatures.toDer(curve,raw));
   for(int index=0;index<cases.size();index++){byte[] der=cases.get(index);int selected=index;tests.add(DynamicTest.dynamicTest(curve+" malformed="+selected,()->{byte[] before=der.clone();IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->EcdsaSignatures.toJose(curve,der));assertEquals("The ECDSA signature is not canonical DER on the curve.",failure.getMessage());assertNull(failure.getCause());assertArrayEquals(before,der);}));}
  }return tests;
 }
 private static void put(@NonNull BigInteger value,byte @NonNull [] out,int offset,int width){byte[] bytes=value.toByteArray();int start=bytes.length>width?1:0;Arrays.fill(out,offset,offset+width,(byte)0);System.arraycopy(bytes,start,out,offset+width-(bytes.length-start),bytes.length-start);}
}
