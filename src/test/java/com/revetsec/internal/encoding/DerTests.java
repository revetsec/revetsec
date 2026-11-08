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


package com.revetsec.internal.encoding;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DerTests {
 @Test void exactBoundsMinimalLengthAndExpectedTag() {
  byte[] input={9,0x30,3,2,1,7,9};Der.Element sequence=Der.read(input,1,6,Der.SEQUENCE);assertEquals(0x30,sequence.getTag());assertEquals(3,sequence.getStart());assertEquals(6,sequence.getEnd());assertEquals(3,sequence.getLength());Der.Element integer=Der.read(input,sequence.getStart(),sequence.getEnd(),Der.INTEGER);assertEquals(5,integer.getStart());assertEquals(1,integer.getLength());input[5]=0;assertEquals(6,integer.getEnd());
 }
 @Test void malformedLengthsHaveFixedPayloadFreeErrors() {
  for(byte[] input:List.of(new byte[]{2},new byte[]{0x1f,0},new byte[]{0x30,(byte)0x80},new byte[]{0x30,(byte)0x81,0},new byte[]{0x30,(byte)0x81,0x7f},new byte[]{0x30,(byte)0x82,0,(byte)0x80},new byte[]{0x30,(byte)0x85,1,1,1,1,1},new byte[]{0x30,(byte)0x84,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff},new byte[]{0x30,1})) {IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->Der.read(input,0,input.length));assertEquals("The DER element is malformed.",failure.getMessage());assertNull(failure.getCause());}
  assertThrows(IllegalArgumentException.class,()->Der.read(new byte[]{2,0},0,2,Der.SEQUENCE));
 }
 @Test void writerAndReaderRetainAllExistingLengthForms() {
  for(int length:new int[]{0,1,127,128,255,256,65535,65536,16777216}) {byte[] input=new byte[1+Der.lengthOfLength(length)+length];input[0]=4;int start=Der.putLength(input,1,length);assertEquals(1+Der.lengthOfLength(length),start);Der.Element value=Der.read(input,0,input.length,Der.OCTET_STRING);assertEquals(start,value.getStart());assertEquals(length,value.getLength());assertEquals(input.length,value.getEnd());}
 }
}
