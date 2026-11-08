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


package com.revetsec.internal.pem;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DerFacadeTests {
 @Test void facadeRetainsBoundsAndItsExistingErrorVocabulary() throws PemException {
  byte[] input={0x30,3,2,1,7};Der.Element sequence=Der.read(input,0,input.length,Der.SEQUENCE),integer=Der.read(input,sequence.getStart(),sequence.getEnd(),Der.INTEGER);assertEquals(0x30,sequence.getTag());assertEquals(2,sequence.getStart());assertEquals(5,sequence.getEnd());assertEquals(3,sequence.getLength());assertEquals(4,integer.getStart());assertEquals(1,integer.getLength());
  for(byte[] bad:List.of(new byte[]{2},new byte[]{0x1f,0},new byte[]{0x30,(byte)0x80},new byte[]{0x30,(byte)0x81,1},new byte[]{0x30,3,1})) {PemException failure=assertThrows(PemException.class,()->Der.read(bad,0,bad.length));assertEquals(PemException.Kind.MALFORMED_DER,failure.getKind());assertNull(failure.getCause());}
  assertEquals(PemException.Kind.MALFORMED_DER,assertThrows(PemException.class,()->Der.read(new byte[]{2,0},0,2,Der.SEQUENCE)).getKind());
 }
 @Test void writerDelegatesAndLegacyRangeBehaviorIsPreserved() throws PemException {
  byte[] input=new byte[132];input[0]=4;assertEquals(3,Der.putLength(input,1,129));assertEquals(2,Der.lengthOfLength(129));assertEquals(129,Der.read(input,0,input.length,Der.OCTET_STRING).getLength());
  assertThrows(ArrayIndexOutOfBoundsException.class,()->Der.read(new byte[2],-1,2));assertThrows(ArrayIndexOutOfBoundsException.class,()->Der.read(new byte[2],2,9));
 }
}
