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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

/** PEM-specific error adapter for the single shared bounded DER reader/writer. */
@ThreadSafe
final class Der {
 static final int INTEGER=com.revetsec.internal.encoding.Der.INTEGER;
 static final int BIT_STRING=com.revetsec.internal.encoding.Der.BIT_STRING;
 static final int OCTET_STRING=com.revetsec.internal.encoding.Der.OCTET_STRING;
 static final int NULL=com.revetsec.internal.encoding.Der.NULL;
 static final int OBJECT_IDENTIFIER=com.revetsec.internal.encoding.Der.OBJECT_IDENTIFIER;
 static final int SEQUENCE=com.revetsec.internal.encoding.Der.SEQUENCE;
 static final int CONTEXT_0_CONSTRUCTED=com.revetsec.internal.encoding.Der.CONTEXT_0_CONSTRUCTED;
 static final int CONTEXT_1_PRIMITIVE=com.revetsec.internal.encoding.Der.CONTEXT_1_PRIMITIVE;
 private Der() { }
 @Immutable static final class Element {
  private final com.revetsec.internal.encoding.Der.@NonNull Element bounds;
  private Element(com.revetsec.internal.encoding.Der.@NonNull Element bounds){this.bounds=bounds;}
  int getTag(){return this.bounds.getTag();}int getStart(){return this.bounds.getStart();}int getEnd(){return this.bounds.getEnd();}int getLength(){return this.bounds.getLength();}
 }
 static @NonNull Element read(byte @NonNull [] der,int offset,int limit)throws PemException {
  try{return new Element(com.revetsec.internal.encoding.Der.read(der,offset,limit));}
  catch(IllegalArgumentException malformed){throw new PemException(PemException.Kind.MALFORMED_DER);}
 }
 static @NonNull Element read(byte @NonNull [] der,int offset,int limit,int tag)throws PemException {
  try{return new Element(com.revetsec.internal.encoding.Der.read(der,offset,limit,tag));}
  catch(IllegalArgumentException malformed){throw new PemException(PemException.Kind.MALFORMED_DER);}
 }
 static int lengthOfLength(int length){return com.revetsec.internal.encoding.Der.lengthOfLength(length);}
 static int putLength(byte @NonNull [] out,int position,int length){return com.revetsec.internal.encoding.Der.putLength(out,position,length);}
}
