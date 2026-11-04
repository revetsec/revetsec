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

package com.revetsec.internal.webauthn;
import com.revetsec.*;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.internal.crypto.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.revetsec.internal.crypto.MigrationCodecTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-04 WAR1 admin/WAR2 native payload and authenticated chunk/framing matrix. */
final class WebAuthnMigrationCorruptionConformanceTests {
 @Test void corpusAndAllApplicablePositiveControls()throws Exception{verifyCorpus();for(Spec s:specs("WEBAUTHN")){open(s,frame(s,s.bytes(),"payload"),new byte[]{1});if(s.format()==1)open(s,frame(s,s.bytes(),"payload"),new byte[128]);}}
 @TestFactory @NonNull List<@NonNull DynamicTest> normalAuthenticatedCorruptions(){return corruptionTests(true);}
 @TestFactory @NonNull List<@NonNull DynamicTest> closedMigrationAuthenticatedCorruptions(){return corruptionTests(false);}
 private @NonNull List<@NonNull DynamicTest> corruptionTests(boolean normal){List<DynamicTest> tests=new ArrayList<>();for(Case c:cases("WEBAUTHN"))if((c.spec().format()==2)==normal)tests.add(DynamicTest.dynamicTest(c.name(),()->{if(c.op().equals("cas-length"))assertThrows(IllegalArgumentException.class,()->open(c.spec(),frame(c.spec(),c.body(),"payload"),new byte[Integer.parseInt(c.get("value"))]));else assertThrows(WebAuthnRecordException.class,()->open(c.spec(),frame(c.spec(),c.body(),c.op()),new byte[]{1}));}));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedLegacyHasNoNormalFallback(){List<DynamicTest> tests=new ArrayList<>();for(Spec s:specs("WEBAUTHN"))if(s.format()==1)tests.add(DynamicTest.dynamicTest("MIG-04/no-fallback/"+s.name(),()->{byte[] old=frame(s,s.bytes(),"payload");open(s,old,new byte[]{1});assertThrows(WebAuthnRecordException.class,()->new WebAuthnRecordCodecV2(sealer()).open(WebAuthnStoreKey.fromStoredForm(s.get("key")),old,CLOCK));}));return tests;}
 private static void open(@NonNull Spec s,byte @NonNull [] raw,byte @NonNull [] version)throws Exception{
  var key=WebAuthnStoreKey.fromStoredForm(s.get("key"));
  if(s.format()==2){try(var decoded=new WebAuthnRecordCodecV2(sealer()).openRecord(key,raw,CLOCK)){assertNotNull(decoded);}}
  else{var migration=new WebAuthnRecordMigration(sealer());var intent=ClosedMigrationIntent.fromExternalIntent(s.get("migrationId"),StoreAdmission.fromIdentifiers(s.get("authority"),s.get("recovery")),Set.of(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));byte[] root=rawFrame(s,s.get("rootKey"),HexFormat.of().parseHex(s.get("rootPlain")),"payload");var anchor=migration.authenticateRoot(intent,s.get("rootKey"),root);if(s.get("kind").equals("NAMESPACE_CLOCK"))anchor=migration.authenticateRoot(intent,s.get("key"),raw);migration.prepare(intent,anchor,s.get("key"),version,raw);}
 }
 private static byte @NonNull [] frame(@NonNull Spec s,byte @NonNull [] body,@NonNull String op)throws Exception{
  byte[] result=rawFrame(s,s.get("key"),body,op);switch(op){
   case "frame-magic":result[3]='9';break;case "frame-count-zero":ByteBuffer.wrap(result).putShort(4,(short)0);break;case "frame-count-257":ByteBuffer.wrap(result).putShort(4,(short)257);break;case "frame-size-zero":ByteBuffer.wrap(result).putShort(6,(short)0);break;case "frame-size-over":ByteBuffer.wrap(result).putShort(6,(short)65535);break;case "frame-id":result[8]^=1;break;
   case "frame-trailing":result=Arrays.copyOf(result,result.length+1);break;case "frame-truncation":result=Arrays.copyOf(result,result.length-1);break;
   case "swap-chunks":{int first=Short.toUnsignedInt(ByteBuffer.wrap(result).getShort(24));int second=26+first;int length=Short.toUnsignedInt(ByteBuffer.wrap(result).getShort(second));assertEquals(first,length);byte[] copy=result.clone();System.arraycopy(copy,second+2,result,26,first);System.arraycopy(copy,26,result,second+2,first);break;}
   case "splice-chunks":{byte[] other=rawFrame(s,s.get("key"),body,"payload");int first=Short.toUnsignedInt(ByteBuffer.wrap(result).getShort(24));int otherLength=Short.toUnsignedInt(ByteBuffer.wrap(other).getShort(24));assertEquals(first,otherLength);System.arraycopy(other,26,result,26,first);break;}
   default:break;
  }return result;
 }
 private static byte @NonNull [] rawFrame(@NonNull Spec s,@NonNull String key,byte @NonNull [] raw,@NonNull String op)throws Exception{
  int size=467;if(op.equals("chunk-noncanonical") && raw.length%3==0 && raw.length<size)size=Math.max(1,raw.length-1);byte[] id=EntropySource.fromDefaults().nextBytes(16);List<byte[]> chunks=new ArrayList<>();if(raw.length==0)chunks.add(new byte[0]);else for(int at=0;at<raw.length;at+=size)chunks.add(Arrays.copyOfRange(raw,at,Math.min(raw.length,at+size)));
  if(op.equals("nonfinal-short")){byte[] first=chunks.get(0);chunks.set(0,Arrays.copyOf(first,first.length-1));}
  if(op.equals("final-oversized"))chunks.set(chunks.size()-1,new byte[size+1]);
  ByteArrayOutputStream buffer=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(buffer)){
   out.writeBytes("WAR"+s.format());out.writeShort(chunks.size());out.writeShort(size);out.write(id);
   for(int n=0;n<chunks.size();n++){
    int position=op.equals("chunk-wrong-position")?n+1:n,count=op.equals("chunk-wrong-count")?chunks.size()+1:chunks.size(),chunkSize=op.equals("chunk-wrong-size")?size+1:size;
    byte[] contextId=id.clone();if(op.equals("chunk-wrong-record-id"))contextId[0]^=1;
    String address=op.equals("wrong-key")?key+"x":key;
    String context="revetsec/wa-record/v"+s.format()+":"+digest(address)+':'+encode(contextId)+':'+count+':'+chunkSize+':'+position;if(op.equals("wrong-context"))context+="x";
    String encoded=encode(chunks.get(n));if(op.equals("chunk-noncanonical") && encoded.length()%4!=0)encoded=alias(encoded);
    byte[] plaintext=op.equals("chunk-invalid-utf8")?new byte[]{(byte)255}:encoded.getBytes(StandardCharsets.US_ASCII);
    long expiry=key.equals(s.get("rootKey"))?WebAuthnRecordPayloadV2.PERMANENT.getEpochSecond():Long.parseLong(s.get("expiresSeconds"))+(Integer.parseInt(s.get("expiresNanos"))==0?0:1);
    String sealed=seal(op.equals("wrong-type")?SealedStateType.APP:SealedStateType.WEBAUTHN_RECORD,context,expiry,plaintext,op.equals("outer-spare-bits"));if(op.startsWith("outer-"))sealed=alter(sealed,op);byte[] ascii=sealed.getBytes(StandardCharsets.US_ASCII);out.writeShort(ascii.length);out.write(ascii);
   }
  }return buffer.toByteArray();
 }
}
