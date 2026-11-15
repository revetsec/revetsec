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
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-05: exact WAR2 envelope, logical-index and ceremony capacities. WAR1 was removed before release. */
final class WebAuthnMigrationCapacityConformanceTests {
 private static final @NonNull Instant TIME=Instant.ofEpochSecond(1700000010,123456789),PERMANENT=Instant.ofEpochSecond(Instant.MAX.getEpochSecond());
 @TestFactory @NonNull List<@NonNull DynamicTest> rawEnvelopeBudgetAndExactFinalOutput(){List<DynamicTest> tests=new ArrayList<>();for(int cap:List.of(1024,1026,3800,16384))for(int keyLength:List.of(1,64))for(int length:List.of(0,1,109999,110000,110001))tests.add(DynamicTest.dynamicTest("MIG-05/WA/envelope/2/"+cap+"/"+keyLength+"/"+length,()->{
  var s=sealer(keyLength,cap);var key=WebAuthnStoreKey.forCredential("capacity","login.example.test",new byte[]{1});byte[] data=pattern(length,7);if(length==0 || length>110000){assertThrows(IllegalArgumentException.class,()->seal(s,key,data));return;}
  byte[] frame=seal(s,key,data);assertArrayEquals(data,open(s,key,frame));int chunk=(cap*3/4-54-64-16)*3/4-8,count=(length+chunk-1)/chunk;assertEquals(chunk,Short.toUnsignedInt(ByteBuffer.wrap(frame).getShort(6)));assertEquals(count,Short.toUnsignedInt(ByteBuffer.wrap(frame).getShort(4)));long expected=24;
  for(int offset=0;offset<length;offset+=chunk){int raw=Math.min(chunk,length-offset),text=(raw*4+2)/3;expected+=2+((54+keyLength+text)*4+2)/3;}
  assertEquals(expected,frame.length);assertTrue(frame.length<=262144);if(cap==1024 && length==110000)assertEquals(236,count);if(cap==1026 && length==110000 && keyLength==64)assertEquals(233340,frame.length);assertEquals(cap,SealedStateAccess.get().getMaximumSealedLength(s));assertArrayEquals(pattern(length,7),data);
 }));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> readerChunkCountAndDeclaredSizeEndpoints(){List<DynamicTest> tests=new ArrayList<>();for(int keyLength:List.of(1,64)){
  for(int count:List.of(0,1,255,256,257))tests.add(DynamicTest.dynamicTest("MIG-05/WA/chunk-count/2/"+keyLength+"/"+count,()->{var key=WebAuthnStoreKey.forCredential("capacity","login.example.test",new byte[]{1});byte[] frame=explicitFrame(keyLength,key,count,1);if(count>=1 && count<=256)assertArrayEquals(pattern(count,0),open(sealer(keyLength,1024),key,frame));else assertThrows(WebAuthnRecordException.class,()->open(sealer(keyLength,1024),key,frame));}));
  for(int size:List.of(0,1,16383,16384,16385))tests.add(DynamicTest.dynamicTest("MIG-05/WA/chunk-size/2/"+keyLength+"/"+size,()->{var key=WebAuthnStoreKey.forCredential("capacity","login.example.test",new byte[]{1});byte[] frame=explicitFrame(keyLength,key,1,size);if(size>=1 && size<=16384)assertArrayEquals(new byte[]{0},open(sealer(keyLength,1024),key,frame));else assertThrows(WebAuthnRecordException.class,()->open(sealer(keyLength,1024),key,frame));}));
 }return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> logicalIndexAtAndOneBeyondEachDeclaredLimit(){List<DynamicTest> tests=new ArrayList<>();int[][] parameters={{63,1,64},{64,1,64},{65,1,64},{0,1023,64},{1,1023,64},{63,1023,64},{64,1023,64},{65,1023,64},{64,1022,64},{64,1024,64},{64,1023,63},{64,1023,65}};
  for(int keyLength:List.of(1,64))for(int[] row:parameters)tests.add(DynamicTest.dynamicTest("MIG-05/WA/index/2/"+keyLength+"/"+row[0]+"/"+row[1]+"/"+row[2],()->{
   int count=row[0],idLength=row[1],handleLength=row[2];byte[] handle=pattern(handleLength,71);var key=WebAuthnStoreKey.forAccountCredentialIndex("capacity","login.example.test",Arrays.copyOf(handle,Math.min(64,handle.length)));ByteArrayOutputStream buffer=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(buffer)){out.writeByte(1);out.writeByte(handleLength);out.writeByte(count);out.write(handle);for(int n=0;n<count;n++){out.writeShort(idLength);byte[] id=new byte[idLength];id[0]=(byte)n;out.write(id);}}
   byte[] inner=buffer.toByteArray();assertEquals(3+handleLength+count*(2+idLength),inner.length);boolean valid=count<=64 && idLength<=1023 && handleLength<=64;var s=sealer(keyLength,1024);byte[] payload=ByteBuffer.allocate(12+inner.length).putLong(TIME.getEpochSecond()).putInt(TIME.getNano()).put(inner).array();byte[] frame=seal(s,key,payload);
   if(!valid){assertThrows(WebAuthnRecordException.class,()->new WebAuthnRecordCodecV2(s).openRecord(key,frame,clock()));assertThrows(IllegalArgumentException.class,()->new WebAuthnRecordCodec(s).sealEntity(key,inner,PERMANENT,TIME));}
   else{try(var decoded=new WebAuthnRecordCodecV2(s).openRecord(key,frame,clock())){assertArrayEquals(inner,decoded.innerPayload());assertEquals(TIME,decoded.floor());}var state=new WebAuthnCredentialIndex("capacity","login.example.test",new WebAuthnRecordCodec(s)).decode(key,frame,clock());assertEquals(count,state.size());assertArrayEquals(handle,state.userHandle());for(int n=0;n<count;n++){assertEquals(idLength,state.credentialIds().get(n).length);assertEquals((byte)n,state.credentialIds().get(n)[0]);}if(count==64 && idLength==1023 && handleLength==64){assertEquals(65667,inner.length);assertEquals(65679,new WebAuthnRecordCodecV2(s).open(key,frame,clock()).length);}}
   assertArrayEquals(payload,open(s,key,frame));
  }));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> exactCeremonyInnerAndPrefixByteBudget(){List<DynamicTest> tests=new ArrayList<>();for(int keyLength:List.of(1,64))for(int length:List.of(2399,2400,2401))tests.add(DynamicTest.dynamicTest("MIG-05/WA/ceremony-bytes/2/"+keyLength+"/"+length,()->{
  String rp="a".repeat(63)+'.'+"b".repeat(63)+'.'+"c".repeat(63)+'.'+"d".repeat(61),ns="n".repeat(128);assertEquals(253,rp.length());List<String> origins=new ArrayList<>();for(int n=65528;n<=65535;n++)origins.add("https://"+rp+':'+n);for(String origin:origins)assertEquals(267,origin.length());String purpose="p".repeat(length-2342);byte[] id=pattern(32,1),challenge=pattern(32,2),binding=pattern(32,3),handle=pattern(64,4);var state=WebAuthnCeremonyState.accountReauthentication(id,challenge,binding,Set.copyOf(origins),handle,purpose,TIME,TIME.plusSeconds(30));var key=WebAuthnStoreKey.forCeremony(ns,rp,id);assertTrue(key.getStorageKey().length()<=583);var s=sealer(keyLength,1024);byte[] inner=ceremonyBytes(id,challenge,binding,handle,purpose,origins);assertEquals(length,inner.length);byte[] payload=ByteBuffer.allocate(12+inner.length).putLong(TIME.getEpochSecond()).putInt(TIME.getNano()).put(inner).array();byte[] frame=seal(s,key,payload,TIME.plusSeconds(30));
  if(length>2400){assertThrows(IllegalArgumentException.class,()->new WebAuthnCeremonyRecordCodec(ns,rp,new WebAuthnRecordCodec(s)).encode(state,TIME));assertThrows(WebAuthnRecordException.class,()->new WebAuthnRecordCodecV2(s).openRecord(key,frame,clock()));}
  else{byte[] written=new WebAuthnCeremonyRecordCodec(ns,rp,new WebAuthnRecordCodec(s)).encode(state,TIME).sealedBytes();assertArrayEquals(payload,open(s,key,written));var actual=new WebAuthnCeremonyRecordCodec(ns,rp,new WebAuthnRecordCodec(s)).decode(key,written,clock());assertEquals(purpose,actual.actionPurpose());assertEquals(Set.copyOf(origins),actual.allowedOrigins());assertArrayEquals(handle,actual.expectedHandle());assertArrayEquals(challenge,actual.challenge());assertArrayEquals(binding,actual.browserBinding());assertEquals(TIME.plusSeconds(30),actual.expiresAt());assertEquals(length+12,new WebAuthnRecordCodecV2(s).open(key,written,clock()).length);}
  assertEquals(length-2342,Objects.requireNonNull(state.actionPurpose()).length());assertEquals(8,state.allowedOrigins().size());
 }));return tests;}
 private static byte @NonNull [] ceremonyBytes(byte @NonNull [] id,byte @NonNull [] challenge,byte @NonNull [] binding,byte @NonNull [] handle,@NonNull String purpose,@NonNull List<@NonNull String> origins)throws Exception{var buffer=new ByteArrayOutputStream();try(var out=new DataOutputStream(buffer)){out.writeByte(1);out.writeByte(0);out.writeByte(3);out.write(id);out.write(challenge);out.write(binding);out.writeLong(TIME.getEpochSecond());out.writeInt(TIME.getNano());out.writeLong(TIME.plusSeconds(30).getEpochSecond());out.writeInt(TIME.getNano());out.writeByte(handle.length);out.writeByte(purpose.length());out.writeByte(origins.size());out.write(handle);out.write(purpose.getBytes(StandardCharsets.US_ASCII));for(String origin:origins){out.writeShort(origin.length());out.write(origin.getBytes(StandardCharsets.US_ASCII));}}return buffer.toByteArray();}
 private static byte @NonNull [] explicitFrame(int keyLength,@NonNull WebAuthnStoreKey key,int count,int size)throws Exception{var buffer=new ByteArrayOutputStream();byte[] recordId=EntropySource.fromDefaults().nextBytes(16);try(var out=new DataOutputStream(buffer)){out.writeBytes("WAR2");out.writeShort(count);out.writeShort(size);out.write(recordId);for(int n=0;n<count;n++){String context="revetsec/wa-record/v2:"+Base64Url.encode(java.security.MessageDigest.getInstance("SHA-256").digest(key.getStorageKey().getBytes(StandardCharsets.US_ASCII)))+':'+Base64Url.encode(recordId)+':'+count+':'+size+':'+n;String text=Base64Url.encode(new byte[]{(byte)n});String sealed=SealerV1.seal(SealerV1.Key.fromMasterKey("k".repeat(keyLength),master()),SealedStateType.WEBAUTHN_RECORD,context,PERMANENT.getEpochSecond(),text.getBytes(StandardCharsets.US_ASCII),EntropySource.fromDefaults().nextBytes(16),EntropySource.fromDefaults().nextBytes(12));out.writeShort(sealed.length());out.writeBytes(sealed);}}return buffer.toByteArray();}
 private static byte @NonNull [] seal(@NonNull StateSealer s,@NonNull WebAuthnStoreKey key,byte @NonNull [] raw){return seal(s,key,raw,PERMANENT);}
 private static byte @NonNull [] seal(@NonNull StateSealer s,@NonNull WebAuthnStoreKey key,byte @NonNull [] raw,@NonNull Instant expiry){return new WebAuthnRecordCodecV2(s).seal(key,raw,expiry);}
 private static byte @NonNull [] open(@NonNull StateSealer s,@NonNull WebAuthnStoreKey key,byte @NonNull [] raw)throws Exception{return new WebAuthnRecordCodecV2(s).open(key,raw,clock());}
 private static @NonNull StateSealer sealer(int keyLength,int cap){return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(keyLength),java.util.Base64.getEncoder().encodeToString(master()))).maximumSealedLength(cap).clock(clock()).build();}
 private static @NonNull Clock clock(){return Clock.fixed(TIME,ZoneOffset.UTC);}
 private static byte @NonNull [] master(){byte[] b=new byte[32];for(int n=0;n<b.length;n++)b[n]=(byte)(n+1);return b;}
 private static byte @NonNull [] pattern(int length,int start){byte[] b=new byte[length];for(int n=0;n<b.length;n++)b[n]=(byte)(start+n);return b;}
}
