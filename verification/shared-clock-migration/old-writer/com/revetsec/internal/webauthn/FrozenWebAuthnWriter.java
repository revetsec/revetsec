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
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.json.*;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import java.nio.charset.StandardCharsets;
import com.revetsec.webauthn.WebAuthnStoreKey;
import example.migration.CodecSupport;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Synthetic legacy fixtures generated exclusively against the frozen old artifact. */
public final class FrozenWebAuthnWriter {
 private FrozenWebAuthnWriter(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.fixtureMain(args,FrozenWebAuthnWriter::fixtures);}
 private static @NonNull JsonArray fixtures(@NonNull JsonObject config)throws Exception{
  var old=new WebAuthnRecordCodec(sealer(config));@NonNull String ns="migration",rp="login.example.com",scope=text(config,"webauthnScope");@NonNull Instant minimum=Instant.ofEpochSecond(number(config,"minimumSeconds",1700000000),number(config,"minimumNanos",999999999));@NonNull Instant permanent=Instant.ofEpochSecond(Instant.MAX.getEpochSecond());@NonNull List<@NonNull JsonValue> rows=new ArrayList<>();
  var root=new WebAuthnNamespaceClock(ns,rp,old);rows.add(row(scope,root.key(),root.encode(minimum),permanent,1));
  byte @NonNull [] id={1,2,3},revokedId={7,8,9},handle={4,5,6},emptyHandle={10,11,12};var pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();byte @NonNull [] spki=pair.getPublic().getEncoded();var cose=new ByteArrayOutputStream();for(int v:new int[]{0xa4,1,1,3,0x27,0x20,6,0x21,0x58,32})cose.write(v);cose.write(spki,spki.length-32,32);
  var credentials=new WebAuthnCredentialRecordCodec(ns,rp,old);var active=credentials.encode(WebAuthnCredentialState.checked(id,handle,cose.toByteArray(),-8,0xffff_ffffL,true,true));rows.add(row(scope,active.key(),active.sealedBytes(),permanent,2));
  var revoked=credentials.encodeRevoked(revokedId,handle);rows.add(row(scope,revoked.key(),revoked.sealedBytes(),permanent,3));
  var indexes=new WebAuthnCredentialIndex(ns,rp,old);var index=indexes.encode(indexes.empty(handle).withAdded(id));rows.add(row(scope,index.key(),index.sealedBytes(),permanent,4));var empty=indexes.encode(indexes.empty(emptyHandle));rows.add(row(scope,empty.key(),empty.sealedBytes(),permanent,5));
  var fences=new WebAuthnAccountFence(ns,rp,old);var fence=fences.encode(emptyHandle,false);rows.add(row(scope,fence.key(),fence.sealedBytes(),permanent,6));var enabled=fences.encode(handle,true);rows.add(row(scope,enabled.key(),enabled.sealedBytes(),permanent,7));
  var ceremonies=new WebAuthnCeremonyRecordCodec(ns,rp,old);@NonNull Instant issued=Instant.ofEpochSecond(number(config,"ceremonyIssuedSeconds",minimum.minusSeconds(60).getEpochSecond()),number(config,"ceremonyIssuedNanos",minimum.getNano())),expiry=Instant.ofEpochSecond(number(config,"ceremonyExpiresSeconds",issued.plusSeconds(30).getEpochSecond()),number(config,"ceremonyExpiresNanos",issued.getNano()));var ceremony=ceremonies.encode(WebAuthnCeremonyState.accountReauthentication(pattern(1),pattern(2),pattern(3),Set.of("https://login.example.com"),handle,"remove credential",issued,expiry).consume());rows.add(row(scope,ceremony.key(),ceremony.sealedBytes(),expiry,8));
  if(config.find("multiKeyFrame").isPresent()){
   byte @NonNull [] largeHandle={11,12,13};var indexState=indexes.empty(largeHandle);var ids=new ArrayList<byte @NonNull []>();for(int i=0;i<64;i++){byte @NonNull [] credential=new byte[1023];Arrays.fill(credential,(byte)17);credential[0]=(byte)i;ids.add(credential);indexState=indexState.withAdded(credential);}var large=indexes.encode(indexState);
   @NonNull ByteBuffer raw=ByteBuffer.allocate(3+largeHandle.length+64*(2+1023));raw.put((byte)1).put((byte)largeHandle.length).put((byte)64).put(largeHandle);for(byte @NonNull [] credential:ids)raw.putShort((short)credential.length).put(credential);
   byte @NonNull [] changed=mixedFrame(config,large.key(),large.sealedBytes(),raw.array(),permanent);rows.add(row(scope,large.key(),changed,permanent,9));Arrays.fill(raw.array(),(byte)0);Arrays.fill(changed,(byte)0);
  }
  return JsonArray.fromElements(rows);
 }
 private static byte @NonNull [] mixedFrame(@NonNull JsonObject config,@NonNull WebAuthnStoreKey key,byte @NonNull [] frame,byte @NonNull [] plaintext,@NonNull Instant retention)throws Exception{
  @NonNull ByteBuffer reader=ByteBuffer.wrap(frame);reader.position(4);int count=Short.toUnsignedInt(reader.getShort()),size=Short.toUnsignedInt(reader.getShort());if(count<2)throw new IllegalArgumentException("Synthetic frame requires multiple chunks");byte @NonNull [] recordId=new byte[16];reader.get(recordId);var configMembers=new LinkedHashMap<@NonNull String,@NonNull JsonValue>(config.getMembers());configMembers.put("activeKeyId",JsonString.fromValue(text(config,"secondaryKeyId")));var secondary=sealer(JsonObject.fromMembers(configMembers));@NonNull ByteArrayOutputStream output=new ByteArrayOutputStream();output.write(frame,0,24);
  try{
   for(int index=0;index<count;index++){int length=Short.toUnsignedInt(reader.getShort());byte @NonNull [] original=new byte[length];reader.get(original);byte @NonNull [] chunk=original;
    if(index==1){byte @NonNull [] raw=Arrays.copyOfRange(plaintext,index*size,Math.min(plaintext.length,(index+1)*size));try{@NonNull String context="revetsec/wa-record/v1:"+hash(key.getStorageKey().getBytes(StandardCharsets.US_ASCII))+':'+b64(recordId)+':'+count+':'+size+':'+index;chunk=SealedStateAccess.get().seal(secondary,SealedStateType.WEBAUTHN_RECORD,b64(raw),context,retention).getBytes(StandardCharsets.US_ASCII);}finally{Arrays.fill(raw,(byte)0);}}
    output.write(chunk.length>>>8);output.write(chunk.length);output.write(chunk);Arrays.fill(chunk,(byte)0);Arrays.fill(original,(byte)0);
   }
   return output.toByteArray();
  }finally{Arrays.fill(recordId,(byte)0);}
 }
 private static byte @NonNull [] pattern(int v){byte @NonNull [] bytes=new byte[32];for(int i=0;i<32;i++)bytes[i]=(byte)(i+v);return bytes;}
 private static @NonNull JsonObject row(@NonNull String scope,@NonNull WebAuthnStoreKey k,byte @NonNull [] sealed,@NonNull Instant retention,long version){@NonNull String key=k.getStorageKey();return JsonObject.builder().put("family","WEBAUTHN").put("scope",scope).put("handle",hash("WEBAUTHN\0"+scope+'\0'+key)).put("key",key).put("version",b64(ByteBuffer.allocate(8).putLong(version).array())).put("ciphertext",b64(sealed)).put("retention",instant(retention)).build();}
}

