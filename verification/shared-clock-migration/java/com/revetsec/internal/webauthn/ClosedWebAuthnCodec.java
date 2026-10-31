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
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.*;
import com.revetsec.json.*;
import example.migration.CodecSupport;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Private administrative WAR1/WAR2 bridge; never credential admission. */
public final class ClosedWebAuthnCodec {
 private ClosedWebAuthnCodec(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.main(args,ClosedWebAuthnCodec::process);}
 private static @NonNull JsonArray process(@NonNull JsonObject config)throws Exception{
  @NonNull StateSealer sealer=sealer(config);var codec=new WebAuthnRecordCodecV2(sealer);var migration=new WebAuthnRecordMigration(sealer);
  var intent=ClosedMigrationIntent.fromExternalIntent(text(config,"migrationId"),StoreAdmission.fromIdentifiers(text(config,"authorityId"),text(config,"recoveryGeneration")),Set.of(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));
  if(text(config,"operation").equals("inspect-legacy"))return inspectLegacy(config,codec,migration,intent);
  boolean verify=text(config,"operation").equals("verify");var outputs=new ArrayList<@NonNull JsonValue>();var roots=new HashMap<@NonNull String,@NonNull JsonObject>();for(var root:rows(config,"roots"))if(roots.put(text(root,"key"),root)!=null)throw new IllegalArgumentException("Duplicate root");
  for(@NonNull JsonObject source:rows(config,"rows")){
   @NonNull List<@NonNull String> required=List.of();
   try{
    @NonNull String address=text(source,"key");var rootKey=WebAuthnRecordPayloadV2.namespaceKeyForAddress(address);@Nullable JsonObject rootRow=roots.get(rootKey.getStorageKey());if(rootRow==null)throw new IllegalArgumentException("Missing root");
    byte @NonNull [] sealed=bytes(text(source,"ciphertext"));byte @NonNull [] rootBytes=bytes(text(rootRow,"ciphertext"));@NonNull String opening=frameKey(sealed);@NonNull String rootOpening=frameKey(rootBytes);
    required=requiredKeys(frameKeys(sealed),frameKeys(rootBytes));
    if(!keyIds(config).containsAll(required)){outputs.add(refusal(source,"BLOCKED_DEPENDENCY","WAR2",required));continue;}
    @NonNull Instant floor,retention;@NonNull String before,after;byte @NonNull [] targetBytes,version;
    if(verify){
     try(var root=raw(sealer,text(rootRow,"key"),rootBytes,intent,false);var decodedRoot=WebAuthnRecordPayloadV2.decode(text(rootRow,"key"),root.payload,root.notAfter);var target=raw(sealer,address,sealed,intent,false);var decoded=WebAuthnRecordPayloadV2.decode(address,target.payload,target.notAfter)){
      if(!decodedRoot.authorityId().orElseThrow().equals(text(config,"authorityId")))throw new IllegalArgumentException("Wrong authority");floor=decoded.floor();retention=decoded.expiresAt();before=semantic(address,decoded.innerPayload(),floor,retention,decoded.authorityId().isPresent());after=before;targetBytes=sealed;version=bytes(text(source,"version"));
     }
    }else{
     var root=migration.authenticateRoot(intent,text(rootRow,"key"),rootBytes);
     try(var opened=codec.openLegacyForMigration(address,sealed,intent)){
      byte @NonNull [] plain=opened.plaintext();try{
       if(address.equals(rootKey.getStorageKey())){floor=WebAuthnRecordPayloadV2.legacyMinimum(address,plain,opened.notAfter());retention=WebAuthnRecordPayloadV2.PERMANENT;before=semantic(address,plain,floor,retention,true);}
       else try(var decoded=WebAuthnRecordPayloadV2.legacyEntity(address,plain,opened.notAfter(),root.minimum())){floor=decoded.floor();retention=decoded.expiresAt();before=semantic(address,plain,floor,retention,false);}
      }finally{Arrays.fill(plain,(byte)0);}
     }
     var prepared=migration.prepare(intent,root,address,bytes(text(source,"version")),sealed);targetBytes=prepared.sealedBytes();
     // Native adapter's opaque CAS version is a positive big-endian signed-long, independent of authenticated envelope bytes.
     long nextVersion;do{nextVersion=new SecureRandom().nextLong()&Long.MAX_VALUE;}while(nextVersion==0||Arrays.equals(ByteBuffer.allocate(8).putLong(nextVersion).array(),bytes(text(source,"version"))));version=ByteBuffer.allocate(8).putLong(nextVersion).array();
     try(var target=raw(sealer,address,targetBytes,intent,false);var decoded=WebAuthnRecordPayloadV2.decode(address,target.payload,target.notAfter)){
      if(!decoded.floor().equals(floor)||!decoded.expiresAt().equals(retention)||(address.equals(rootKey.getStorageKey())&&!decoded.authorityId().orElseThrow().equals(text(config,"authorityId"))))throw new IllegalArgumentException("Floor/authority mismatch");
      after=semantic(address,decoded.innerPayload(),decoded.floor(),decoded.expiresAt(),decoded.authorityId().isPresent());
     }
     if(!before.equals(after))throw new IllegalArgumentException("Semantic mismatch");
    }
    if(!instant((JsonObject)source.find("retention").orElseThrow()).equals(retention))throw new IllegalArgumentException("Carrier retention mismatch");
    @NonNull JsonObject targetRow=row(source,version,targetBytes,retention);@NonNull String kind=address.split(":",-1)[3];outputs.add(decision(source,targetRow,"FIT",before,after,floor,retention,retention.equals(WebAuthnRecordPayloadV2.PERMANENT),kind,verify?"WAR2":"WAR1","WAR2",targetBytes.length,targetBytes.length,b64(targetBytes).length(),opening,text(config,"activeKeyId"),rootCommitment(rootRow),required));
   }catch(Exception failure){outputs.add(refusal(source,"CORRUPT","WAR2",required));}
  }
  return JsonArray.fromElements(outputs);
 }
 /** Authenticated legacy metadata only: no sealing, replacement version, target row or ordinary admission. */
 private static @NonNull JsonArray inspectLegacy(@NonNull JsonObject config,
   @NonNull WebAuthnRecordCodecV2 codec,@NonNull WebAuthnRecordMigration migration,
   @NonNull ClosedMigrationIntent intent)throws Exception{
  var outputs=new ArrayList<@NonNull JsonValue>();var roots=new HashMap<@NonNull String,@NonNull JsonObject>();
  for(var root:rows(config,"roots"))if(roots.put(text(root,"key"),root)!=null)throw new IllegalArgumentException("Duplicate root");
  for(@NonNull JsonObject source:rows(config,"rows")){
   @NonNull List<@NonNull String> required=List.of();
   try{
    if(!text(source,"family").equals("WEBAUTHN")||!text(source,"scope").equals(text(config,"webauthnScope")))throw new IllegalArgumentException("Wrong native scope");
    byte @NonNull [] sourceVersion=bytes(text(source,"version"));if(sourceVersion.length!=8||ByteBuffer.wrap(sourceVersion).getLong()<=0)throw new IllegalArgumentException("Invalid native version");
    @NonNull String address=text(source,"key");var rootKey=WebAuthnRecordPayloadV2.namespaceKeyForAddress(address);@Nullable JsonObject rootRow=roots.get(rootKey.getStorageKey());
    if(rootRow==null||!text(rootRow,"family").equals("WEBAUTHN")||!text(rootRow,"scope").equals(text(source,"scope")))throw new IllegalArgumentException("Missing or wrong root");
    byte @NonNull [] sealed=bytes(text(source,"ciphertext"));byte @NonNull [] rootBytes=bytes(text(rootRow,"ciphertext"));
    required=requiredKeys(frameKeys(sealed),frameKeys(rootBytes));
    if(!keyIds(config).containsAll(required)){outputs.add(inspection(source,"BLOCKED_DEPENDENCY",null,null,null,null,null,required));continue;}
    var root=migration.authenticateRoot(intent,text(rootRow,"key"),rootBytes);
    @NonNull Instant floor,retention;@NonNull String semantics;
    try(var opened=codec.openLegacyForMigration(address,sealed,intent)){
     byte @NonNull [] plain=opened.plaintext();try{
      if(address.equals(rootKey.getStorageKey())){floor=WebAuthnRecordPayloadV2.legacyMinimum(address,plain,opened.notAfter());retention=WebAuthnRecordPayloadV2.PERMANENT;semantics=semantic(address,plain,floor,retention,true);}
      else try(var decoded=WebAuthnRecordPayloadV2.legacyEntity(address,plain,opened.notAfter(),root.minimum())){floor=decoded.floor();retention=decoded.expiresAt();semantics=semantic(address,plain,floor,retention,false);}
     }finally{Arrays.fill(plain,(byte)0);}
    }
    // Native legacy TIMESTAMPTZ is an untrusted, lossy projection. Only the authenticated inner payload owns this exact value.
    outputs.add(inspection(source,"FIT",floor,retention,address.split(":",-1)[3],semantics,rootCommitment(rootRow),required));
   }catch(Exception failure){outputs.add(inspection(source,"CORRUPT",null,null,null,null,null,required));}
  }
  return JsonArray.fromElements(outputs);
 }
 private static @NonNull JsonObject inspection(@NonNull JsonObject source,@NonNull String classification,
   @Nullable Instant floor,@Nullable Instant retention,@Nullable String kind,@Nullable String semantics,
   @Nullable String root,@NonNull List<@NonNull String> required){
  return JsonObject.builder().put("classification",classification).put("source",source)
   .put("sourceFormat","WAR1").put("floor",floor==null?JsonNull.defaultInstance():instant(floor))
   .put("retention",retention==null?JsonNull.defaultInstance():instant(retention))
   .put("permanent",retention!=null&&retention.equals(WebAuthnRecordPayloadV2.PERMANENT))
   .put("kind",kind==null?JsonNull.defaultInstance():JsonString.fromValue(kind))
   .put("semanticCommitment",semantics==null?JsonNull.defaultInstance():JsonString.fromValue(semantics))
   .put("rootCommitment",root==null?JsonNull.defaultInstance():JsonString.fromValue(root))
   .put("openingKeyIds",JsonArray.fromElements(required.stream().map(JsonString::fromValue).toList())).build();
 }
 private static @NonNull String semantic(@NonNull String address,byte @NonNull [] inner,@NonNull Instant floor,@NonNull Instant retention,boolean root){
  try {return hash(address+'\0'+floor+'\0'+retention+'\0'+(root?"ROOT":b64(inner)));}finally{Arrays.fill(inner,(byte)0);}
 }
 private static @NonNull String frameKey(byte @NonNull [] frame){return frameKeys(frame).iterator().next();}
 private static @NonNull Set<@NonNull String> frameKeys(byte @NonNull [] frame){
  if(frame.length<27||frame.length>262144)throw new IllegalArgumentException("Invalid frame");@NonNull ByteBuffer b=ByteBuffer.wrap(frame);b.position(4);int count=Short.toUnsignedInt(b.getShort());int size=Short.toUnsignedInt(b.getShort());if(count<1||count>256||size<1||size>16384)throw new IllegalArgumentException("Invalid frame");b.position(24);@NonNull Set<@NonNull String> keys=new LinkedHashSet<>();
  for(int i=0;i<count;i++){int n=Short.toUnsignedInt(b.getShort());if(n<1||n>16384||n>b.remaining())throw new IllegalArgumentException("Invalid chunk");byte @NonNull [] chunk=new byte[n];b.get(chunk);@NonNull String actual=asciiKey(chunk);keys.add(actual);}if(b.hasRemaining())throw new IllegalArgumentException("Trailing frame");return keys;
 }
 /** Restricted current-format authentication, including expired retained ceremonies, with full existing payload validation afterward. */
 private static @NonNull Raw raw(@NonNull StateSealer sealer,@NonNull String address,byte @NonNull [] frame,@NonNull ClosedMigrationIntent intent,boolean legacy)throws Exception{
  if(frame.length<27||frame.length>262144)throw new IllegalArgumentException("Invalid frame");@NonNull ByteBuffer b=ByteBuffer.wrap(frame);byte @NonNull [] magic=new byte[4];b.get(magic);if(!new String(magic,StandardCharsets.US_ASCII).equals(legacy?"WAR1":"WAR2"))throw new IllegalArgumentException("Invalid generation");int count=Short.toUnsignedInt(b.getShort()),size=Short.toUnsignedInt(b.getShort());if(count<1||count>256||size<1||size>16384)throw new IllegalArgumentException("Invalid frame");byte @NonNull [] id=new byte[16];b.get(id);byte @NonNull [] output=new byte[110000];int used=0;@Nullable Long retention=null;
  try{
   for(int i=0;i<count;i++){int n=Short.toUnsignedInt(b.getShort());if(n<1||n>16384||n>b.remaining())throw new IllegalArgumentException("Invalid chunk");byte @NonNull [] c=new byte[n];b.get(c);@NonNull String encoded=new String(c,StandardCharsets.US_ASCII);@NonNull String context=(legacy?"revetsec/wa-record/v1:":"revetsec/wa-record/v2:")+hash(address.getBytes(StandardCharsets.US_ASCII))+':'+b64(id)+':'+count+':'+size+':'+i;
    try(AuthenticatedRecord opened=SealedStateAccess.get().openForMigration(sealer,SealedStateType.WEBAUTHN_RECORD,encoded,context,intent)){
     long expiry=opened.getNotAfterEpochSecond();if(retention!=null&&retention!=expiry)throw new IllegalArgumentException("Mixed retention");retention=expiry;byte @NonNull [] chunk=bytes(opened.getPlaintext());try{if(chunk.length<1||chunk.length>size||(i<count-1&&chunk.length!=size)||used>output.length-chunk.length)throw new IllegalArgumentException("Invalid chunk length");System.arraycopy(chunk,0,output,used,chunk.length);used+=chunk.length;}finally{Arrays.fill(chunk,(byte)0);}
    }
   }
   if(b.hasRemaining())throw new IllegalArgumentException("Trailing frame");return new Raw(Arrays.copyOf(output,used),Objects.requireNonNull(retention));
  }finally{Arrays.fill(output,(byte)0);Arrays.fill(id,(byte)0);}
 }
 private static final class Raw implements AutoCloseable{private final byte @NonNull [] payload;private final long notAfter;private Raw(byte @NonNull [] payload,long notAfter){this.payload=payload;this.notAfter=notAfter;}@Override public void close(){Arrays.fill(payload,(byte)0);}}
}

