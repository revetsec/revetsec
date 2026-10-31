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

package com.revetsec.oauth.server;
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.*;
import com.revetsec.json.*;
import example.migration.CodecSupport;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Private closed inventory/transform bridge; absent from the exported core artifact. */
public final class ClosedIssuerCodec {
 private ClosedIssuerCodec(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.main(args,ClosedIssuerCodec::process);}
 private static @NonNull JsonArray process(@NonNull JsonObject config)throws Exception{
  @NonNull StateSealer sealer=sealer(config);int cap=(int)number(config,"maximumRecordBytes",16384);var next=new OAuthStoreRecordCodecV2(text(config,"issuer"),sealer,cap,new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128),1024);
  var intent=ClosedMigrationIntent.fromExternalIntent(text(config,"migrationId"),StoreAdmission.fromIdentifiers(text(config,"authorityId"),text(config,"recoveryGeneration")),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2));
  boolean verify=text(config,"operation").equals("verify");var outputs=new ArrayList<@NonNull JsonValue>();var roots=rows(config,"roots");@Nullable JsonObject rootRow=roots.stream().filter(x->text(x,"key").equals(next.issuerKey().getStorageKey())).findFirst().orElse(null);
  for(@NonNull JsonObject source:rows(config,"rows")){
   @NonNull List<@NonNull String> required=List.of();
   try{
    if(rootRow==null)throw new IllegalArgumentException("Missing root");@NonNull OAuthStoreEntry row=carrier(source);@NonNull String opening=asciiKey(row.toSealedForm().getBytes(StandardCharsets.US_ASCII));@NonNull String rootOpening=asciiKey(carrier(rootRow).toSealedForm().getBytes(StandardCharsets.US_ASCII));
    required=requiredKeys(List.of(opening),List.of(rootOpening));
    if(!keyIds(config).containsAll(required)){outputs.add(refusal(source,"BLOCKED_DEPENDENCY","ISSUER2",required));continue;}
    @NonNull Instant floor;@NonNull String before,after;@NonNull OAuthStoreEntry target;
    if(verify){
     var openedRoot=openNew(next,carrier(rootRow),intent);var root=OAuthIssuerRootV2.decode(openedRoot.payload());if(!root.authorityId().equals(text(config,"authorityId")))throw new IllegalArgumentException("Wrong authority");
     var opened=openNew(next,row,intent);floor=opened.floor();before=semantic(row.getKey(),opened.payload(),row.getRetainUntil(),floor,true);after=before;target=row;
    }else{
     var migration=new OAuthStoreMigrationCodec(next,(int)number(config,"legacyMaximumRecordBytes",16384),intent);var pinned=migration.openRoot(carrier(rootRow));@NonNull JsonObject payload=openOld(next,row,intent,(int)number(config,"legacyMaximumRecordBytes",16384));
     floor=pinned.minimum();@NonNull JsonObject targetPayload=payload;
     if(row.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE){var oldRoot=OAuthStoreFence.decode(payload,OAuthStoreKey.Kind.ISSUER_STATE);targetPayload=OAuthStoreRecordCodecV2.parse(OAuthIssuerRootV2.fromLegacy(oldRoot,text(config,"authorityId")).toPayload(),12170);}
     else if(row.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN){@NonNull Instant issued=Instant.ofEpochSecond(OAuthStoreFormat.longMember(payload,"issued").orElseThrow());if(issued.isAfter(floor))floor=issued;}
     before=semantic(row.getKey(),payload,row.getRetainUntil(),floor,false);
     @NonNull String prepared="{\"schema\":2,\"issuer\":"+JsonString.fromValue(next.issuer()).toJson()+",\"key\":"+JsonString.fromValue(row.getKey().getStorageKey()).toJson()+",\"version\":\""+identifier(0)+"\",\"retainUntil\":"+row.getRetainUntil().getEpochSecond()+",\"floorSeconds\":"+floor.getEpochSecond()+",\"floorNanos\":"+floor.getNano()+",\"payload\":"+targetPayload.toJson()+"}";
     int plaintext=prepared.getBytes(StandardCharsets.UTF_8).length;
     if(plaintext>cap*3/4-118){boolean permanent=row.getRetainUntil().equals(OAuthStoreFormat.PERMANENT);outputs.add(decision(source,null,permanent?"UNSUPPORTED":"WAIT_RETENTION",before,null,floor,row.getRetainUntil(),permanent,row.getKey().getKind().name(),"ISSUER1","ISSUER2",0,0,0,opening,text(config,"activeKeyId"),rootCommitment(rootRow),required));continue;}
     target=migration.convert(row,pinned);var opened=openNew(next,target,intent);after=semantic(target.getKey(),opened.payload(),target.getRetainUntil(),opened.floor(),true);
     if(!floor.equals(opened.floor())||!before.equals(after)||row.getVersion().equals(target.getVersion())||!row.getRetainUntil().equals(target.getRetainUntil()))throw new IllegalArgumentException("Semantic mismatch");
    }
    byte @NonNull [] sealed=target.toSealedForm().getBytes(StandardCharsets.US_ASCII);@NonNull JsonObject targetRow=row(source,bytes(target.getVersion()),sealed,target.getRetainUntil());
    outputs.add(decision(source,targetRow,"FIT",before,after,floor,target.getRetainUntil(),target.getRetainUntil().equals(OAuthStoreFormat.PERMANENT),target.getKey().getKind().name(),verify?"ISSUER2":"ISSUER1","ISSUER2",sealed.length,sealed.length,sealed.length,opening,text(config,"activeKeyId"),rootCommitment(rootRow),required));
   }catch(Exception failure){outputs.add(refusal(source,"CORRUPT","ISSUER2",required));}
  }
  return JsonArray.fromElements(outputs);
 }
 private static @NonNull OAuthStoreEntry carrier(@NonNull JsonObject row){return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(text(row,"key")),text(row,"version"),instant((JsonObject)row.find("retention").orElseThrow()),new String(bytes(text(row,"ciphertext")),StandardCharsets.US_ASCII));}
 private static OAuthStoreRecordCodecV2.@NonNull Opened openNew(@NonNull OAuthStoreRecordCodecV2 next,@NonNull OAuthStoreEntry row,@NonNull ClosedMigrationIntent intent)throws Exception{
  try(AuthenticatedRecord auth=SealedStateAccess.get().openForMigration(next.sealer(),SealedStateType.AS_RECORD,row.toSealedForm(),OAuthStoreRecordCodecV2.context(row.getKey()),intent)){return next.decode(row,auth.getPlaintext(),auth.getNotAfter());}
 }
 private static @NonNull JsonObject openOld(@NonNull OAuthStoreRecordCodecV2 next,@NonNull OAuthStoreEntry row,@NonNull ClosedMigrationIntent intent,int cap)throws Exception{
  next.namespace(row.getKey());try(AuthenticatedRecord auth=SealedStateAccess.get().openForMigration(next.sealer(),SealedStateType.AS_RECORD,row.toSealedForm(),"revetsec/as-record/v1:"+row.getKey().getStorageKey(),intent)){
   @NonNull JsonObject outer=OAuthStoreRecordCodecV2.parse(auth.getPlaintext(),cap*3/4-55);
   if(!outer.getMembers().keySet().equals(Set.of("schema","issuer","key","version","retainUntil","payload"))||number(outer,"schema")!=1||!text(outer,"issuer").equals(next.issuer())||!text(outer,"key").equals(row.getKey().getStorageKey())||!text(outer,"version").equals(row.getVersion())||number(outer,"retainUntil")!=row.getRetainUntil().getEpochSecond()||!auth.getNotAfter().equals(row.getRetainUntil()))throw new IllegalArgumentException("Bad carrier");
   @NonNull JsonObject p=(JsonObject)outer.find("payload").orElseThrow();if(row.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE||row.getKey().getKind()==OAuthStoreKey.Kind.SUBJECT_STATE)OAuthStoreFence.decode(p,row.getKey().getKind());else{var record=OAuthAuthorizationRecord.decode(row.getKey().getKind(),OAuthStoreRecordCodecV2.identifier(row.getKey()),p,next.ingress(),1024);if(!record.retention().equals(row.getRetainUntil()))throw new IllegalArgumentException("Bad retention");}return p;
  }
 }
 private static @NonNull String semantic(@NonNull OAuthStoreKey key,@NonNull JsonObject payload,@NonNull Instant retention,@NonNull Instant floor,boolean target){
  @NonNull JsonObject normalized=payload;if(key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE){@NonNull String incarnation;long epoch;@NonNull Instant minimum;if(target){var root=OAuthIssuerRootV2.decode(payload);incarnation=root.incarnation();epoch=root.epoch();minimum=root.minimum();}else{var root=OAuthStoreFence.decode(payload,OAuthStoreKey.Kind.ISSUER_STATE);incarnation=root.incarnation();epoch=root.epoch();minimum=root.highWater();}normalized=JsonObject.builder().put("incarnation",incarnation).put("epoch",epoch).put("minimum",instant(minimum)).build();}
  return hash(key.getStorageKey()+'\0'+retention+'\0'+floor+'\0'+normalized.toJson());
 }
}

