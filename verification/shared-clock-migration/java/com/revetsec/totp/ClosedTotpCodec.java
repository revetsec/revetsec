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

package com.revetsec.totp;
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.json.*;
import example.migration.CodecSupport;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Private app-owned closed migration bridge; not included in the core artifact. */
public final class ClosedTotpCodec {
 private ClosedTotpCodec(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.main(args,ClosedTotpCodec::process);}
 private static @NonNull JsonArray process(@NonNull JsonObject config)throws Exception{
  @NonNull StateSealer sealer=sealer(config);var old=new TotpRecords(sealer);var next=new TotpRecordsV3(sealer);var migration=new TotpMigrationV3(sealer);
  var intent=ClosedMigrationIntent.fromExternalIntent(text(config,"migrationId"),StoreAdmission.fromIdentifiers(text(config,"authorityId"),text(config,"recoveryGeneration")),Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));
  boolean verify=text(config,"operation").equals("verify");var outputs=new ArrayList<@NonNull JsonValue>();@NonNull Map<@NonNull String,@NonNull JsonObject> roots=new HashMap<>();for(@NonNull JsonObject r:rows(config,"roots")){if(roots.put(text(r,"key"),r)!=null)throw new IllegalArgumentException("Duplicate root");}
  for(@NonNull JsonObject source:rows(config,"rows")){
   @NonNull List<@NonNull String> required=List.of();
   try{
    @NonNull TotpStoreRecord row=carrier(source);@NonNull TotpStoreKey key=row.getKey();@Nullable JsonObject rootRow=roots.get(TotpStoreKey.forNamespace(key.getCredentialNamespace(),key.getRecoveryEpoch()).getStorageKey());if(rootRow==null)throw new IllegalArgumentException("Missing root");
    @NonNull String opening=asciiKey(row.getSealedBytes());@NonNull String rootOpening=asciiKey(carrier(rootRow).getSealedBytes());
    required=requiredKeys(List.of(opening),List.of(rootOpening));
    if(!keyIds(config).containsAll(required)){outputs.add(refusal(source,"BLOCKED_DEPENDENCY","TTR3",required));continue;}
    @NonNull Instant floor;@NonNull String before,after;@NonNull TotpStoreRecord target;
    if(verify){
     try(var root=next.open(carrier(rootRow));var decoded=next.open(row)){
      if(root.namespace==null||!root.namespace.getAuthorityId().equals(text(config,"authorityId")))throw new IllegalArgumentException("Wrong root");
      floor=key.getKind()==TotpStoreKey.Kind.NAMESPACE_STATE?Objects.requireNonNull(decoded.namespace).getMinimum():Objects.requireNonNull(decoded.account).observedAt;
      before=semantic(key,decoded.account,floor);after=before;target=row;
     }
    }else{
     try(var root=old.open(carrier(rootRow));var decoded=old.open(row)){
      if(decoded.account!=null&&decoded.account.observedAt.isAfter(root.namespace.observedAt))throw new IllegalArgumentException("Old floor invariant");
      floor=decoded.account==null?decoded.namespace.observedAt:decoded.account.observedAt;before=semantic(key,decoded.account,floor);
     }
     target=key.getKind()==TotpStoreKey.Kind.NAMESPACE_STATE?migration.migrateNamespace(row,intent):migration.migrateAccount(row,carrier(rootRow),intent);
     try(var decoded=next.open(target)){
      @NonNull Instant actual=decoded.account==null?Objects.requireNonNull(decoded.namespace).getMinimum():decoded.account.observedAt;
      if(!floor.equals(actual)||(decoded.namespace!=null&&!decoded.namespace.getAuthorityId().equals(text(config,"authorityId"))))throw new IllegalArgumentException("Floor/authority mismatch");
      after=semantic(key,decoded.account,actual);
     }
     if(row.getVersion().equals(target.getVersion())||!before.equals(after))throw new IllegalArgumentException("Semantic mismatch");
    }
    byte @NonNull [] sealed=target.getSealedBytes();int reserve=reserve(sealed);if(reserve>65536)throw new IllegalArgumentException("Carrier bound");
    @NonNull JsonObject targetRow=row(source,bytes(target.getVersion()),sealed,Instant.ofEpochSecond(Instant.MAX.getEpochSecond()));
    outputs.add(decision(source,targetRow,"FIT",before,after,floor,Instant.ofEpochSecond(Instant.MAX.getEpochSecond()),true,key.getKind().name(),verify?"TTR3":"TTR1_OR_TTR2","TTR3",reserve,sealed.length,b64(sealed).length(),opening,text(config,"activeKeyId"),rootCommitment(rootRow),required));
   }catch(Exception failure){outputs.add(refusal(source,"CORRUPT","TTR3",required));}
  }
  return JsonArray.fromElements(outputs);
 }
 private static @NonNull TotpStoreRecord carrier(@NonNull JsonObject row){if(!instant((JsonObject)row.find("retention").orElseThrow()).equals(Instant.ofEpochSecond(Instant.MAX.getEpochSecond())))throw new IllegalArgumentException("Invalid permanent carrier");return TotpStoreRecord.fromStoredForm(TotpStoreKey.fromStoredForm(text(row,"key")),text(row,"version"),bytes(text(row,"ciphertext")));}
 private static @NonNull String semantic(@NonNull TotpStoreKey key,TotpRecords.@Nullable Account a,@NonNull Instant floor)throws Exception{
  @NonNull MessageDigest d=MessageDigest.getInstance("SHA-256");try(@NonNull DataOutputStream o=new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(),d))){
   o.writeUTF(key.getStorageKey());time(o,floor);o.writeBoolean(a!=null);if(a!=null){o.writeUTF(a.accountId);o.writeUTF(a.fence);o.writeBoolean(a.active!=null);if(a.active!=null){o.writeUTF(a.active.factorId);blob(o,a.active.secret);time(o,a.active.enrolledAt);o.writeLong(a.active.usedStep);}o.writeBoolean(a.pending!=null);if(a.pending!=null){o.writeUTF(a.pending.enrollmentId);o.writeUTF(a.pending.factorId);blob(o,a.pending.secret);blob(o,a.pending.browserHash);time(o,a.pending.expiresAt);o.writeBoolean(a.pending.expectedFactorId!=null);if(a.pending.expectedFactorId!=null)o.writeUTF(a.pending.expectedFactorId);}o.writeBoolean(a.batchId!=null);if(a.batchId!=null)o.writeUTF(a.batchId);o.writeInt(a.recoveryHashes.size());for(byte @NonNull [] h:a.recoveryHashes)blob(o,h);o.writeInt(a.charges.size());for(var c:a.charges){o.writeUTF(c.id);time(o,c.at);}o.writeInt(a.totpCharges.size());for(var c:a.totpCharges){o.writeUTF(c.id);time(o,c.at);}}
  }return b64(d.digest());
 }
 private static void time(@NonNull DataOutputStream o,@NonNull Instant v)throws IOException{o.writeLong(v.getEpochSecond());o.writeInt(v.getNano());}
 private static void blob(@NonNull DataOutputStream o,byte @NonNull [] v)throws IOException{o.writeInt(v.length);o.write(v);}
}

