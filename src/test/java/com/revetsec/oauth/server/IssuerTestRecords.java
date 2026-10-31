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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.ScriptedOAuthStore;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

/** Test-only authenticated schema-two payload mutation, including intentionally malformed inner records. */
final class IssuerTestRecords {
 private IssuerTestRecords() { }
 static @NonNull JsonObject open(@NonNull OAuthStoreRecordCodec codec,@NonNull OAuthStoreEntry entry,@NonNull Clock clock) {
  return codec.openAdmitted(entry,clock).payload();
 }
 static @NonNull JsonObject malformedPayload(@NonNull OAuthStoreEntry entry,@NonNull Clock clock) {
  byte[] material=new byte[32];for(int n=0;n<32;n++)material[n]=(byte)(n+1);
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(material))).maximumSealedLength(16384).build();
  try {
   var text=SealedStateAccess.get().unseal(sealer,SealedStateType.AS_RECORD,entry.toSealedForm(),OAuthStoreRecordCodecV2.context(entry.getKey()),clock);
   return (JsonObject)OAuthStoreRecordCodecV2.parse(text,16384).find("payload").orElseThrow();
  } catch(com.revetsec.internal.crypto.UnsealException failure) {throw new AssertionError(failure);}
 }
 static @NonNull OAuthStoreEntry seal(@NonNull OAuthStoreRecordCodec codec,@NonNull OAuthStoreKey key,
   @NonNull Instant retention,@NonNull String text) {
  JsonObject payload=OAuthStoreRecordCodecV2.parse(text,16384);
  Instant floor=Instant.EPOCH;
  if(key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE) {
   // Deliberately avoid the payload decoder: negative cases must reach the real normal decoder.
   if(text.contains("\"highWaterSeconds\"")) {
    text=text.replace("\"schema\":1","\"schema\":2").replace("highWaterSeconds","minimumSeconds").replace("highWaterNanos","minimumNanos");
    text=text.substring(0,text.length()-1)+",\"authorityId\":\""+new ScriptedOAuthStore(Instant.EPOCH).admission().getAuthorityId()+"\"}";
    payload=OAuthStoreRecordCodecV2.parse(text,16384);
   }
   try {floor=Instant.ofEpochSecond(OAuthStoreFormat.longMember(payload,"minimumSeconds").orElse(0L),OAuthStoreFormat.longMember(payload,"minimumNanos").orElse(0L));}
   catch(IllegalArgumentException | java.time.DateTimeException ignored){floor=Instant.EPOCH;}
  } else if(key.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN) {
   floor=Instant.ofEpochSecond(OAuthStoreFormat.longMember(payload,"issued").orElse(0L));
  }
  byte[] material=new byte[32];for(int n=0;n<32;n++)material[n]=(byte)(n+1);
  StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(material)))
    .maximumSealedLength(16384).build();
  String version=codec.freshVersion();
  String envelope="{\"schema\":2,\"issuer\":"+JsonString.fromValue(codec.issuer()).toJson()
    +",\"key\":"+JsonString.fromValue(key.getStorageKey()).toJson()+",\"version\":\""+version
    +"\",\"retainUntil\":"+retention.getEpochSecond()+",\"floorSeconds\":"+floor.getEpochSecond()
    +",\"floorNanos\":"+floor.getNano()+",\"payload\":"+text+"}";
  String sealed=SealedStateAccess.get().seal(sealer,SealedStateType.AS_RECORD,envelope,OAuthStoreRecordCodecV2.context(key),retention);
  return OAuthStoreEntry.fromStoredForm(key,version,retention,sealed);
 }
}
