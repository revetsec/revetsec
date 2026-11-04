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
import com.revetsec.*;
import com.revetsec.internal.crypto.*;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-05 exact plaintext/final-output boundaries; all settings are explicit fixture policies. */
final class OAuthMigrationCapacityConformanceTests {
 private static final @NonNull OAuthServerIngressLimits LIMITS=new OAuthServerIngressLimits(16384,16384,16384,4096,4096,8,16,128,128);
 private static final @NonNull Instant RETAIN=Instant.ofEpochSecond(1700000100);
 private static final @NonNull Clock CLOCK=Clock.fixed(Instant.EPOCH,ZoneOffset.UTC);
 private static final @NonNull JsonObject GRANT=loadGrant();
 @TestFactory @NonNull List<@NonNull DynamicTest> oldAndNewExactPlaintextAndFinalOutput(){List<DynamicTest> tests=new ArrayList<>();for(int format:List.of(1,2))for(int cap:List.of(1024,3800,16384))for(int keyLength:List.of(1,64))for(boolean unicode:List.of(false,true))for(boolean worst:List.of(false,true))for(int delta:List.of(-1,0,1))tests.add(DynamicTest.dynamicTest("MIG-05/ISSUER/envelope/"+format+"/"+cap+"/"+keyLength+"/"+unicode+"/"+worst+"/"+delta,()->{
  int bound=cap*3/4-(format==1?54+keyLength:118),size=bound+delta;Fixture f=fixture(format,cap,unicode,worst,size);StateSealer sealer=sealer(keyLength,cap);var old=new OAuthStoreRecordCodec(f.issuer,sealer,cap);var next=target(f.issuer,sealer,cap);String original=f.payload.toJson();
  if(delta>0){assertThrows(IllegalArgumentException.class,()->write(format,old,next,f));}
  else{var row=write(format,old,next,f);String text=raw(row,sealer,format);assertEquals(size,text.getBytes(StandardCharsets.UTF_8).length);assertEquals(outer(format,f.issuer,row.getKey(),row.getVersion(),f.retention,f.floor,f.payload),text);assertEquals(((54+keyLength+size)*4+2)/3,row.toSealedForm().length());assertEquals(original,(format==1?old.open(row,CLOCK):next.open(row,CLOCK).payload()).toJson());semantic(f,f.payload);if(delta==0)assertEquals(format==2 && keyLength==1?cap-84:cap,row.toSealedForm().length());}
  // Independent larger-cap sealing authenticates the exact over-budget JSON for the declared reader.
  if(delta>0){String text=outer(format,f.issuer,f.key,id(70),f.retention,f.floor,f.payload);String sealed=rawSeal(keyLength,"revetsec/as-record/v"+format+':'+f.key.getStorageKey(),f.retention,text);if(sealed.length()>16384)assertThrows(IllegalArgumentException.class,()->OAuthStoreEntry.fromStoredForm(f.key,id(70),f.retention,sealed));else{var row=OAuthStoreEntry.fromStoredForm(f.key,id(70),f.retention,sealed);assertThrows(IllegalArgumentException.class,()->{if(format==1)old.open(row,CLOCK);else next.open(row,CLOCK);});}}
  assertEquals(original,f.payload.toJson());assertEquals(cap,next.maximumRecordBytes());assertEquals(cap*3/4-118,next.maximumPlaintextBytes());assertEquals(cap,SealedStateAccess.get().getMaximumSealedLength(sealer));
 }));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> closedConversionAtTargetBoundaryKeepsOriginalFacts(){List<DynamicTest> tests=new ArrayList<>();for(int cap:List.of(1024,3800,16384))for(int keyLength:List.of(1,64))for(boolean unicode:List.of(false,true))for(boolean worst:List.of(false,true))for(int delta:List.of(-1,0,1))tests.add(DynamicTest.dynamicTest("MIG-05/ISSUER/closed-fit/"+cap+"/"+keyLength+"/"+unicode+"/"+worst+"/"+delta,()->{
  Fixture f=fixture(2,cap,unicode,worst,cap*3/4-118+delta);var s=sealer(keyLength,16384);var old=new OAuthStoreRecordCodec(f.issuer,s,16384);var next=target(f.issuer,s,cap);JsonObject oldPayload=f.key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE?root(1,f.floor):f.payload;var source=old.seal(f.key,f.retention,oldPayload.toJson());var oldRoot=f.key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE?source:old.seal(old.issuerKey(),OAuthStoreFormat.PERMANENT,root(1,f.floor).toJson());String sealedBefore=source.toSealedForm(),versionBefore=source.getVersion();var migration=new OAuthStoreMigrationCodec(next,16384,ClosedMigrationIntent.fromExternalIntent(id(1),StoreAdmission.fromIdentifiers(id(2),id(3)),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));var pinned=migration.openRoot(oldRoot);
  if(delta>0)assertThrows(IllegalArgumentException.class,()->migration.convert(source,pinned));else{var replacement=migration.convert(source,pinned);assertNotEquals(source.getVersion(),replacement.getVersion());assertEquals(source.getKey(),replacement.getKey());assertEquals(source.getRetainUntil(),replacement.getRetainUntil());String text=raw(replacement,s,2);assertEquals(cap*3/4-118+delta,text.getBytes(StandardCharsets.UTF_8).length);assertEquals(f.payload,next.open(replacement,CLOCK).payload());assertEquals(f.floor,next.open(replacement,CLOCK).floor());semantic(f,next.open(replacement,CLOCK).payload());assertTrue(replacement.toSealedForm().length()<=cap);}
  assertEquals(sealedBefore,source.toSealedForm());assertEquals(versionBefore,source.getVersion());assertEquals(oldPayload,old.open(source,CLOCK));assertEquals(cap,next.maximumRecordBytes());
 }));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> utf8ByteBudgetIsNotACharacterBudget(){List<DynamicTest> tests=new ArrayList<>();for(int cap:List.of(1024,3800,16384))for(int width:List.of(1,2,4))for(int delta:List.of(-1,0,1))tests.add(DynamicTest.dynamicTest("MIG-05/ISSUER/utf8/"+cap+"/"+width+"/"+delta,()->{int bound=cap*3/4-118,length=bound+delta;String unit=width==1?"a":width==2?"é":"😀";String text=unit.repeat(length/width)+"x".repeat(length%width);assertEquals(length,text.getBytes(StandardCharsets.UTF_8).length);if(delta<=0)assertArrayEquals(text.getBytes(StandardCharsets.UTF_8),OAuthStoreRecordCodecV2.boundedUtf8(text,bound));else assertThrows(IllegalArgumentException.class,()->OAuthStoreRecordCodecV2.boundedUtf8(text,bound));}));return tests;}
 private record Fixture(@NonNull String issuer,@NonNull OAuthStoreKey key,@NonNull JsonObject payload,@NonNull Instant retention,@NonNull Instant floor){}
 private static @NonNull Fixture fixture(int format,int cap,boolean unicode,boolean worst,int wanted){
  Instant floor=worst?Instant.ofEpochSecond(-31557014167219200L,999999999):Instant.ofEpochSecond(253402300799L,999999999);String issuer="https://capacity.issuer.example/"+(unicode?"é":"a");var scratch=new OAuthStoreRecordCodec(issuer,sealer(1,16384),16384);OAuthStoreKey key;JsonObject payload;Instant retention;
  if(cap==1024){payload=root(format,floor);key=scratch.issuerKey();retention=OAuthStoreFormat.PERMANENT;int base=outer(format,issuer,key,id(70),retention,floor,payload).getBytes(StandardCharsets.UTF_8).length;int count=wanted-base;assertTrue(count>=0);issuer+="x".repeat(count);assertTrue(issuer.length()<=2048);key=new OAuthStoreRecordCodec(issuer,sealer(1,16384),16384).issuerKey();}
  else{Map<String,JsonValue> members=new LinkedHashMap<>(GRANT.getMembers());members.put("subject",JsonString.fromValue(unicode?"é".repeat(512):"subject"));members.put("clientId",JsonString.fromValue("c"));List<JsonString> scopes=new ArrayList<>();for(int n=0;n<(cap==16384?64:1);n++)scopes.add(JsonString.fromValue(String.format(Locale.ROOT,"%03d",n)+"s".repeat(125)));members.put("scopes",JsonArray.fromElements(scopes));payload=JsonObject.fromMembers(members);key=scratch.key(OAuthStoreKey.Kind.GRANT,OAuthStoreFormat.stringMember(payload,"id").orElseThrow());retention=RETAIN;int base=outer(format,issuer,key,id(70),retention,floor,payload).getBytes(StandardCharsets.UTF_8).length;int count=wanted-base;assertTrue(count>=0 && count+1<=4096);members.put("clientId",JsonString.fromValue("c".repeat(count+1)));payload=JsonObject.fromMembers(members);}
  Fixture result=new Fixture(issuer,key,payload,retention,floor);assertEquals(wanted,outer(format,issuer,key,id(70),retention,floor,payload).getBytes(StandardCharsets.UTF_8).length);semantic(result,payload);return result;
 }
 private static void semantic(@NonNull Fixture f,@NonNull JsonObject payload){if(f.key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE){long schema=OAuthStoreFormat.longMember(payload,"schema").orElseThrow();if(schema==1)OAuthStoreFence.decode(payload,f.key.getKind());else OAuthIssuerRootV2.decode(payload);}else{var record=OAuthAuthorizationRecord.decode(f.key.getKind(),OAuthStoreRecordCodecV2.identifier(f.key),payload,LIMITS,1024);assertEquals("PENDING",record.text("status"));assertEquals(f.retention,record.retention());}}
 private static @NonNull JsonObject root(int format,@NonNull Instant floor){var b=JsonObject.builder().put("schema",(long)format).put("incarnation",id(4)).put("epoch",Long.MAX_VALUE);if(format==1)return b.put("highWaterSeconds",floor.getEpochSecond()).put("highWaterNanos",(long)floor.getNano()).build();return b.put("authorityId",id(2)).put("minimumSeconds",floor.getEpochSecond()).put("minimumNanos",(long)floor.getNano()).build();}
 private static @NonNull OAuthStoreEntry write(int format,@NonNull OAuthStoreRecordCodec old,@NonNull OAuthStoreRecordCodecV2 next,@NonNull Fixture f){return format==1?old.seal(f.key,f.retention,f.payload.toJson()):next.sealVersion(f.key,id(70),f.retention,f.floor,f.payload.toJson());}
 private static @NonNull String outer(int format,@NonNull String issuer,@NonNull OAuthStoreKey key,@NonNull String version,@NonNull Instant retention,@NonNull Instant floor,@NonNull JsonObject payload){return "{\"schema\":"+format+",\"issuer\":"+JsonString.fromValue(issuer).toJson()+",\"key\":"+JsonString.fromValue(key.getStorageKey()).toJson()+",\"version\":\""+version+"\",\"retainUntil\":"+retention.getEpochSecond()+(format==1?"":",\"floorSeconds\":"+floor.getEpochSecond()+",\"floorNanos\":"+floor.getNano())+",\"payload\":"+payload.toJson()+"}";}
 private static @NonNull String raw(@NonNull OAuthStoreEntry row,@NonNull StateSealer s,int format)throws Exception{return SealedStateAccess.get().unseal(s,SealedStateType.AS_RECORD,row.toSealedForm(),"revetsec/as-record/v"+format+':'+row.getKey().getStorageKey(),CLOCK);}
 private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull String issuer,@NonNull StateSealer s,int cap){return new OAuthStoreRecordCodecV2(issuer,s,cap,LIMITS,1024);}
 private static @NonNull String rawSeal(int keyLength,@NonNull String context,@NonNull Instant retain,@NonNull String text)throws Exception{byte[] master=java.util.Base64.getDecoder().decode("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");String id="k".repeat(keyLength);var key=SealerV1.Key.fromMasterKey(id,master);var entropy=EntropySource.fromDefaults();String sealed=SealerV1.seal(key,SealedStateType.AS_RECORD,context,retain.getEpochSecond(),text.getBytes(StandardCharsets.UTF_8),entropy.nextBytes(16),entropy.nextBytes(12));assertEquals(text,SealerV1.open(sealed,sealed.length(),Map.of(id,key),SealedStateType.AS_RECORD,context,Instant.EPOCH));return sealed;}
 private static @NonNull StateSealer sealer(int keyLength,int cap){return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(keyLength),"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(cap).clock(CLOCK).build();}
 private static @NonNull String id(int n){return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array());}
 private static @NonNull JsonObject loadGrant(){Properties p=new Properties();try(var in=new InputStreamReader(Objects.requireNonNull(OAuthMigrationCapacityConformanceTests.class.getResourceAsStream("/fixtures/oauth/mig-03.properties")),StandardCharsets.UTF_8)){p.load(in);}catch(Exception e){throw new ExceptionInInitializerError(e);}for(int n=0;n<Integer.parseInt(p.getProperty("count"));n++)if(p.getProperty("v."+n+".name").equals("GRANT/PENDING/matching/1"))return OAuthStoreRecordCodecV2.parse(new String(HexFormat.of().parseHex(p.getProperty("v."+n+".payloadHex")),StandardCharsets.UTF_8),16000);throw new ExceptionInInitializerError("Missing golden grant");}
}
