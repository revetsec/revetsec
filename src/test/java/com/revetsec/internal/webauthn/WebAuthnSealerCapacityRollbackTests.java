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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StateUnsealResult;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.testing.ScriptedWebAuthnStore;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Historical WebAuthn decode capacity is independent of the current emission cap; no size/floor/type bypass. */
final class WebAuthnSealerCapacityRollbackTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-11-02T12:00:00.123456789Z"),PERMANENT=WebAuthnRecordPayloadV2.PERMANENT;
 private static final @NonNull Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final @NonNull String NS="tenant",RP="login.example.com";
 private static final byte @NonNull [] HANDLE=pattern(64),ID=pattern(1023);
 private static final @NonNull WebAuthnStoreKey CREDENTIAL=WebAuthnStoreKey.forCredential(NS,RP,ID);
 private record Caps(int oldCap,int newCap){}
 private record Row(@NonNull WebAuthnStoreKey key,byte @NonNull [] sealed){}
 private static @NonNull Stream<@NonNull Caps> transitions(){return Stream.of(new Caps(3800,1024),new Caps(16384,1024),new Caps(16384,3800));}
 private static @NonNull SealingKey key(@NonNull String id,int seed){byte[] bytes=pattern(32);bytes[0]=(byte)seed;return SealingKey.fromBase64(id,Base64.getEncoder().encodeToString(bytes));}
 private static @NonNull StateSealer sealer(@NonNull String id,int cap,boolean rotated){
  var b=StateSealer.withActiveKey(key(rotated?"next":id,rotated?2:1)).maximumSealedLength(cap).clock(CLOCK);
  return (rotated?b.verificationKeys(List.of(key(id,1))):b).build();
 }
 private static byte @NonNull [] pattern(int size){byte[] b=new byte[size];for(int i=0;i<size;i++)b[i]=(byte)(i*37+11);return b;}
 private static int u16(byte @NonNull [] b,int p){return (b[p]&255)*256+(b[p+1]&255);}
 private static void emittedUnder(byte @NonNull [] b,int cap){int count=u16(b,4),position=24;assertTrue(count>=1&&count<=256);for(int i=0;i<count;i++){int n=u16(b,position);assertTrue(n>0&&n<=cap);position+=2+n;}assertEquals(b.length,position);assertTrue(b.length<=262144);}
 private static @NonNull ClosedMigrationIntent intent(){var a=new ScriptedWebAuthnStore(NOW).admission();return ClosedMigrationIntent.fromExternalIntent(Base64Url.encode(pattern(32)),a,Set.of(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> largerHistoricalChunksOpenAtTheLowerCapInEveryRecordPath(){return transitions().flatMap(c->Stream.of("k","k".repeat(64)).flatMap(id->Stream.of("legacy","normal","migration").map(mode->DynamicTest.dynamicTest(c+"/"+id.length()+"/"+mode,()->{
  var old=sealer(id,c.oldCap(),false);var current=sealer(id,c.newCap(),true);byte[] plain=pattern(90000);byte[] sealed=mode.equals("normal")?new WebAuthnRecordCodecV2(old).seal(CREDENTIAL,plain,PERMANENT):new WebAuthnRecordCodec(old).seal(CREDENTIAL,plain,PERMANENT);byte[] original=sealed.clone();assertTrue(u16(sealed,24)>c.newCap());
  byte[] opened;
  if(mode.equals("legacy"))opened=assertDoesNotThrow(()->new WebAuthnRecordCodec(current).open(CREDENTIAL,sealed,CLOCK));
  else if(mode.equals("normal"))opened=assertDoesNotThrow(()->new WebAuthnRecordCodecV2(current).open(CREDENTIAL,sealed,CLOCK));
  else try(var result=assertDoesNotThrow(()->new WebAuthnRecordCodecV2(current).openLegacyForMigration(CREDENTIAL.getStorageKey(),sealed,intent()))){opened=result.plaintext();}
  assertArrayEquals(plain,opened);assertArrayEquals(original,sealed);
  byte[] replacement=mode.equals("normal")?new WebAuthnRecordCodecV2(current).seal(CREDENTIAL,plain,PERMANENT):new WebAuthnRecordCodec(current).seal(CREDENTIAL,plain,PERMANENT);emittedUnder(replacement,c.newCap());
 }))));}
 private static byte @NonNull [] cose() throws Exception {byte[] spki=KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();ByteArrayOutputStream out=new ByteArrayOutputStream();for(int n:new int[]{0xa4,1,1,3,0x27,0x20,6,0x21,0x58,32})out.write(n);out.write(spki,spki.length-32,32);return out.toByteArray();}
 private static @NonNull Row row(@NonNull String kind,@NonNull WebAuthnRecordCodec codec) throws Exception {
  return switch(kind){
   case "credential"->{var r=new WebAuthnCredentialRecordCodec(NS,RP,codec).encode(WebAuthnCredentialState.checked(ID,HANDLE,cose(),-8,0xffff_ffffL,true,true),NOW);yield new Row(r.key(),r.sealedBytes());}
   case "tombstone"->{var r=new WebAuthnCredentialRecordCodec(NS,RP,codec).encodeRevoked(ID,HANDLE,NOW);yield new Row(r.key(),r.sealedBytes());}
   case "index"->{var indexes=new WebAuthnCredentialIndex(NS,RP,codec);var state=indexes.empty(HANDLE);for(int i=0;i<64;i++){byte[] id=ID.clone();id[0]=(byte)i;state=state.withAdded(id);}var r=indexes.encode(state,NOW);yield new Row(r.key(),r.sealedBytes());}
   case "fence"->{var r=new WebAuthnAccountFence(NS,RP,codec).encode(HANDLE,false,NOW);yield new Row(r.key(),r.sealedBytes());}
   default->{var root=WebAuthnStoreKey.forNamespaceClock(NS,RP);yield new Row(root,codec.sealNamespace(root,new ScriptedWebAuthnStore(NOW).admission().getAuthorityId(),NOW));}
  };
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> durableKindsResealUnderCurrentCapWithoutChangingAuthorityOrPayload(){return transitions().flatMap(c->Stream.of(false,true).flatMap(rotated->Stream.of("credential","tombstone","index","fence","root").map(kind->DynamicTest.dynamicTest(c+"/"+rotated+"/"+kind,()->{
  var old=new WebAuthnRecordCodec(sealer("k".repeat(64),c.oldCap(),false));var low=new WebAuthnRecordCodec(sealer("k".repeat(64),c.newCap(),rotated));Row r=row(kind,old);byte[] original=r.sealed().clone();
  try(var expected=old.openAdmittedRecord(r.key(),r.sealed(),CLOCK);var actual=assertDoesNotThrow(()->low.openAdmittedRecord(r.key(),r.sealed(),CLOCK))){
   assertEquals(expected.floor(),actual.floor());assertEquals(expected.expiresAt(),actual.expiresAt());assertEquals(expected.authorityId(),actual.authorityId());assertArrayEquals(expected.innerPayload(),actual.innerPayload());
   byte[] resealed=low.resealAdmitted(r.key(),r.sealed(),CLOCK);emittedUnder(resealed,c.newCap());
   try(var after=low.openAdmittedRecord(r.key(),resealed,CLOCK)){assertEquals(actual.floor(),after.floor());assertEquals(actual.expiresAt(),after.expiresAt());assertEquals(actual.authorityId(),after.authorityId());assertArrayEquals(actual.innerPayload(),after.innerPayload());}
  }
  assertArrayEquals(original,r.sealed());
 }))));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rollbackDoesNotRelaxBindingAuthenticationExpiryOrFloors(){return Stream.of("tag","key","address","floor","legacy-normal","oversize","truncated","chunk-limit").map(mode->DynamicTest.dynamicTest(mode,()->{
  var old=new WebAuthnRecordCodec(sealer("k",16384,false));var low=new WebAuthnRecordCodec(sealer("k",1024,false));Row r=row("index",old);byte[] bytes=r.sealed().clone();WebAuthnStoreKey key=r.key();Clock clock=CLOCK;
  switch(mode){case "tag"->bytes[bytes.length-1]^=1;case "key"->low=new WebAuthnRecordCodec(sealer("absent",1024,false));case "address"->key=WebAuthnStoreKey.forAccountCredentialIndex("other",RP,HANDLE);case "floor"->clock=Clock.fixed(NOW.minusNanos(1),ZoneOffset.UTC);case "legacy-normal"->bytes=old.seal(key,pattern(2000),PERMANENT);case "oversize"->bytes=new byte[262145];case "truncated"->bytes=Arrays.copyOf(bytes,bytes.length-1);case "chunk-limit"->{bytes[24]=0x40;bytes[25]=1;}default->{}}
  var codec=low;var addressed=key;byte[] input=bytes;Clock admitted=clock;assertThrows(WebAuthnRecordException.class,()->codec.openAdmittedRecord(addressed,input,admitted));
 }));}
 @Test void finiteRecordExpiryAndLegacyMigrationAuthorityRemainSeparate() throws Exception {
  var high=sealer("k",16384,false);var low=sealer("k",1024,false);byte[] plain=pattern(8000);Instant expiry=NOW.plusSeconds(30);byte[] war2=new WebAuthnRecordCodecV2(high).seal(CREDENTIAL,plain,expiry);var decoder=new WebAuthnRecordCodecV2(low);
  assertArrayEquals(plain,assertDoesNotThrow(()->decoder.open(CREDENTIAL,war2,Clock.fixed(Instant.ofEpochSecond(expiry.getEpochSecond()+1).minusNanos(1),ZoneOffset.UTC))));
  var expired=assertThrows(WebAuthnRecordException.class,()->decoder.open(CREDENTIAL,war2,Clock.fixed(Instant.ofEpochSecond(expiry.getEpochSecond()+1),ZoneOffset.UTC)));assertTrue(expired.isExpired());
  byte[] legacy=new WebAuthnRecordCodec(high).seal(CREDENTIAL,plain,NOW.minusSeconds(1));try(var opened=decoder.openLegacyForMigration(CREDENTIAL.getStorageKey(),legacy,intent())){assertArrayEquals(plain,opened.plaintext());}
  var wrong=ClosedMigrationIntent.fromExternalIntent(Base64Url.encode(pattern(32)),new ScriptedWebAuthnStore(NOW).admission(),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2));assertThrows(IllegalArgumentException.class,()->decoder.openLegacyForMigration(CREDENTIAL.getStorageKey(),legacy,wrong));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> otherSealingDomainsAndGeneralOpeningKeepConfiguredLengthCap(){return Stream.of(SealedStateType.values()).map(type->DynamicTest.dynamicTest(type.name(),()->{
  var high=sealer("k",16384,false);var low=sealer("k",1024,false);String text="p".repeat(2000),context=type==SealedStateType.AS_RECORD?"revetsec/as-record/v2:test":"context";
  String sealed=SealedStateAccess.get().seal(high,type,text,context,NOW.plusSeconds(60));assertTrue(sealed.length()>1024);var failure=assertThrows(UnsealException.class,()->SealedStateAccess.get().unseal(low,type,sealed,context,CLOCK));assertEquals(UnsealException.Kind.INVALID,failure.getKind());assertThrows(IllegalArgumentException.class,()->SealedStateAccess.get().seal(low,type,text,context,NOW.plusSeconds(60)));
  if(type==SealedStateType.AS_RECORD){assertThrows(UnsealException.class,()->SealedStateAccess.get().openRecord(low,type,sealed,context,CLOCK));var i=ClosedMigrationIntent.fromExternalIntent(Base64Url.encode(pattern(32)),new ScriptedWebAuthnStore(NOW).admission(),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2));assertThrows(UnsealException.class,()->SealedStateAccess.get().openForMigration(low,type,sealed,context,i));}
 }));}
 @Test void fixedWebAuthnCeilingIsExactly16384AndStillTyped() throws Exception {
  var high=sealer("k",16384,false);var low=sealer("k",1024,false);int length=0;while(SealerV1.sealedLength(1,length)<16384)length++;assertEquals(16384,SealerV1.sealedLength(1,length));String text="x".repeat(length),context="revetsec/wa-record/v2:fixed-test";
  String sealed=SealedStateAccess.get().seal(high,SealedStateType.WEBAUTHN_RECORD,text,context,NOW.plusSeconds(60));assertEquals(16384,sealed.length());try(var record=assertDoesNotThrow(()->SealedStateAccess.get().openRecord(low,SealedStateType.WEBAUTHN_RECORD,sealed,context,CLOCK))){assertEquals(text,record.getPlaintext());}
  assertThrows(UnsealException.class,()->SealedStateAccess.get().openRecord(low,SealedStateType.WEBAUTHN_RECORD,sealed+"A",context,CLOCK));assertThrows(UnsealException.class,()->SealedStateAccess.get().openRecord(low,SealedStateType.AS_RECORD,sealed,"revetsec/as-record/v2:fixed-test",CLOCK));assertThrows(IllegalArgumentException.class,()->SealedStateAccess.get().openRecord(low,SealedStateType.WEBAUTHN_RECORD,sealed,"context",CLOCK));
  String app=high.seal(text,"app",Duration.ofSeconds(60));assertInstanceOf(StateUnsealResult.Rejected.class,low.unsealResult(app,"app"));
 }
 @Test void invalidGeneralContextIsRejectedBeforeSamplingTheCallerClock(){
  var low=sealer("k",1024,false);Clock never=new Clock(){@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}@Override public @NonNull Instant instant(){throw new AssertionError("Invalid context must not invoke the caller clock.");}};
  for(String invalid:List.of("","x".repeat(257),"\ud800"))assertThrows(IllegalArgumentException.class,()->SealedStateAccess.get().openRecord(low,SealedStateType.WEBAUTHN_RECORD,"untrusted",invalid,never));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rebuiltEngineListsAndResealsRetainedInventoryAtLowerCap(){return transitions().map(c->DynamicTest.dynamicTest(c.toString(),()->{
  var source=new ScriptedWebAuthnStore(NOW);var old=new WebAuthnRecordCodec(sealer("k",c.oldCap(),false));Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present> inventory=new LinkedHashMap<>();
  for(String kind:List.of("root","fence","index")){Row r=row(kind,old);if(kind.equals("fence")){var f=new WebAuthnAccountFence(NS,RP,old).encode(HANDLE,true,NOW);r=new Row(f.key(),f.sealedBytes());}inventory.put(r.key(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{(byte)inventory.size()},r.sealed()));}
  var credentials=new WebAuthnCredentialRecordCodec(NS,RP,old);byte[] cose=cose();for(int i=0;i<64;i++){byte[] id=ID.clone();id[0]=(byte)i;var r=credentials.encode(WebAuthnCredentialState.checked(id,HANDLE,cose,-8,7,false,false),NOW);inventory.put(r.key(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{(byte)inventory.size()},r.sealedBytes()));}
  source.seedClosedMigration(inventory);var lowSealer=sealer("k",c.newCap(),true);WebAuthnRecoveryGate gate=budget->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};var engine=new WebAuthnEngine(NS,RP,Set.of("https://"+RP),source,lowSealer,gate,CLOCK,WebAuthnSettings.builder().build());
  var listing=engine.listCredentials(HANDLE);assertEquals(WebAuthnEngine.ManagementStatus.LISTED,listing.status());assertEquals(64,listing.credentialIds().size());var low=new WebAuthnRecordCodec(lowSealer);
  for(WebAuthnStoreKey key:List.of(WebAuthnStoreKey.forNamespaceClock(NS,RP),WebAuthnStoreKey.forAccountFence(NS,RP,HANDLE),WebAuthnStoreKey.forAccountCredentialIndex(NS,RP,HANDLE),WebAuthnStoreKey.forCredential(NS,RP,listing.credentialIds().get(0)))){
   var before=source.records();assertEquals(WebAuthnStoreCommitResult.COMMITTED,engine.resealStoreEntry(key).getStatus());var after=source.records();emittedUnder(requireNonNull(after.get(key)).getSealedBytes(),c.newCap());
   try(var a=old.openAdmittedRecord(key,requireNonNull(before.get(key)).getSealedBytes(),CLOCK);var b=low.openAdmittedRecord(key,requireNonNull(after.get(key)).getSealedBytes(),CLOCK)){assertEquals(a.floor(),b.floor());assertEquals(a.authorityId(),b.authorityId());assertEquals(a.expiresAt(),b.expiresAt());assertArrayEquals(a.innerPayload(),b.innerPayload());}
   for(var other:before.keySet())if(!other.equals(key)){assertArrayEquals(requireNonNull(before.get(other)).getVersion(),requireNonNull(after.get(other)).getVersion());assertArrayEquals(requireNonNull(before.get(other)).getSealedBytes(),requireNonNull(after.get(other)).getSealedBytes());}
  }
  assertEquals(WebAuthnEngine.ManagementStatus.LISTED,engine.listCredentials(HANDLE).status());assertEquals(64,engine.listCredentials(HANDLE).credentialIds().size());
 }));}
}
