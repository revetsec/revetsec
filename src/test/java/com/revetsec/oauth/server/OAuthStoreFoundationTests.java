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
import com.revetsec.internal.crypto.UnsealException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Transport/codec/read-set tests only; no engine issuance or durable-backend evidence. */
class OAuthStoreFoundationTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00Z");
 private static final @NonNull String NONCE = "A".repeat(43);
 private static final @NonNull String VERSION = "B".repeat(42) + "A";
 private static final @NonNull String ISSUER = "https://issuer.example/tenant";
 private static @NonNull StateSealer sealer(@NonNull String id, byte fill, int cap) {
  byte[] bytes = new byte[32]; for(int i=0;i<bytes.length;i++) bytes[i]=(byte)(fill+i);
  return StateSealer.withActiveKey(SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(bytes)))
    .maximumSealedLength(cap).clock(clock(NOW)).build();
 }
 private static @NonNull Clock clock(@NonNull Instant time) { return Clock.fixed(time, ZoneOffset.UTC); }
 private static @NonNull OAuthStoreRecordCodec codec() { return new OAuthStoreRecordCodec(ISSUER, sealer("k", (byte) 1, 3800), 3800); }
 private static @NonNull OAuthStoreKey key(OAuthStoreKey.@NonNull Kind kind) {
  return OAuthStoreFormat.key(NONCE, kind, NONCE);
 }
 private static @NonNull OAuthStoreEntry entry(@NonNull OAuthStoreKey key) {
  return OAuthStoreEntry.fromStoredForm(key, VERSION,
   key.getKind() == OAuthStoreKey.Kind.ISSUER_STATE || key.getKind() == OAuthStoreKey.Kind.SUBJECT_STATE
    ? OAuthStoreFormat.PERMANENT : NOW.plusSeconds(60), "opaque");
 }
 private static void rejected(@NonNull Executable operation) {
  IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, operation);
  assertEquals("Invalid OAuth store value.", failure.getMessage()); assertNull(failure.getCause());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyKindRoundTripsWithoutIdentityDiagnostics() {
  return Stream.of(OAuthStoreKey.Kind.values()).map(kind -> DynamicTest.dynamicTest(kind.name(), () -> {
   OAuthStoreKey original = key(kind); OAuthStoreKey copy = OAuthStoreKey.fromStoredForm(original.getStorageKey());
   assertEquals(original, copy); assertEquals(original.hashCode(), copy.hashCode()); assertEquals(kind, copy.getKind());
   assertFalse(copy.equals("other")); assertFalse(copy.equals(null)); assertEquals("OAuthStoreKey{address=<redacted>}", copy.toString());
   OAuthStoreEntry row = entry(copy); assertEquals(copy, row.getKey()); assertEquals(VERSION, row.getVersion());
   assertEquals("opaque", row.toSealedForm()); assertEquals("OAuthStoreEntry{record=<redacted>}", row.toString());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedStorageAddressesRejectBeforeReconstruction() {
  String good = key(OAuthStoreKey.Kind.CODE).getStorageKey();
  return Stream.of("", "x".repeat(257), good + ":suffix", good.replace(":1:", ":2:"),
   good.replace(":CODE:", ":UNKNOWN:"), good.replace(":CODE:", ":code:"),
   good.replace(":CODE:", ":CODE::"), good.substring(0, good.length()-1),
   good.substring(0, good.length()-1)+"B", good.replace("A", "é"), good.replace(":CODE:", ":CODE/"),
   "revetsec:as:1:"+NONCE+":ISSUER_STATE:"+VERSION).map(value -> DynamicTest.dynamicTest("bad-key-"+value.length()+"-"+value.hashCode(),
    () -> rejected(() -> OAuthStoreKey.fromStoredForm(value))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedVersionsRejectWithoutReflectingInput() {
  return Stream.of("", "A".repeat(42), "A".repeat(44), "A".repeat(42)+"B", "A".repeat(42)+"=",
    "A".repeat(42)+"é", "A".repeat(42)+"/", "A".repeat(42)+" ").map(value ->
    DynamicTest.dynamicTest("bad-version-"+value.length()+"-"+value.hashCode(), () -> rejected(() ->
     OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), value, NOW, "a"))));
 }
 @Test void canonicalNonceEndingBitsAndInclusiveEnvelopeCap() {
  for (char c : "AEIMQUYcgkosw048".toCharArray()) OAuthStoreFormat.nonce("A".repeat(42)+c);
  assertEquals(16384, OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW, "a".repeat(16384)).toSealedForm().length());
  rejected(() -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW, "a".repeat(16385)));
  rejected(() -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW, "é"));
  rejected(() -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW, ""));
 }
 @Test void permanentFencesAndFiniteRetentionAreDistinct() {
  for (OAuthStoreKey.Kind kind : List.of(OAuthStoreKey.Kind.ISSUER_STATE, OAuthStoreKey.Kind.SUBJECT_STATE)) {
   assertEquals(OAuthStoreFormat.PERMANENT, entry(key(kind)).getRetainUntil());
   rejected(() -> OAuthStoreEntry.fromStoredForm(key(kind), VERSION, NOW, "x"));
   rejected(() -> OAuthStoreEntry.fromStoredForm(key(kind), VERSION, Instant.MAX, "x"));
  }
  rejected(() -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, OAuthStoreFormat.PERMANENT, "x"));
  rejected(() -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW.plusNanos(1), "x"));
 }
 @SuppressWarnings("NullAway") // Deliberate null boundary probes.
 @Test void allPublicConstructionArgumentsRejectNull() {
  assertThrows(NullPointerException.class, () -> OAuthStoreKey.fromStoredForm(null));
  assertThrows(NullPointerException.class, () -> OAuthStoreEntry.fromStoredForm(null, VERSION, NOW, "x"));
  assertThrows(NullPointerException.class, () -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), null, NOW, "x"));
  assertThrows(NullPointerException.class, () -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, null, "x"));
  assertThrows(NullPointerException.class, () -> OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE), VERSION, NOW, null));
 }
 @Test void barrierIncludesAbsentAndPresentObservationsAndUsesSnapshots() {
  OAuthStoreReadSet reads = new OAuthStoreReadSet(); OAuthStoreKey code = key(OAuthStoreKey.Kind.CODE), grant = key(OAuthStoreKey.Kind.GRANT);
  reads.observe(code, Optional.of(entry(code))); reads.observe(grant, Optional.empty());
  reads.observe(OAuthStoreKey.fromStoredForm(code.getStorageKey()), Optional.of(entry(code)));
  OAuthStoreTransaction barrier = reads.transaction(List.of()); assertEquals(2, barrier.getConditions().size());
  assertEquals(Optional.of(VERSION), barrier.getConditions().get(0).getExpectedVersion());
  assertEquals(Optional.empty(), barrier.getConditions().get(1).getExpectedVersion()); assertTrue(barrier.getMutations().isEmpty());
  reads.observe(key(OAuthStoreKey.Kind.ACCESS_TOKEN), Optional.empty()); assertEquals(2, barrier.getConditions().size());
  assertThrows(UnsupportedOperationException.class, () -> barrier.getConditions().clear());
  assertThrows(UnsupportedOperationException.class, () -> barrier.getMutations().clear());
  assertEquals("OAuthStoreTransaction{transaction=<redacted>}", barrier.toString());
  assertEquals("Condition{predicate=<redacted>}", barrier.getConditions().get(0).toString());
 }
 @SuppressWarnings("NullAway") // Deliberate null boundary probes.
 @Test void readSetRejectsMissingChangedAndMismatchedObservations() {
  OAuthStoreReadSet reads = new OAuthStoreReadSet(); rejected(() -> reads.transaction(List.of()));
  OAuthStoreKey code = key(OAuthStoreKey.Kind.CODE); reads.observe(code, Optional.empty());
  rejected(() -> reads.observe(code, Optional.of(entry(code))));
  rejected(() -> reads.observe(code, Optional.of(entry(key(OAuthStoreKey.Kind.GRANT)))));
  assertThrows(NullPointerException.class, () -> reads.observe(code, null));
 }
 @Test void completePutRemoveTransactionsRequireAllExactPredicates() {
  OAuthStoreKey code = key(OAuthStoreKey.Kind.CODE), grant = key(OAuthStoreKey.Kind.GRANT); OAuthStoreEntry row = entry(code);
  var put = OAuthStoreTransaction.Mutation.fromPut(row); var remove = OAuthStoreTransaction.Mutation.fromRemove(grant);
  List<OAuthStoreTransaction.Condition> conditions = new ArrayList<>(List.of(
   OAuthStoreTransaction.Condition.fromAbsent(code), OAuthStoreTransaction.Condition.fromVersion(grant, VERSION)));
  List<OAuthStoreTransaction.Mutation> mutations = new ArrayList<>(List.of(put, remove));
  OAuthStoreTransaction transaction = OAuthStoreTransaction.fromConditions(conditions, mutations); conditions.clear(); mutations.clear();
  assertEquals(2, transaction.getConditions().size()); assertEquals(2, transaction.getMutations().size());
  assertEquals(code, put.getKey()); assertEquals(Optional.of(row), put.getEntry()); assertEquals(OAuthStoreTransaction.Mutation.Kind.PUT, put.getKind());
  assertEquals(grant, remove.getKey()); assertEquals(Optional.empty(), remove.getEntry()); assertEquals(OAuthStoreTransaction.Mutation.Kind.REMOVE, remove.getKind());
  assertEquals("Mutation{change=<redacted>}", put.toString());
  rejected(() -> OAuthStoreTransaction.fromConditions(List.of(OAuthStoreTransaction.Condition.fromAbsent(code)), List.of(remove)));
  rejected(() -> OAuthStoreTransaction.fromConditions(List.of(OAuthStoreTransaction.Condition.fromAbsent(grant)), List.of(remove)));
  rejected(() -> OAuthStoreTransaction.fromConditions(List.of(OAuthStoreTransaction.Condition.fromAbsent(code)), List.of(put, put)));
  rejected(() -> OAuthStoreTransaction.fromConditions(List.of(OAuthStoreTransaction.Condition.fromAbsent(code), OAuthStoreTransaction.Condition.fromAbsent(code)), List.of()));
 }
 @Test void inclusiveConditionAndMutationCapsBoundBeforeCopy() {
  List<OAuthStoreTransaction.Condition> conditions = new ArrayList<>(); List<OAuthStoreTransaction.Mutation> mutations = new ArrayList<>();
  OAuthStoreReadSet reads = new OAuthStoreReadSet();
  for (int i=0;i<16;i++) {
   String id = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {(byte)i,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
   OAuthStoreKey k = OAuthStoreFormat.key(NONCE, OAuthStoreKey.Kind.CODE, id); reads.observe(k, Optional.empty());
   conditions.add(OAuthStoreTransaction.Condition.fromAbsent(k));
   if(i<8) mutations.add(OAuthStoreTransaction.Mutation.fromPut(entry(k)));
  }
  assertEquals(16, reads.transaction(mutations).getConditions().size());
  assertEquals(8, OAuthStoreTransaction.fromConditions(conditions, mutations).getMutations().size());
  mutations.add(OAuthStoreTransaction.Mutation.fromPut(entry(conditions.get(8).getKey())));
  rejected(() -> OAuthStoreTransaction.fromConditions(conditions, mutations));
  conditions.add(OAuthStoreTransaction.Condition.fromAbsent(key(OAuthStoreKey.Kind.GRANT)));
  rejected(() -> OAuthStoreTransaction.fromConditions(conditions, List.of()));
  rejected(() -> reads.observe(key(OAuthStoreKey.Kind.GRANT), Optional.empty()));
 }
 @Test void codecBindsIssuerExactSpellingSubjectKindAndRandomVersions() {
  OAuthStoreRecordCodec codec = codec(); OAuthStoreKey code = codec.key(OAuthStoreKey.Kind.CODE, NONCE);
  OAuthStoreEntry first = codec.seal(code, NOW.plusSeconds(60), "{\"scope\":\"read\"}");
  OAuthStoreEntry next = codec.seal(code, NOW.plusSeconds(60), "{\"scope\":\"read\"}");
  assertNotEquals(first.getVersion(), next.getVersion()); assertNotEquals(first.toSealedForm(), next.toSealedForm());
  assertEquals("read", codec.open(first, clock(NOW)).findString("scope").orElseThrow());
  assertEquals(codec.issuerKey(), new OAuthStoreRecordCodec(ISSUER, sealer("k", (byte) 1,3800),3800).issuerKey());
  assertNotEquals(codec.issuerKey(), new OAuthStoreRecordCodec(ISSUER+"/",sealer("k",(byte)1,3800),3800).issuerKey());
  assertNotEquals(codec.subjectKey("Alice"),codec.subjectKey("alice"));
  assertNotEquals(codec.subjectKey("Alice"),new OAuthStoreRecordCodec(ISSUER+"/",sealer("k",(byte)1,3800),3800).subjectKey("Alice"));
 }
 @Test void codecRejectsSubstitutedAddressVersionRetentionAndNamespace() {
  OAuthStoreRecordCodec codec = codec(); OAuthStoreKey code = codec.key(OAuthStoreKey.Kind.CODE, NONCE);
  OAuthStoreEntry row = codec.seal(code,NOW.plusSeconds(60),"{}");
  for (OAuthStoreEntry altered : List.of(
   OAuthStoreEntry.fromStoredForm(codec.key(OAuthStoreKey.Kind.GRANT,NONCE),row.getVersion(),row.getRetainUntil(),row.toSealedForm()),
   OAuthStoreEntry.fromStoredForm(code,VERSION,row.getRetainUntil(),row.toSealedForm()),
   OAuthStoreEntry.fromStoredForm(code,row.getVersion(),NOW.plusSeconds(61),row.toSealedForm()),
   OAuthStoreEntry.fromStoredForm(key(OAuthStoreKey.Kind.CODE),row.getVersion(),row.getRetainUntil(),row.toSealedForm()),
   OAuthStoreEntry.fromStoredForm(code,row.getVersion(),row.getRetainUntil(),row.toSealedForm()+"!")))
    rejected(() -> codec.open(altered,clock(NOW)));
 }
 @Test void domainLabelCannotBeSubstitutedForApplicationOrOtherProtocolState() throws UnsealException {
  OAuthStoreRecordCodec codec = codec(); StateSealer sealer = sealer("k",(byte)1,3800);
  OAuthStoreEntry row=codec.seal(codec.key(OAuthStoreKey.Kind.CODE,NONCE),NOW.plusSeconds(60),"{}");
  String context="revetsec/as-record/v1:"+row.getKey().getStorageKey();
  for(SealedStateType type : SealedStateType.values()) if(type!=SealedStateType.AS_RECORD) {
   assertThrows(UnsealException.class,()->SealedStateAccess.get().unseal(sealer,type,row.toSealedForm(),context,clock(NOW)));
   String other=SealedStateAccess.get().seal(sealer,type,"{}",context,NOW.plusSeconds(60));
   rejected(()->codec.open(OAuthStoreEntry.fromStoredForm(row.getKey(),row.getVersion(),row.getRetainUntil(),other),clock(NOW)));
  }
 }
 @Test void finiteExpiryAndPermanentResealingUseExistingKeys() {
  OAuthStoreRecordCodec codec=codec(); OAuthStoreEntry finite=codec.seal(codec.key(OAuthStoreKey.Kind.CODE,NONCE),NOW.plusSeconds(60),"{}");
  assertEquals("{}",codec.open(finite,clock(NOW.plusSeconds(59).plusNanos(999999999))).toJson());
  rejected(()->codec.open(finite,clock(NOW.plusSeconds(60))));
  OAuthStoreEntry permanent=codec.seal(codec.issuerKey(),OAuthStoreFormat.PERMANENT,"{\"epoch\":1}");
  assertEquals(1L,codec.open(permanent,clock(NOW.plusSeconds(86400*401L))).findLong("epoch").orElseThrow());
  byte[] oldKey=new byte[32],newKey=new byte[32];for(int i=0;i<32;i++){oldKey[i]=(byte)(1+i);newKey[i]=(byte)(2+i);}
  StateSealer rotated=StateSealer.withActiveKey(SealingKey.fromBase64("new",Base64.getEncoder().encodeToString(newKey)))
    .verificationKeys(List.of(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(oldKey)))).build();
  assertEquals(1L,new OAuthStoreRecordCodec(ISSUER,rotated,3800).open(permanent,clock(NOW)).findLong("epoch").orElseThrow());
  rejected(()->new OAuthStoreRecordCodec(ISSUER,sealer("new",(byte)2,3800),3800).open(permanent,clock(NOW)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> strictBoundedPayloadsReject() {
  return Stream.of("[]","null","{\"x\":1,\"x\":2}","{\"x\":\"\ud800\"}","{\"x\":\""+"é".repeat(2000)+"\"}","{\"x\":\""+"a".repeat(20000)+"\"}")
   .map(payload -> DynamicTest.dynamicTest("bad-payload-"+payload.length()+"-"+payload.hashCode(),()->{
    OAuthStoreRecordCodec codec=codec(); rejected(()->codec.seal(codec.key(OAuthStoreKey.Kind.CODE,NONCE),NOW.plusSeconds(60),payload));
   }));
 }
 @SuppressWarnings("NullAway") // Deliberate null boundary probes.
 @Test void sealerCapGetterAndCrossFieldRecordLimitsArePure() {
  StateSealer sealer=sealer("k",(byte)1,1024); assertEquals(1024,SealedStateAccess.get().getMaximumSealedLength(sealer));
  assertThrows(NullPointerException.class,()->SealedStateAccess.get().getMaximumSealedLength(null));
  rejected(()->new OAuthStoreRecordCodec(ISSUER,sealer,1025)); rejected(()->new OAuthStoreRecordCodec(ISSUER,sealer,1023));
  OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,sealer,1024);
  assertTrue(codec.seal(codec.issuerKey(),OAuthStoreFormat.PERMANENT,"{}").toSealedForm().length()<=1024);
 }
 @Test void everyExportedCarrierConstructorAndTransactionFactoryIsRestricted() {
  for(Class<?> type:List.of(OAuthStoreKey.class,OAuthStoreEntry.class,OAuthStoreTransaction.class,
    OAuthStoreTransaction.Condition.class,OAuthStoreTransaction.Mutation.class))
   for(var constructor:type.getDeclaredConstructors()) assertTrue(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()));
  for(Class<?> type:List.of(OAuthStoreTransaction.class,OAuthStoreTransaction.Condition.class,OAuthStoreTransaction.Mutation.class))
   for(var method:type.getDeclaredMethods()) if(java.lang.reflect.Modifier.isStatic(method.getModifiers()))
    assertFalse(java.lang.reflect.Modifier.isPublic(method.getModifiers()));
  assertEquals(List.of(OAuthStoreCommitStatus.COMMITTED,OAuthStoreCommitStatus.CONFLICT,OAuthStoreCommitStatus.UNKNOWN),List.of(OAuthStoreCommitStatus.values()));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> authenticatedMalformedCommonBindingsStillReject() {
  OAuthStoreRecordCodec codec=codec(); OAuthStoreKey key=codec.key(OAuthStoreKey.Kind.CODE,NONCE);
  String raw="{\"schema\":1,\"issuer\":\""+ISSUER+"\",\"key\":\""+key.getStorageKey()
    +"\",\"version\":\""+VERSION+"\",\"retainUntil\":"+NOW.plusSeconds(60).getEpochSecond()+",\"payload\":{}}";
  return Stream.of("[]", raw.replace("\"schema\":1","\"schema\":2"), raw.replace(ISSUER,ISSUER+"/"),
    raw.replace(key.getStorageKey(),codec.key(OAuthStoreKey.Kind.GRANT,NONCE).getStorageKey()),
    raw.replace(VERSION,NONCE),raw.replace(Long.toString(NOW.plusSeconds(60).getEpochSecond()),"1"),
    raw.replace("\"payload\":{}","\"payload\":[]"),raw.replace("\"schema\":1,",""),
    raw.replace("\"schema\":1,","\"schema\":1,\"extra\":0,"),"{bad}",
    raw.replace("\"schema\":1,","\"schema\":1,\"schema\":1,"))
    .map(text->DynamicTest.dynamicTest("bad-authenticated-binding-"+text.length()+"-"+text.hashCode(),()->{
     StateSealer sealer=sealer("k",(byte)1,3800);
     String sealed=SealedStateAccess.get().seal(sealer,SealedStateType.AS_RECORD,text,
       "revetsec/as-record/v1:"+key.getStorageKey(),NOW.plusSeconds(60));
     rejected(()->codec.open(OAuthStoreEntry.fromStoredForm(key,VERSION,NOW.plusSeconds(60),sealed),clock(NOW)));
    }));
 }
 @Test void boundedConfigurationAndAggregateUtf8SerializationReject() {
  StateSealer sealer=sealer("k",(byte)1,3800);
  rejected(()->new OAuthStoreRecordCodec("",sealer,3800)); rejected(()->new OAuthStoreRecordCodec("a".repeat(2049),sealer,3800));
  rejected(()->new OAuthStoreRecordCodec("\ud800",sealer,3800));
  OAuthStoreRecordCodec codec=codec(); rejected(()->codec.subjectKey(""));
  rejected(()->codec.subjectKey("a".repeat(2049))); rejected(()->codec.subjectKey("\ud800"));
  OAuthStoreKey key=codec.key(OAuthStoreKey.Kind.CODE,NONCE);
  rejected(()->codec.seal(key,NOW.plusSeconds(60),"{\"x\":\""+"a".repeat(2600)+"\"}"));
  rejected(()->codec.seal(key,NOW.plusSeconds(60),"{\"x\":\""+"é".repeat(1300)+"\"}"));
  String tooBig="a".repeat(3801);
  rejected(()->codec.open(OAuthStoreEntry.fromStoredForm(key,VERSION,NOW.plusSeconds(60),tooBig),clock(NOW)));
  String shorter="revetsec:as:1:"+NONCE+"XCODE:"+NONCE;
  rejected(()->OAuthStoreKey.fromStoredForm(shorter));
 }

}
