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
import com.revetsec.StoreAdmission;
import com.revetsec.internal.http.Deadline;
import com.revetsec.testing.ScriptedOAuthStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-13 source/volatile-store cells. Neither fixture supplies durable or real UTC evidence. */
final class OAuthFenceOnlyMigrationTests {
 private static final @NonNull Instant L=Instant.parse("2026-10-04T12:00:00.123456789Z");
 private static @NonNull Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(10));}
 private static final class Worker extends Clock {
  private int reads;
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){this.reads++;throw new IllegalStateException("UTC outage and unusable worker");}
 }
 private static final class Fixture implements OAuthAuthorizationServerStore {
  private final @NonNull Worker worker=new Worker();
  private final @NonNull OAuthAtomicStoreFixture atomic=new OAuthAtomicStoreFixture(L.plusSeconds(10));
  private final @NonNull ScriptedOAuthStore volatileStore=new ScriptedOAuthStore(L.plusSeconds(10));
  private final boolean scripted;
  private final @NonNull OAuthStoreRecordCodec codec;
  private final @NonNull OAuthStoreCoordinator coordinator;
  private int commits;
  private @Nullable OAuthStoreTransaction last;
  private @Nullable Runnable beforeCommit;
  private boolean closed,unknownRecovery;
  Fixture(boolean scripted,int nano,@NonNull String damage){
   this.scripted=scripted;byte[] material=new byte[32];for(int i=0;i<material.length;i++)material[i]=(byte)(i+1);String key=Base64.getEncoder().encodeToString(material);
   StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",key)).clock(this.worker).build();
   this.codec=new OAuthStoreRecordCodec("https://issuer.example/mig13",sealer,3800);
   this.coordinator=new OAuthStoreCoordinator(this,this.codec,this.worker,3,255);
   Instant minimum=Instant.ofEpochSecond(L.getEpochSecond(),nano),floor=minimum.plusNanos(1);
   String root=OAuthIssuerRootV2.initial("A".repeat(43),admission().getAuthorityId(),minimum).toPayload();
   String subject=OAuthStoreFence.initialSubject(("B".repeat(42)+"A")).toPayload();
   if(damage.equals("AUTHORITY"))root=root.replace(admission().getAuthorityId(),("C".repeat(42)+"A"));
   if(damage.equals("ROOT_OVERFLOW"))root=root.replace("\"epoch\":0","\"epoch\":"+Long.MAX_VALUE);
   if(damage.equals("SUBJECT_OVERFLOW"))subject=subject.replace("\"epoch\":0","\"epoch\":"+Long.MAX_VALUE);
   OAuthStoreEntry issuer=this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,minimum,root);
   OAuthStoreEntry entity=this.codec.sealAdmitted(this.codec.subjectKey("subject"),OAuthStoreFormat.PERMANENT,floor,subject);
   if(damage.equals("ROOT_CORRUPT"))issuer=corrupt(issuer);
   if(damage.equals("SUBJECT_CORRUPT"))entity=corrupt(entity);
   if(damage.equals("FINITE_ROOT"))issuer=OAuthStoreEntry.fromStoredForm(issuer.getKey(),issuer.getVersion(),Instant.ofEpochSecond(L.getEpochSecond()+100),issuer.toSealedForm());
   Map<OAuthStoreKey,OAuthStoreEntry> seed=new java.util.LinkedHashMap<>();
   if(!damage.equals("MISSING_ROOT"))seed.put(issuer.getKey(),issuer);
   if(!damage.equals("MISSING_SUBJECT"))seed.put(entity.getKey(),entity);
   if(scripted){this.volatileStore.seedClosedMigration(seed);this.volatileStore.setHealthy(false);}
   else {this.atomic.rows.putAll(seed);this.atomic.healthy=false;}
   this.closed=damage.equals("CLOSED_RECOVERY");this.unknownRecovery=damage.equals("UNKNOWN_RECOVERY");
  }
  private static @NonNull OAuthStoreEntry corrupt(@NonNull OAuthStoreEntry entry){return OAuthStoreEntry.fromStoredForm(entry.getKey(),entry.getVersion(),entry.getRetainUntil(),"corrupt");}
  private @NonNull StoreAdmission admission(){return this.scripted?this.volatileStore.admission():this.atomic.admission;}
  private @NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> rows(){return this.scripted?this.volatileStore.records():Map.copyOf(this.atomic.rows);}
  private @NonNull OAuthStoreEntry root(){return requireNonNull(rows().get(this.codec.issuerKey()));}
  private @NonNull OAuthStoreEntry entity(){return requireNonNull(rows().get(this.codec.subjectKey("subject")));}
  private void rotateRecovery(){if(this.scripted)this.volatileStore.rotateRecoveryGeneration();else this.atomic.admission=StoreAdmission.fromIdentifiers(admission().getAuthorityId(),("D".repeat(42)+"A"));}
  @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
   if(this.closed)return OAuthStoreReadResult.Fenced.get();
   if(this.unknownRecovery)return OAuthStoreReadResult.Unavailable.get();
   return this.scripted?this.volatileStore.read(key,budget):this.atomic.read(key,budget);
  }
  @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){
   this.commits++;this.last=tx;Runnable hook=this.beforeCommit;this.beforeCommit=null;if(hook!=null)hook.run();
   return this.scripted?this.volatileStore.commit(tx,budget):this.atomic.commit(tx,budget);
  }
  private void revoke(boolean all){if(all)this.coordinator.revokeAll(deadline());else this.coordinator.revokeSubject("subject",deadline());}
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> outageAdvancesOnlyEpochWithExactPermanentFacts(){
  List<DynamicTest> cases=new ArrayList<>();
  for(boolean scripted:List.of(false,true))for(boolean all:List.of(false,true))for(int nano:List.of(1,123456789,999999999))
   cases.add(DynamicTest.dynamicTest("MIG-13/preserve/"+scripted+"/"+all+"/"+nano,()->{
    Fixture f=new Fixture(scripted,nano,"CONTROL");var before=f.rows();var root=f.root();var entity=f.entity();
    var oldRoot=f.codec.openPermanentFence(root,f.admission(),root);var oldEntity=f.codec.openPermanentFence(entity,f.admission(),root);
    f.revoke(all);var afterRoot=f.codec.openPermanentFence(f.root(),f.admission(),f.root());var afterEntity=f.codec.openPermanentFence(f.entity(),f.admission(),f.root());
    assertEquals(oldRoot.floor(),afterRoot.floor());assertEquals(oldEntity.floor(),afterEntity.floor());
    assertEquals(oldRoot.payload().toJson().replace("\"epoch\":0","\"epoch\":"+(all?1:0)),afterRoot.payload().toJson());
    assertEquals(oldEntity.payload().toJson().replace("\"epoch\":0","\"epoch\":"+(all?0:1)),afterEntity.payload().toJson());
    OAuthStoreKey changed=all?root.getKey():entity.getKey(),untouched=all?entity.getKey():root.getKey();
    assertEquals(before.keySet(),f.rows().keySet());assertSame(before.get(untouched),f.rows().get(untouched));
    assertNotEquals(requireNonNull(before.get(changed)).getVersion(),requireNonNull(f.rows().get(changed)).getVersion());
    assertTrue(f.rows().values().stream().allMatch(e->e.getRetainUntil().equals(OAuthStoreFormat.PERMANENT)));
    var tx=requireNonNull(f.last);assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertTrue(tx.getTemporalCondition().isEmpty());
    assertEquals(all?1:2,tx.getConditions().size());assertTrue(tx.getConditions().stream().allMatch(c->c.getExpectedVersion().orElseThrow().equals(requireNonNull(before.get(c.getKey())).getVersion())));
    assertEquals(1,tx.getMutations().size());assertEquals(changed,tx.getMutations().get(0).getKey());assertEquals(1,f.commits);assertEquals(0,f.worker.reads);
   }));
  return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> recoveryAndAuthenticatedRootFailuresHaveZeroEffects(){
  List<DynamicTest> cases=new ArrayList<>();
  for(boolean scripted:List.of(false,true))for(boolean all:List.of(false,true))for(String damage:List.of("MISSING_ROOT","ROOT_CORRUPT","AUTHORITY","FINITE_ROOT","CLOSED_RECOVERY","UNKNOWN_RECOVERY","ROOT_OVERFLOW","MISSING_SUBJECT","SUBJECT_CORRUPT","SUBJECT_OVERFLOW")){
   if(all&&damage.startsWith("SUBJECT_"))continue;if(all&&damage.equals("MISSING_SUBJECT"))continue;
   // Issuer-wide fencing needs only its root; subject epoch exhaustion is local to subject fencing.
   if(!all&&damage.equals("ROOT_OVERFLOW"))continue;
   cases.add(DynamicTest.dynamicTest("MIG-13/refuse/"+scripted+"/"+all+"/"+damage,()->{
    if(damage.equals("FINITE_ROOT")){assertThrows(IllegalArgumentException.class,()->new Fixture(scripted,123456789,damage));return;}
    Fixture f=new Fixture(scripted,123456789,damage);var before=f.rows();assertThrows(OAuthStoreFailure.class,()->f.revoke(all));
    assertEquals(before,f.rows());assertEquals(0,f.commits);assertEquals(0,f.worker.reads);
   }));
  }
  return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> otherMutationPurposesCannotBorrowOutageAdmission(){
  List<DynamicTest> cases=new ArrayList<>();
  for(boolean scripted:List.of(false,true))for(String purpose:List.of("INITIALIZE","ESTABLISH","RESEAL_ROOT","RESEAL_SUBJECT","STATUS_BARRIER"))
   cases.add(DynamicTest.dynamicTest("MIG-13/purpose/"+scripted+"/"+purpose,()->{
    Fixture f=new Fixture(scripted,123456789,"CONTROL");var before=f.rows();
    assertThrows(OAuthStoreFailure.class,()->{switch(purpose){
     case "INITIALIZE"->f.coordinator.initializeFreshIssuerResult(deadline());case "ESTABLISH"->f.coordinator.establishNewSubject("new-subject",deadline());
     case "RESEAL_ROOT"->f.coordinator.reseal(f.codec.issuerKey(),deadline());case "RESEAL_SUBJECT"->f.coordinator.reseal(f.codec.subjectKey("subject"),deadline());
     case "STATUS_BARRIER"->f.coordinator.begin(deadline()).barrier();default->throw new AssertionError();
    }});assertEquals(before,f.rows());assertEquals(0,f.commits);assertEquals(0,f.worker.reads);
   }));
  return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> staleRecoveryAtDispatchCannotAdvanceEitherFence(){
  List<DynamicTest> cases=new ArrayList<>();
  for(boolean scripted:List.of(false,true))for(boolean all:List.of(false,true))cases.add(DynamicTest.dynamicTest("MIG-13/stale/"+scripted+"/"+all,()->{
   Fixture f=new Fixture(scripted,123456789,"CONTROL");var before=f.rows();f.beforeCommit=f::rotateRecovery;
   assertThrows(OAuthStoreFailure.class,()->f.revoke(all));assertEquals(before,f.rows());assertEquals(1,f.commits);assertEquals(0,f.worker.reads);
  }));return cases;
 }
}
