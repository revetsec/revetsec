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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** MIG-01 A: fixed wire vectors plus actual normal engine reads/writes after closed fixture conversion. */
final class TotpMigrationGoldenConformanceTests {
    private static final @NonNull String RESOURCE="/fixtures/totp/mig-01.properties";
    private static final @NonNull Properties VECTORS=load();
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(10);

    @Test void fixedCorpusHasExactBytesAndDeclaredDimensions() throws Exception {
        try(var input=Objects.requireNonNull(TotpMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE))){
            assertEquals("b87744cb2e1a3b546393828d3f1949b6068a38a2cba988d1d5042d464c610b3c",
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes())));
        }
        assertEquals(104,Integer.parseInt(value("count")));
        assertEquals(84,vectors("golden").size());assertEquals(20,vectors("invariant").size());
        assertEquals(value("rootKey"),root().getStorageKey());assertEquals(value("accountKey"),accountKey().getStorageKey());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> goldenOldAndNewRecordsPreserveCompleteState(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:vectors("golden"))tests.add(DynamicTest.dynamicTest(vector.name(),()->{
            StateSealer sealer=sealer();TotpRecords legacy=new TotpRecords(sealer);TotpRecordsV3 target=new TotpRecordsV3(sealer);
            TotpStoreRecord oldRoot=record(sealer,root(),vector.bytes("root"),false),oldAccount=record(sealer,accountKey(),vector.bytes("account"),false);
            byte[] originalRoot=oldRoot.getSealedBytes(),originalAccount=oldAccount.getSealedBytes();
            try(var sourceRoot=legacy.open(oldRoot);var sourceAccount=legacy.open(oldAccount)){
                assertEquals(vector.rootTime(),sourceRoot.namespace.observedAt);assertEquals(vector.time(),require(sourceAccount.account).observedAt);
                TotpMigrationV3 migration=new TotpMigrationV3(sealer);
                TotpStoreRecord convertedRoot=migration.migrateNamespace(oldRoot,intent(admission()));
                TotpStoreRecord converted=migration.migrateAccount(oldAccount,oldRoot,intent(admission()));
                assertEquals(oldRoot.getKey(),convertedRoot.getKey());assertEquals(oldAccount.getKey(),converted.getKey());
                assertNotEquals(oldRoot.getVersion(),convertedRoot.getVersion());assertNotEquals(oldAccount.getVersion(),converted.getVersion());
                assertArrayEquals(withVersion(vector.bytes("targetRoot"),root(),convertedRoot.getVersion()),plaintext(sealer,convertedRoot,true));
                assertArrayEquals(withVersion(vector.bytes("targetAccount"),accountKey(),converted.getVersion()),plaintext(sealer,converted,true));
                try(var decodedRoot=target.open(convertedRoot);var decoded=target.open(converted)){
                    assertEquals(value("authority"),require(decodedRoot.namespace).getAuthorityId());
                    assertEquals(vector.rootTime(),require(decodedRoot.namespace).getMinimum());
                    assertSameState(require(sourceAccount.account),require(decoded.account));
                    assertEquals(Long.parseLong(vector.field("usedStep")),require(decoded.account).active==null?0:require(require(decoded.account).active).usedStep);
                    assertEquals(Integer.parseInt(vector.field("shortCount")),require(decoded.account).charges.size());
                    assertEquals(Integer.parseInt(vector.field("dailyCount")),require(decoded.account).totpCharges.size());
                }
            }
            assertArrayEquals(originalRoot,oldRoot.getSealedBytes());assertArrayEquals(originalAccount,oldAccount.getSealedBytes());
            assertThrows(IOException.class,()->target.open(oldRoot));assertThrows(IOException.class,()->target.open(oldAccount));
        }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedOldAccountRootRelationIsCheckedBeforeConversion(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:vectors("invariant"))tests.add(DynamicTest.dynamicTest(vector.name(),()->{
            StateSealer sealer=sealer();TotpRecords legacy=new TotpRecords(sealer);
            TotpStoreRecord oldRoot=record(sealer,root(),vector.bytes("root"),false),oldAccount=record(sealer,accountKey(),vector.bytes("account"),false);
            // Both records must be independently authentic/valid; another decoder guard must not mask this relation.
            try(var decodedRoot=assertDoesNotThrow(()->legacy.open(oldRoot));var decoded=assertDoesNotThrow(()->legacy.open(oldAccount))){
                assertEquals(vector.rootTime(),decodedRoot.namespace.observedAt);assertEquals(vector.time(),require(decoded.account).observedAt);
            }
            TotpMigrationV3 migration=new TotpMigrationV3(sealer);
            if(vector.field("relation").equals("above"))assertThrows(IOException.class,()->migration.migrateAccount(oldAccount,oldRoot,intent(admission())));
            else{
                TotpStoreRecord converted=assertDoesNotThrow(()->migration.migrateAccount(oldAccount,oldRoot,intent(admission())));
                assertArrayEquals(withVersion(vector.bytes("targetAccount"),accountKey(),converted.getVersion()),plaintext(sealer,converted,true));
            }
        }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> actualNewFloorAboveStableMinimumRequiresAuthorityCatchup(){
        List<DynamicTest> tests=new ArrayList<>();
        for(int format:List.of(1,2))for(long nanos:List.of(1L,1000000001L))tests.add(DynamicTest.dynamicTest("MIG-01/normal-floor/TTR"+format+"/"+nanos,()->{
            Vector vector=find(format,"empty");StateSealer sealer=sealer();Instant advanced=vector.rootTime().plusNanos(nanos);
            ScriptedTotpStore source=new ScriptedTotpStore(value("namespace"),value("epoch"),advanced);
            List<TotpStoreRecord> converted=convert(vector,sealer,source.admission());source.seedClosedMigration(converted);
            CountingStore recording=new CountingStore(source);TotpAuthenticator auth=auth(recording,sealer,advanced);
            TotpStoreRecord rootBefore=read(source,root());
            assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,auth.beginEnrollmentResult(TotpEnrollmentOptions.withAccountId(value("account")).accountName("fixture@example.test").build(),"fixture-browser"));
            TotpStoreRecord account=read(source,accountKey());
            try(var decoded=new TotpRecordsV3(sealer).open(account)){
                assertEquals(advanced,require(decoded.account).observedAt);assertTrue(require(decoded.account).observedAt.isAfter(vector.rootTime()));
            }
            assertEquals(1,recording.commits.get());assertInstanceOf(TotpStatusResult.Present.class,auth.getStatusResult(value("account")));
            assertEquals(rootBefore.getVersion(),read(source,root()).getVersion());assertArrayEquals(rootBefore.getSealedBytes(),read(source,root()).getSealedBytes());
            // A distinct closed fixture universe starts just below F, without fabricating an authority rollback.
            ScriptedTotpStore early=new ScriptedTotpStore(value("namespace"),value("epoch"),advanced.minusNanos(1));early.seedClosedMigration(List.of(rootBefore,account));
            CountingStore observed=new CountingStore(early);
            assertEquals(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE,assertInstanceOf(TotpStatusResult.Unavailable.class,auth(observed,sealer,advanced.minusNanos(1)).getStatusResult(value("account"))).getReason());
            for(Instant now:List.of(advanced,advanced.plusNanos(1))){early.setTime(now);assertInstanceOf(TotpStatusResult.Present.class,auth(observed,sealer,now).getStatusResult(value("account")));}
            assertEquals(0,observed.commits.get());assertEquals(account.getVersion(),read(early,accountKey()).getVersion());
        }));
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> previouslyConsumedRecoveryCodesStayConsumedAndRemainingCodesStaySingleUse(){
        List<DynamicTest> tests=new ArrayList<>();
        for(int format:List.of(1,2))for(String shape:List.of("active-partial","active-one","active-none"))tests.add(DynamicTest.dynamicTest("MIG-01/recovery/TTR"+format+"/"+shape,()->{
            Vector vector=find(format,shape);StateSealer sealer=sealer();Instant now=vector.rootTime().plusSeconds(400);
            ScriptedTotpStore source=new ScriptedTotpStore(value("namespace"),value("epoch"),now);source.seedClosedMigration(convert(vector,sealer,source.admission()));
            TotpAuthenticator auth=auth(new CountingStore(source),sealer,now);
            int expected=vector.field("remaining").isEmpty()?0:vector.field("remaining").split(",",-1).length;
            assertEquals(Integer.valueOf(expected),assertInstanceOf(TotpStatusResult.Present.class,auth.getStatusResult(value("account"))).getStatus().getRemainingRecoveryCodeCount());
            assertEquals(TotpRejectionReason.INVALID_CODE,assertInstanceOf(RecoveryCodeUseResult.Rejected.class,auth.consumeRecoveryCodeResult(value("account"),value("code.1"),"recovery")).getReason());
            if(expected>0){
                String code=value(shape.equals("active-one")?"code.9":"code.0");
                var use=assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,auth.consumeRecoveryCodeResult(value("account"),code,"recovery")).getUse();
                assertEquals(Integer.valueOf(expected-1),use.getRemainingRecoveryCodeCount());assertEquals(TotpAuthenticationMethod.RECOVERY_CODE,use.getMethod());
                assertEquals(TotpRejectionReason.INVALID_CODE,assertInstanceOf(RecoveryCodeUseResult.Rejected.class,auth.consumeRecoveryCodeResult(value("account"),code,"replay")).getReason());
            }
            try(var decoded=new TotpRecordsV3(sealer).open(read(source,accountKey()))){
                assertEquals(expected==0?0:expected-1,require(decoded.account).recoveryHashes.size());
                assertEquals(Long.parseLong(vector.field("usedStep")),require(require(decoded.account).active).usedStep);
                assertEquals(value("activeFactorId"),require(require(decoded.account).active).factorId);assertEquals(value("batchId"),require(decoded.account).batchId);
            }
        }));
        return tests;
    }

    private static void assertSameState(TotpRecords.@NonNull Account old,TotpRecords.@NonNull Account next){
        assertEquals(old.accountId,next.accountId);assertEquals(old.fence,next.fence);assertEquals(old.observedAt,next.observedAt);assertEquals(old.batchId,next.batchId);
        assertEquals(old.active==null,next.active==null);assertEquals(old.pending==null,next.pending==null);
        if(old.active!=null){var active=require(old.active);var actual=require(next.active);assertEquals(active.factorId,actual.factorId);assertArrayEquals(active.secret,actual.secret);assertEquals(active.enrolledAt,actual.enrolledAt);assertEquals(active.usedStep,actual.usedStep);}
        if(old.pending!=null){var pending=require(old.pending);var actual=require(next.pending);assertEquals(pending.enrollmentId,actual.enrollmentId);assertEquals(pending.factorId,actual.factorId);assertArrayEquals(pending.secret,actual.secret);assertArrayEquals(pending.browserHash,actual.browserHash);assertEquals(pending.expiresAt,actual.expiresAt);assertEquals(pending.expectedFactorId,actual.expectedFactorId);}
        assertEquals(old.recoveryHashes.size(),next.recoveryHashes.size());for(int i=0;i<old.recoveryHashes.size();i++)assertArrayEquals(old.recoveryHashes.get(i),next.recoveryHashes.get(i));
        for(boolean daily:List.of(false,true)){var before=daily?old.totpCharges:old.charges;var after=daily?next.totpCharges:next.charges;assertEquals(before.size(),after.size());for(int i=0;i<before.size();i++){assertEquals(before.get(i).id,after.get(i).id);assertEquals(before.get(i).at,after.get(i).at);}}
    }
    private static @NonNull List<@NonNull TotpStoreRecord> convert(@NonNull Vector vector,@NonNull StateSealer sealer,@NonNull StoreAdmission admission)throws Exception{
        var migration=new TotpMigrationV3(sealer);var oldRoot=record(sealer,root(),vector.bytes("root"),false);
        return List.of(migration.migrateNamespace(oldRoot,intent(admission)),migration.migrateAccount(record(sealer,accountKey(),vector.bytes("account"),false),oldRoot,intent(admission)));
    }
    private static @NonNull TotpAuthenticator auth(@NonNull TotpStore store,@NonNull StateSealer sealer,@NonNull Instant now){
        return TotpAuthenticator.withIssuer("MIG-01 fixture").credentialNamespace(value("namespace")).recoveryEpoch(value("epoch")).store(store).stateSealer(sealer).clock(Clock.fixed(now,ZoneOffset.UTC)).operationTimeout(BUDGET).recoveryGate(new Gate()).build();
    }
    @ThreadSafe private static final class Gate implements TotpRecoveryGate{
        @Override public @NonNull Permit acquire(@NonNull TotpRecoveryContext context,@NonNull Duration budget){return new Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};}
    }
    @ThreadSafe private static final class CountingStore implements TotpStore{
        final @NonNull ScriptedTotpStore source;final @NonNull AtomicInteger commits=new AtomicInteger();
        CountingStore(@NonNull ScriptedTotpStore source){this.source=source;}
        @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){return this.source.read(keys,budget);}
        @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){this.commits.incrementAndGet();return this.source.compareAndCommit(write,budget);}
    }
    private static @NonNull TotpStoreRecord read(@NonNull ScriptedTotpStore source,@NonNull TotpStoreKey key){return assertInstanceOf(TotpStoreEntry.Present.class,assertInstanceOf(TotpStoreReadResult.Available.class,source.read(Set.of(key),BUDGET)).getSnapshot().getEntry(key)).getRecord();}
    private static @NonNull StateSealer sealer(){return StateSealer.withActiveKey(SealingKey.fromBase64("fixture","AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(16384).build();}
    private static @NonNull StoreAdmission admission(){return StoreAdmission.fromIdentifiers(value("authority"),value("version"));}
    private static @NonNull ClosedMigrationIntent intent(@NonNull StoreAdmission admission){return ClosedMigrationIntent.fromExternalIntent(value("version"),admission,Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));}
    private static @NonNull TotpStoreKey root(){return TotpStoreKey.forNamespace(value("namespace"),value("epoch"));}
    private static @NonNull TotpStoreKey accountKey(){return TotpStoreKey.forAccount(value("namespace"),value("epoch"),value("account"));}
    private static @NonNull TotpStoreRecord record(@NonNull StateSealer sealer,@NonNull TotpStoreKey key,byte @NonNull [] bytes,boolean target){return TotpStoreRecord.fromStoredForm(key,value("version"),SealedStateAccess.get().sealDurable(sealer,Base64Url.encode(bytes),context(key,target)).getBytes(StandardCharsets.US_ASCII));}
    private static byte @NonNull [] plaintext(@NonNull StateSealer sealer,@NonNull TotpStoreRecord record,boolean target)throws Exception{return Base64Url.decode(SealedStateAccess.get().unsealDurable(sealer,new String(record.getSealedBytes(),StandardCharsets.US_ASCII),context(record.getKey(),target)));}
    private static @NonNull String context(@NonNull TotpStoreKey key,boolean target){byte[] digest=TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey());try{return "revetsec/totp/durable/v"+(target?"2:":"1:")+Base64Url.encode(digest);}finally{Arrays.fill(digest,(byte)0);}}
    private static byte @NonNull [] withVersion(byte @NonNull [] template,@NonNull TotpStoreKey key,@NonNull String version){byte[] result=template.clone();assertEquals(43,version.length());int offset=12+key.getStorageKey().getBytes(StandardCharsets.UTF_8).length;System.arraycopy(version.getBytes(StandardCharsets.US_ASCII),0,result,offset,43);return result;}
    private static @NonNull List<@NonNull Vector> vectors(@NonNull String kind){List<Vector> result=new ArrayList<>();for(int i=0;i<Integer.parseInt(value("count"));i++){Vector vector=new Vector(i);if(vector.field("kind").equals(kind))result.add(vector);}return result;}
    private static @NonNull Vector find(int format,@NonNull String shape){return vectors("golden").stream().filter(v->v.field("format").equals(Integer.toString(format)) && v.field("shape").equals(shape) && v.time().equals(Instant.ofEpochSecond(1700000010,123456789))).findFirst().orElseThrow();}
    private static @NonNull String value(@NonNull String name){return Objects.requireNonNull(VECTORS.getProperty(name));}
    private static @NonNull Properties load(){Properties properties=new Properties();try(var reader=new InputStreamReader(Objects.requireNonNull(TotpMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE)),StandardCharsets.UTF_8)){properties.load(reader);}catch(IOException failure){throw new ExceptionInInitializerError(failure);}return properties;}
    private static <T> @NonNull T require(@Nullable T value){return Objects.requireNonNull(value);}
    private static final class Vector{
        private final int index;Vector(int index){this.index=index;}
        @NonNull String field(@NonNull String name){return value("v."+this.index+'.'+name);}
        byte @NonNull [] bytes(@NonNull String name){return HexFormat.of().parseHex(field(name));}
        @NonNull Instant time(){return Instant.ofEpochSecond(Long.parseLong(field("seconds")),Integer.parseInt(field("nanos")));}
        @NonNull Instant rootTime(){return Instant.ofEpochSecond(Long.parseLong(field("rootSeconds")),Integer.parseInt(field("rootNanos")));}
        @NonNull String name(){return "MIG-01/"+field("kind")+"/"+this.index+"/TTR"+field("format")+"/"+field("shape")+"/"+field("relation");}
    }
}
