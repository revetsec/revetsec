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
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.TotpPrimitives;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit normal-engine mixed-generation controls; closed seeds are fixture-only. */
final class TotpMixedMigrationBoundaryTests {
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(10);

    @TestFactory @NonNull List<@NonNull DynamicTest> frozenRootAccountPairingsNeverPromoteMixedGenerations() throws Exception {
        Properties vectors=new Properties();
        try(InputStream input=Objects.requireNonNull(getClass().getResourceAsStream("/fixtures/totp/mig-01.properties"))){vectors.load(new InputStreamReader(input,StandardCharsets.UTF_8));}
        List<DynamicTest> tests=new ArrayList<>();
        for(int format:List.of(1,2))for(boolean newRoot:List.of(false,true))for(boolean newAccount:List.of(false,true)){
            int selected=-1;
            for(int i=0;i<Integer.parseInt(value(vectors,"count"));i++)if(value(vectors,"v."+i+".kind").equals("golden")&&value(vectors,"v."+i+".format").equals(Integer.toString(format))&&value(vectors,"v."+i+".shape").equals("empty")){selected=i;break;}
            assertTrue(selected>=0);String prefix="v."+selected+'.';
            tests.add(DynamicTest.dynamicTest("SC-MIG-01/mixed/TTR"+format+"/root-"+(newRoot?"new":"old")+"/account-"+(newAccount?"new":"old"),()->{
                String namespace=value(vectors,"namespace"),epoch=value(vectors,"epoch"),account=value(vectors,"account");
                Instant minimum=Instant.ofEpochSecond(Long.parseLong(value(vectors,prefix+"rootSeconds")),Integer.parseInt(value(vectors,prefix+"rootNanos")));
                Instant now=minimum.plusSeconds(1);
                StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture","AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(16384).build();
                TotpStoreKey rootKey=TotpStoreKey.fromStoredForm(value(vectors,"rootKey")),accountKey=TotpStoreKey.fromStoredForm(value(vectors,"accountKey"));
                assertEquals(TotpStoreKey.forAccount(namespace,epoch,account),accountKey);
                TotpStoreRecord oldRoot=legacy(sealer,rootKey,value(vectors,"version"),value(vectors,prefix+"root"));
                TotpStoreRecord oldAccount=legacy(sealer,accountKey,value(vectors,"version"),value(vectors,prefix+"account"));
                ScriptedTotpStore source=new ScriptedTotpStore(namespace,epoch,now);
                ClosedMigrationIntent intent=ClosedMigrationIntent.fromExternalIntent(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]),source.admission(),Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));
                TotpMigrationV3 migration=new TotpMigrationV3(sealer);
                TotpStoreRecord root=newRoot?migration.migrateNamespace(oldRoot,intent):oldRoot;
                TotpStoreRecord entity=newAccount?migration.migrateAccount(oldAccount,oldRoot,intent):oldAccount;
                source.seedClosedMigration(List.of(root,entity));
                AtomicInteger mutations=new AtomicInteger();
                TotpStore recording=new TotpStore(){
                    @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){return source.read(keys,budget);}
                    @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){mutations.incrementAndGet();return source.compareAndCommit(write,budget);}
                };
                TotpRecoveryGate gate=(context,budget)->new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};
                TotpAuthenticator auth=TotpAuthenticator.withIssuer("Mixed migration fixture").credentialNamespace(namespace).recoveryEpoch(epoch).store(recording).stateSealer(sealer).clock(Clock.fixed(now,ZoneOffset.UTC)).recoveryGate(gate).operationTimeout(BUDGET).build();
                if(newRoot&&newAccount)assertInstanceOf(TotpStatusResult.Present.class,auth.getStatusResult(account));
                else assertEquals(TotpUnavailableReason.INVALID_STORED_STATE,assertInstanceOf(TotpStatusResult.Unavailable.class,auth.getStatusResult(account)).getReason());
                assertEquals(0,mutations.get());unchanged(source,root);unchanged(source,entity);
                TotpEnrollmentRequestResult begin=auth.beginEnrollmentResult(TotpEnrollmentOptions.withAccountId(account).accountName("Fixture").build(),"fixture-browser");
                if(newRoot&&newAccount){assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,begin);assertEquals(1,mutations.get());}
                else{assertEquals(TotpUnavailableReason.INVALID_STORED_STATE,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,begin).getReason());assertEquals(0,mutations.get());unchanged(source,entity);}
                unchanged(source,root);
            }));
        }
        return tests;
    }

    @Test void migratedFutureUsedStepSurvivesClockGenerationAndRequiresAnUnusedLaterStep() throws Exception {
        String namespace="future-used-step",epoch="one",accountId="account";
        Instant minimum=Instant.ofEpochSecond(1700000010);
        ScriptedTotpStore source=new ScriptedTotpStore(namespace,epoch,minimum);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture","AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(16384).build();
        TotpRecords legacy=new TotpRecords(sealer);TotpMigrationV3 migration=new TotpMigrationV3(sealer);
        TotpStoreKey rootKey=TotpStoreKey.forNamespace(namespace,epoch),accountKey=TotpStoreKey.forAccount(namespace,epoch,accountId);
        TotpStoreRecord oldRoot=legacy.seal(rootKey,new TotpRecords.Namespace(minimum),null);
        byte[] secret=new byte[20];for(int i=0;i<secret.length;i++)secret[i]=(byte)(i+1);
        byte[] nonce=new byte[32];Arrays.fill(nonce,(byte)7);String id=Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
        long current=minimum.getEpochSecond()/30,used=current+100000;
        TotpRecords.Account account=new TotpRecords.Account(accountId,id,minimum);
        account.active=new TotpRecords.Active(id,secret.clone(),minimum.minusSeconds(30),used);account.batchId=id;
        TotpStoreRecord oldAccount;
        try{oldAccount=legacy.seal(accountKey,new TotpRecords.Namespace(minimum),account);}finally{account.erase();}
        ClosedMigrationIntent intent=ClosedMigrationIntent.fromExternalIntent(id,source.admission(),Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));
        TotpStoreRecord root=migration.migrateNamespace(oldRoot,intent),entity=migration.migrateAccount(oldAccount,oldRoot,intent);
        source.seedClosedMigration(List.of(root,entity));
        try{
            assertEquals(TotpRejectionReason.INVALID_CODE,assertInstanceOf(TotpVerificationResult.Rejected.class,auth(source,sealer,minimum,namespace,epoch).verifyResult(accountId,TotpPrimitives.hotp(secret,current,"HmacSHA1",6),"current")).getReason());
            assertUsed(source,sealer,accountKey,id,used);unchanged(source,root);
            source.rotateClockGeneration();
            assertEquals(TotpRejectionReason.INVALID_CODE,assertInstanceOf(TotpVerificationResult.Rejected.class,auth(source,sealer,minimum,namespace,epoch).verifyResult(accountId,TotpPrimitives.hotp(secret,current,"HmacSHA1",6),"clock-only")).getReason());
            assertUsed(source,sealer,accountKey,id,used);unchanged(source,root);
            Instant alreadyUsed=Instant.ofEpochSecond(used*30);source.setTime(alreadyUsed);
            assertEquals(TotpRejectionReason.INVALID_CODE,assertInstanceOf(TotpVerificationResult.Rejected.class,auth(source,sealer,alreadyUsed,namespace,epoch).verifyResult(accountId,TotpPrimitives.hotp(secret,used,"HmacSHA1",6),"used-boundary")).getReason());
            assertUsed(source,sealer,accountKey,id,used);
            Instant later=alreadyUsed.plusSeconds(30);source.setTime(later);String fresh=TotpPrimitives.hotp(secret,used+1,"HmacSHA1",6);
            assertEquals(used+1,TotpPrimitives.matchingStep(secret,fresh,used+1,used));
            assertInstanceOf(TotpVerificationResult.Succeeded.class,auth(source,sealer,later,namespace,epoch).verifyResult(accountId,fresh,"unused-later"));
            assertUsed(source,sealer,accountKey,id,used+1);unchanged(source,root);
        }finally{Arrays.fill(secret,(byte)0);Arrays.fill(nonce,(byte)0);}
    }

    private static @NonNull TotpAuthenticator auth(@NonNull TotpStore store,@NonNull StateSealer sealer,@NonNull Instant now,@NonNull String namespace,@NonNull String epoch){
        TotpRecoveryGate gate=(context,budget)->new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};
        return TotpAuthenticator.withIssuer("Future history fixture").credentialNamespace(namespace).recoveryEpoch(epoch).store(store).stateSealer(sealer).clock(Clock.fixed(now,ZoneOffset.UTC)).recoveryGate(gate).operationTimeout(BUDGET).build();
    }
    private static void assertUsed(@NonNull ScriptedTotpStore source,@NonNull StateSealer sealer,@NonNull TotpStoreKey key,@NonNull String factor,long used)throws Exception{
        var snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,source.read(Set.of(key),BUDGET)).getSnapshot();
        var record=assertInstanceOf(TotpStoreEntry.Present.class,snapshot.getEntry(key)).getRecord();
        try(var decoded=new TotpRecordsV3(sealer).open(record)){
            var account=Objects.requireNonNull(decoded.account);var active=Objects.requireNonNull(account.active);
            assertEquals(used,active.usedStep);assertEquals(factor,active.factorId);assertEquals(factor,account.batchId);
            assertTrue(account.recoveryHashes.isEmpty());
        }
    }

    private static @NonNull String value(@NonNull Properties values,@NonNull String key){return Objects.requireNonNull(values.getProperty(key),key);}
    private static @NonNull TotpStoreRecord legacy(@NonNull StateSealer sealer,@NonNull TotpStoreKey key,@NonNull String version,@NonNull String hex){
        byte[] address=TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey());
        try{
            String context="revetsec/totp/durable/v1:"+Base64.getUrlEncoder().withoutPadding().encodeToString(address);
            String payload=Base64.getUrlEncoder().withoutPadding().encodeToString(HexFormat.of().parseHex(hex));
            return TotpStoreRecord.fromStoredForm(key,version,SealedStateAccess.get().sealDurable(sealer,payload,context).getBytes(StandardCharsets.US_ASCII));
        }finally{Arrays.fill(address,(byte)0);}
    }
    private static void unchanged(@NonNull ScriptedTotpStore source,@NonNull TotpStoreRecord expected){
        var snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,source.read(Set.of(expected.getKey()),BUDGET)).getSnapshot();
        var actual=assertInstanceOf(TotpStoreEntry.Present.class,snapshot.getEntry(expected.getKey())).getRecord();
        assertEquals(expected.getVersion(),actual.getVersion());assertArrayEquals(expected.getSealedBytes(),actual.getSealedBytes());
    }
}
