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
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** MIG-02 A: literal genuine frozen-old WAR1 records and independently fixed expected WAR2 plaintext. */
final class WebAuthnMigrationGoldenConformanceTests {
    private static final @NonNull String RESOURCE="/fixtures/webauthn/mig-02.properties";
    private static final @NonNull Properties VECTORS=load();

    @Test void fixedCorpusHasExactBytesAndAllSixPayloadForms() throws Exception {
        try(var input=Objects.requireNonNull(WebAuthnMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE))){
            assertEquals("3a3352b2ebd5b6da9f28c797c1d73fff1c28ccd34416e77d85f09c7ddb9e1efc",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes())));
        }
        assertEquals(106,vectors().size());
        assertEquals(7,selected("NAMESPACE_CLOCK").size());assertEquals(19,selected("CREDENTIAL").size());
        assertEquals(4,selected("ACCOUNT_CREDENTIAL_INDEX").size());assertEquals(4,selected("ACCOUNT_FENCE").size());assertEquals(72,selected("CEREMONY").size());
        assertEquals(17,vectors().stream().filter(v->v.optional("form").equals("active")).count());
        assertEquals(2,vectors().stream().filter(v->v.optional("form").equals("revoked")).count());
        assertEquals(value("rootKey"),root().getStorageKey());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> allSixFrozenFormsConvertToExactGoldenState(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:vectors())tests.add(DynamicTest.dynamicTest("MIG-02/golden/"+vector.name(),()->{
            StateSealer sealer=sealer();var migration=new WebAuthnRecordMigration(sealer);var next=new WebAuthnRecordCodecV2(sealer);
            byte[] oldRoot=vector.bytes("oldRoot"),sealed=vector.bytes("sealed"),original=sealed.clone(),rootOriginal=oldRoot.clone(),version={7};
            var anchor=migration.authenticateRoot(intent(),root().getStorageKey(),oldRoot);assertEquals(vector.time("root"),anchor.minimum());
            var prepared=migration.prepare(intent(),anchor,vector.key().getStorageKey(),version,sealed);
            assertEquals(vector.key(),prepared.key());assertArrayEquals(version,prepared.expectedVersion());assertArrayEquals(sealed,prepared.expectedBytes());
            assertEquals(32,prepared.version().length);assertFalse(Arrays.equals(version,prepared.version()));
            assertEquals(vector.time("floor"),prepared.floor());assertEquals(vector.time("expires"),prepared.expiresAt());
            assertEquals("WAR2",new String(prepared.sealedBytes(),0,4,StandardCharsets.US_ASCII));
            Clock clock=clock(vector.kind().equals("NAMESPACE_CLOCK")?Instant.EPOCH:vector.time("floor"));
            try(var opened=next.openWithMetadata(vector.key(),prepared.sealedBytes(),clock)){
                assertArrayEquals(vector.bytes("target"),opened.plaintext());assertEquals(ceiling(vector.time("expires")),opened.notAfter());
            }
            try(var decoded=next.openRecord(vector.key(),prepared.sealedBytes(),clock)){
                assertEquals(vector.key(),decoded.key());assertEquals(vector.time("floor"),decoded.floor());assertEquals(vector.time("expires"),decoded.expiresAt());
                if(vector.kind().equals("NAMESPACE_CLOCK"))assertEquals(value("authority"),decoded.authorityId().orElseThrow());
                else{assertTrue(decoded.authorityId().isEmpty());assertArrayEquals(vector.bytes("inner"),decoded.innerPayload());}
            }
            assertTypedState(vector,sealer,prepared.sealedBytes());
            assertThrows(WebAuthnRecordException.class,()->next.openRecord(vector.key(),sealed,clock));
            assertThrows(WebAuthnRecordException.class,()->new WebAuthnRecordCodec(sealer).open(vector.key(),prepared.sealedBytes(),clock));
            assertArrayEquals(original,sealed);assertArrayEquals(rootOriginal,oldRoot);
            byte[] copy=prepared.sealedBytes();copy[0]=0;assertEquals('W',prepared.sealedBytes()[0]);
        }));return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> ceremonyBindingConsumptionAndSubsecondExpiryStayExact(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:selected("CEREMONY"))tests.add(DynamicTest.dynamicTest("MIG-02/ceremony-edge/"+vector.name(),()->{
            StateSealer sealer=sealer();var prepared=convert(vector,sealer);var raw=new WebAuthnRecordCodecV2(sealer);
            var typed=new WebAuthnCeremonyRecordCodec(value("namespace"),value("rp"),new WebAuthnRecordCodec(sealer));
            Instant expiry=vector.time("expires");assertEquals(123456789,expiry.getNano());
            for(Instant now:List.of(vector.time("floor"),expiry.minusNanos(1))){
                var state=typed.decode(vector.key(),prepared.sealedBytes(),clock(now));assertCeremony(vector,state);
                assertEquals(vector.integer("consumed")==0,state.isPendingAt(now));
            }
            // The envelope remains authentic at exact expiry because notAfter is its next whole second.
            // Refusal must therefore come from the precise inner-expiry rule, not an unrelated auth failure.
            for(Instant now:List.of(expiry,expiry.plusNanos(1))){
                try(var opened=assertDoesNotThrow(()->raw.openWithMetadata(vector.key(),prepared.sealedBytes(),clock(now)))){assertEquals(ceiling(expiry),opened.notAfter());}
                assertThrows(WebAuthnRecordException.class,()->raw.openRecord(vector.key(),prepared.sealedBytes(),clock(now)));
                assertThrows(WebAuthnRecordException.class,()->typed.decode(vector.key(),prepared.sealedBytes(),clock(now)));
            }
        }));return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> closedExpiredCeremonyConversionPreservesAuthenticatedEnvelopeCeiling(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:selected("CEREMONY"))for(long after:new long[]{0,1,1000000000L})tests.add(DynamicTest.dynamicTest("MIG12/WAR1-expired/"+vector.name()+"/"+after,()->{
            StateSealer sealer=sealer();var codec=new WebAuthnRecordCodecV2(sealer);byte[] old=vector.bytes("sealed"),before=old.clone();
            try(var opened=codec.openLegacyForMigration(vector.key().getStorageKey(),old,intent())){assertEquals(ceiling(vector.time("expires")),opened.notAfter());}
            var prepared=convert(vector,sealer);Instant end=Instant.ofEpochSecond(ceiling(vector.time("expires")));assertEquals(vector.time("expires"),prepared.expiresAt());
            try(var opened=codec.openWithMetadata(vector.key(),prepared.sealedBytes(),clock(end.minusNanos(1)))){assertEquals(end.getEpochSecond(),opened.notAfter());}
            assertThrows(WebAuthnRecordException.class,()->codec.openWithMetadata(vector.key(),prepared.sealedBytes(),clock(end.plusNanos(after))));
            assertThrows(WebAuthnRecordException.class,()->new WebAuthnRecordCodec(sealer).openAdmittedRecord(vector.key(),prepared.sealedBytes(),clock(end.plusNanos(after))));
            assertArrayEquals(before,old);assertEquals(vector.time("floor"),prepared.floor());
        }));return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> revokedOwnersStayPermanentAndInactiveThroughNormalReseal(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:selected("CREDENTIAL"))if(vector.optional("form").equals("revoked"))tests.add(DynamicTest.dynamicTest("MIG-02/revoked-reseal/"+vector.name(),()->{
            StateSealer sealer=sealer();var prepared=convert(vector,sealer);var normal=new WebAuthnRecordCodec(sealer);
            var credentials=new WebAuthnCredentialRecordCodec(value("namespace"),value("rp"),normal);
            Clock late=clock(Instant.ofEpochSecond(253402300799L,999999999));
            assertTypedState(vector,sealer,prepared.sealedBytes());
            byte[] resealed=normal.resealAdmitted(vector.key(),prepared.sealedBytes(),late);
            var owner=credentials.decodeRecord(vector.key(),resealed,late);assertTrue(owner.isRevoked());assertNull(owner.activeState());assertArrayEquals(vector.bytes("id"),owner.credentialId());assertArrayEquals(vector.bytes("handle"),owner.userHandle());
            assertThrows(WebAuthnRecordException.class,()->credentials.decode(vector.key(),resealed,late));
            try(var opened=new WebAuthnRecordCodecV2(sealer).openWithMetadata(vector.key(),resealed,late)){
                assertEquals(WebAuthnRecordPayloadV2.PERMANENT.getEpochSecond(),opened.notAfter());assertArrayEquals(vector.bytes("target"),opened.plaintext());
            }
        }));return tests;
    }

    private static void assertTypedState(@NonNull Vector vector,@NonNull StateSealer sealer,byte @NonNull [] sealed)throws Exception{
        var records=new WebAuthnRecordCodec(sealer);Clock clock=clock(vector.time("floor"));
        switch(vector.kind()){
            case "NAMESPACE_CLOCK":break;
            case "CREDENTIAL":{
                var codec=new WebAuthnCredentialRecordCodec(value("namespace"),value("rp"),records);var owner=codec.decodeRecord(vector.key(),sealed,clock);
                assertArrayEquals(vector.bytes("id"),owner.credentialId());assertArrayEquals(vector.bytes("handle"),owner.userHandle());
                assertEquals(vector.field("form").equals("revoked"),owner.isRevoked());
                if(owner.isRevoked()){assertNull(owner.activeState());assertThrows(WebAuthnRecordException.class,()->codec.decode(vector.key(),sealed,clock));}
                else{var state=Objects.requireNonNull(owner.activeState());assertEquals(-8,state.algorithm());assertEquals(Long.parseLong(vector.field("counter")),state.counter());assertEquals((vector.integer("flags")&1)!=0,state.backupEligible());assertEquals((vector.integer("flags")&2)!=0,state.backedUp());assertArrayEquals(vector.bytes("cose"),state.keyCbor());}
                break;
            }
            case "ACCOUNT_CREDENTIAL_INDEX":{
                var state=new WebAuthnCredentialIndex(value("namespace"),value("rp"),records).decode(vector.key(),sealed,clock);assertArrayEquals(vector.bytes("handle"),state.userHandle());
                List<byte[]> expected=new ArrayList<>();if(!vector.field("ids").isEmpty())for(String id:vector.field("ids").split(",",-1))expected.add(HexFormat.of().parseHex(id));
                assertEquals(vector.integer("count"),state.size());assertEquals(expected.size(),state.credentialIds().size());for(int i=0;i<expected.size();i++){assertArrayEquals(expected.get(i),state.credentialIds().get(i));assertTrue(state.contains(expected.get(i)));}
                break;
            }
            case "ACCOUNT_FENCE":{var state=new WebAuthnAccountFence(value("namespace"),value("rp"),records).decode(vector.key(),sealed,clock);assertEquals(vector.integer("active")==1,state.isActive());assertArrayEquals(vector.bytes("handle"),state.userHandle());break;}
            case "CEREMONY":assertCeremony(vector,new WebAuthnCeremonyRecordCodec(value("namespace"),value("rp"),records).decode(vector.key(),sealed,clock));break;
            default:fail("Unknown fixture kind");
        }
    }
    private static void assertCeremony(@NonNull Vector vector,@NonNull WebAuthnCeremonyState state){
        assertEquals(WebAuthnCeremonyState.Kind.values()[vector.integer("ceremonyKind")-1],state.kind());assertArrayEquals(vector.bytes("id"),state.ceremonyId());assertArrayEquals(vector.bytes("challenge"),state.challenge());assertArrayEquals(vector.bytes("binding"),state.browserBinding());
        assertEquals(Set.copyOf(List.of(vector.field("origins").split(",",-1))),state.allowedOrigins());assertEquals(vector.integer("consumed")==1,state.isConsumed());
        assertEquals(vector.time("issued"),state.issuedAt());assertEquals(vector.time("expires"),state.expiresAt());
        if(vector.bytes("handle").length==0)assertNull(state.expectedHandle());else assertArrayEquals(vector.bytes("handle"),state.expectedHandle());
        String purpose=new String(vector.bytes("purpose"),StandardCharsets.US_ASCII);assertEquals(purpose.isEmpty()?null:purpose,state.actionPurpose());
        assertTrue(state.matchesBrowserBinding(vector.bytes("binding")));byte[] wrong=vector.bytes("binding");wrong[0]^=1;assertFalse(state.matchesBrowserBinding(wrong));
        if(state.isConsumed())assertThrows(IllegalStateException.class,state::consume);else assertTrue(state.consume().isConsumed());
    }
    private static WebAuthnRecordMigration.@NonNull Prepared convert(@NonNull Vector vector,@NonNull StateSealer sealer)throws Exception{
        var migration=new WebAuthnRecordMigration(sealer);var anchor=migration.authenticateRoot(intent(),root().getStorageKey(),vector.bytes("oldRoot"));return migration.prepare(intent(),anchor,vector.key().getStorageKey(),new byte[]{7},vector.bytes("sealed"));
    }
    private static @NonNull StateSealer sealer(){return StateSealer.withActiveKey(SealingKey.fromBase64("f".repeat(64),"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(1024).clock(clock(Instant.EPOCH)).build();}
    private static @NonNull ClosedMigrationIntent intent(){return ClosedMigrationIntent.fromExternalIntent(value("migrationId"),StoreAdmission.fromIdentifiers(value("authority"),value("recovery")),Set.of(ClosedMigrationIntent.Format.WEBAUTHN_WAR2));}
    private static @NonNull Clock clock(@NonNull Instant at){return Clock.fixed(at,ZoneOffset.UTC);}
    private static long ceiling(@NonNull Instant at){return at.getEpochSecond()+(at.getNano()==0?0:1);}
    private static @NonNull WebAuthnStoreKey root(){return WebAuthnStoreKey.forNamespaceClock(value("namespace"),value("rp"));}
    private static @NonNull String value(@NonNull String name){return Objects.requireNonNull(VECTORS.getProperty(name));}
    private static @NonNull List<@NonNull Vector> vectors(){List<Vector> result=new ArrayList<>();for(int i=0;i<Integer.parseInt(value("count"));i++)result.add(new Vector(i));return result;}
    private static @NonNull List<@NonNull Vector> selected(@NonNull String kind){return vectors().stream().filter(v->v.kind().equals(kind)).toList();}
    private static @NonNull Properties load(){Properties p=new Properties();try(var input=new InputStreamReader(Objects.requireNonNull(WebAuthnMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE)),StandardCharsets.UTF_8)){p.load(input);}catch(IOException e){throw new ExceptionInInitializerError(e);}return p;}
    private static final class Vector{
        private final int index;Vector(int index){this.index=index;}
        @NonNull String field(@NonNull String name){return value("v."+this.index+'.'+name);}
        @NonNull String optional(@NonNull String name){return VECTORS.getProperty("v."+this.index+'.'+name,"");}
        int integer(@NonNull String name){return Integer.parseInt(field(name));}
        byte @NonNull [] bytes(@NonNull String name){return HexFormat.of().parseHex(field(name));}
        @NonNull Instant time(@NonNull String name){return Instant.ofEpochSecond(Long.parseLong(field(name+"Seconds")),integer(name+"Nanos"));}
        @NonNull String kind(){return field("kind");}
        @NonNull String name(){return this.index+"/"+field("name");}
        @NonNull WebAuthnStoreKey key(){return WebAuthnStoreKey.fromStoredForm(field("key"));}
    }
}
