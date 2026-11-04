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
import com.revetsec.internal.crypto.AuthenticatedRecord;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** MIG-03 A: genuine frozen outer1 records, independent fixed expected outer2 JSON and typed state controls. */
final class OAuthMigrationGoldenConformanceTests {
    private static final @NonNull String RESOURCE="/fixtures/oauth/mig-03.properties";
    private static final @NonNull Properties VECTORS=load();
    private static final @NonNull OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();

    @Test void fixedCorpusHasExactBytesAndEveryStatusSpecificForm() throws Exception {
        try(var input=Objects.requireNonNull(OAuthMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE))){
            assertEquals("1bd9a34a5238b1797db3a4e733159ab602be1ab1179428d15050aac2c113024e",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes())));
        }
        assertEquals(153,vectors().size());assertEquals(135,authorizationVectors().size());
        assertEquals(14,vectors().stream().filter(v->v.kind()==OAuthStoreKey.Kind.ISSUER_STATE).count());
        assertEquals(4,vectors().stream().filter(v->v.kind()==OAuthStoreKey.Kind.SUBJECT_STATE).count());
        assertEquals(Set.of("INTERACTION/PENDING","INTERACTION/COMPLETED","CODE/UNUSED","CODE/USED","CODE/CANCELLED","GRANT/PENDING","GRANT/DENIED","GRANT/ACTIVE","GRANT/REVOKED","ACCESS_TOKEN/ISSUED","REFRESH_TOKEN/ACTIVE","REFRESH_TOKEN/USED"),authorizationVectors().stream().map(v->v.kind()+"/"+v.field("status")).collect(Collectors.toSet()));
        var codec=target(sealer(Instant.EPOCH));assertEquals(value("rootKey"),codec.issuerKey().getStorageKey());assertEquals(value("subjectKey"),codec.subjectKey(utf8(value("subjectHex"))).getStorageKey());
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> frozenOuterOneConvertsToExactGoldenOuterTwo(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:vectors())tests.add(DynamicTest.dynamicTest("MIG-03/golden/"+vector.name(),()->{
            StateSealer sealer=sealer(Instant.EPOCH);var next=target(sealer);var old=legacy(sealer);var migration=migration(next);
            OAuthStoreEntry source=vector.entry(),root=vector.root();String original=source.toSealedForm(),rootOriginal=root.toSealedForm();
            var pinned=migration.openRoot(root);assertEquals(vector.time("root"),pinned.minimum());assertEquals(value("authority"),pinned.authorityId());
            assertEquals(vector.json("payloadHex"),old.open(source,clock(Instant.EPOCH)));
            try(AuthenticatedRecord opened=SealedStateAccess.get().openRecord(sealer,SealedStateType.AS_RECORD,original,"revetsec/as-record/v1:"+source.getKey().getStorageKey(),clock(Instant.EPOCH))){
                assertEquals(vector.text("oldOuterHex"),opened.getPlaintext());assertEquals(source.getRetainUntil(),opened.getNotAfter());
            }
            OAuthStoreEntry converted=migration.convert(source,pinned);
            assertEquals(source.getKey(),converted.getKey());assertNotEquals(source.getVersion(),converted.getVersion());assertEquals(43,converted.getVersion().length());assertEquals(source.getRetainUntil(),converted.getRetainUntil());
            try(AuthenticatedRecord opened=SealedStateAccess.get().openRecord(sealer,SealedStateType.AS_RECORD,converted.toSealedForm(),OAuthStoreRecordCodecV2.context(converted.getKey()),clock(Instant.EPOCH))){
                // Replace only the fresh opaque version slot in the independent literal JSON expectation.
                assertEquals(vector.text("targetOuterHex").replace("@VERSION@",converted.getVersion()),opened.getPlaintext());assertEquals(source.getRetainUntil(),opened.getNotAfter());
            }
            var opened=next.open(converted,clock(Instant.EPOCH));assertEquals(vector.time("floor"),opened.floor());assertEquals(vector.json("targetPayloadHex"),opened.payload());
            assertTypedState(vector,opened.payload());
            assertThrows(IllegalArgumentException.class,()->next.open(source,clock(Instant.EPOCH)));assertThrows(IllegalArgumentException.class,()->old.open(converted,clock(Instant.EPOCH)));
            assertEquals(original,source.toSealedForm());assertEquals(rootOriginal,root.toSealedForm());assertEquals(vector.field("version"),source.getVersion());assertEquals(vector.field("rootVersion"),root.getVersion());
        }));return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> convertedHistoricalStateKeepsLineageAndReplayFacts(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:authorizationVectors())tests.add(DynamicTest.dynamicTest("MIG-03/history/"+vector.name(),()->{
            StateSealer sealer=sealer(Instant.EPOCH);var next=target(sealer);var migration=migration(next);var pinned=migration.openRoot(vector.root());
            OAuthStoreEntry converted=migration.convert(vector.entry(),pinned),root=migration.convert(vector.root(),pinned);
            var record=decode(vector,next.open(converted,clock(Instant.EPOCH)).payload());var before=decode(vector,vector.json("payloadHex"));
            var issuer=OAuthStoreFence.fromRoot(OAuthIssuerRootV2.decode(next.open(root,clock(Instant.EPOCH)).payload()));
            JsonObject subject=OAuthStoreRecordCodecV2.parse("{\"schema\":1,\"incarnation\":\""+value("subjectIncarnation")+"\",\"epoch\":"+value("subjectEpoch")+"}",512);
            assertEquals(Boolean.parseBoolean(vector.field("issuerMatch")),record.matchesIssuer(issuer));
            if(vector.kind()!=OAuthStoreKey.Kind.INTERACTION){assertEquals(Boolean.parseBoolean(vector.field("subjectMatch")),record.matchesSubject(OAuthStoreFence.decode(subject,OAuthStoreKey.Kind.SUBJECT_STATE)));assertTrue(before.sameLineage(record));}
            assertEquals(vector.field("status"),record.text("status"));assertEquals(vector.field("id"),record.text("id"));assertEquals(vector.entry().getRetainUntil(),record.retention());assertEquals(before.toPayload(),record.toPayload());
            switch(vector.kind()){
                case INTERACTION:if(record.text("status").equals("COMPLETED"))assertThrows(IllegalArgumentException.class,record::completed);break;
                case CODE:if(!record.text("status").equals("UNUSED"))assertThrows(IllegalArgumentException.class,()->record.consumed(record.retention(),LIMITS,1024));break;
                case GRANT:
                    if(!record.text("status").equals("PENDING"))assertThrows(IllegalArgumentException.class,()->record.activated(record.expires(),record.retention(),Duration.ofSeconds(30),Set.of("read"),null,LIMITS,1024));
                    if(record.text("status").equals("REVOKED"))assertThrows(IllegalArgumentException.class,()->record.rotated(value("migrationId"),LIMITS,1024));
                    break;
                default:break;
            }
        }));return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> originalCredentialExpiryAndPhysicalRetentionNeverRefresh(){
        List<DynamicTest> tests=new ArrayList<>();
        for(Vector vector:authorizationVectors())tests.add(DynamicTest.dynamicTest("MIG-03/retention/"+vector.name(),()->{
            Instant retain=vector.entry().getRetainUntil();StateSealer sealer=sealer(retain.plusSeconds(600));var old=legacy(sealer);var next=target(sealer);var migration=migration(next);
            assertEquals(vector.json("payloadHex"),old.open(vector.entry(),clock(retain.minusNanos(1))));
            assertThrows(IllegalArgumentException.class,()->old.open(vector.entry(),clock(retain.plusSeconds(1))));
            // The externally CLOSED converter authenticates retained expired envelopes, with no live-credential output.
            var converted=migration.convert(vector.entry(),migration.openRoot(vector.root()));assertEquals(retain,converted.getRetainUntil());
            var opened=next.open(converted,clock(retain.minusNanos(1)));var state=decode(vector,opened.payload());
            assertEquals(vector.json("payloadHex"),opened.payload());assertEquals(vector.time("floor"),opened.floor());assertEquals(retain,state.retention());assertEquals(decode(vector,vector.json("payloadHex")).expires(),state.expires());
            for(Instant at:List.of(retain,retain.plusNanos(1),retain.plusSeconds(600)))assertThrows(IllegalArgumentException.class,()->next.open(converted,clock(at)));
            if(state.expires().isBefore(retain)){
                // Reading retained replay state does not change its already elapsed original credential expiry.
                var retained=decode(vector,next.open(converted,clock(state.expires())).payload());assertEquals(state.expires(),retained.expires());assertEquals(state.text("status"),retained.text("status"));
            }
        }));return tests;
    }

    private static void assertTypedState(@NonNull Vector vector,@NonNull JsonObject payload){
        if(vector.kind()==OAuthStoreKey.Kind.ISSUER_STATE){var root=OAuthIssuerRootV2.decode(payload);assertEquals(value("rootIncarnation"),root.incarnation());assertEquals(Long.parseLong(vector.field("rootEpoch")),root.epoch());assertEquals(value("authority"),root.authorityId());assertEquals(vector.time("root"),root.minimum());}
        else if(vector.kind()==OAuthStoreKey.Kind.SUBJECT_STATE){var subject=OAuthStoreFence.decode(payload,vector.kind());assertEquals(OAuthStoreFormat.longMember(vector.json("payloadHex"),"epoch").orElseThrow(),Long.valueOf(subject.epoch()));assertEquals(value("subjectIncarnation"),subject.incarnation());}
        else{
            var record=decode(vector,payload);assertEquals(vector.json("payloadHex").getMembers().keySet(),payload.getMembers().keySet());assertEquals(vector.field("status"),record.text("status"));assertEquals(1L,record.number("schema"));assertEquals(vector.entry().getRetainUntil(),record.retention());
            if(vector.kind()==OAuthStoreKey.Kind.GRANT && (record.text("status").equals("ACTIVE")||record.text("status").equals("REVOKED"))){
                var old=vector.json("payloadHex");Duration expected=Duration.ofSeconds(OAuthStoreFormat.longMember(old,"maximumAccessSeconds").orElseThrow(),OAuthStoreFormat.longMember(old,"maximumAccessNanos").orElseThrow());assertEquals(expected,record.maximumAccessLifetime());assertEquals(vector.integer("option")==1,record.refresh());
            }
        }
    }
    private static @NonNull OAuthAuthorizationRecord decode(@NonNull Vector vector,@NonNull JsonObject payload){return OAuthAuthorizationRecord.decode(vector.kind(),vector.field("id"),payload,LIMITS,1024);}
    private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull StateSealer sealer){return new OAuthStoreRecordCodecV2(value("issuer"),sealer,16384,LIMITS,1024);}
    private static @NonNull OAuthStoreRecordCodec legacy(@NonNull StateSealer sealer){return new OAuthStoreRecordCodec(value("issuer"),sealer,16384);}
    private static @NonNull OAuthStoreMigrationCodec migration(@NonNull OAuthStoreRecordCodecV2 target){return new OAuthStoreMigrationCodec(target,16384,ClosedMigrationIntent.fromExternalIntent(value("migrationId"),StoreAdmission.fromIdentifiers(value("authority"),value("recovery")),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));}
    private static @NonNull StateSealer sealer(@NonNull Instant at){return StateSealer.withActiveKey(SealingKey.fromBase64("f".repeat(64),"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(16384).clock(clock(at)).build();}
    private static @NonNull Clock clock(@NonNull Instant at){return Clock.fixed(at,ZoneOffset.UTC);}
    private static @NonNull String utf8(@NonNull String hex){return new String(HexFormat.of().parseHex(hex),StandardCharsets.UTF_8);}
    private static @NonNull String value(@NonNull String name){return Objects.requireNonNull(VECTORS.getProperty(name));}
    private static @NonNull List<@NonNull Vector> vectors(){List<Vector> result=new ArrayList<>();for(int i=0;i<Integer.parseInt(value("count"));i++)result.add(new Vector(i));return result;}
    private static @NonNull List<@NonNull Vector> authorizationVectors(){return vectors().stream().filter(v->v.kind()!=OAuthStoreKey.Kind.ISSUER_STATE && v.kind()!=OAuthStoreKey.Kind.SUBJECT_STATE).toList();}
    private static @NonNull Properties load(){Properties p=new Properties();try(var input=new InputStreamReader(Objects.requireNonNull(OAuthMigrationGoldenConformanceTests.class.getResourceAsStream(RESOURCE)),StandardCharsets.UTF_8)){p.load(input);}catch(IOException e){throw new ExceptionInInitializerError(e);}return p;}
    private static final class Vector{
        private final int index;Vector(int index){this.index=index;}
        @NonNull String field(@NonNull String name){return value("v."+this.index+'.'+name);}
        @NonNull String text(@NonNull String name){return utf8(field(name));}
        @NonNull JsonObject json(@NonNull String name){return OAuthStoreRecordCodecV2.parse(text(name),16000);}
        int integer(@NonNull String name){return Integer.parseInt(field(name));}
        @NonNull Instant time(@NonNull String name){return Instant.ofEpochSecond(Long.parseLong(field(name+"Seconds")),integer(name+"Nanos"));}
        OAuthStoreKey.@NonNull Kind kind(){return OAuthStoreKey.Kind.valueOf(field("kind"));}
        @NonNull String name(){return this.index+"/"+field("name");}
        @NonNull OAuthStoreEntry entry(){return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(field("key")),field("version"),Instant.ofEpochSecond(Long.parseLong(field("retain"))),field("sealed"));}
        @NonNull OAuthStoreEntry root(){return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(value("rootKey")),field("rootVersion"),OAuthStoreFormat.PERMANENT,field("rootSealed"));}
    }
}
