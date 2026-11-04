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
package com.revetsec;

import com.revetsec.internal.StoreTimeRules;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/** SC-API-02 A: named grammar/profile partitions and immutable family read-envelope joins. */
final class StoreIdentityProfileConformanceTests {
    private static final @NonNull String ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final @NonNull String AUTHORITY="A".repeat(43), RECOVERY="E"+"A".repeat(42), GENERATION="I"+"A".repeat(42);
    private static final @NonNull Instant NOW=Instant.parse("2026-11-03T12:00:00.123456789Z");
    private static final @NonNull Instant MAX=Instant.ofEpochSecond(253402300799L,999999999);
    private enum Domain { AUTHORITY, RECOVERY, CLOCK }

    @TestFactory @NonNull List<@NonNull DynamicTest> exactIdentifierGrammar() {
        List<DynamicTest> tests=new ArrayList<>();
        for (Domain domain:Domain.values()) {
            // All 64 alphabet characters are legal in each representative full six-bit slot.
            for (int position:new int[]{0,21,41}) for (int index=0;index<64;index++) {
                String input=replace(AUTHORITY,position,ALPHABET.charAt(index));
                tests.add(DynamicTest.dynamicTest("id/"+domain+"/alphabet/"+position+"/"+index,()->accept(domain,input)));
            }
            // 32 bytes leave exactly two spare bits in the last character, not a free six-bit slot.
            for (int index=0;index<64;index++) {
                String input=replace(AUTHORITY,42,ALPHABET.charAt(index));boolean canonical=(index&3)==0;
                tests.add(DynamicTest.dynamicTest("id/"+domain+"/tail/"+index,()->{
                    assertEquals(32,Base64.getUrlDecoder().decode(input).length);
                    if(canonical)accept(domain,input);else reject(domain,input);
                }));
            }
            // Every position rejects non-URL, non-ASCII, whitespace, NUL and isolated-surrogate classes.
            for (int position=0;position<43;position++) for (char invalid:new char[]{'+','/','=',' ','\n','\0','\u00e9','\ud800'}) {
                String input=replace(AUTHORITY,position,invalid);int point=invalid;
                tests.add(DynamicTest.dynamicTest("id/"+domain+"/bad-character/"+position+"/"+point,()->reject(domain,input)));
            }
            for (int length:new int[]{0,1,41,42,44,45,4096,32768}) {
                String input="A".repeat(length);
                tests.add(DynamicTest.dynamicTest("id/"+domain+"/length/"+length,()->reject(domain,input)));
            }
            String padded=AUTHORITY+"=";
            tests.add(DynamicTest.dynamicTest("id/"+domain+"/padding",()->reject(domain,padded)));
            Random random=new Random(0x534341504930324cL);
            for (int sample=0;sample<64;sample++) {
                byte[] bytes=new byte[32];random.nextBytes(bytes);
                String input=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
                tests.add(DynamicTest.dynamicTest("id/"+domain+"/seed-534341504930324c/"+sample,()->accept(domain,input)));
            }
        }
        return tests;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> exactTimeAndErrorBoundaries() {
        List<DynamicTest> tests=new ArrayList<>();
        List<Instant> accepted=List.of(Instant.EPOCH,Instant.EPOCH.plusNanos(1),Instant.ofEpochSecond(0,999999999),
                Instant.ofEpochSecond(1),Instant.ofEpochSecond(253402300799L),MAX.minusNanos(1),MAX,NOW);
        for(int index=0;index<accepted.size();index++) {
            Instant time=accepted.get(index);
            tests.add(DynamicTest.dynamicTest("time/accepted/"+index,()->assertEquals(time,observation(time,Duration.ZERO).getObservedAt())));
        }
        List<Instant> rejected=List.of(Instant.EPOCH.minusNanos(1),Instant.ofEpochSecond(-1),MAX.plusNanos(1),Instant.MIN,Instant.MAX);
        for(int index=0;index<rejected.size();index++) {
            Instant time=rejected.get(index);
            tests.add(DynamicTest.dynamicTest("time/rejected/"+index,()->{
                IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->observation(time,Duration.ZERO));
                assertEquals("Invalid store-time instant.",failure.getMessage());assertNull(failure.getCause());
            }));
        }
        for(long nanos:new long[]{0,1,249999999,250000000}) {
            Duration error=Duration.ofNanos(nanos);
            tests.add(DynamicTest.dynamicTest("profile/error/accepted/"+nanos,()->{
                StoreTimeObservation.Healthy value=observation(NOW,error);
                assertEquals(error,value.getMaximumUtcError());assertEquals(2,value.getMaximumUtcAdvanceRate());
                assertEquals(Duration.ofSeconds(5),value.getMaximumWorkerClockOffset());
            }));
        }
        for(Duration error:List.of(Duration.ofNanos(-1),Duration.ofNanos(250000001),Duration.ofSeconds(Long.MAX_VALUE))) {
            tests.add(DynamicTest.dynamicTest("profile/error/rejected/"+error,()->{
                IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->observation(NOW,error));
                assertEquals("Invalid store-time UTC-error bound.",failure.getMessage());assertNull(failure.getCause());
            }));
        }
        return tests;
    }

    @Test
    void identityDomainsAreOpaqueEqualityValuesAndEqualEncodingsAreAllowed() {
        StoreTimeObservation.Healthy first=observation(NOW,Duration.ZERO);
        for(String alternate:List.of("A".repeat(42)+"E","_".repeat(42)+"8")) {
            for(StoreTimeObservation.Healthy changed:List.of(
                    StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(alternate,RECOVERY),GENERATION,NOW,Duration.ZERO),
                    StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(AUTHORITY,alternate),GENERATION,NOW,Duration.ZERO),
                    StoreTimeObservation.Healthy.fromObservation(first.getAdmission(),alternate,NOW,Duration.ZERO))) {
                assertFalse(StoreTimeRules.sameProfile(first,changed));assertFalse(StoreTimeRules.sameProfile(changed,first));
            }
        }
        StoreAdmission swapped=StoreAdmission.fromIdentifiers(RECOVERY,AUTHORITY);
        assertFalse(StoreTimeRules.sameAdmission(first.getAdmission(),swapped));assertFalse(StoreTimeRules.sameAdmission(swapped,first.getAdmission()));
        StoreAdmission equal=StoreAdmission.fromIdentifiers(GENERATION,GENERATION);
        assertEquals(GENERATION,equal.getAuthorityId());assertEquals(GENERATION,equal.getRecoveryGeneration());
        for(Duration before:List.of(Duration.ZERO,Duration.ofMillis(250))) for(Duration after:List.of(Duration.ZERO,Duration.ofMillis(250))) {
            assertEquals(before.equals(after),StoreTimeRules.sameProfile(observation(NOW,before),observation(NOW.plusNanos(1),after)));
        }
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> familyEnvelopesKeepCopiedValuesAndFixedDiagnostics() {
        List<DynamicTest> tests=new ArrayList<>();
        for(boolean healthy:List.of(false,true)) for(boolean boundary:List.of(false,true)) {
            StoreAdmission admission=boundary?StoreAdmission.fromIdentifiers(RECOVERY,AUTHORITY):StoreAdmission.fromIdentifiers(AUTHORITY,RECOVERY);
            StoreTimeObservation observation=healthy?StoreTimeObservation.Healthy.fromObservation(admission,boundary?AUTHORITY:GENERATION,boundary?MAX:Instant.EPOCH,boundary?Duration.ofMillis(250):Duration.ZERO):StoreTimeObservation.Unavailable.fromAdmission(admission);
            tests.add(DynamicTest.dynamicTest("envelope/TOTP/"+healthy+"/"+boundary,()->{
                TotpStoreKey key=TotpStoreKey.forNamespace("scope","epoch-text-not-a-store-time-identifier");
                var keys=new HashSet<>(List.of(key));var entries=new HashMap<TotpStoreKey,TotpStoreEntry>();entries.put(key,TotpStoreEntry.Absent.confirmed());
                var snapshot=TotpStoreSnapshot.fromEntries(keys,entries,observation);keys.clear();entries.clear();
                assertEquals(1,snapshot.getEntries().size());assertSame(observation,snapshot.getTimeObservation());
                assertThrows(UnsupportedOperationException.class,()->snapshot.getEntries().clear());
                assertEquals("epoch-text-not-a-store-time-identifier",key.getRecoveryEpoch());
                assertEquals("TotpStoreSnapshot{entries=<redacted>}",snapshot.toString());
            }));
            tests.add(DynamicTest.dynamicTest("envelope/WEBAUTHN/"+healthy+"/"+boundary,()->{
                WebAuthnStoreKey key=WebAuthnStoreKey.forNamespaceClock("scope","login.example.com");
                var keys=new HashSet<>(List.of(key));var entries=new HashMap<WebAuthnStoreKey,WebAuthnStoreEntry>();entries.put(key,WebAuthnStoreEntry.Absent.confirmed());
                var snapshot=WebAuthnStoreSnapshot.fromEntries(keys,entries,observation);keys.clear();entries.clear();
                assertEquals(1,snapshot.getEntries().size());assertSame(observation,snapshot.getTimeObservation());
                assertThrows(UnsupportedOperationException.class,()->snapshot.getEntries().clear());
                assertEquals("WebAuthnStoreSnapshot{entries=<redacted>}",snapshot.toString());
            }));
            for(String mode:List.of("ISSUER_NORMAL","ISSUER_FENCE_ONLY")) tests.add(DynamicTest.dynamicTest("envelope/"+mode+"/"+healthy+"/"+boundary,()->{
                OAuthStoreKey key=OAuthStoreKey.fromStoredForm("revetsec:as:1:"+AUTHORITY+":ISSUER_STATE:"+AUTHORITY);
                var snapshot=OAuthStoreReadResult.Available.fromObservation(key,null,observation);
                assertEquals(key,snapshot.getKey());assertTrue(snapshot.getEntry().isEmpty());assertSame(observation,snapshot.getTimeObservation());
                assertEquals("Available{observation=<redacted>}",snapshot.toString());
            }));
            assertEquals(healthy?"Healthy{observation=<redacted>}":"Unavailable{admission=<redacted>}",observation.toString());
            assertEquals("StoreAdmission{admission=<redacted>}",admission.toString());
        }
        return tests;
    }

    private static void accept(@NonNull Domain domain,@NonNull String input) {
        String authority=domain==Domain.AUTHORITY?input:AUTHORITY,recovery=domain==Domain.RECOVERY?input:RECOVERY,generation=domain==Domain.CLOCK?input:GENERATION;
        StoreAdmission admission=StoreAdmission.fromIdentifiers(authority,recovery);
        StoreTimeObservation.Healthy result=StoreTimeObservation.Healthy.fromObservation(admission,generation,NOW,Duration.ZERO);
        assertEquals(authority,result.getAdmission().getAuthorityId());assertEquals(recovery,result.getAdmission().getRecoveryGeneration());
        assertEquals(generation,result.getClockGeneration());
    }
    private static void reject(@NonNull Domain domain,@NonNull String input) {
        IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->accept(domain,input));
        assertEquals("Invalid store-time identifier.",failure.getMessage());assertNull(failure.getCause());
    }
    private static @NonNull String replace(@NonNull String input,int position,char value) {
        return input.substring(0,position)+value+input.substring(position+1);
    }
    private static StoreTimeObservation.@NonNull Healthy observation(@NonNull Instant time,@NonNull Duration error) {
        return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(AUTHORITY,RECOVERY),GENERATION,time,error);
    }
}
