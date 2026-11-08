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
import com.revetsec.testing.ScriptedWebAuthnStore;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Same entry-compilable fixture; reflection detects a missing reconstruction capability by assertion. */
final class WebAuthnTombstoneResealTests {
    private static final String NS="tombstone-tests",RP="login.example.com";
    private static final Instant BASE=Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK=Clock.fixed(BASE,ZoneOffset.UTC);
    private static final byte[] ID={1,2,3},HANDLE={4,5,6};

    @TestFactory @NonNull Stream<@NonNull DynamicTest> removedTombstoneRotatesFromPersistedAddressWithoutActiveIndex() {
        return Stream.of(false,true).map(disabled->DynamicTest.dynamicTest("stored address / disabled="+disabled,()->{
            Fixture f=removed(disabled);String stored=f.source.records().keySet().stream()
                    .filter(key->key.getKind()==WebAuthnStoreKey.Kind.CREDENTIAL)
                    .map(WebAuthnStoreKey::getStorageKey).findFirst().orElseThrow();
            // Maintenance receives only the persisted address; no raw credential ID or active list.
            WebAuthnStoreKey key=restore(stored);assertEquals(stored,key.getStorageKey());assertEquals(WebAuthnStoreKey.Kind.CREDENTIAL,key.getKind());
            rotate(f,key,true);
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> retainedRawCredentialAddressIsAnExistingResealControl() {
        return Stream.of(false,true).map(disabled->DynamicTest.dynamicTest("retained ID / disabled="+disabled,()->rotate(removed(disabled),credential(),false)));
    }
    @Test void aDifferentWellFormedAddressDoesNotAuthenticateTheTombstone() throws Exception {
        Fixture f=removed(false);var impostor=WebAuthnStoreKey.forCredential(NS,RP,new byte[]{9});
        Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present> rows=new HashMap<>(f.source.records());rows.put(impostor,Objects.requireNonNull(rows.get(credential())));
        var source=new ScriptedWebAuthnStore(BASE);source.seedClosedMigration(rows);
        assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,party(source,sealer(true,true)).resealStoreEntry(impostor).getStatus());
        assertEquals(rows.keySet(),source.records().keySet());for(var key:rows.keySet()){assertArrayEquals(Objects.requireNonNull(rows.get(key)).getVersion(),Objects.requireNonNull(source.records().get(key)).getVersion());assertArrayEquals(Objects.requireNonNull(rows.get(key)).getSealedBytes(),Objects.requireNonNull(source.records().get(key)).getSealedBytes());}
    }

    private static void rotate(@NonNull Fixture f,@NonNull WebAuthnStoreKey tombstone,boolean imported) throws Exception {
        var oldRecords=new WebAuthnRecordCodec(sealer(false,false));var oldCodec=new WebAuthnCredentialRecordCodec(NS,RP,oldRecords);
        byte[] before=Objects.requireNonNull(f.source.records().get(tombstone)).getSealedBytes();
        var original=oldCodec.decodeRecord(tombstone,before,CLOCK);assertTrue(original.isRevoked());assertArrayEquals(HANDLE,original.userHandle());
        byte[] payload;Instant floor,expires;
        try(var decoded=oldRecords.openAdmittedRecord(tombstone,before,CLOCK)){payload=decoded.innerPayload();floor=decoded.floor();expires=decoded.expiresAt();}
        var rotated=party(f.source,sealer(true,true));
        assertEquals(WebAuthnStoreCommitResult.COMMITTED,rotated.resealStoreEntry(tombstone).getStatus());
        byte[] after=Objects.requireNonNull(f.source.records().get(tombstone)).getSealedBytes();assertFalse(Arrays.equals(before,after));
        var newRecords=new WebAuthnRecordCodec(sealer(true,false));
        try(var decoded=newRecords.openAdmittedRecord(tombstone,after,CLOCK)){assertArrayEquals(payload,decoded.innerPayload());assertEquals(floor,decoded.floor());assertEquals(expires,decoded.expiresAt());}
        assertTrue(new WebAuthnCredentialRecordCodec(NS,RP,newRecords).decodeRecord(tombstone,after,CLOCK).isRevoked());
        assertThrows(WebAuthnRecordException.class,()->oldCodec.decodeRecord(tombstone,after,CLOCK));
        // Finish the bounded four-row inventory before retiring the old opening key.
        for(var key:List.copyOf(f.source.records().keySet()))if(!key.equals(tombstone))
            assertEquals(WebAuthnStoreCommitResult.COMMITTED,rotated.resealStoreEntry(imported?restore(key.getStorageKey()):key).getStatus());
        var retired=party(f.source,sealer(true,false));
        var listed=retired.listCredentials(HANDLE);assertEquals(WebAuthnEngine.ManagementStatus.LISTED,listed.status());assertTrue(listed.credentialIds().isEmpty());
        assertEquals(WebAuthnEngine.ManagementStatus.ABSENT,retired.removeCredential(HANDLE,ID).status());
        assertTrue(new WebAuthnCredentialRecordCodec(NS,RP,newRecords).decodeRecord(tombstone,Objects.requireNonNull(f.source.records().get(tombstone)).getSealedBytes(),CLOCK).isRevoked());
        assertEquals(4,f.source.records().size());
        for(var entry:f.source.records().entrySet())try(var decoded=newRecords.openAdmittedRecord(entry.getKey(),entry.getValue().getSealedBytes(),CLOCK)){assertEquals(WebAuthnRecordPayloadV2.PERMANENT,decoded.expiresAt());}
    }
    private static @NonNull WebAuthnStoreKey restore(@NonNull String stored) {
        Method factory=assertDoesNotThrow(()->WebAuthnStoreKey.class.getMethod("fromStoredForm",String.class),"Persisted tombstones need a typed address without a credential-ID preimage");
        return assertInstanceOf(WebAuthnStoreKey.class,assertDoesNotThrow(()->factory.invoke(null,stored)));
    }
    private record Fixture(@NonNull ScriptedWebAuthnStore source){}
    private static @NonNull Fixture removed(boolean disabled) throws Exception {
        var source=new ScriptedWebAuthnStore(BASE);var records=new WebAuthnRecordCodec(sealer(false,false));
        byte[] spki=KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();ByteArrayOutputStream cose=new ByteArrayOutputStream();
        for(int n:new int[]{0xa4,1,1,3,0x27,0x20,6,0x21,0x58,32})cose.write(n);cose.write(spki,spki.length-32,32);
        var credentials=new WebAuthnCredentialRecordCodec(NS,RP,records);var indexes=new WebAuthnCredentialIndex(NS,RP,records);
        var credential=credentials.encode(WebAuthnCredentialState.checked(ID,HANDLE,cose.toByteArray(),-8,7,false,false),BASE);
        var index=indexes.encode(indexes.empty(HANDLE).withAdded(ID),BASE);var fence=new WebAuthnAccountFence(NS,RP,records).encode(HANDLE,true,BASE);
        var root=WebAuthnStoreKey.forNamespaceClock(NS,RP);
        source.seedClosedMigration(Map.of(credential.key(),present(1,credential.sealedBytes()),index.key(),present(2,index.sealedBytes()),fence.key(),present(3,fence.sealedBytes()),root,present(4,records.sealNamespace(root,source.admission().getAuthorityId(),BASE))));
        var rp=party(source,sealer(false,false));
        if(disabled)assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,rp.disableAccount(HANDLE).status());
        assertEquals(WebAuthnEngine.ManagementStatus.REMOVED,rp.removeCredential(HANDLE,ID).status());
        assertTrue(rp.listCredentials(HANDLE).credentialIds().isEmpty());
        return new Fixture(source);
    }
    private static WebAuthnStoreEntry.@NonNull Present present(int version,byte @NonNull [] sealed){return WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{(byte)version},sealed);}
    private static @NonNull WebAuthnStoreKey credential(){return WebAuthnStoreKey.forCredential(NS,RP,ID);}
    private static @NonNull StateSealer sealer(boolean next,boolean overlap){
        var old=SealingKey.fromBase64("old","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
        var active=SealingKey.fromBase64("next","ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");
        return StateSealer.withActiveKey(next?active:old).verificationKeys(overlap?List.of(old):List.of()).clock(CLOCK).build();
    }
    private static @NonNull WebAuthnEngine party(@NonNull WebAuthnStore store,@NonNull StateSealer sealer){
        return new WebAuthnEngine(NS,RP,Set.of("https://"+RP),store,sealer,budget->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}},CLOCK,WebAuthnSettings.builder().build());
    }
}
