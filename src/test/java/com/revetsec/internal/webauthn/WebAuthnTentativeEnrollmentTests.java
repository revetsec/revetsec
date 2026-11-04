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
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.testing.ScriptedWebAuthnStore;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Account state is established by credential commitment, never a tentative browser begin. */
final class WebAuthnTentativeEnrollmentTests {
    private static final @NonNull String NS="tentative-tests",RP="login.example.com",ORIGIN="https://"+RP;
    private static final @NonNull Instant BASE=Instant.parse("2026-10-09T12:00:00Z");
    private static final byte @NonNull [] HANDLE={4,5,6},ID={1,2,3},BINDING=new byte[32];

    @Test void beginCommitsOnlyExpiringCeremonyAndOneNamespaceRoot() throws Exception {
        F f=new F();var request=f.begin(HANDLE);assertTentative(f,HANDLE);
        assertEquals(Set.of(f.root(),f.ceremonyKey(request)),f.source.records().keySet());
        var write=f.store.writes.get(0);assertInstanceOf(WebAuthnStoreEntry.Absent.class,write.getSnapshot().getEntry(f.fence(HANDLE)));
        assertInstanceOf(WebAuthnStoreEntry.Absent.class,write.getSnapshot().getEntry(f.index(HANDLE)));
        assertEquals(Set.of(f.root(),f.ceremonyKey(request)),mutationKeys(write));
        assertEquals(BASE.plusSeconds(300),write.getMutations().stream().filter(m->m.getKey().equals(f.ceremonyKey(request))).findFirst().orElseThrow().getExpiresAt().orElseThrow());
        assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());
        assertTrue(f.engine.listCredentials(HANDLE).credentialIds().isEmpty());
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.beginReauthentication(HANDLE,"change",BINDING).status());
    }
    @Test void manyAbandonedHandlesAddNoPermanentPerAccountRows() {
        F f=new F();for(int i=0;i<64;i++)f.begin(new byte[]{(byte)(i+1)});
        assertEquals(65,f.source.records().size());
        assertEquals(1,f.source.records().keySet().stream().filter(k->k.getKind()!=WebAuthnStoreKey.Kind.CEREMONY).count());
    }
    @Test void explicitExpiredCeremonyMaintenanceRecoversCapacityAcrossAbandonedAccounts() throws Exception {
        F f=new F(3);
        for(int i=0;i<64;i++){
            byte[] handle={(byte)(i+1)};var request=f.begin(handle);assertTentative(f,handle);
            assertEquals(2,f.source.records().size());f.advance(Duration.ofSeconds(300));
            var key=f.ceremonyKey(request);var snapshot=assertInstanceOf(WebAuthnStoreReadResult.Available.class,f.source.read(Set.of(key,f.root()),Duration.ofSeconds(1))).getSnapshot();
            // Explicit fixture maintenance at the known authenticated expiry, never a read side effect.
            assertEquals(WebAuthnStoreCommitResult.COMMITTED,f.source.compareAndCommit(ScriptedWebAuthnStore.write(snapshot,List.of(WebAuthnStoreWrite.Mutation.delete(key))),Duration.ofSeconds(1)).getStatus());
            assertEquals(Set.of(f.root()),f.source.records().keySet());
        }
        f.begin(new byte[]{100});
    }
    @Test void firstCredentialEstablishesFenceIndexAndConsumptionInOneWrite() throws Exception {
        F f=new F();var request=f.begin(HANDLE);f.store.writes.clear();
        assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(request,ID).status());
        var write=f.store.writes.get(0);assertInstanceOf(WebAuthnStoreEntry.Absent.class,write.getSnapshot().getEntry(f.fence(HANDLE)));
        assertEquals(Set.of(f.ceremonyKey(request),f.fence(HANDLE),f.index(HANDLE),f.credential(ID)),mutationKeys(write));
        assertTrue(f.active(HANDLE));assertTrue(f.pending(request).isConsumed());
        assertTrue(f.ids(HANDLE).contains(ID));
        for(var m:write.getMutations())if(m.getKey().getKind()!=WebAuthnStoreKey.Kind.CEREMONY)assertTrue(m.getExpiresAt().isEmpty());
    }
    @Test void authenticatedPendingRegistrationCanEstablishAnAbsentAccount() throws Exception {
        F f=new F();var request=f.seedPending(Map.of());
        assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(request,ID).status());assertTrue(f.active(HANDLE));
    }
    @Test void indexWithoutFenceCannotBeAdmittedByBegin() {
        F f=new F();f.seed(Map.of(f.index(HANDLE),f.indexBytes(HANDLE)));
        var before=f.source.records();assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.beginRegistration(HANDLE,BINDING).status());assertSameRecords(before,f.source.records());
    }
    @Test void indexWithoutFenceCannotBeReactivatedByCompletion() throws Exception {
        F f=new F();var request=f.seedPending(Map.of(f.index(HANDLE),f.indexBytes(HANDLE)));var before=f.source.records();
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.complete(request,ID).status());assertSameRecords(before,f.source.records());
    }
    @Test void rejectedResponseDoesNotEstablishAnAccount() {
        F f=new F();var request=f.begin(HANDLE);
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.completeRegistration(request.ceremonyId(),BINDING,"{}".getBytes(StandardCharsets.UTF_8)).status());assertTentative(f,HANDLE);
    }
    @Test void wrongBindingCannotEstablishAnAccount() throws Exception {
        F f=new F();var request=f.begin(HANDLE);byte[] wrong=BINDING.clone();wrong[0]=1;
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.completeRegistration(request.ceremonyId(),wrong,registrationJson(f.pair,ID,Base64Url.encode(request.challenge()))).status());assertTentative(f,HANDLE);
    }
    @Test void exactExpiryCannotEstablishAnAccount() throws Exception {
        F f=new F();var request=f.begin(HANDLE);f.advance(Duration.ofSeconds(300));
        assertEquals(WebAuthnEngine.Status.REJECTED,f.complete(request,ID).status());assertTentative(f,HANDLE);
    }
    @Test void expiryAtCommitLeavesNoPartialAccountOrConsumption() throws Exception {
        F f=new F();var request=f.begin(HANDLE);var before=f.source.records();
        f.store.before=write->{f.advance(Duration.ofSeconds(300));};
        assertEquals(WebAuthnEngine.Status.REJECTED,f.complete(request,ID).status());assertSameRecords(before,f.source.records());assertTentative(f,HANDLE);
    }
    @Test void capacityRefusalLeavesTentativeCeremonyUnconsumed() throws Exception {
        F f=new F(3);var request=f.begin(HANDLE);var before=f.source.records();
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.complete(request,ID).status());assertSameRecords(before,f.source.records());assertFalse(f.pending(request).isConsumed());assertTentative(f,HANDLE);
    }
    @Test void definiteStoreRefusalCannotEstablishAccountState() throws Exception {
        F f=new F();var request=f.begin(HANDLE);var before=f.source.records();f.store.refuse=WebAuthnStoreCommitResult.UNAVAILABLE;
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.complete(request,ID).status());assertSameRecords(before,f.source.records());assertTentative(f,HANDLE);
    }
    @Test void disableBeforeEnrollmentIsPermanentAndNeverReopened() throws Exception {
        F f=new F();assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(HANDLE).status());var fence=f.record(f.fence(HANDLE));
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.beginRegistration(HANDLE,BINDING).status());f.advance(Duration.ofDays(1));
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.beginRegistration(HANDLE,BINDING).status());assertFalse(f.active(HANDLE));assertArrayEquals(fence.getVersion(),f.record(f.fence(HANDLE)).getVersion());
    }
    @Test void disableOfTentativeAccountBlocksItsPendingCompletion() throws Exception {
        F f=new F();var request=f.begin(HANDLE);assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(HANDLE).status());var before=f.source.records();
        assertEquals(WebAuthnEngine.Status.REJECTED,f.complete(request,ID).status());assertSameRecords(before,f.source.records());assertFalse(f.active(HANDLE));
    }
    @Test void disableWinningBeginRacePreventsCeremonyCommit() {
        F f=new F();f.store.before=write->{f.store.before=null;assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(HANDLE).status());};
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.beginRegistration(HANDLE,BINDING).status());
        assertTrue(f.source.records().keySet().stream().noneMatch(k->k.getKind()==WebAuthnStoreKey.Kind.CEREMONY));assertFalse(f.source.records().containsKey(f.index(HANDLE)));
    }
    @Test void disableWinningCompletionRacePreventsAllCredentialMutations() throws Exception {
        F f=new F();var request=f.begin(HANDLE);
        f.store.before=write->{f.store.before=null;assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(HANDLE).status());};
        assertEquals(WebAuthnEngine.Status.REJECTED,f.complete(request,ID).status());assertFalse(f.active(HANDLE));assertFalse(f.source.records().containsKey(f.index(HANDLE)));assertFalse(f.source.records().containsKey(f.credential(ID)));assertFalse(f.pending(request).isConsumed());
    }
    @Test void twoFirstCompletionsRaceWithoutLosingCredentialsOrRewritingEstablishedFence() throws Exception {
        F f=new F();var one=f.begin(HANDLE);var two=f.begin(HANDLE);byte[] second={7,8,9};AtomicReference<byte[]> fenceVersion=new AtomicReference<>();f.store.writes.clear();
        f.store.before=write->{f.store.before=null;assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(two,second).status());fenceVersion.set(f.record(f.fence(HANDLE)).getVersion());};
        assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(one,ID).status());
        assertEquals(4,f.store.writes.get(0).getMutations().size());assertEquals(3,f.store.writes.get(f.store.writes.size()-1).getMutations().size());
        assertArrayEquals(fenceVersion.get(),f.record(f.fence(HANDLE)).getVersion());assertTrue(f.ids(HANDLE).contains(ID));assertTrue(f.ids(HANDLE).contains(second));assertEquals(2,f.ids(HANDLE).size());assertTrue(f.pending(one).isConsumed());assertTrue(f.pending(two).isConsumed());
    }
    @Test void duplicateCredentialOnAnotherTentativeAccountDoesNotCreateFence() throws Exception {
        F f=new F();assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(f.begin(HANDLE),ID).status());byte[] other={9};var request=f.begin(other);
        assertEquals(WebAuthnEngine.Status.REJECTED,f.complete(request,ID).status());assertTentative(f,other);assertFalse(f.pending(request).isConsumed());
    }
    @Test void competingFirstCompletionRespectsConfiguredCredentialLimit() throws Exception {
        F f=new F(65536,1);var one=f.begin(HANDLE);var two=f.begin(HANDLE);byte[] second={7,8,9};
        f.store.before=write->{f.store.before=null;assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(two,second).status());};
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.complete(one,ID).status());
        assertEquals(1,f.ids(HANDLE).size());assertTrue(f.ids(HANDLE).contains(second));assertFalse(f.ids(HANDLE).contains(ID));
        assertFalse(f.pending(one).isConsumed());assertTrue(f.pending(two).isConsumed());assertFalse(f.source.records().containsKey(f.credential(ID)));
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.beginRegistration(HANDLE,BINDING).status());
    }
    @Test void existingLegacyActiveFenceIsPreservedAcrossBeginAndCompletion() throws Exception {
        F f=new F();f.seed(Map.of(f.fence(HANDLE),f.fenceBytes(HANDLE,true)));var before=f.record(f.fence(HANDLE));
        var request=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.complete(request,ID).status());assertTrue(f.active(HANDLE));
        assertArrayEquals(before.getVersion(),f.record(f.fence(HANDLE)).getVersion());assertArrayEquals(before.getSealedBytes(),f.record(f.fence(HANDLE)).getSealedBytes());
    }
    @Test void malformedFenceCannotBeReplacedByARegistration() throws Exception {
        F f=new F();var request=f.seedPending(Map.of(f.fence(HANDLE),new byte[]{1}));var before=f.source.records();
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.beginRegistration(HANDLE,BINDING).status());assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.complete(request,ID).status());assertSameRecords(before,f.source.records());
    }
    @Test void uncertainAppliedCompletionRetainsAccountFactWithoutProof() throws Exception {
        F f=new F();var request=f.begin(HANDLE);f.store.unknown=true;var result=f.complete(request,ID);
        assertEquals(WebAuthnEngine.Status.INDETERMINATE,result.status());assertNull(result.verified());assertTrue(f.active(HANDLE));assertTrue(f.pending(request).isConsumed());assertTrue(f.ids(HANDLE).contains(ID));
    }
    @Test void knownCommitWithLostAdmissionRetainsFenceAndWithholdsProof() throws Exception {
        F f=new F();var request=f.begin(HANDLE);f.store.after=()->f.source.setHealthy(false);var result=f.complete(request,ID);
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.verified());assertTrue(f.source.records().containsKey(f.fence(HANDLE)));assertTrue(f.source.records().containsKey(f.credential(ID)));
    }

    private static void assertTentative(@NonNull F f,byte @NonNull [] handle){assertFalse(f.source.records().containsKey(f.fence(handle)));assertFalse(f.source.records().containsKey(f.index(handle)));}
    private static @NonNull Set<@NonNull WebAuthnStoreKey> mutationKeys(@NonNull WebAuthnStoreWrite write){Set<WebAuthnStoreKey> keys=new HashSet<>();for(var m:write.getMutations())assertTrue(keys.add(m.getKey()));return keys;}
    private static void assertSameRecords(@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> a,@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> b){assertEquals(a.keySet(),b.keySet());for(var k:a.keySet()){assertArrayEquals(Objects.requireNonNull(a.get(k)).getVersion(),Objects.requireNonNull(b.get(k)).getVersion());assertArrayEquals(Objects.requireNonNull(a.get(k)).getSealedBytes(),Objects.requireNonNull(b.get(k)).getSealedBytes());}}
    @FunctionalInterface private interface Before {void run(@NonNull WebAuthnStoreWrite write) throws Exception;}
    @ThreadSafe private static final class RecordingStore implements WebAuthnStore {
        final @NonNull ScriptedWebAuthnStore source;final @NonNull List<@NonNull WebAuthnStoreWrite> writes=new CopyOnWriteArrayList<>();
        volatile @Nullable Before before;volatile @Nullable Runnable after;volatile @Nullable WebAuthnStoreCommitResult refuse;volatile boolean unknown;
        RecordingStore(@NonNull ScriptedWebAuthnStore source){this.source=source;}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){return source.read(keys,budget);}
        @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){
            writes.add(write);Before hook=before;try{if(hook!=null)hook.run(write);}catch(Exception e){throw new IllegalStateException(e);}
            WebAuthnStoreCommitResult refusal=refuse;if(refusal!=null)return WebAuthnStoreCommitReceipt.fromRefusal(refusal);
            var result=source.compareAndCommit(write,budget);Runnable callback=after;if(callback!=null)callback.run();return unknown?WebAuthnStoreCommitReceipt.unknownInstance():result;
        }
    }
    @ThreadSafe private static final class WorkerClock extends Clock {
        final @NonNull AtomicReference<@NonNull Instant> time=new AtomicReference<>(BASE);
        @Override public @NonNull Instant instant(){return Objects.requireNonNull(time.get());}
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
    }
    @NotThreadSafe private static final class F {
        final @NonNull ScriptedWebAuthnStore source;final @NonNull RecordingStore store;final @NonNull WorkerClock worker=new WorkerClock();
        final @NonNull StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).clock(Clock.fixed(BASE,ZoneOffset.UTC)).maximumSealedLength(16384).build();
        final @NonNull WebAuthnRecordCodec records=new WebAuthnRecordCodec(sealer);final @NonNull WebAuthnEngine engine;final @NonNull KeyPair pair;
        F(){this(65536);}
        F(int capacity){this(capacity,64);}
        F(int capacity,int excluded){source=new ScriptedWebAuthnStore(BASE,capacity,268435456L);store=new RecordingStore(source);engine=new WebAuthnEngine(NS,RP,Set.of(ORIGIN),store,sealer,budget->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}},worker,WebAuthnSettings.builder().maximumExcludedCredentials(excluded).build());try{pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(java.security.GeneralSecurityException e){throw new IllegalStateException(e);}}
        WebAuthnEngine.@NonNull Request begin(byte @NonNull [] handle){var r=engine.beginRegistration(handle,BINDING);assertEquals(WebAuthnEngine.Status.PREPARED,r.status());return Objects.requireNonNull(r.request());}
        WebAuthnEngine.@NonNull Finish complete(WebAuthnEngine.@NonNull Request request,byte @NonNull [] id){return engine.completeRegistration(request.ceremonyId(),BINDING,registrationJson(pair,id,Base64Url.encode(request.challenge())));}
        @NonNull WebAuthnStoreKey root(){return WebAuthnStoreKey.forNamespaceClock(NS,RP);}
        @NonNull WebAuthnStoreKey fence(byte @NonNull [] h){return WebAuthnStoreKey.forAccountFence(NS,RP,h);}
        @NonNull WebAuthnStoreKey index(byte @NonNull [] h){return WebAuthnStoreKey.forAccountCredentialIndex(NS,RP,h);}
        @NonNull WebAuthnStoreKey credential(byte @NonNull [] id){return WebAuthnStoreKey.forCredential(NS,RP,id);}
        @NonNull WebAuthnStoreKey ceremonyKey(WebAuthnEngine.@NonNull Request r){return WebAuthnStoreKey.forCeremony(NS,RP,r.ceremonyId());}
        WebAuthnStoreEntry.@NonNull Present record(@NonNull WebAuthnStoreKey key){return Objects.requireNonNull(source.records().get(key));}
        byte @NonNull [] fenceBytes(byte @NonNull [] h,boolean active){return new WebAuthnAccountFence(NS,RP,records).encode(h,active,BASE).sealedBytes();}
        byte @NonNull [] indexBytes(byte @NonNull [] h){var c=new WebAuthnCredentialIndex(NS,RP,records);return c.encode(c.empty(h),BASE).sealedBytes();}
        boolean active(byte @NonNull [] h) throws WebAuthnRecordException{return new WebAuthnAccountFence(NS,RP,records).decode(fence(h),record(fence(h)).getSealedBytes(),worker).isActive();}
        WebAuthnCredentialIndex.@NonNull State ids(byte @NonNull [] h) throws WebAuthnRecordException{return new WebAuthnCredentialIndex(NS,RP,records).decode(index(h),record(index(h)).getSealedBytes(),worker);}
        @NonNull WebAuthnCeremonyState pending(WebAuthnEngine.@NonNull Request r) throws WebAuthnRecordException{return new WebAuthnCeremonyRecordCodec(NS,RP,records).decode(ceremonyKey(r),record(ceremonyKey(r)).getSealedBytes(),worker);}
        void advance(@NonNull Duration amount){source.advance(amount);worker.time.set(source.authorityTime());}
        void seed(@NonNull Map<@NonNull WebAuthnStoreKey,byte @NonNull []> rows){Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present> values=new HashMap<>();int n=1;for(var e:rows.entrySet())values.put(e.getKey(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{(byte)n++},e.getValue()));values.put(root(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{99},records.sealNamespace(root(),source.admission().getAuthorityId(),BASE)));source.seedClosedMigration(values);}
        WebAuthnEngine.@NonNull Request seedPending(@NonNull Map<@NonNull WebAuthnStoreKey,byte @NonNull []> rows){var request=new F().begin(HANDLE);byte[] id=request.ceremonyId(),challenge=request.challenge();var state=WebAuthnCeremonyState.registration(id,challenge,BINDING,Set.of(ORIGIN),HANDLE,BASE,BASE.plusSeconds(300));var encoded=new WebAuthnCeremonyRecordCodec(NS,RP,records).encode(state,BASE);Map<WebAuthnStoreKey,byte[]> all=new HashMap<>(rows);all.put(encoded.key(),encoded.sealedBytes());seed(all);return request;}
    }
    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair, byte @NonNull [] credentialId,
            @NonNull String challenge) {
        byte[] auth = registrationAuth(pair, credentialId);
        String id = Base64Url.encode(credentialId);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"attestationObject\":\"" + Base64Url.encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    private static byte @NonNull [] clientJson(@NonNull String type, @NonNull String challenge) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}");
    }

    private static byte @NonNull [] registrationAuth(@NonNull KeyPair pair, byte @NonNull [] credentialId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(credentialId.length); out.writeBytes(credentialId);
        out.writeBytes(edKey(pair));
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }
    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }
    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
