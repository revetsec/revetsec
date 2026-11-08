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

package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.json.JsonString;
import com.revetsec.testing.ScriptedWebAuthnStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Existing public disable semantics: reopening deployment admission never enables an account. */
final class WebAuthnTerminalDisableTests {
    private static final String RP="login.example.com",ORIGIN="https://"+RP,NS="terminal-tests";
    private static final Instant BASE=Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK=Clock.fixed(BASE,ZoneOffset.UTC);
    private static final byte[] HANDLE={4,5,6},CREDENTIAL_ID={1,2,3};
    private static final String BINDING_TEXT=Base64Url.encode(new byte[32]);

    @TestFactory @NonNull Stream<@NonNull DynamicTest> terminalAtEveryAccountStageAcrossAdmissionAndMaintenance() {
        return Stream.of("empty","tentative","enrolled").flatMap(stage->Stream.of("reopen","fresh-service","repeat-disable","reseal").map(mode->DynamicTest.dynamicTest(stage+"/"+mode,()->{
            F f=new F();WebAuthnBrowserRequest registration=null,authentication=null,reauthentication=null;
            if(stage.equals("tentative"))registration=f.registration();
            if(stage.equals("enrolled")){f.enroll();authentication=f.authentication();reauthentication=assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,f.rp.beginReauthenticationResult(HANDLE,"transfer",BINDING_TEXT)).getRequest();}
            assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class,f.rp.disableAccountResult(HANDLE));
            f.gate.open.set(false);assertInstanceOf(WebAuthnRegistrationRequestResult.Unavailable.class,f.rp.beginRegistrationResult(options(),BINDING_TEXT));f.gate.open.set(true);
            var fence=WebAuthnStoreKey.forAccountFence(NS,RP,HANDLE);var disabled=Objects.requireNonNull(f.source.records().get(fence));
            if(mode.equals("fresh-service"))f.rp=f.party(false);
            if(mode.equals("repeat-disable")){
                assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class,f.rp.disableAccountResult(HANDLE));
                assertArrayEquals(disabled.getVersion(),Objects.requireNonNull(f.source.records().get(fence)).getVersion());assertArrayEquals(disabled.getSealedBytes(),Objects.requireNonNull(f.source.records().get(fence)).getSealedBytes());
            }
            if(mode.equals("reseal")){
                f.rp=f.party(true);for(var key:List.copyOf(f.source.records().keySet()))if(key.getKind()!=WebAuthnStoreKey.Kind.CEREMONY)assertEquals(WebAuthnStoreCommitResult.COMMITTED,f.rp.resealStoreEntry(WebAuthnStoreKey.fromStoredForm(key.getStorageKey())).getStatus());
            }
            var stable=Objects.requireNonNull(f.source.records().get(fence));
            assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,f.rp.beginRegistrationResult(options(),BINDING_TEXT));
            assertInstanceOf(WebAuthnAuthenticationRequestResult.Rejected.class,f.rp.beginReauthenticationResult(HANDLE,"transfer",BINDING_TEXT));
            // Discoverable begin does not know an account; denial is enforced at completion.
            f.authentication();
            if(registration!=null)assertInstanceOf(WebAuthnRegistrationResult.Rejected.class,f.rp.completeRegistrationResult(registration.getCeremonyId(),registrationJson(f.pair,challenge(registration)),BINDING_TEXT));
            if(authentication!=null)assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class,f.rp.completeAuthenticationResult(authentication.getCeremonyId(),assertionJson(f.pair.getPrivate(),challenge(authentication),1),BINDING_TEXT));
            if(reauthentication!=null)assertInstanceOf(WebAuthnReauthenticationResult.Rejected.class,f.rp.completeReauthenticationResult(HANDLE,"transfer",reauthentication.getCeremonyId(),assertionJson(f.pair.getPrivate(),challenge(reauthentication),1),BINDING_TEXT));
            var listed=assertInstanceOf(WebAuthnCredentialListResult.Listed.class,f.rp.listCredentialsResult(HANDLE));assertEquals(stage.equals("enrolled")?1:0,listed.getCredentialIds().size());
            if(stage.equals("enrolled"))assertInstanceOf(WebAuthnCredentialRemovalResult.Removed.class,f.rp.removeCredentialResult(HANDLE,CREDENTIAL_ID));
            else assertInstanceOf(WebAuthnCredentialRemovalResult.Absent.class,f.rp.removeCredentialResult(HANDLE,CREDENTIAL_ID));
            assertTrue(assertInstanceOf(WebAuthnCredentialListResult.Listed.class,f.rp.listCredentialsResult(HANDLE)).getCredentialIds().isEmpty());
            assertArrayEquals(stable.getVersion(),Objects.requireNonNull(f.source.records().get(fence)).getVersion());assertArrayEquals(stable.getSealedBytes(),Objects.requireNonNull(f.source.records().get(fence)).getSealedBytes());
            assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,f.rp.beginRegistrationResult(options(),BINDING_TEXT));
        })));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> outcomeReconciliationNeverPromisesAnEnableTransition() {
        return Stream.of("unknown-applied","known-commit-not-admitted","definite-no-effect").map(mode->DynamicTest.dynamicTest(mode,()->{
            F f=new F();f.enroll();
            if(mode.equals("unknown-applied"))f.store.unknownAfter=true;
            if(mode.equals("known-commit-not-admitted"))f.store.closeAfter=f.gate.open;
            if(mode.equals("definite-no-effect"))f.store.refuse=true;
            var result=f.rp.disableAccountResult(HANDLE);
            if(mode.equals("unknown-applied"))assertInstanceOf(WebAuthnAccountDisableResult.Indeterminate.class,result);
            else if(mode.equals("known-commit-not-admitted"))assertInstanceOf(WebAuthnAccountDisableResult.ReconciliationRequired.class,result);
            else assertInstanceOf(WebAuthnAccountDisableResult.Unavailable.class,result);
            f.store.unknownAfter=false;f.store.refuse=false;f.store.closeAfter=null;f.gate.open.set(true);
            if(mode.equals("definite-no-effect"))f.registration();
            else assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,f.rp.beginRegistrationResult(options(),BINDING_TEXT));
            // A fresh authorized operation reconciles current disable state; it does not undo it.
            assertInstanceOf(WebAuthnAccountDisableResult.Disabled.class,f.rp.disableAccountResult(HANDLE));
            assertInstanceOf(WebAuthnRegistrationRequestResult.Rejected.class,f.rp.beginRegistrationResult(options(),BINDING_TEXT));
        }));
    }
    private static @NonNull WebAuthnRegistrationOptions options(){return WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName("test").userDisplayName("Test").build();}
    private static @NonNull String challenge(@NonNull WebAuthnBrowserRequest request){return ((JsonString)request.getPublicKeyOptions().find("challenge").orElseThrow()).getValue();}
    @ThreadSafe private static final class Gate implements WebAuthnRecoveryGate {
        final AtomicBoolean open=new AtomicBoolean(true);
        @Override public @Nullable Permit acquire(@NonNull Duration budget){return open.get()?new Permit(){@Override public @NonNull Boolean isCurrent(){return open.get();}@Override public void close(){}}:null;}
    }
    @ThreadSafe private static final class Store implements WebAuthnStore {
        final ScriptedWebAuthnStore source;volatile boolean unknownAfter,refuse;volatile @Nullable AtomicBoolean closeAfter;
        Store(@NonNull ScriptedWebAuthnStore source){this.source=source;}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){return source.read(keys,budget);}
        @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){if(refuse)return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);var receipt=source.compareAndCommit(write,budget);AtomicBoolean close=closeAfter;if(close!=null)close.set(false);return unknownAfter?WebAuthnStoreCommitReceipt.unknownInstance():receipt;}
    }
    @NotThreadSafe private static final class F {
        final ScriptedWebAuthnStore source=new ScriptedWebAuthnStore(BASE);final Store store=new Store(source);final Gate gate=new Gate();final KeyPair pair;WebAuthnRelyingParty rp;
        F(){try{pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(GeneralSecurityException e){throw new IllegalStateException(e);}rp=party(false);}
        @NonNull WebAuthnRelyingParty party(boolean rotate){var old=SealingKey.fromBase64("old","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");var next=SealingKey.fromBase64("next","ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");var sealer=StateSealer.withActiveKey(rotate?next:old).verificationKeys(rotate?List.of(old):List.of()).clock(CLOCK).build();return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Test").credentialNamespace(NS).allowedOrigins(Set.of(ORIGIN)).stateSealer(sealer).store(store).recoveryGate(gate).clockForTesting(CLOCK).build();}
        @NonNull WebAuthnBrowserRequest registration(){return assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class,rp.beginRegistrationResult(options(),BINDING_TEXT)).getRequest();}
        @NonNull WebAuthnBrowserRequest authentication(){return assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,rp.beginAuthenticationResult(BINDING_TEXT)).getRequest();}
        void enroll(){var request=registration();assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class,rp.completeRegistrationResult(request.getCeremonyId(),registrationJson(pair,challenge(request)),BINDING_TEXT));}
    }
    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair,
            @NonNull String challenge) {
        byte[] auth = registrationAuth(pair);
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"attestationObject\":\"" + Base64Url.encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    private static byte @NonNull [] assertionJson(@NonNull PrivateKey key,
            @NonNull String challenge, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(clientJson("webauthn.get", challenge)));
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"signature\":\"" + Base64Url.encode(signer.sign())
                + "\",\"userHandle\":\"" + Base64Url.encode(HANDLE)
                + "\"},\"clientExtensionResults\":{}}");
    }

    private static byte @NonNull [] clientJson(@NonNull String type, @NonNull String challenge) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}");
    }

    private static byte @NonNull [] registrationAuth(@NonNull KeyPair pair) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(CREDENTIAL_ID.length); out.writeBytes(CREDENTIAL_ID);
        out.writeBytes(edKey(pair));
        return out.toByteArray();
    }

    private static byte @NonNull [] assertionAuth(long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII))); out.write(0x05);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
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
