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
package consumer;

import com.revetsec.OperationBinding;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreTimeObservation;
import com.revetsec.json.JsonString;
import com.revetsec.webauthn.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Public-only packaged source: nine actual outcomes, no private constructors or test classfiles. */
public final class PublicProofCases {
    private static final String RP="passkeys.example.test", ORIGIN="https://"+RP+":9443", NS="public-proof", PURPOSE="selected-action";
    private static final byte[] ACCOUNT={1,2,3};
    private static int assertions,actions;
    private static boolean exhaustive;
    private PublicProofCases() { }
    public static void main(String[] args)throws Exception {
        Path expected=Path.of(args[0]).toRealPath();String sha=args[1];exhaustive=args.length==3;
        for(Class<?> type:List.of(WebAuthnRelyingParty.class,WebAuthnReauthentication.class,WebAuthnReauthenticationResult.class)) {
            Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
            check(actual.equals(expected)&&HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(sha),"actual-core-origin");
        }
        check(WebAuthnReauthentication.class.getConstructors().length==0,"restricted-proof-construction");
        check(WebAuthnReauthenticationResult.class.getPermittedSubclasses().length==5,"five-leaf-result");
        for(Class<?> leaf:WebAuthnReauthenticationResult.class.getPermittedSubclasses()) {
            check(leaf.getConstructors().length==0,"restricted-leaf-construction");
            if(leaf!=WebAuthnReauthenticationResult.Succeeded.class)
                for(var method:leaf.getMethods())check(method.getReturnType()!=WebAuthnReauthentication.class,"failure-no-proof-accessor");
        }
        for(Mode mode:Mode.values())execute(mode);
        check(actions==2,"two-explicit-matching-success-actions-only");
        System.out.println("PUBLIC-PROOF checks="+assertions+" modes="+Mode.values().length+" actions="+actions);
    }
    private static ProducedCase execute(Mode mode)throws Exception { return execute(mode,JoinedFault.NONE,false); }
    /** Test-only witness for the shared consumer; all results still come from the public RP. */
    public record ProducedCase(String mode,WebAuthnReauthenticationResult result,int reads,int callbacks,int applied,int closes) {
        @Override public String toString(){return "ProducedCase{<redacted>}";}
    }
    public static List<ProducedCase> producedForJoin()throws Exception {
        check(assertions==0&&actions==0,"fresh-joined-producer-process");
        List<ProducedCase> values=new ArrayList<>();
        for(Mode mode:Mode.values())values.add(execute(mode,JoinedFault.NONE,true));
        values.add(execute(Mode.KNOWN_NOT_ADMITTED,JoinedFault.TIME_OUTAGE,true));
        values.add(execute(Mode.KNOWN_NOT_ADMITTED,JoinedFault.CLOSE_FAILURE,true));
        check(actions==2,"joined-two-matching-actions-only");return List.copyOf(values);
    }
    private enum JoinedFault { NONE,TIME_OUTAGE,CLOSE_FAILURE }
    private static ProducedCase execute(Mode mode,JoinedFault fault,boolean joined)throws Exception {
        FaultStore store=new FaultStore();AtomicBoolean allowed=new AtomicBoolean(true),closeFailure=new AtomicBoolean();AtomicInteger closes=new AtomicInteger();
        WebAuthnRecoveryGate gate=remaining->new WebAuthnRecoveryGate.Permit(){public Boolean isCurrent(){return allowed.get();}public void close(){closes.incrementAndGet();if(closeFailure.get())throw new IllegalStateException("Controlled permit close failure");}};
        var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("test",Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))).build();
        var rp=WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Public proof").allowedOrigins(Set.of(ORIGIN)).credentialNamespace(NS).store(store).stateSealer(sealer).recoveryGate(gate).build();
        OperationBinding binding=OperationBinding.fromTrustedPersistence(Base64.getUrlEncoder().withoutPadding().encodeToString("abcdefghijklmnopqrstuvwxyz012345".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        SyntheticAuthenticator authenticator=new SyntheticAuthenticator(ACCOUNT);
        var registration=(WebAuthnRegistrationRequestResult.Prepared)rp.beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(ACCOUNT).userName("test").userDisplayName("Test").build(),binding);
        check(rp.completeRegistrationResult(registration.getRequest().getCeremonyId(),authenticator.registration(challenge(registration.getRequest())),binding)instanceof WebAuthnRegistrationResult.Succeeded,"real-enrollment");
        var prepared=(WebAuthnAuthenticationRequestResult.Prepared)rp.beginReauthenticationResult(ACCOUNT,PURPOSE,binding);
        byte[] response=authenticator.assertion(challenge(prepared.getRequest()),1);byte[] expected=mode==Mode.MUTATED_EXPECTED_A_TO_B?new byte[]{9,9,9}:ACCOUNT.clone();int callbacks=store.callbacks,mutations=store.mutations,reads=store.reads,closed=closes.get();
        switch(mode){case UNAVAILABLE->store.refusal=WebAuthnStoreCommitResult.UNAVAILABLE;case UNKNOWN_NO_EFFECT->store.refusal=WebAuthnStoreCommitResult.UNKNOWN;case UNKNOWN_APPLIED->store.unknownApplied=true;case KNOWN_NOT_ADMITTED->{if(fault==JoinedFault.TIME_OUTAGE)store.after=()->store.timeUnavailable=true;else if(fault==JoinedFault.CLOSE_FAILURE)closeFailure.set(true);else store.after=()->allowed.set(false);}case CANCELLED->Thread.currentThread().interrupt();case MUTATED_EXPECTED_A_TO_B->store.after=()->System.arraycopy(ACCOUNT,0,expected,0,ACCOUNT.length);case MATCHING_EXPECTED_B_TO_A->store.after=()->Arrays.fill(expected,(byte)9);default->{}}
        WebAuthnReauthenticationResult result;
        try{result=rp.completeReauthenticationResult(expected,mode==Mode.REJECTED_CONTEXT?"other":PURPOSE,prepared.getRequest().getCeremonyId(),response,binding);if(mode==Mode.CANCELLED)check(Thread.currentThread().isInterrupted(),"interrupt-retained");}
        finally{if(mode==Mode.CANCELLED)check(Thread.interrupted(),"explicit-fixture-interrupt-clear");}
        boolean committed=mode==Mode.SUCCESS||mode==Mode.REJECTED_CONTEXT||mode==Mode.UNKNOWN_APPLIED||mode==Mode.KNOWN_NOT_ADMITTED||mode==Mode.MUTATED_EXPECTED_A_TO_B||mode==Mode.MATCHING_EXPECTED_B_TO_A;
        check(store.callbacks-callbacks==(mode==Mode.CANCELLED?0:1),"exact-callback-no-retry");check(store.mutations-mutations==(committed?2:0),"exact-physical-mutations");
        switch(mode){
            case SUCCESS,MATCHING_EXPECTED_B_TO_A->{check(result instanceof WebAuthnReauthenticationResult.Succeeded,"success");var proof=((WebAuthnReauthenticationResult.Succeeded)result).getReauthentication();check(proof.getCeremonyId().equals(prepared.getRequest().getCeremonyId()),"exact-ceremony");check(proof.getCredentialNamespace().equals(NS)&&proof.getRelyingPartyId().equals(RP)&&proof.getActionPurpose().equals(PURPOSE)&&MessageDigest.isEqual(proof.getUserHandle(),ACCOUNT),"exact-fact-scope");if(joined)check(Base64.getUrlEncoder().withoutPadding().encodeToString(proof.getCredentialId()).equals(authenticator.credentialId()),"exact-credential-id");consumeSelectedAction(proof);}
            case REJECTED_CONTEXT,MUTATED_EXPECTED_A_TO_B->check(result instanceof WebAuthnReauthenticationResult.Rejected,mode==Mode.MUTATED_EXPECTED_A_TO_B?"entry-handle-alias-must-reject":"known-consumption-context-rejected");
            case UNAVAILABLE,CANCELLED->check(result instanceof WebAuthnReauthenticationResult.Unavailable,"unavailable");
            case UNKNOWN_NO_EFFECT,UNKNOWN_APPLIED->check(result instanceof WebAuthnReauthenticationResult.Indeterminate,"unknown-without-proof");
            case KNOWN_NOT_ADMITTED->check(result instanceof WebAuthnReauthenticationResult.ReconciliationRequired,"known-withheld-without-proof");
        }
        if(exhaustive){String expectedRoute=switch(mode){case SUCCESS,MATCHING_EXPECTED_B_TO_A->"Succeeded";case REJECTED_CONTEXT,MUTATED_EXPECTED_A_TO_B->"Rejected";case UNAVAILABLE,CANCELLED->"Unavailable";case UNKNOWN_NO_EFFECT,UNKNOWN_APPLIED->"Indeterminate";case KNOWN_NOT_ADMITTED->"ReconciliationRequired";};String routed=(String)Class.forName("consumer.ExhaustiveProofResults").getMethod("classify",WebAuthnReauthenticationResult.class).invoke(null,result);check(routed.equals(expectedRoute),"actual-result-exhaustive-route");}
        if(mode!=Mode.SUCCESS&&mode!=Mode.MATCHING_EXPECTED_B_TO_A)check(!(result instanceof WebAuthnReauthenticationResult.Succeeded),"no-failure-proof");
        check(result.toString().equals("WebAuthnReauthenticationResult{<redacted>}"),"result-redaction");
        String selected=fault==JoinedFault.TIME_OUTAGE?"KNOWN_TIME_OUTAGE":fault==JoinedFault.CLOSE_FAILURE?"KNOWN_CLOSE_FAILURE":mode.name();
        return new ProducedCase(selected,result,store.reads-reads,store.callbacks-callbacks,store.mutations-mutations,closes.get()-closed);
    }
    /** A type-only source check; the real app also supplies session/context/target/one-use policy. */
    public static void consumeSelectedAction(WebAuthnReauthentication proof){check(proof.getActionPurpose().equals(PURPOSE),"selected-purpose");actions++;}
    private static String challenge(WebAuthnBrowserRequest prepared){return prepared.getPublicKeyOptions().find("challenge").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow();}
    private static void check(boolean condition,String name){assertions++;if(!condition)throw new AssertionError(name);}
    private enum Mode{SUCCESS,REJECTED_CONTEXT,UNAVAILABLE,UNKNOWN_NO_EFFECT,UNKNOWN_APPLIED,KNOWN_NOT_ADMITTED,CANCELLED,MUTATED_EXPECTED_A_TO_B,MATCHING_EXPECTED_B_TO_A}
    private static final class FaultStore implements WebAuthnStore {
        final WebAuthnStore backing=InMemoryWebAuthnStore.fromLimits(128,1_048_576L);int callbacks,mutations,reads;WebAuthnStoreCommitResult refusal;boolean unknownApplied,timeUnavailable;Runnable after;
        public WebAuthnStoreReadResult read(Set<WebAuthnStoreKey> keys,Duration remaining){this.reads++;var result=this.backing.read(keys,remaining);if(this.timeUnavailable&&result instanceof WebAuthnStoreReadResult.Available available){var snapshot=available.getSnapshot();return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(keys,snapshot.getEntries(),StoreTimeObservation.Unavailable.fromAdmission(snapshot.getTimeObservation().getAdmission())));}return result;}
        public WebAuthnStoreCommitReceipt compareAndCommit(WebAuthnStoreWrite write,Duration remaining){this.callbacks++;WebAuthnStoreCommitResult selected=this.refusal;this.refusal=null;if(selected!=null)return selected==WebAuthnStoreCommitResult.UNKNOWN?WebAuthnStoreCommitReceipt.unknownInstance():WebAuthnStoreCommitReceipt.fromRefusal(selected);var receipt=this.backing.compareAndCommit(write,remaining);if(receipt.getStatus()==WebAuthnStoreCommitResult.COMMITTED)this.mutations+=write.getMutations().size();if(this.after!=null){Runnable action=this.after;this.after=null;action.run();}if(this.unknownApplied){this.unknownApplied=false;return WebAuthnStoreCommitReceipt.unknownInstance();}return receipt;}
    }
}
