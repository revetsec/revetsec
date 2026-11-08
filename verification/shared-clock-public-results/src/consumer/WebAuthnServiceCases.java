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
import com.revetsec.webauthn.*;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import static consumer.PublicServiceChecks.*;

/** Genuine Ed25519 traffic through public WebAuthn APIs; fixture drift is explicitly bounded. */
final class WebAuthnServiceCases {
 private WebAuthnServiceCases() { }
 private static final @NonNull String RP="login.example.com",ORIGIN="https://"+RP,NS="public-consumer";
 private static final byte @NonNull [] HANDLE={4,5,6},CREDENTIAL_ID={1,2,3};
 private static final @NonNull OperationBinding BINDING=OperationBinding.fromTrustedPersistence(encode(filled(65)));
 private static long maxDrift;
 enum Family { REG_BEGIN,AUTH_BEGIN,REGISTER,AUTHENTICATE,REMOVE,DISABLE }
 static long maximumDriftMillis(){return maxDrift;}
 static void run()throws Exception{
  for(Family family:Family.values())for(Mode mode:Mode.values())exercise(family,mode);
  context("REJECTED");
  for(Family family:new Family[]{Family.REG_BEGIN,Family.AUTH_BEGIN,Family.REGISTER,Family.AUTHENTICATE}){
   F f=new F();Object result;
   switch(family){
    case REG_BEGIN->{f.rp.disableAccountResult(HANDLE);result=f.rp.beginRegistrationResult(options(),BINDING);}
    case AUTH_BEGIN->{f.rp.disableAccountResult(HANDLE);result=f.rp.beginReauthenticationResult(HANDLE,"action",BINDING);}
    case REGISTER->{var request=f.registration();result=f.rp.completeRegistrationResult(request.getCeremonyId(),json("{}"),BINDING);}
    case AUTHENTICATE->{f.enroll();var request=expect(WebAuthnAuthenticationRequestResult.Prepared.class,f.rp.beginAuthenticationResult(BINDING)).getRequest();result=f.rp.completeAuthenticationResult(request.getCeremonyId(),json("{}"),BINDING);}
    default->throw new AssertionError("Unexpected rejection family");
   }f.drift();record(name(family),"Rejected",result);
  }
  context("NONMUTATING_VARIANT");
  F f=new F();f.enroll();Object result=f.rp.removeCredentialResult(HANDLE,new byte[]{99});f.drift();record("WebAuthnCredentialRemovalResult","Absent",result);
 }
 private static void exercise(@NonNull Family family,@NonNull Mode mode)throws Exception{
  context(mode.name());
  F f=new F();Supplier<Object> operation=operation(f,family);int initialReads=family==Family.REGISTER||family==Family.AUTHENTICATE?2:1;f.store.reset(mode);f.gate.closes=0;f.gate.fail=mode==Mode.KNOWN_CLOSE_FAILURE;f.drift();Object result=operation.get();f.drift();record(name(family),expected(mode,success(family)),result);
  require(f.store.commits==(mode==Mode.UNAVAILABLE?0:1),"WebAuthn mutation callback count changed for "+family+"/"+mode);require(f.store.reads==(mode==Mode.UNAVAILABLE?1:mode==Mode.UNKNOWN_APPLIED||mode==Mode.UNKNOWN_ABSENT?initialReads:initialReads+1),"WebAuthn read/retry/rescue count changed for "+family+"/"+mode);require(f.gate.closes==1,"WebAuthn permit must close exactly once");require(f.store.applied==(mode==Mode.UNAVAILABLE||mode==Mode.UNKNOWN_ABSENT?0:1),"WebAuthn actual-effect count changed");if(mode==Mode.UNKNOWN_ABSENT)require(f.store.beforeTarget.equals(f.source.records()),"Unknown/no-effect WebAuthn target changed data");
  counts(name(family),mode,f.store.reads,f.store.commits,f.store.applied,f.gate.closes);
 }
 private static @NonNull Supplier<@NonNull Object> operation(@NonNull F f,@NonNull Family family)throws Exception{
  return switch(family){
   case REG_BEGIN->()->f.rp.beginRegistrationResult(options(),BINDING);case AUTH_BEGIN->()->f.rp.beginAuthenticationResult(BINDING);
   case REGISTER->{var request=f.registration();byte[] response=registrationJson(f.pair,challenge(request));yield ()->f.rp.completeRegistrationResult(request.getCeremonyId(),response,BINDING);}
   case AUTHENTICATE->{f.enroll();var request=expect(WebAuthnAuthenticationRequestResult.Prepared.class,f.rp.beginAuthenticationResult(BINDING)).getRequest();byte[] response=assertionJson(f.pair.getPrivate(),challenge(request),1);yield ()->f.rp.completeAuthenticationResult(request.getCeremonyId(),response,BINDING);}
   case REMOVE->{f.enroll();yield ()->f.rp.removeCredentialResult(HANDLE,CREDENTIAL_ID);}
   case DISABLE->()->f.rp.disableAccountResult(HANDLE);
  };
 }
 private static @NonNull String name(@NonNull Family family){return switch(family){case REG_BEGIN->"WebAuthnRegistrationRequestResult";case AUTH_BEGIN->"WebAuthnAuthenticationRequestResult";case REGISTER->"WebAuthnRegistrationResult";case AUTHENTICATE->"WebAuthnAuthenticationResult";case REMOVE->"WebAuthnCredentialRemovalResult";case DISABLE->"WebAuthnAccountDisableResult";};}
 private static @NonNull String success(@NonNull Family family){return switch(family){case REG_BEGIN,AUTH_BEGIN->"Prepared";case REGISTER,AUTHENTICATE->"Succeeded";case REMOVE->"Removed";case DISABLE->"Disabled";};}
 private static @NonNull WebAuthnRegistrationOptions options(){return WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName("alice").userDisplayName("Alice Fixture").build();}
 private static @NonNull String challenge(@NonNull WebAuthnBrowserRequest request){return request.getPublicKeyOptions().find("challenge").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow();}
 private static final class Gate implements WebAuthnRecoveryGate {
  int closes;boolean fail;
  @Override public @NonNull Permit acquire(@NonNull Duration budget){return new Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){closes++;if(fail)throw new IllegalStateException("TEST-ONLY permit close");}};}
 }
 private static final class F {
  final @NonNull Instant base=Instant.now();final @NonNull PublicWebAuthnStore source=new PublicWebAuthnStore(this.base);final @NonNull Store store=new Store(this.source);final @NonNull Gate gate=new Gate();final @NonNull KeyPair pair;final @NonNull WebAuthnRelyingParty rp;
  F()throws Exception{this.pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(filled(1)))).clock(Clock.fixed(this.base,ZoneOffset.UTC)).build();this.rp=WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Public fixture").allowedOrigins(Set.of(ORIGIN)).credentialNamespace(NS).store(this.store).stateSealer(sealer).recoveryGate(this.gate).build();drift();}
  @NonNull WebAuthnBrowserRequest registration(){return expect(WebAuthnRegistrationRequestResult.Prepared.class,this.rp.beginRegistrationResult(options(),BINDING)).getRequest();}
  void enroll(){var request=registration();expect(WebAuthnRegistrationResult.Succeeded.class,this.rp.completeRegistrationResult(request.getCeremonyId(),registrationJson(this.pair,challenge(request)),BINDING));}
  void drift(){Duration drift=Duration.between(this.base,Instant.now()).abs();maxDrift=Math.max(maxDrift,drift.toMillis());require(drift.compareTo(Duration.ofSeconds(3))<=0,"FIXTURE_CLOCK_DRIFT: fixed authority/default public worker exceeded declared three-second fixture drift; no product-policy change is permitted");}
 }
 private static final class Store implements WebAuthnStore {
  final @NonNull PublicWebAuthnStore source;@NonNull Mode mode=Mode.ELIGIBLE;int reads,commits,applied;@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> beforeTarget=Map.of();
  Store(@NonNull PublicWebAuthnStore source){this.source=source;}
  void reset(@NonNull Mode selected){this.mode=selected;this.reads=this.commits=this.applied=0;}
  @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){this.reads++;return this.mode==Mode.UNAVAILABLE?WebAuthnStoreReadResult.Unavailable.get():this.source.read(keys,budget);}
  @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){
   this.commits++;this.beforeTarget=this.source.records();if(this.mode==Mode.UNKNOWN_ABSENT)return WebAuthnStoreCommitReceipt.unknownInstance();var receipt=this.source.compareAndCommit(write,budget);require(receipt.getStatus()==WebAuthnStoreCommitResult.COMMITTED,"Fixture store refused genuine WebAuthn transaction");require(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty(),"Fixture completion stamp changed");this.applied++;
   for(var mutation:write.getMutations()){var actual=this.source.records().get(mutation.getKey());if(mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.DELETE)require(actual==null,"Committed ceremony deletion not retained");else require(actual!=null&&Arrays.equals(actual.getSealedBytes(),mutation.getSealedBytes().orElseThrow()),"Committed WebAuthn bytes not retained");}
   if(this.mode==Mode.KNOWN_TIME_OUTAGE)this.source.setHealthy(false);return this.mode==Mode.UNKNOWN_APPLIED?WebAuthnStoreCommitReceipt.unknownInstance():receipt;
  }
 }
    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair,
            @NonNull String challenge) {
        byte[] auth = registrationAuth(pair);
        String id = encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + encode(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + encode(auth)
                + "\",\"attestationObject\":\"" + encode(attestation(auth))
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
        String id = encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + encode(clientJson("webauthn.get", challenge))
                + "\",\"authenticatorData\":\"" + encode(auth)
                + "\",\"signature\":\"" + encode(signer.sign())
                + "\",\"userHandle\":\"" + encode(HANDLE)
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
    private static byte @NonNull [] filled(int first) {
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte) (first + i);
        return result;
    }

    private static @NonNull String encode(byte @NonNull [] value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value);}
}
