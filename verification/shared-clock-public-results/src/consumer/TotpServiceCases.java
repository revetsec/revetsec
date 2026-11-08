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
import com.revetsec.totp.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import static consumer.PublicServiceChecks.*;

/** Public TOTP operations supply all fifty legal leaf identities; mutation effects remain opaque. */
final class TotpServiceCases {
 private TotpServiceCases() { }
 private static final @NonNull Instant BASE=Instant.parse("2026-10-09T12:00:00Z");
 private static final @NonNull String NS="public-consumer",EPOCH="one",ACCOUNT="account";
 private static final @NonNull OperationBinding BROWSER=OperationBinding.fromTrustedPersistence("browser");
 private static final @NonNull OperationBinding LOGIN=OperationBinding.fromTrustedPersistence("login");
 private static final @NonNull OperationBinding RECOVERY=OperationBinding.fromTrustedPersistence("recovery");
 enum Family { BEGIN,CONFIRM,VERIFY,RECOVERY,ROTATE,REMOVE,CANCEL,INITIALIZE,RESEAL }
 static void run()throws Exception{
  for(Family family:Family.values())for(Mode mode:Mode.values())exercise(family,mode);
  context("REJECTED");
  for(Family family:List.of(Family.BEGIN,Family.CONFIRM,Family.VERIFY,Family.RECOVERY,Family.ROTATE,Family.REMOVE,Family.CANCEL)){
   F f=new F(true);Object result;
   switch(family){
    case BEGIN->{f.pending();result=f.auth.beginEnrollmentResult(options(),BROWSER);}
    case CONFIRM->{var pending=f.pending();result=f.auth.confirmEnrollmentResult(ACCOUNT,pending.getEnrollmentId(),"invalid",BROWSER);}
    case CANCEL->{f.pending();result=f.auth.cancelEnrollmentResult(ACCOUNT,"A".repeat(43),BROWSER);}
    case VERIFY->{f.enroll();result=f.auth.verifyResult(ACCOUNT,"invalid",LOGIN);}
    case RECOVERY->{f.enroll();result=f.auth.consumeRecoveryCodeResult(ACCOUNT,"invalid",LOGIN);}
    case ROTATE->{f.enroll();result=f.auth.rotateRecoveryCodesResult(ACCOUNT,f.recovery().getFactorId(),"A".repeat(43));}
    case REMOVE->{f.enroll();result=f.auth.removeFactorResult(ACCOUNT,"A".repeat(43));}
    default->throw new AssertionError("Unexpected rejection family");
   }record(name(family),"Rejected",result);
  }
  context("THROTTLED");
  for(Family family:List.of(Family.BEGIN,Family.CONFIRM,Family.VERIFY,Family.RECOVERY)){
   F f=new F(true);Object result=null;
   if(family==Family.BEGIN||family==Family.CONFIRM){var pending=f.pending();for(int n=0;n<6;n++)result=f.auth.confirmEnrollmentResult(ACCOUNT,pending.getEnrollmentId(),"invalid",BROWSER);if(family==Family.BEGIN)result=f.auth.beginEnrollmentResult(options(),BROWSER);}
   else{f.enroll();for(int n=0;n<6;n++)result=family==Family.VERIFY?f.auth.verifyResult(ACCOUNT,"invalid",LOGIN):f.auth.consumeRecoveryCodeResult(ACCOUNT,"invalid",LOGIN);}
   record(name(family),"Throttled",Objects.requireNonNull(result));
  }
  context("NONMUTATING_VARIANT");
  F initialized=new F(true);record("TotpNamespaceInitializationResult","AlreadyInitialized",initialized.auth.initializeNamespaceResult());F reseal=new F(true);record("TotpStoreResealResult","AlreadyCurrent",reseal.auth.resealStoreEntryResult(TotpStoreKey.forNamespace(NS,EPOCH)));record("TotpStoreResealResult","Absent",reseal.auth.resealStoreEntryResult(TotpStoreKey.forAccount(NS,EPOCH,"missing")));
 }
 private static void exercise(@NonNull Family family,@NonNull Mode mode)throws Exception{
  context(mode.name());
  F f=new F(family!=Family.INITIALIZE);Supplier<Object> operation=operation(f,family);int target=Set.of(Family.CONFIRM,Family.VERIFY,Family.RECOVERY).contains(family)?2:1;f.store.reset(mode,target);f.gate.closes=0;f.gate.fail=mode==Mode.KNOWN_CLOSE_FAILURE;Object result=operation.get();record(name(family),expected(mode,success(family)),result);
  require(f.store.commits==(mode==Mode.UNAVAILABLE?0:target),"TOTP callback count changed for "+family+"/"+mode);require(f.store.reads==(mode==Mode.UNAVAILABLE?1:mode==Mode.UNKNOWN_APPLIED||mode==Mode.UNKNOWN_ABSENT?target:target+1),"TOTP read/retry/rescue count changed for "+family+"/"+mode);require(f.gate.closes==1,"TOTP permit must close exactly once");require(f.store.applied==(mode==Mode.UNAVAILABLE?0:mode==Mode.UNKNOWN_ABSENT?target-1:target),"TOTP actual-effect count changed");
  if(mode==Mode.UNKNOWN_ABSENT)require(f.store.beforeTarget.equals(f.source.records()),"Unknown/no-effect target changed data");
  counts(name(family),mode,f.store.reads,f.store.commits,f.store.applied,f.gate.closes);
 }
 private static @NonNull Supplier<@NonNull Object> operation(@NonNull F f,@NonNull Family family)throws Exception{
  return switch(family){
   case INITIALIZE->f.auth::initializeNamespaceResult;case BEGIN->()->f.auth.beginEnrollmentResult(options(),BROWSER);
   case CONFIRM->{var pending=f.pending();String code=f.code();yield ()->f.auth.confirmEnrollmentResult(ACCOUNT,pending.getEnrollmentId(),code,BROWSER);}
   case CANCEL->{var pending=f.pending();yield ()->f.auth.cancelEnrollmentResult(ACCOUNT,pending.getEnrollmentId(),BROWSER);}
   case VERIFY->{f.enroll();f.source.advance(Duration.ofSeconds(60));f.worker.time=f.worker.time.plusSeconds(60);String code=f.code();yield ()->f.auth.verifyResult(ACCOUNT,code,LOGIN);}
   case RECOVERY->{f.enroll();String code=f.recovery().getCodes().get(0);yield ()->f.auth.consumeRecoveryCodeResult(ACCOUNT,code,RECOVERY);}
   case ROTATE->{f.enroll();yield ()->f.auth.rotateRecoveryCodesResult(ACCOUNT,f.recovery().getFactorId(),f.recovery().getBatchId());}
   case REMOVE->{f.enroll();yield ()->f.auth.removeFactorResult(ACCOUNT,f.recovery().getFactorId());}
   case RESEAL->{f.auth=f.build(rotated());yield ()->f.auth.resealStoreEntryResult(TotpStoreKey.forNamespace(NS,EPOCH));}
  };
 }
 private static @NonNull String name(@NonNull Family f){return switch(f){case BEGIN->"TotpEnrollmentRequestResult";case CONFIRM->"TotpEnrollmentResult";case VERIFY->"TotpVerificationResult";case RECOVERY->"RecoveryCodeUseResult";case ROTATE->"RecoveryCodeRotationResult";case REMOVE->"TotpFactorRemovalResult";case CANCEL->"TotpEnrollmentCancellationResult";case INITIALIZE->"TotpNamespaceInitializationResult";case RESEAL->"TotpStoreResealResult";};}
 private static @NonNull String success(@NonNull Family f){return switch(f){case BEGIN->"Prepared";case INITIALIZE->"Initialized";case RESEAL->"Resealed";default->"Succeeded";};}
 private static @NonNull TotpEnrollmentOptions options(){return TotpEnrollmentOptions.withAccountId(ACCOUNT).accountName("Fixture").build();}
 private static @NonNull SealingKey key(){return SealingKey.fromBase64("old","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");}
 private static @NonNull StateSealer sealer(){return StateSealer.withActiveKey(key()).maximumSealedLength(16384).build();}
 private static @NonNull StateSealer rotated(){return StateSealer.withActiveKey(SealingKey.fromBase64("new","ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=")).verificationKeys(List.of(key())).maximumSealedLength(16384).build();}
 private static final class Worker extends Clock {
  @NonNull Instant time=BASE;@Override public @NonNull Instant instant(){return this.time;}@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(this.time,zone);}
 }
 private static final class Gate implements TotpRecoveryGate {
  int closes;boolean fail;
  @Override public @NonNull Permit acquire(@NonNull TotpRecoveryContext context,@NonNull Duration budget){return new Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){closes++;if(fail)throw new IllegalStateException("TEST-ONLY permit close");}};}
 }
 private static final class Store implements TotpStore {
  final @NonNull PublicTotpStore source;@NonNull Mode mode=Mode.ELIGIBLE;int target=1,commits,reads,applied;@NonNull Map<@NonNull TotpStoreKey,@NonNull TotpStoreRecord> beforeTarget=Map.of();
  Store(@NonNull PublicTotpStore source){this.source=source;}
  void reset(@NonNull Mode selected,int target){this.mode=selected;this.target=target;this.commits=this.reads=this.applied=0;}
  @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){this.reads++;return this.mode==Mode.UNAVAILABLE?TotpStoreReadResult.Unavailable.get():this.source.read(keys,budget);}
  @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){
   this.commits++;boolean selected=this.commits==this.target;if(selected)this.beforeTarget=this.source.records();if(selected&&this.mode==Mode.UNKNOWN_ABSENT)return TotpStoreCommitReceipt.unknownInstance();var receipt=this.source.compareAndCommit(write,budget);require(receipt.getStatus()==TotpStoreCommitResult.COMMITTED,"Fixture store refused genuine TOTP transaction");require(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty(),"Fixture completion stamp changed");this.applied++;
   for(var mutation:write.getMutations()){var actual=Objects.requireNonNull(this.source.records().get(mutation.getKey()));require(actual.getVersion().equals(mutation.getRecord().getVersion())&&Arrays.equals(actual.getSealedBytes(),mutation.getRecord().getSealedBytes()),"Committed TOTP bytes not retained");}
   if(selected&&this.mode==Mode.KNOWN_TIME_OUTAGE)this.source.setHealthy(false);return selected&&this.mode==Mode.UNKNOWN_APPLIED?TotpStoreCommitReceipt.unknownInstance():receipt;
  }
 }
 private static final class F {
  final @NonNull PublicTotpStore source=new PublicTotpStore(NS,EPOCH,BASE);final @NonNull Store store=new Store(this.source);final @NonNull Worker worker=new Worker();final @NonNull Gate gate=new Gate();@NonNull TotpAuthenticator auth=build(sealer());@Nullable String secret;@Nullable RecoveryCodes recovery;
  F(boolean initialized){if(initialized)expect(TotpNamespaceInitializationResult.Initialized.class,this.auth.initializeNamespaceResult());this.store.reset(Mode.ELIGIBLE,1);}
  @NonNull TotpAuthenticator build(@NonNull StateSealer sealer){return TotpAuthenticator.withIssuer("Public service fixture").credentialNamespace(NS).recoveryEpoch(EPOCH).store(this.store).stateSealer(sealer).recoveryGate(this.gate).clock(this.worker).build();}
  @NonNull RecoveryCodes recovery(){return Objects.requireNonNull(this.recovery);}
  @NonNull TotpEnrollment pending(){var enrollment=expect(TotpEnrollmentRequestResult.Prepared.class,this.auth.beginEnrollmentResult(options(),BROWSER)).getEnrollment();this.secret=enrollment.getManualEntryKey();return enrollment;}
  void enroll()throws Exception{var enrollment=pending();this.recovery=expect(TotpEnrollmentResult.Succeeded.class,this.auth.confirmEnrollmentResult(ACCOUNT,enrollment.getEnrollmentId(),code(),BROWSER)).getRecoveryCodes();}
  @NonNull String code()throws Exception{
   byte[] bytes=base32(Objects.requireNonNull(this.secret));try{Mac mac=Mac.getInstance("HmacSHA1");mac.init(new SecretKeySpec(bytes,"HmacSHA1"));byte[] hash=mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(this.source.authorityTime().getEpochSecond()/30).array());try{int p=hash[hash.length-1]&15;int n=((hash[p]&127)<<24)|((hash[p+1]&255)<<16)|((hash[p+2]&255)<<8)|(hash[p+3]&255);return String.format(Locale.ROOT,"%06d",n%1000000);}finally{Arrays.fill(hash,(byte)0);}}finally{Arrays.fill(bytes,(byte)0);}
  }
 }
 private static byte @NonNull [] base32(@NonNull String value){var out=new java.io.ByteArrayOutputStream();int bits=0,word=0;for(char character:value.toCharArray()){int index="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character);require(index>=0,"Invalid fixture Base32");word=(word<<5)|index;bits+=5;if(bits>=8){bits-=8;out.write((word>>>bits)&255);}}return out.toByteArray();}
}
