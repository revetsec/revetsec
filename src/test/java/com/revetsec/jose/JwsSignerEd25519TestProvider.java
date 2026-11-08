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


package com.revetsec.jose;

import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.util.*;
import static java.util.Objects.requireNonNull;

/** Own child JVM only: opaque Ed25519 operations, malformed output, time/error/array ownership. */
public final class JwsSignerEd25519TestProvider extends Provider {
 private static final long serialVersionUID=1L;
 private static @Nullable Provider original;
 private static @NonNull String mode="opaque";
 private static int lookups,instances,signCalls,verifyCalls,encodedCalls,signEngines,verifyEngines;
 private static byte @Nullable [] lastSigned,lastVerified;
 private static final @NonNull String SENTINEL="TEST-ONLY-ed-provider-secret";
 public JwsSignerEd25519TestProvider(){super("RevetsecEd25519SignerProbe","1","Owned Ed25519 signer fixture");putService(new Service(this,"Signature","Ed25519",Engine.class.getName(),List.of(),null));}
 @Override public @Nullable Service getService(@NonNull String type,@NonNull String name){lookups++;return super.getService(type,name);}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  mode=args[0];original=requireNonNull(Security.getProvider("SunEC"));var key=JwsSignerEd25519ExpansionTests.key();PrivateKey real=mode.equals("opaque-wrong-curve")?KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPrivate():key.getPrivateKey();PublicKey publicKey=key.getPublicKey();Provider installed=new JwsSignerEd25519TestProvider();Security.insertProviderAt(installed,1);
  try{
   lookups=instances=signCalls=verifyCalls=encodedCalls=signEngines=verifyEngines=0;int threads=Thread.getAllStackTraces().size();JwsSigner signer=JwsSignerEd25519ExpansionTests.construct(new OpaqueKey(real),publicKey);check(lookups==0&&instances==0&&signCalls==0&&verifyCalls==0&&encodedCalls==0,"Ed25519 construction invoked a provider or encoded a key");check(signer.getAlgorithm()==JwsAlgorithm.ED25519,"Wrong emitted algorithm");
   if(mode.equals("vm-error")||mode.equals("verify-vm-error")){try{signer.warmUp(Duration.ofSeconds(5));throw new AssertionError("VM error swallowed");}catch(ProbeVmError expected){check(SENTINEL.equals(expected.getMessage()),"Wrong VM error");}}
   else if(mode.equals("opaque")){byte[] claims=" {\"marker\":1e+0} ".getBytes(StandardCharsets.UTF_8);String compact=signer.toCompactSerialization("JWT","ed",null,claims,Duration.ofSeconds(5));check(independentVerify(compact,publicKey),"Original provider oracle refused output");check(zeros(lastSigned)&&zeros(lastVerified),"Successful signing retained owned signature");signer.warmUp(Duration.ofSeconds(5));check(signCalls==2&&verifyCalls==2&&signEngines==2&&verifyEngines==2&&instances>=4,"Ed25519 engine reused");check(zeros(lastSigned)&&zeros(lastVerified),"Warmup retained owned signature");}
   else{if(mode.equals("interrupt"))Thread.currentThread().interrupt();JwsSigningException.Reason expected=mode.startsWith("late-")?JwsSigningException.Reason.BUDGET_EXHAUSTED:mode.equals("mismatch")?JwsSigningException.Reason.KEY_PAIR_MISMATCH:JwsSigningException.Reason.SIGNING_UNAVAILABLE;try{var unused = signer.toCompactSerialization("JWT",SENTINEL,null,"{}".getBytes(StandardCharsets.UTF_8),mode.startsWith("late-")?Duration.ofMillis(80):Duration.ofSeconds(5));throw new AssertionError("Ed25519 credential released after failure");}catch(JwsSigningException failure){check(failure.getReason()==expected,"Wrong Ed25519 failure reason: "+failure.getReason());check(failure.getCause()==null&&failure.getSuppressed().length==0&&!failure.toString().contains(SENTINEL),"Provider details retained");}if(mode.equals("late-init")||mode.equals("late-update"))check(signCalls==0,"Signing began after deadline");if(Set.of("zero-length","short","trailing","oversized","r-at-p","r-nondecoding","r-zero-x-sign","s-at-l").contains(mode))check(verifyCalls==0,"Malformed Ed25519 signature reached provider verification");if(mode.equals("interrupt"))check(Thread.currentThread().isInterrupted(),"Interruption erased");}
   check(zeros(lastSigned)&&zeros(lastVerified),"Owned signature retained on terminal path");check(encodedCalls==0,"Opaque private encoded");check(Thread.getAllStackTraces().size()<=threads,"Signer created a thread");
  }finally{Thread.interrupted();Security.removeProvider(installed.getName());}
  System.out.println("scenario="+mode+" passed");
 }
 private static boolean independentVerify(@NonNull String compact,@NonNull PublicKey key)throws GeneralSecurityException{String[] parts=compact.split("\\.",-1);Signature verifier=Signature.getInstance("Ed25519",requireNonNull(original));verifier.initVerify(key);verifier.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));return verifier.verify(Base64.getUrlDecoder().decode(parts[2]));}
 private static boolean zeros(byte @Nullable [] values){if(values==null)return true;for(byte value:values)if(value!=0)return false;return true;}
 private static void check(boolean condition,@NonNull String message){if(!condition)throw new AssertionError(message);}
 private static void delay(){try{Thread.sleep(180);}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IllegalStateException(SENTINEL);}}
 private static void little(@NonNull BigInteger value,byte @NonNull [] out,int offset){byte[] bytes=value.toByteArray();Arrays.fill(out,offset,offset+32,(byte)0);for(int index=0;index<Math.min(32,bytes.length);index++)out[offset+index]=bytes[bytes.length-1-index];Arrays.fill(bytes,(byte)0);}
 private static final class OpaqueKey implements PrivateKey {private static final long serialVersionUID=1L;private final @NonNull PrivateKey delegate;private OpaqueKey(@NonNull PrivateKey delegate){this.delegate=delegate;}@Override public @NonNull String getAlgorithm(){return "EdDSA";}@Override public @Nullable String getFormat(){encodedCalls++;throw new AssertionError("Opaque private format inspected");}@Override public byte @Nullable [] getEncoded(){encodedCalls++;throw new AssertionError("Opaque private encoded");}}
 private static final class ProbeVmError extends VirtualMachineError {private static final long serialVersionUID=1L;private ProbeVmError(){super(SENTINEL);}}
 public static final class Engine extends SignatureSpi {
  private @Nullable Signature delegate;private boolean initialized;
  public Engine(){instances++;}
  @Override protected void engineInitSign(@NonNull PrivateKey privateKey)throws InvalidKeyException{check(!this.initialized,"Signing engine reused");this.initialized=true;signEngines++;if(!(privateKey instanceof OpaqueKey opaque))throw new InvalidKeyException(SENTINEL);if(mode.equals("late-init"))delay();try{this.delegate=Signature.getInstance("Ed25519",requireNonNull(original));this.delegate.initSign(opaque.delegate);}catch(GeneralSecurityException failure){throw new InvalidKeyException(SENTINEL);}}
  @Override protected void engineInitVerify(@NonNull PublicKey publicKey)throws InvalidKeyException{check(!this.initialized,"Verification engine reused");this.initialized=true;verifyEngines++;try{this.delegate=Signature.getInstance("Ed25519",requireNonNull(original));this.delegate.initVerify(publicKey);}catch(GeneralSecurityException failure){throw new InvalidKeyException(SENTINEL);}}
  @Override protected void engineUpdate(byte value)throws SignatureException{requireNonNull(this.delegate).update(value);}
  @Override protected void engineUpdate(byte @NonNull [] input,int offset,int length)throws SignatureException{if(signEngines>verifyEngines&&mode.equals("late-update"))delay();requireNonNull(this.delegate).update(input,offset,length);}
  @Override protected byte @NonNull [] engineSign()throws SignatureException{
   signCalls++;if(mode.equals("vm-error"))throw new ProbeVmError();if(mode.equals("throwing")||mode.equals("interrupt"))throw new IllegalStateException(SENTINEL);if(mode.equals("late-sign"))delay();byte[] result=requireNonNull(this.delegate).sign();
   if(mode.equals("zero-length")||mode.equals("short")||mode.equals("trailing")||mode.equals("oversized")){int size=switch(mode){case "zero-length"->0;case "short"->63;case "trailing"->65;default->4096;};byte[] replaced=Arrays.copyOf(result,size);Arrays.fill(result,(byte)0);result=replaced;}
   else if(mode.equals("r-at-p"))little(TestJwk.ED25519_FIELD_PRIME,result,0);
   else if(mode.equals("r-nondecoding"))little(BigInteger.TWO,result,0);
   else if(mode.equals("r-zero-x-sign")){little(BigInteger.ONE,result,0);result[31]|=(byte)0x80;}
   else if(mode.equals("s-at-l"))little(TestJwk.ED25519_GROUP_ORDER,result,32);
   lastSigned=result;return result;
  }
  @Override protected boolean engineVerify(byte @NonNull [] signature)throws SignatureException{verifyCalls++;lastVerified=signature;if(mode.equals("late-verify"))delay();if(mode.equals("verify-vm-error"))throw new ProbeVmError();if(mode.equals("throwing-verifier"))throw new IllegalStateException(SENTINEL);return !mode.equals("mismatch")&&requireNonNull(this.delegate).verify(signature);}
  @Override protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters){throw new UnsupportedOperationException("Ed25519 does not set parameters here");}
  @Override @SuppressWarnings("deprecation") protected void engineSetParameter(@NonNull String name,@NonNull Object value){throw new UnsupportedOperationException();}
  @Override @SuppressWarnings("deprecation") protected @Nullable Object engineGetParameter(@NonNull String name){throw new UnsupportedOperationException();}
 }
}
