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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcdsaSignatures;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.SignatureVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.util.*;
import static java.util.Objects.requireNonNull;

/** Installed only in its owned child JVM; captures provider-owned array references to test cleanup. */
public final class JwsSignerEcTestProvider extends Provider {
 private static final long serialVersionUID=1L;
 private static @Nullable Provider original;
 private static @NonNull JwsAlgorithm algorithm=JwsAlgorithm.ES256;
 private static @NonNull String mode="opaque";
 private static int lookups,instances,signCalls,verifyCalls,encodedCalls,signEngines,verifyEngines;
 private static byte @Nullable [] lastSigned,lastVerified;
 private static final @NonNull String SENTINEL="TEST-ONLY-ec-provider-secret";
 public JwsSignerEcTestProvider(){
  super("RevetsecEcSignerProbe","1","Owned EC signer fixture");
  for(String name:List.of("SHA256withECDSA","SHA384withECDSA"))putService(new Service(this,"Signature",name,Engine.class.getName(),List.of(),null){@Override public @NonNull Object newInstance(@Nullable Object parameter){check(parameter==null,"Unexpected JCA constructor argument");return new Engine(getAlgorithm());}});
 }
 @Override public @Nullable Service getService(@NonNull String type,@NonNull String name){lookups++;return super.getService(type,name);}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  algorithm=JwsAlgorithm.valueOf(args[0]);mode=args[1];original=requireNonNull(Security.getProvider("SunEC"));var key=JwsSignerEcExpansionTests.key(algorithm);PrivateKey real=key.getPrivateKey();PublicKey publicKey=key.getPublicKey();Provider installed=new JwsSignerEcTestProvider();Security.insertProviderAt(installed,1);
  try{
   lookups=instances=signCalls=verifyCalls=encodedCalls=signEngines=verifyEngines=0;int threads=Thread.getAllStackTraces().size();JwsSigner signer=JwsSignerEcExpansionTests.construct(new OpaqueKey(real),publicKey,algorithm);check(lookups==0&&instances==0&&signCalls==0&&verifyCalls==0&&encodedCalls==0,"EC construction invoked a provider or encoded a key");
   if(mode.equals("vm-error")||mode.equals("verify-vm-error")){
    try{signer.warmUp(Duration.ofSeconds(5));throw new AssertionError("VM error swallowed");}catch(ProbeVmError expected){check(SENTINEL.equals(expected.getMessage()),"Wrong VM error");}
   }else if(mode.equals("opaque")){
    byte[] claims=" {\"marker\":1e+0} ".getBytes(StandardCharsets.UTF_8);String compact=signer.toCompactSerialization("JWT","ec",null,claims,Duration.ofSeconds(5));check(JwsSignerEcExpansionTests.verify(algorithm,compact,publicKey),"Independent P1363 oracle refused output");check(zeros(lastSigned)&&zeros(lastVerified),"Successful signing retained owned DER");signer.warmUp(Duration.ofSeconds(5));check(signCalls==2&&verifyCalls==2&&signEngines==2&&verifyEngines==2&&instances>=4,"EC engine reused");check(zeros(lastSigned)&&zeros(lastVerified),"Warmup retained owned DER");
    String[] pieces=compact.split("\\.",-1);byte[] caller=Base64.getUrlDecoder().decode(pieces[2]),before=caller.clone();EcCurve curve=JwsSignerEcExpansionTests.curve(algorithm);HashAlgorithm hash=algorithm==JwsAlgorithm.ES256?HashAlgorithm.SHA_256:HashAlgorithm.SHA_384;check(SignatureVerifier.verifyEcdsa(curve,hash,publicKey,(pieces[0]+"."+pieces[1]).getBytes(StandardCharsets.US_ASCII),caller)==VerifyResult.VALID,"Caller signature refused");check(Arrays.equals(before,caller),"Verifier changed caller JOSE input");check(zeros(lastVerified),"Verifier DER copy retained");
   }else{
    if(mode.equals("interrupt"))Thread.currentThread().interrupt();
    JwsSigningException.Reason expected=mode.startsWith("late-")?JwsSigningException.Reason.BUDGET_EXHAUSTED:mode.equals("mismatch")?JwsSigningException.Reason.KEY_PAIR_MISMATCH:JwsSigningException.Reason.SIGNING_UNAVAILABLE;
    try{var unused = signer.toCompactSerialization("JWT",SENTINEL,null,"{}".getBytes(StandardCharsets.UTF_8),mode.startsWith("late-")?Duration.ofMillis(80):Duration.ofSeconds(5));throw new AssertionError("EC credential released after failure");}catch(JwsSigningException failure){check(failure.getReason()==expected,"Wrong fixed EC failure reason: "+failure.getReason());check(failure.getCause()==null&&failure.getSuppressed().length==0&&!failure.toString().contains(SENTINEL),"Provider details retained");}
    if(mode.equals("late-init")||mode.equals("late-update"))check(signCalls==0,"Signing began after deadline");
    if(Set.of("zero","range","nonminimal","trailing","oversized").contains(mode))check(verifyCalls==0,"Malformed DER reached a verification provider");
    if(mode.equals("interrupt"))check(Thread.currentThread().isInterrupted(),"Interruption erased");
   }
   check(zeros(lastSigned)&&zeros(lastVerified),"Owned signature buffer not wiped on terminal path");check(encodedCalls==0,"Opaque key encoded");check(Thread.getAllStackTraces().size()<=threads,"Signer created a thread");
  }finally{Thread.interrupted();Security.removeProvider(installed.getName());}
  System.out.println("scenario="+mode+" passed");
 }
 private static boolean zeros(byte @Nullable [] values){if(values==null)return true;for(byte value:values)if(value!=0)return false;return true;}
 private static void check(boolean condition,@NonNull String message){if(!condition)throw new AssertionError(message);}
 private static void delay(){try{Thread.sleep(180);}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IllegalStateException(SENTINEL);}}
 private static final class OpaqueKey implements PrivateKey {private static final long serialVersionUID=1L;private final @NonNull PrivateKey delegate;private OpaqueKey(@NonNull PrivateKey delegate){this.delegate=delegate;}@Override public @NonNull String getAlgorithm(){return "EC";}@Override public @Nullable String getFormat(){encodedCalls++;throw new AssertionError("Opaque private format inspected");}@Override public byte @Nullable [] getEncoded(){encodedCalls++;throw new AssertionError("Opaque private encoded");}}
 private static final class ProbeVmError extends VirtualMachineError {private static final long serialVersionUID=1L;private ProbeVmError(){super(SENTINEL);}}
 public static final class Engine extends SignatureSpi {
  private final @NonNull String name;private @Nullable Signature delegate;private boolean initialized;
  private Engine(@NonNull String name){this.name=name;instances++;}
  @Override protected void engineInitSign(@NonNull PrivateKey privateKey)throws InvalidKeyException{check(!this.initialized,"Signing engine reused");this.initialized=true;signEngines++;if(!(privateKey instanceof OpaqueKey opaque))throw new InvalidKeyException(SENTINEL);if(mode.equals("late-init"))delay();try{this.delegate=Signature.getInstance(this.name,requireNonNull(original));this.delegate.initSign(opaque.delegate);}catch(GeneralSecurityException failure){throw new InvalidKeyException(SENTINEL);}}
  @Override protected void engineInitVerify(@NonNull PublicKey publicKey)throws InvalidKeyException{check(!this.initialized,"Verification engine reused");this.initialized=true;verifyEngines++;try{this.delegate=Signature.getInstance(this.name,requireNonNull(original));this.delegate.initVerify(publicKey);}catch(GeneralSecurityException failure){throw new InvalidKeyException(SENTINEL);}}
  @Override protected void engineUpdate(byte value)throws SignatureException{requireNonNull(this.delegate).update(value);}
  @Override protected void engineUpdate(byte @NonNull [] input,int offset,int length)throws SignatureException{if(signEngines>verifyEngines&&mode.equals("late-update"))delay();requireNonNull(this.delegate).update(input,offset,length);}
  @Override protected byte @NonNull [] engineSign()throws SignatureException{
   signCalls++;if(mode.equals("vm-error"))throw new ProbeVmError();if(mode.equals("throwing")||mode.equals("interrupt"))throw new IllegalStateException(SENTINEL);if(mode.equals("late-sign"))delay();byte[] result;
   if(mode.equals("zero"))result=new byte[]{0x30,6,2,1,0,2,1,1};
   else if(mode.equals("range")){EcCurve curve=JwsSignerEcExpansionTests.curve(algorithm);byte[] wire=new byte[curve.getSignatureLength()];byte[] order=curve.getOrder().toByteArray();System.arraycopy(order,Math.max(0,order.length-curve.getCoordinateLength()),wire,Math.max(0,curve.getCoordinateLength()-order.length),Math.min(order.length,curve.getCoordinateLength()));wire[wire.length-1]=1;result=EcdsaSignatures.toDer(curve,wire);Arrays.fill(wire,(byte)0);}
   else if(mode.equals("nonminimal"))result=new byte[]{0x30,7,2,2,0,1,2,1,1};
   else if(mode.equals("oversized")){result=new byte[4096];Arrays.fill(result,(byte)7);}
   else{result=requireNonNull(this.delegate).sign();if(mode.equals("trailing")){byte[] extended=Arrays.copyOf(result,result.length+1);Arrays.fill(result,(byte)0);extended[extended.length-1]=5;result=extended;}}
   lastSigned=result;return result;
  }
  @Override protected boolean engineVerify(byte @NonNull [] signature)throws SignatureException{verifyCalls++;lastVerified=signature;if(mode.equals("late-verify"))delay();if(mode.equals("verify-vm-error"))throw new ProbeVmError();if(mode.equals("throwing-verifier"))throw new IllegalStateException(SENTINEL);return !mode.equals("mismatch")&&requireNonNull(this.delegate).verify(signature);}
  @Override protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters)throws InvalidAlgorithmParameterException{requireNonNull(this.delegate).setParameter(parameters);}
  @Override @SuppressWarnings("deprecation") protected void engineSetParameter(@NonNull String name,@NonNull Object value){throw new UnsupportedOperationException();}
  @Override @SuppressWarnings("deprecation") protected @Nullable Object engineGetParameter(@NonNull String name){throw new UnsupportedOperationException();}
 }
}
