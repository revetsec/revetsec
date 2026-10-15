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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import javax.crypto.Mac;
import javax.crypto.MacSpi;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.util.*;

/** Deterministic provider aliases make intermediate HKDF cleanup externally observable. */
@ResourceLock("java.security.Security")
final class HkdfRc1MutationTests {
 private static final String PROVIDER="Rc1HkdfProvider";
 private static final ThreadLocal<@Nullable State> STATE=new ThreadLocal<>();
 @Test void invalidDeriveLengthNeverComputesAKey() throws Exception {
  withProvider(state->{Assertions.assertThrows(IllegalArgumentException.class,()->Hkdf.derive(null,new byte[32],new byte[0],0));Assertions.assertEquals(0,state.finals);});
 }
 @Test void exactBlockBoundaryTerminatesWithoutAnExtraIteration() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->Assertions.assertEquals(32,Hkdf.expand(new byte[32],new byte[0],32).length));
 }
 @Test void everyIntermediateExpansionBlockIsErased() throws Exception {
  withProvider(state->{byte[] result=Hkdf.expand(new byte[32],new byte[]{1},65);Assertions.assertEquals(65,result.length);Assertions.assertEquals(3,state.outputs.size());for(byte[] output:state.outputs)Assertions.assertArrayEquals(new byte[32],output);});
 }
 @Test void deriveErasesTheExtractedPseudorandomKey() throws Exception {
  withProvider(state->{Assertions.assertEquals(33,Hkdf.derive(null,new byte[]{7},new byte[0],33).length);Assertions.assertEquals(3,state.outputs.size());for(byte[] output:state.outputs)Assertions.assertArrayEquals(new byte[32],output);});
 }
 @Test void failureOnLaterExpansionErasesPreviousBlock() throws Exception {
  withProvider(state->{state.failAt=2;Assertions.assertThrows(ProviderException.class,()->Hkdf.expand(new byte[32],new byte[0],65));Assertions.assertEquals(1,state.outputs.size());Assertions.assertArrayEquals(new byte[32],state.outputs.get(0));});
 }
 @Test void hmacProviderFailureReturnsTheFailureResult()throws Exception {
  withProvider(state->{state.failAt=1;Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE,Hmac.verifyTag(HashAlgorithm.SHA_256,new byte[32],new byte[]{7},new byte[32]));});
 }
 @Test void computedHmacVerificationTagIsErased()throws Exception {
  Mac baseline=Mac.getInstance("HmacSHA256","SunJCE");baseline.init(new javax.crypto.spec.SecretKeySpec(new byte[32],"HmacSHA256"));byte[] tag=baseline.doFinal(new byte[]{7});
  withProvider(state->{Assertions.assertEquals(VerifyResult.VALID,Hmac.verifyTag(HashAlgorithm.SHA_256,new byte[32],new byte[]{7},tag));Assertions.assertEquals(1,state.outputs.size());Assertions.assertArrayEquals(new byte[32],state.outputs.get(0));});
 }
 private static void withProvider(@NonNull Checked body)throws Exception {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->{State state=new State();STATE.set(state);Security.insertProviderAt(new ProbeProvider(),1);
  try {body.run(state);}finally {Security.removeProvider(PROVIDER);STATE.remove();}});
 }
 private interface Checked {void run(@NonNull State state)throws Exception;}
 private static final class State {private int finals;private int failAt=Integer.MAX_VALUE;private final @NonNull List<byte @NonNull []> outputs=new ArrayList<>();}
 public static final class ProbeProvider extends Provider {
  public ProbeProvider(){super(PROVIDER,"1","RC1 local fixture provider");put("Mac.HmacSHA256",ProbeMac.class.getName());}
 }
 public static final class ProbeMac extends MacSpi {
  private final @NonNull Mac delegate;
  public ProbeMac(){try {delegate=Mac.getInstance("HmacSHA256","SunJCE");}catch(GeneralSecurityException failure){throw new ProviderException(failure);}}
  @Override protected int engineGetMacLength(){return delegate.getMacLength();}
  @Override protected void engineInit(@NonNull Key key,@Nullable AlgorithmParameterSpec parameters)throws InvalidKeyException,InvalidAlgorithmParameterException{delegate.init(key,parameters);}
  @Override protected void engineUpdate(byte value){delegate.update(value);}
  @Override protected void engineUpdate(byte @NonNull [] value,int offset,int length){delegate.update(value,offset,length);}
  @Override protected byte @NonNull [] engineDoFinal(){State state=STATE.get();if(state!=null&&++state.finals==state.failAt)throw new ProviderException("controlled later-block failure");byte[] output=delegate.doFinal();if(state!=null){Assertions.assertFalse(Arrays.equals(new byte[32],output),"positive control requires nonzero provider output");state.outputs.add(output);}return output;}
  @Override protected void engineReset(){delegate.reset();}
 }
}
