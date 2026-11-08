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

package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.security.*;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Isolated test JVM: actual named-provider RSA signing, then one controlled caller-health change. */
@ThreadSafe
public final class OAuthIssuerClockHealthTestProvider {
 private static final @NonNull AtomicInteger SIGNS=new AtomicInteger();
 private static final @NonNull AtomicReference<@Nullable Runnable> HOOK=new AtomicReference<>();
 private OAuthIssuerClockHealthTestProvider(){}
 static void arm(@NonNull Runnable hook){SIGNS.set(0);HOOK.set(hook);}
 static int signOperations(){return SIGNS.get();}
 static boolean hasUnconsumedHook(){return HOOK.get()!=null;}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  if(args.length!=1)throw new IllegalArgumentException("Fixed signing-health case required");Provider provider=new StepProvider();if(Security.insertProviderAt(provider,1)!=1)throw new AssertionError("Isolated provider selection failed");
  try{if(args[0].startsWith("ENG04/"))OAuthIssuerSharedClockTests.runSemanticSigningCase(args[0]);else OAuthIssuerSharedClockTests.runSigningHealthCase(args[0]);}finally{HOOK.set(null);Security.removeProvider(provider.getName());}
  System.out.println("scenario="+args[0]+" passed");
 }
 @ThreadSafe private static final class StepProvider extends Provider {
  private static final long serialVersionUID=1L;
  StepProvider(){super("RevetsecIssuerClockHealth","1.0","TEST-ONLY named RSA signing and health control");putService(new Service(this,"Signature","SHA256withRSA",Engine.class.getName(),List.of(),Map.of()){@Override public @NonNull Object newInstance(@Nullable Object ignored)throws NoSuchAlgorithmException{return new Engine();}});}
 }
 @NotThreadSafe public static final class Engine extends SignatureSpi {
  private final @NonNull Signature delegate;
  public Engine()throws NoSuchAlgorithmException{try{this.delegate=Signature.getInstance("SHA256withRSA","SunRsaSign");}catch(NoSuchProviderException error){throw new NoSuchAlgorithmException(error);}}
  @Override protected void engineInitVerify(@NonNull PublicKey key)throws InvalidKeyException{this.delegate.initVerify(key);}
  @Override protected void engineInitSign(@NonNull PrivateKey key)throws InvalidKeyException{this.delegate.initSign(key);}
  @Override protected void engineUpdate(byte value)throws SignatureException{this.delegate.update(value);}
  @Override protected void engineUpdate(byte @NonNull [] value,int offset,int length)throws SignatureException{this.delegate.update(value,offset,length);}
  @Override protected byte @NonNull [] engineSign()throws SignatureException{
   byte[] value=this.delegate.sign();SIGNS.incrementAndGet();boolean released=false;try{Runnable hook=HOOK.getAndSet(null);if(hook!=null)hook.run();released=true;return value;}finally{if(!released)Arrays.fill(value,(byte)0);}
  }
  @Override protected boolean engineVerify(byte @NonNull [] value)throws SignatureException{return this.delegate.verify(value);}
  @Deprecated @Override protected void engineSetParameter(@NonNull String name,@Nullable Object value){throw new UnsupportedOperationException();}
  @Deprecated @Override protected @Nullable Object engineGetParameter(@NonNull String name){throw new UnsupportedOperationException();}
 }
}
