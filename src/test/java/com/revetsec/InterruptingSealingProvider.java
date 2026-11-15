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

package com.revetsec;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.function.Executable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/** Serialized test provider: authenticates existing rows, then raises the selected failure only on a new seal. */
@SuppressWarnings({"StaticAssignmentOfThrowable", "TypeParameterUnusedInFormals"}) // Test provider preserves exact throwable identity and the SPI generic signature.
public final class InterruptingSealingProvider extends Provider {
 private static final long serialVersionUID=1L;
 private static final @NonNull String NAME="RevetsecInterruptingSealing";
 private static final @NonNull Object LOCK=new Object();
 private static @Nullable Throwable signal;
 private InterruptingSealingProvider() {
  super(NAME,"1.0","Revetsec test provider that raises a selected failure during AES-GCM encryption.");
  put("Cipher.AES/GCM/NoPadding",InterruptingGcm.class.getName());
 }
 public static void around(@NonNull Executable operation) {
  around(new InterruptedException("fixture"),operation);
 }
 public static void around(@NonNull Throwable selected,@NonNull Executable operation) {
  synchronized(LOCK) {
   if(Security.getProvider(NAME)!=null)throw new AssertionError("interrupting provider already installed");
   signal=selected;
   try {
    if(Security.insertProviderAt(new InterruptingSealingProvider(),1)!=1)throw new AssertionError("interrupting provider was not first");
    operation.execute();
   }
   catch(RuntimeException|Error failure){throw failure;}
   catch(Throwable failure){InterruptingSealingProvider.<RuntimeException>raise(failure);}
   finally {Security.removeProvider(NAME);signal=null;}
  }
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T {throw (T)failure;}
 private static @NonNull Throwable selectedSignal(){Throwable selected=signal;if(selected==null)throw new AssertionError("no provider signal");return selected;}
 @SuppressWarnings("unchecked") private static <T extends Throwable,R> @NonNull R raiseResult(@NonNull Throwable failure) throws T {throw (T)failure;}

 /** The normal JDK provider handles reads; the issuer's attempted write raises the selected failure. */
 public static final class InterruptingGcm extends StateSealerTests.DelegatingGcm {
  private boolean encrypt;
  public InterruptingGcm() throws GeneralSecurityException { }
  @Override protected void engineInit(int mode,@NonNull Key key,@NonNull SecureRandom random) throws InvalidKeyException {
   super.engineInit(mode,key,random);this.encrypt=mode==Cipher.ENCRYPT_MODE;
  }
  @Override protected void engineInit(int mode,@NonNull Key key,@NonNull AlgorithmParameterSpec parameters,
    @NonNull SecureRandom random) throws InvalidKeyException,InvalidAlgorithmParameterException {
   super.engineInit(mode,key,parameters,random);this.encrypt=mode==Cipher.ENCRYPT_MODE;
  }
  @Override protected void engineInit(int mode,@NonNull Key key,@NonNull AlgorithmParameters parameters,
    @NonNull SecureRandom random) throws InvalidKeyException,InvalidAlgorithmParameterException {
   super.engineInit(mode,key,parameters,random);this.encrypt=mode==Cipher.ENCRYPT_MODE;
  }
  @Override protected byte @NonNull [] engineDoFinal(byte @NonNull [] input,int offset,int length)
    throws IllegalBlockSizeException,BadPaddingException {
   return this.encrypt ? InterruptingSealingProvider.<RuntimeException,byte[]>raiseResult(selectedSignal()) : super.engineDoFinal(input,offset,length);
  }
  @Override protected int engineDoFinal(byte @NonNull [] input,int offset,int length,byte @NonNull [] output,int outputOffset)
    throws ShortBufferException,IllegalBlockSizeException,BadPaddingException {
   return this.encrypt ? InterruptingSealingProvider.<RuntimeException,Integer>raiseResult(selectedSignal())
    : super.engineDoFinal(input,offset,length,output,outputOffset);
  }
 }
}
