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
import org.junit.jupiter.api.function.Executable;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/** Deterministic application-provider interruption seam; installation is serialized and always reversed. */
public final class InterruptingSignatureProvider extends Provider {
 private static final long serialVersionUID=1L;
 private static final @NonNull String NAME="RevetsecInterruptingSignature";
 private static final @NonNull Object LOCK=new Object();
 private InterruptingSignatureProvider() {
  super(NAME,"1.0","Revetsec test provider that interrupts RS256 signing.");
  put("Signature.SHA256withRSA",InterruptingSignatureSpi.class.getName());
 }
 static void around(@NonNull Executable operation) {
  synchronized(LOCK) {
   if(Security.getProvider(NAME)!=null)throw new AssertionError("interrupting provider already installed");
   if(Security.insertProviderAt(new InterruptingSignatureProvider(),1)!=1)throw new AssertionError("interrupting provider was not first");
   try {operation.execute();}
   catch(RuntimeException|Error failure){throw failure;}
   catch(Throwable failure){InterruptingSignatureProvider.<RuntimeException>raise(failure);}
   finally {Security.removeProvider(NAME);}
  }
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T {throw (T)failure;}

 /** Provider SPI deliberately uses Java's permitted sneaky checked-exception boundary. */
 public static final class InterruptingSignatureSpi extends SignatureSpi {
  public InterruptingSignatureSpi() { }
  @Override protected void engineInitVerify(@NonNull PublicKey publicKey) throws InvalidKeyException { }
  @Override protected void engineInitSign(@NonNull PrivateKey privateKey) throws InvalidKeyException { }
  @Override protected void engineUpdate(byte input) throws SignatureException { }
  @Override protected void engineUpdate(byte @NonNull [] input,int offset,int length) throws SignatureException { }
  @Override protected byte @NonNull [] engineSign() throws SignatureException {
   return InterruptingSignatureProvider.<RuntimeException,byte[]>raiseResult(new InterruptedException("fixture"));
  }
  @Override protected boolean engineVerify(byte @NonNull [] signature) throws SignatureException {
   return InterruptingSignatureProvider.<RuntimeException,Boolean>raiseResult(new InterruptedException("fixture"));
  }
  @Override protected void engineSetParameter(@NonNull String parameter,@Nullable Object value) { }
  @Override protected @Nullable Object engineGetParameter(@NonNull String parameter) {return null;}
  @Override protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters) { }
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable,R> @NonNull R raiseResult(@NonNull Throwable failure) throws T {throw (T)failure;}
}
