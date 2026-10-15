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

import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import javax.crypto.*;
import java.lang.reflect.Method;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/** Provider qualification and pre-lookup admission probes retained from RC-1 review. */
@ResourceLock("java.security.Security")
final class SealerRc1MutationTests {
 private static final @NonNull ThreadLocal<@NonNull String> MODE = ThreadLocal.withInitial(() -> "delegate");
 private static byte @Nullable [] observed;

 @Test void theSmallestPositiveMaximumIsAValidSetting() {
  Assertions.assertThrows(UnsealException.class, () -> SealerV1.open("", 1, Map.of(), SealedStateType.APP, "c", Instant.EPOCH));
 }

 @Test void malformedHeaderLengthAndKeyCharactersRejectBeforeKeyLookup() {
  for (boolean malformedCharacter : new boolean[]{false, true}) {
   byte[] wire = new byte[malformedCharacter ? 55 : 117];
   wire[0] = 1; wire[1] = (byte) (malformedCharacter ? 1 : 64);
   Arrays.fill(wire, 2, 2 + (wire[1] & 255), (byte) 'a');
   if (malformedCharacter) wire[2] = '!';
   LookupMap keys = new LookupMap();
   Assertions.assertThrows(UnsealException.class,
     () -> SealerV1.open(Base64Url.encode(wire), 4096, keys, SealedStateType.APP, "c", Instant.EPOCH));
   Assertions.assertEquals(0, keys.lookups);
  }
 }

 @Test void rejectionPredicateDistinguishesValidAndExpiredOutcomes() throws Exception {
  SealerV1.Key key = SealerV1.Key.fromMasterKey("k", new byte[32]);
  Method predicate = SealerV1.class.getDeclaredMethod("isRejected", String.class, Map.class, String.class);
  predicate.setAccessible(true);
  for (long notAfter : new long[]{Long.MAX_VALUE, 0}) {
   String sealed = SealerV1.seal(key, SealedStateType.APP, "c", notAfter, new byte[]{'x'}, new byte[16], new byte[12]);
   Assertions.assertEquals(Boolean.FALSE, predicate.invoke(null, sealed, Map.of("k", key), "c"));
  }
 }

 @Test void selfTestRefusesAProviderThatDropsAuthenticatedData() throws Exception {
  ProbeProvider provider = new ProbeProvider();
  Security.insertProviderAt(provider, 1);
  MODE.set("drop-aad");
  try {
   Assertions.assertEquals(provider.getName(), Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
   Assertions.assertFalse(SealerV1.passesSelfTest(SealerV1.Key.fromMasterKey("k", new byte[32]), new byte[16], new byte[12]));
  } finally { MODE.remove(); Security.removeProvider(provider.getName()); }
 }

 @Test void decryptedBodyIsErasedAfterSuccessAndExpiry() throws Exception {
  SealerV1.Key key = SealerV1.Key.fromMasterKey("k", new byte[32]);
  for (long notAfter : new long[]{Long.MAX_VALUE, 0}) {
   String sealed = SealerV1.seal(key, SealedStateType.APP, "c", notAfter, new byte[]{'s', 'e', 'c', 'r', 'e', 't'}, new byte[16], new byte[12]);
   ProbeProvider provider = new ProbeProvider();
   Security.insertProviderAt(provider, 1);
   observed = null; MODE.set("retain");
   try {
    if (notAfter == 0) Assertions.assertThrows(UnsealException.class,
      () -> SealerV1.open(sealed, 4096, Map.of("k", key), SealedStateType.APP, "c", Instant.EPOCH));
    else Assertions.assertEquals("secret", SealerV1.open(sealed, 4096, Map.of("k", key), SealedStateType.APP, "c", Instant.EPOCH));
    byte[] plaintext = java.util.Objects.requireNonNull(observed);
    Assertions.assertEquals(14, plaintext.length);
    Assertions.assertArrayEquals(new byte[plaintext.length], plaintext);
   } finally { observed = null; MODE.remove(); Security.removeProvider(provider.getName()); }
  }
 }

 private static final class LookupMap extends AbstractMap<@NonNull String, SealerV1.@NonNull Key> {
  int lookups;
  @Override public SealerV1.@Nullable Key get(@Nullable Object key) { ++this.lookups; return null; }
  @Override public @NonNull Set<Map.@NonNull Entry<@NonNull String, SealerV1.@NonNull Key>> entrySet() { return Set.of(); }
 }
 public static final class ProbeProvider extends Provider {
  private static final long serialVersionUID = 1L;
  public ProbeProvider() {
   super("RevetsecRc1SealerProbe", "1", "Local RC-1 cipher qualification probe");
   putService(new Service(this, "Cipher", "AES/GCM/NoPadding", ProbeCipher.class.getName(), null, null));
  }
 }
 public static final class ProbeCipher extends CipherSpi {
  private final @NonNull Cipher delegate;
  private int operation;
  public ProbeCipher() throws GeneralSecurityException { this.delegate = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE"); }
  @Override protected void engineSetMode(@NonNull String mode) { }
  @Override protected void engineSetPadding(@NonNull String padding) { }
  @Override protected int engineGetBlockSize() { return this.delegate.getBlockSize(); }
  @Override protected int engineGetOutputSize(int length) { return this.delegate.getOutputSize(length); }
  @Override protected byte @Nullable [] engineGetIV() { return this.delegate.getIV(); }
  @Override protected @Nullable AlgorithmParameters engineGetParameters() { return this.delegate.getParameters(); }
  @Override protected void engineInit(int operation, @NonNull Key key, @Nullable SecureRandom random) throws InvalidKeyException {
   this.operation = operation; this.delegate.init(operation, key, random);
  }
  @Override protected void engineInit(int operation, @NonNull Key key, @Nullable AlgorithmParameterSpec parameters, @Nullable SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
   this.operation = operation; this.delegate.init(operation, key, parameters, random);
  }
  @Override protected void engineInit(int operation, @NonNull Key key, @Nullable AlgorithmParameters parameters, @Nullable SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
   this.operation = operation; this.delegate.init(operation, key, parameters, random);
  }
  @Override protected byte @Nullable [] engineUpdate(byte @NonNull [] input, int offset, int length) { return this.delegate.update(input, offset, length); }
  @Override protected int engineUpdate(byte @NonNull [] input, int offset, int length, byte @NonNull [] output, int outputOffset) throws ShortBufferException {
   return this.delegate.update(input, offset, length, output, outputOffset);
  }
  @Override protected byte @NonNull [] engineDoFinal(byte @NonNull [] input, int offset, int length) throws IllegalBlockSizeException, BadPaddingException {
   byte[] output = this.delegate.doFinal(input, offset, length);
   if (MODE.get().equals("retain") && this.operation == Cipher.DECRYPT_MODE) observed = output;
   return output;
  }
  @Override protected int engineDoFinal(byte @NonNull [] input, int offset, int length, byte @NonNull [] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
   return this.delegate.doFinal(input, offset, length, output, outputOffset);
  }
  @Override protected void engineUpdateAAD(byte @NonNull [] input, int offset, int length) {
   if (!MODE.get().equals("drop-aad")) this.delegate.updateAAD(input, offset, length);
  }
 }
}
