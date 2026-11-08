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

package example;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Public recipe execution and bounded file admission, with disposable test-only generated keys. */
final class KeyImportExampleTests {
 @TestFactory @NonNull Stream<@NonNull DynamicTest> ordinaryFamiliesLoadAndCheck(@NonNull @TempDir Path directory){
  return List.of("RSA","P-256","P-384","Ed25519").stream().map(family->DynamicTest.dynamicTest(family,()->{
   var generator=KeyPairGenerator.getInstance(family.startsWith("P-")?"EC":family);
   if(family.equals("RSA"))generator.initialize(2048);
   else if(family.startsWith("P-"))generator.initialize(new ECGenParameterSpec(family.equals("P-256")?"secp256r1":"secp384r1"));
   var pair=generator.generateKeyPair();var privateFile=directory.resolve(family+".pk8");var publicFile=directory.resolve(family+".spki");
   var privateBytes=pair.getPrivate().getEncoded();
   try{Files.write(privateFile,privateBytes);Files.write(publicFile,pair.getPublic().getEncoded());KeyImportExample.main(new String[]{privateFile.toString(),publicFile.toString()});}
   finally{java.util.Arrays.fill(privateBytes,(byte)0);Files.deleteIfExists(privateFile);Files.deleteIfExists(publicFile);}
  }));
 }
 @Test void oversizedInputIsRefusedBeforeItIsParsed(@NonNull @TempDir Path directory)throws IOException{
  var privateFile=directory.resolve("oversize.pk8");Files.write(privateFile,new byte[65_537]);
  var failure=assertThrows(IOException.class,()->KeyImportExample.main(new String[]{privateFile.toString(),directory.resolve("absent.spki").toString()}));
  assertEquals("Key import file exceeds its size limit.",failure.getMessage());
 }
 @Test void missingArgumentsAreAConfigurationError(){assertThrows(IllegalArgumentException.class,()->KeyImportExample.main(new String[0]));}
}
