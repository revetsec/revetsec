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

package verification.temporary;
import com.revetsec.KeyImports;
import com.revetsec.KeyImportException;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
public final class TemporaryConditionApi {
 public static void main(@NonNull String @NonNull [] args) throws Exception {
  String origin=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(RevetsecException.class.getProtectionDomain().getCodeSource().getLocation().toURI()))));
  if(args.length!=1||!origin.equals(args[0]))throw new AssertionError("wrong core origin");
  try{KeyImports.certificateFromDer(new byte[]{0x30,0});throw new AssertionError("invalid certificate accepted");}
  catch(KeyImportException failure){if(!Boolean.FALSE.equals(((RevetsecException)failure).isTemporaryCondition()))throw new AssertionError("fixed parse classification changed");}
  if(RevetsecException.class.getMethod("isTemporaryCondition").getReturnType()!=Boolean.class)throw new AssertionError("descriptor changed");
  try{RevetsecException.class.getMethod("isTransient");throw new AssertionError("old alias retained");}catch(NoSuchMethodException expected){}
  System.out.println("PASS actual public temporary-condition member, fixed classification, descriptor and absent alias");
 }
}
