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

package verification.issuerfactory;
import org.jspecify.annotations.NonNull;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
public final class IssuerFactoryApi {
 public static void main(@NonNull String @NonNull []args)throws Exception{
  String origin=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(OAuthIssuerSigningKey.class.getProtectionDomain().getCodeSource().getLocation().toURI()))));if(args.length!=1||!origin.equals(args[0]))throw new AssertionError("wrong core origin");
  var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();var holder=OAuthIssuerSigningKey.fromRsaKeyPair("synthetic",pair.getPrivate(),pair.getPublic());if(!holder.getKeyId().equals("synthetic")||!(holder.getPublicKey() instanceof RSAPublicKey))throw new AssertionError();
  for(var m:OAuthIssuerSigningKey.class.getDeclaredMethods())if(m.getName().equals("fromKeyPair"))throw new AssertionError("old public alias");
  var ec=KeyPairGenerator.getInstance("EC").generateKeyPair();try{OAuthIssuerSigningKey.fromRsaKeyPair("unsupported",ec.getPrivate(),ec.getPublic());throw new AssertionError("issuer profile widened");}catch(IllegalArgumentException expected){}
  System.out.println("PASS explicit RSA issuer factory, unchanged RS256 profile, no old alias; exactcore="+origin);
 }
}
