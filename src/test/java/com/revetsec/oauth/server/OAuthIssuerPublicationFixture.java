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

import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Test-only single-writer file publication control plane. Never stores private key material. */
final class OAuthIssuerPublicationFixture implements OAuthIssuerKeyProvider {
 private final @NonNull Path directory;
 OAuthIssuerPublicationFixture(@NonNull Path directory){this.directory=directory;}
 static TestJwk.@NonNull Fixture key(@NonNull String id){return switch(id){case "a"->TestJwk.Fixture.IDP_SIGNING_RSA_2048;case "b"->TestJwk.Fixture.IDP_SIGNING_RSA_3072;default->throw new IllegalArgumentException("Unknown fixture key.");};}
 private static @NonNull String fingerprint(@NonNull String id){try{return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key(id).getPublicKey().getEncoded()));}catch(java.security.NoSuchAlgorithmException failure){throw new AssertionError(failure);}}
 @NonNull Properties state() throws IOException {Properties p=new Properties();try(var in=Files.newBufferedReader(this.directory.resolve("current.properties"))){p.load(in);}return p;}
 private static @NonNull String value(@NonNull Properties p,@NonNull String name){return requireNonNull(p.getProperty(name));}
 private static @NonNull Set<@NonNull String> keys(@NonNull Properties p){return Set.of(value(p,"keys").split(",",-1));}
 static @NonNull Map<@NonNull String,@NonNull PublicKey> publicKeys(@NonNull Set<@NonNull String> ids){Map<String,PublicKey> keys=new LinkedHashMap<>();for(String id:ids)keys.put(id,key(id).getPublicKey());return keys;}
 /** Publication is a forced immutable local JWKS artifact followed by an atomic manifest replacement. */
 void publish(@NonNull String active,@NonNull Set<@NonNull String> ids,@NonNull Instant now,@NonNull Map<@NonNull String,@NonNull Instant> floors) throws IOException {
  Files.createDirectories(this.directory);Properties old=Files.exists(this.directory.resolve("current.properties"))?state():new Properties();
  if(!ids.contains(active) || !floors.keySet().equals(ids))throw new IllegalArgumentException("Incomplete lifecycle declaration.");
  if(!old.isEmpty()){
   if(!now.isAfter(Instant.parse(value(old,"publishedAt"))))throw new IllegalArgumentException("Publication must advance.");
   for(String id:keys(old)){
    Instant retained=Instant.parse(value(old,"retained."+id));
    if(!ids.contains(id) && now.isBefore(retained))throw new IllegalArgumentException("Required verification key omitted.");
    if(ids.contains(id) && requireNonNull(floors.get(id)).isBefore(retained))throw new IllegalArgumentException("Retention shortened.");
   }
  }
  Properties next=new Properties();next.putAll(old);
  for(String id:ids){
   String known=old.getProperty("material."+id);
   if(known!=null && !known.equals(fingerprint(id)))throw new IllegalArgumentException("Key identifier reused.");
   if(!requireNonNull(floors.get(id)).isAfter(now))throw new IllegalArgumentException("Retention already ended.");
   next.setProperty("material."+id,fingerprint(id));next.putIfAbsent("firstPublished."+id,now.toString());next.setProperty("retained."+id,requireNonNull(floors.get(id)).toString());
  }
  int revision=Integer.parseInt(old.getProperty("revision","0"))+1;String generation="g"+revision;
  String jwks=OAuthIssuerPublicKeys.jwks(publicKeys(ids)).toJson();String artifact=generation+".jwks.json";force(this.directory.resolve(artifact),jwks);
  next.setProperty("revision",Integer.toString(revision));next.setProperty("active",active);next.setProperty("keys",String.join(",",ids.stream().sorted().toList()));next.setProperty("publishedAt",now.toString());next.setProperty("artifact",artifact);next.setProperty("artifactSha256",digest(jwks));
  // A fixed known format permits exact round-trip checks; no private key bytes enter the file.
  StringWriter writer=new StringWriter();next.store(writer,"test-only public lifecycle facts");force(this.directory.resolve("current.next"),writer.toString());
  Files.move(this.directory.resolve("current.next"),this.directory.resolve("current.properties"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
 }
 private static void force(@NonNull Path path,@NonNull String text) throws IOException {try(FileChannel f=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){ByteBuffer b=java.nio.charset.StandardCharsets.UTF_8.encode(text);while(b.hasRemaining())f.write(b);f.force(true);}}
 private static @NonNull String digest(@NonNull String text){try{return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(java.security.NoSuchAlgorithmException e){throw new AssertionError(e);}}
 @Override public @NonNull OAuthIssuerKeySnapshot getSnapshot(@NonNull Duration budget){
  try{
   if(budget.isZero()||budget.isNegative())throw new IllegalStateException("No fixture budget.");Properties p=state();Set<String> ids=keys(p);String jwks=Files.readString(this.directory.resolve(value(p,"artifact")));
   if(!digest(jwks).equals(value(p,"artifactSha256")))throw new IllegalStateException("Publication artifact mismatch.");
   Map<String,Instant> floors=new LinkedHashMap<>();for(String id:ids){if(!fingerprint(id).equals(value(p,"material."+id)))throw new IllegalStateException("Material changed.");floors.put(id,Instant.parse(value(p,"retained."+id)));}
   String active=value(p,"active");var k=key(active);
   return OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair(active,k.getPrivateKey(),k.getPublicKey())).generation("g"+value(p,"revision")).publishedAt(Instant.parse(value(p,"publishedAt"))).verificationKeys(publicKeys(ids)).retirementNotBefore(floors).build();
  }catch(IOException failure){throw new IllegalStateException("Publication unavailable.");}
 }
 /** Deliberately dishonest/incomplete declaration, used only to demonstrate the initial-snapshot boundary. */
 void unsupportedOmission(@NonNull Instant at,@NonNull Instant bFloor) throws IOException {
  Properties old=state();Properties p=new Properties();p.putAll(old);p.setProperty("keys","b");p.setProperty("active","b");p.setProperty("revision",Integer.toString(Integer.parseInt(value(old,"revision"))+1));p.setProperty("publishedAt",at.toString());p.setProperty("retained.b",bFloor.toString());
  String jwks=OAuthIssuerPublicKeys.jwks(publicKeys(Set.of("b"))).toJson();String artifact="unsupported.jwks.json";force(this.directory.resolve(artifact),jwks);p.setProperty("artifact",artifact);p.setProperty("artifactSha256",digest(jwks));StringWriter writer=new StringWriter();p.store(writer,"deliberate invalid provider history");Files.writeString(this.directory.resolve("current.properties"),writer.toString());
 }
}
