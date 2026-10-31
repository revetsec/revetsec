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

package com.revetsec.webauthn;

import com.revetsec.json.JsonObject;
import example.pending.PostgresqlWebAuthnStore;
import org.jspecify.annotations.NonNull;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Set;
import static example.migration.CodecSupport.*;

/** Seeds through the genuine old adapter, including its JDBC expiry projection. */
public final class AdapterLegacySeed {
 private AdapterLegacySeed() { }
 public static void main(@NonNull String @NonNull [] args) {
  try {
   if(args.length!=1)throw new IllegalArgumentException();
   if(!Path.of(WebAuthnStore.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().equals(Path.of(System.getenv("OLD_CORE_JAR")).toRealPath()))throw new AssertionError();
   JsonObject config=(JsonObject)com.revetsec.internal.json.JsonCodec.parse(Files.readAllBytes(Path.of(args[0])),com.revetsec.internal.json.JsonLimits.protocolDocument(4194304));
   var store=new PostgresqlWebAuthnStore("migration",remaining->DriverManager.getConnection(System.getenv("DB_URL"),System.getenv("DB_USER"),System.getenv("DB_PASSWORD")),1000000);
   for(JsonObject row:rows(config,"rows")){
    if(!text(row,"family").equals("WEBAUTHN"))continue;
    WebAuthnStoreKey key=keys().stream().filter(k->k.getStorageKey().equals(text(row,"key"))).findFirst().orElseThrow();
    var read=store.read(Set.of(key),Duration.ofSeconds(10));
    if(!(read instanceof WebAuthnStoreReadResult.Available available))throw new AssertionError();
    byte[] sealed=bytes(text(row,"ciphertext"));
    var mutation=key.getKind().name().equals("CEREMONY")?WebAuthnStoreWrite.Mutation.insertExpiring(key,sealed,instant((JsonObject)row.find("retention").orElseThrow())):WebAuthnStoreWrite.Mutation.insert(key,sealed);
    if(store.compareAndCommit(WebAuthnStoreWrite.fromSnapshotAndMutations(available.getSnapshot(),java.util.List.of(mutation)),Duration.ofSeconds(10))!=WebAuthnStoreCommitResult.COMMITTED)throw new AssertionError();
   }
   System.out.println("PASS genuine-old-adapter-jdbc-seed");
  }catch(Throwable failure){System.err.println("LEGACY_SEED_FAILED "+failure.getClass().getSimpleName());System.exit(1);}
 }
 private static @NonNull Set<@NonNull WebAuthnStoreKey> keys(){
  byte[] ceremony=new byte[32];for(int i=0;i<32;i++)ceremony[i]=(byte)(i+1);
  return Set.of(WebAuthnStoreKey.forNamespaceClock("migration","login.example.com"),
   WebAuthnStoreKey.forCredential("migration","login.example.com",new byte[]{1,2,3}),
   WebAuthnStoreKey.forCredential("migration","login.example.com",new byte[]{7,8,9}),
   WebAuthnStoreKey.forAccountCredentialIndex("migration","login.example.com",new byte[]{4,5,6}),
   WebAuthnStoreKey.forAccountCredentialIndex("migration","login.example.com",new byte[]{10,11,12}),
   WebAuthnStoreKey.forAccountFence("migration","login.example.com",new byte[]{4,5,6}),
   WebAuthnStoreKey.forAccountFence("migration","login.example.com",new byte[]{10,11,12}),
   WebAuthnStoreKey.forCeremony("migration","login.example.com",ceremony));
 }
}
