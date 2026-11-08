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

package example.pending;

import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Genuine public-engine transaction and runtime capacity baseline; no new cleanup API is referenced. */
public final class IssuerRetentionBaselineProbe {
 static final @NonNull String NAMESPACE="fixture_issuer";
 private IssuerRetentionBaselineProbe() { }
 static void check(boolean value,@NonNull String label){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
 private static final class Capture implements OAuthAuthorizationServerStore {
  private final @NonNull OAuthAuthorizationServerStore reads;private @Nullable OAuthStoreTransaction last;
  private Capture(@NonNull OAuthAuthorizationServerStore reads){this.reads=reads;}
  @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return this.reads.read(key,budget);}
  @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){this.last=transaction;return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);}
 }
 /** Captures actual engine-generated work whose changed key shares an assigned bucket with retained finite rows. */
 static @NonNull OAuthStoreTransaction target(@NonNull PostgresqlIssuerStore store)throws Exception{
  Set<Integer> target=new HashSet<>();
  try(var connection=PendingStoreProbe.connection(Duration.ofSeconds(10));var statement=connection.prepareStatement("SELECT storage_key FROM issuer_store_entry WHERE namespace=? AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE')")){
   statement.setString(1,NAMESPACE);try(var rows=statement.executeQuery()){while(rows.next())target.add(IssuerPgCapacity.bucket(rows.getString(1)));}
  }
  check(!target.isEmpty(),"genuine-retained-finite-rows-supply-assigned-buckets");
  Capture capture=new Capture(store);var prepared=IssuerStoreProbe.server(capture);
  String query="client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example%2Fmcp&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=fixture";
  for(int i=0;i<2048;i++){
   try{prepared.beginAuthorizationResult("GET",query,new byte[0],Map.of(),com.revetsec.BrowserBinding.fromTrustedPersistence("A".repeat(43)));throw new AssertionError("Capturing store must conflict");}
   catch(OAuthServerStoreException expected){if(expected.getReason()!=OAuthServerException.Reason.STORE_UNAVAILABLE)throw expected;}
   OAuthStoreTransaction transaction=requireNonNull(capture.last);
   if(transaction.getMutations().size()==1 && target.contains(IssuerPgCapacity.bucket(transaction.getMutations().get(0).getKey().getStorageKey()))){check(true,"genuine-current-engine-timed-transaction-matches-retained-assigned-bucket");return transaction;}
  }
  throw new AssertionError("Bounded genuine target search exhausted");
 }
 private static void seed(@NonNull PostgresqlIssuerStore store)throws Exception{
  var server=IssuerStoreProbe.server(store);check(server.initializeFreshIssuer().getStatus()==OAuthStoreCommitStatus.COMMITTED,"genuine-initial-root");server.establishNewSubject("subject");
  String query="client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example%2Fmcp&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=fixture";
  var binding=com.revetsec.BrowserBinding.fromTrustedPersistence("A".repeat(43));
  var interaction=((OAuthAuthorizationResult.InteractionRequired)server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),binding)).getInteraction();
  var decision=OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of("https://resource.example/mcp",Set.of("read"))).refreshTokenPermitted(true).build();
  var completed=(OAuthAuthorizationResult.Completed)server.completeAuthorizationResult(interaction.getInteractionValue(),binding,decision);
  String location=completed.getResponse().getLocationWithCredentials().orElseThrow().toString();int begin=location.indexOf("code="),end=location.indexOf("&state=",begin);if(begin<0||end<=begin)throw new AssertionError("Genuine completion code absent");String code=location.substring(begin+5,end);
  byte[] body=("grant_type=authorization_code&client_id=client&code="+code+"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&resource=https%3A%2F%2Fresource.example%2Fmcp&redirect_uri=https%3A%2F%2Fclient.example%2Fcb").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  try{check(server.tokenResult("POST",null,body,Map.of("Content-Type",java.util.List.of("application/x-www-form-urlencoded"))) instanceof OAuthTokenResult.Succeeded,"genuine-code-redemption-produces-credentials-without-logging-them");}finally{java.util.Arrays.fill(body,(byte)0);}
 }
 static void verifyCoreOrigin()throws Exception{
  var expected=java.nio.file.Path.of(requireNonNull(System.getenv("REVETSEC_CLEANUP_CORE_JAR"))).toRealPath();
  var actual=java.nio.file.Path.of(OAuthAuthorizationServer.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
  String digest=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(actual)));
  check(actual.equals(expected)&&digest.equals(requireNonNull(System.getenv("REVETSEC_CLEANUP_CORE_SHA256"))),"actual-selected-core-origin-no-shadow");
 }
 public static void main(@NonNull String @NonNull [] arguments)throws Exception{
  verifyCoreOrigin();
  PostgresqlIssuerStore store=IssuerFixtureAuthority.store(NAMESPACE,PendingStoreProbe::connection,4096);
  if(arguments.length==1&&arguments[0].equals("seed")){seed(store);return;}
  OAuthStoreTransaction transaction=target(store);
  OAuthStoreCommitStatus observed=store.commit(transaction,Duration.ofSeconds(5)).getStatus();
  System.out.println("OBSERVED "+observed);
  check(observed==OAuthStoreCommitStatus.COMMITTED,"full-retention-capacity-needs-explicit-reclamation");
 }
}
