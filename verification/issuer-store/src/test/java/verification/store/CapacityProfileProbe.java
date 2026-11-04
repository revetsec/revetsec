/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package verification.store;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;

/** CAP-01 structural/configuration probe; observations are scripted, never approved UTC. */
public final class CapacityProfileProbe {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private static final @NonNull String NAMESPACE="cap01_verification",PREFIX="verification";
 private CapacityProfileProbe(){}
 private static void check(boolean pass,@NonNull String id){if(!pass)throw new AssertionError(id);System.out.println("PASS "+id);}
 private static @NonNull Object field(@NonNull Object owner,@NonNull String name)throws Exception{var f=owner.getClass().getDeclaredField(name);f.setAccessible(true);return Objects.requireNonNull(f.get(owner));}
 private static void caps(@NonNull OAuthAuthorizationServer server,@NonNull String label,@NonNull String part)throws Exception{
  if(!part.equals("sealer"))check(((Integer)field(field(server,"settings"),"maximumStoreRecordBytes"))==16384,label+"-issuer-explicit-16384");
  if(!part.equals("issuer")){var sealer=(StateSealer)field(field(field(server,"coordinator"),"codec"),"sealer");check(SealedStateAccess.get().getMaximumSealedLength(sealer)==16384,label+"-sealer-explicit-16384");}
 }
 private static final class Counting implements OAuthAuthorizationServerStore {
  int reads,commits;@Nullable OAuthStoreTransaction last;final @Nullable OAuthAuthorizationServerStore delegate;
  Counting(@Nullable OAuthAuthorizationServerStore delegate){this.delegate=delegate;}
  @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){this.reads++;return this.delegate==null?OAuthStoreReadResult.Unavailable.get():this.delegate.read(key,budget);}
  @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction txn,@NonNull Duration budget){this.commits++;this.last=txn;return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);}
 }
 private static final class Connections {
  int opened,writes;
  @NonNull Connection open(@NonNull Duration budget)throws SQLException{
   this.opened++;var properties=new Properties();properties.setProperty("user",Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_USER")));properties.setProperty("password",Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_PASSWORD")));properties.setProperty("connectTimeout","5");properties.setProperty("socketTimeout","10");
   Connection actual=DriverManager.getConnection(Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_URL")),properties);
   return (Connection)java.lang.reflect.Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
    if(method.getName().equals("prepareStatement") && args!=null && args.length>0 && args[0] instanceof String text){String sql=text.stripLeading().toUpperCase(Locale.ROOT);if(sql.startsWith("INSERT") || sql.startsWith("UPDATE") || sql.startsWith("DELETE"))this.writes++;}
    try{return method.invoke(actual,args);}catch(java.lang.reflect.InvocationTargetException failure){throw Objects.requireNonNull(failure.getCause());}
   });
  }
 }
 private static @NonNull OAuthAuthorizationServer server(@NonNull OAuthAuthorizationServerStore store,@NonNull String mode)throws Exception{return new IssuerFixture(store,Path.of(Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_SECRET_DIR"))),"https://issuer.example",NOW,mode).server;}
 private static @NonNull OAuthAuthorizationServerStore backend(@NonNull Connections c,int capacity){return new FixtureIssuerStore(NAMESPACE,identity("issuer-physical/"+NAMESPACE),c::open,capacity,(scope,budget)->com.revetsec.StoreTimeObservation.Healthy.fromObservation(com.revetsec.StoreAdmission.fromIdentifiers(identity("issuer-authority/"+NAMESPACE),identity("issuer-recovery/"+NAMESPACE)),identity("issuer-clock/"+NAMESPACE),NOW,Duration.ZERO));}
 private static @NonNull String identity(@NonNull String text){return PostgresStore.identity(text);}
 private static @NonNull String query(){return "client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example%2Fmcp&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state="+"\"\\".repeat(512);}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  if(args[0].equals("profiles")){
   for(String mode:List.of("old","old-with-next","next-with-old","next-only","lost")){var empty=new Counting(null);OAuthAuthorizationServer server;
    try{server=server(empty,mode);}catch(IllegalArgumentException failure){throw new AssertionError(PREFIX+"-profile-build");}
    caps(server,PREFIX+'-'+mode,args.length>1?args[1]:"both");check(empty.reads==0 && empty.commits==0,PREFIX+'-'+mode+"-construction-no-store-io");
   }return;
  }
  var connections=new Connections();var store=backend(connections,4096);var server=server(store,"old");caps(server,PREFIX,"both");
  check(connections.opened==0,PREFIX+"-construction-no-connection");
  check(server.initializeFreshIssuer().getStatus()==OAuthStoreCommitStatus.COMMITTED,PREFIX+"-genuine-initialization");
  var capture=new Counting(store);var prepared=server(capture,"old");
  try{var result=prepared.beginAuthorizationResult("GET",query(),new byte[0],Map.of(),"A".repeat(43));throw new AssertionError(PREFIX+"-capture-must-conflict-"+(result instanceof OAuthAuthorizationResult.Rejected rejected?rejected.getReason():result.getClass().getSimpleName()));}
  catch(OAuthServerStoreException failure){check(failure.getReason()==OAuthServerException.Reason.STORE_UNAVAILABLE,PREFIX+"-genuine-capture-refusal");}
  var txn=Objects.requireNonNull(capture.last);var mutation=txn.getMutations().stream().filter(x->x.getEntry().isPresent()).findFirst().orElseThrow();var row=mutation.getEntry().orElseThrow();
  check(row.toSealedForm().length()>3800 && row.toSealedForm().length()<=16384,PREFIX+"-genuine-record-exceeds-global-default");
  connections.writes=0;var mismatch=backend(connections,4095);
  check(mismatch.read(txn.getConditions().get(0).getKey(),Duration.ofSeconds(5)) instanceof OAuthStoreReadResult.Unavailable,PREFIX+"-mismatched-cap-read-refused");
  check(mismatch.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.UNAVAILABLE,PREFIX+"-mismatched-cap-commit-refused");
  check(connections.writes==0,PREFIX+"-mismatch-before-data-dml");
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.COMMITTED,PREFIX+"-genuine-wide-record-committed");
  check(connections.writes>0,PREFIX+"-dml-counter-positive-control");
  var loaded=store.read(row.getKey(),Duration.ofSeconds(5));check(loaded instanceof OAuthStoreReadResult.Available found && found.getEntry().orElseThrow().toSealedForm().equals(row.toSealedForm()),PREFIX+"-genuine-wide-record-roundtrip");
  if(args.length>1){var props=new Properties();try(var in=Files.newInputStream(Path.of(args[1]))){props.load(in);}var key=OAuthStoreKey.fromStoredForm(Objects.requireNonNull(props.getProperty("key")));var before=connections.writes;
   var result=store.read(key,Duration.ofSeconds(5));check(result instanceof OAuthStoreReadResult.Available available && available.getEntry().orElseThrow().toSealedForm().equals(props.getProperty("sealed")),PREFIX+"-native-exact-16384-carrier-roundtrip");
   check(connections.writes==before,PREFIX+"-exact-carrier-read-no-data-dml");
  }
 }
}
