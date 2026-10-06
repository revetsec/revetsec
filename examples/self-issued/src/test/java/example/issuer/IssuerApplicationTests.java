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
package example.issuer;

import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.server.*;
import com.soklet.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

final class IssuerApplicationTests {
 static final String VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 static @NonNull IssuerConfig config(int http,int mcp) {
  return new IssuerConfig(URI.create("http://127.0.0.1:"+http),URI.create("http://127.0.0.1:"+mcp+"/mcp"),URI.create("https://client.example/cb?original=%2f"),http,mcp,
    "A".repeat(43),"B".repeat(42)+"A","C".repeat(42)+"A",true);
 }
 static @NonNull IssuerResources app() throws Exception {return new IssuerResources(config(8089,8090),Clock.systemUTC());}
 static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> fields) {
  return String.join("&",fields.entrySet().stream().map(e->URLEncoder.encode(e.getKey(),StandardCharsets.UTF_8)+"="+URLEncoder.encode(e.getValue(),StandardCharsets.UTF_8)).toList());
 }
 static @NonNull String query(@NonNull IssuerResources app,@NonNull String client,@NonNull String scopes) {
  return form(Map.of("response_type","code","client_id",client,"redirect_uri",app.config.redirect.toString(),"resource",app.config.resource.toString(),"scope",scopes,"state","client-state","code_challenge",CHALLENGE,"code_challenge_method","S256"));
 }
 static @NonNull Request request(@NonNull IssuerResources app,@NonNull HttpMethod method,@NonNull String path,@Nullable String body,@Nullable String cookie) {
  Map<String,Set<String>> headers=new LinkedHashMap<>(Map.of("Host",Set.of(app.config.origin.getRawAuthority())));
  if(body!=null) {headers.put("Content-Type",Set.of("application/x-www-form-urlencoded"));headers.put("Origin",Set.of(app.config.origin.toString()));}
  if(cookie!=null)headers.put("Cookie",Set.of(cookie));
  var builder=Request.withRawUrl(method,path).headers(headers);if(body!=null)builder.body(body.getBytes(StandardCharsets.UTF_8));return builder.build();
 }
 static @NonNull String text(@NonNull MarshaledResponse response) {return new String(assertInstanceOf(MarshaledResponseBody.Bytes.class,response.getBody().orElseThrow()).getBytes(),StandardCharsets.UTF_8);}
 static @NonNull String scalar(@NonNull String json,@NonNull String field) {
  var match=Pattern.compile("\\\""+field+"\\\"\\s*:\\s*\\\"([A-Za-z0-9_.-]+)\\\"").matcher(json);assertTrue(match.find(),"Expected fixed response field "+field);return match.group(1);
 }
 static @NonNull String code(@NonNull IssuerResources app,@NonNull String client,@NonNull String scopes) {
  String binding=LocalInputs.randomId();var i=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.beginAuthorizationResult("GET",query(app,client,scopes),new byte[0],Map.of(),binding)).getInteraction();
  var response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,app.server.completeAuthorizationResult(i.getInteractionValue(),binding,OAuthAuthorizationDecision.withSubject(IssuerConfig.SUBJECT).authorizedScopesByResource(i.getRequestedScopesByResource()).refreshTokenPermitted(true).build())).getResponse();
  var location=response.getLocationWithCredentials().orElseThrow().toString();return location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
 }
 static @NonNull MarshaledResponse redeem(@NonNull IssuerResources app,@NonNull String client,@NonNull String code,@Nullable String secret) {
  Map<String,String> params=new LinkedHashMap<>(Map.of("grant_type","authorization_code","client_id",client,"code",code,"code_verifier",VERIFIER,"redirect_uri",app.config.redirect.toString(),"resource",app.config.resource.toString()));
  if(secret!=null)params.remove("client_id");
  var request=request(app,HttpMethod.POST,"/token",form(params),null);
  if(secret!=null)request=request.copy().headers(h->h.put("Authorization",Set.of("Basic "+Base64.getEncoder().encodeToString((client+":"+secret).getBytes(StandardCharsets.UTF_8))))).finish();return app.token(request);
 }
 static @NonNull String issued(@NonNull IssuerResources app,@NonNull String scopes) {var response=redeem(app,"demo-public",code(app,"demo-public",scopes),null);assertEquals(200,response.getStatusCode());return text(response);}
 static @NonNull BearerToken bearer(@NonNull String token) {return BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+token)).orElseThrow();}
 @Test void publicAndConfidentialClientsUsePkceAndNoCredentialLeaksInRedirectPage() throws Exception {
  var app=app();for(String client:List.of("demo-public","demo-confidential")) {
   String code=code(app,client,"mcp:discover mcp:whoami");
   if(client.equals("demo-confidential"))assertEquals(401,redeem(app,client,code,"wrong").getStatusCode());
   var token=redeem(app,client,code,client.equals("demo-confidential")?app.config.clientKey:null);assertEquals(200,token.getStatusCode());
   String access=scalar(text(token),"access_token");assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,app.server.validateAccessTokenResult(bearer(access),app.config.resource.toString()));
   assertEquals(400,redeem(app,client,code,client.equals("demo-confidential")?app.config.clientKey:null).getStatusCode());
  }
 }
 @Test void rotatingRefreshReplayInvalidatesTheWholeFamilyOnline() throws Exception {
  var app=app();String first=issued(app,"mcp:discover mcp:whoami"),refresh=scalar(first,"refresh_token");
  String form=form(Map.of("grant_type","refresh_token","client_id","demo-public","resource",app.config.resource.toString(),"refresh_token",refresh));
  var rotated=app.token(request(app,HttpMethod.POST,"/token",form,null));assertEquals(200,rotated.getStatusCode());String next=scalar(text(rotated),"access_token");
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,app.server.validateAccessTokenResult(bearer(next),app.config.resource.toString()));
  assertEquals(400,app.token(request(app,HttpMethod.POST,"/token",form,null)).getStatusCode());
  for(String access:List.of(scalar(first,"access_token"),next))assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,app.server.validateAccessTokenResult(bearer(access),app.config.resource.toString()));
 }
 @Test void resourceOnlyIntrospectionAndRevocationUseCurrentIssuerState() throws Exception {
  var app=app();String access=scalar(issued(app,"mcp:discover"),"access_token");
  var introspect=request(app,HttpMethod.POST,"/introspect",form(Map.of("token",access)),null).copy().headers(h->h.put("Authorization",Set.of("Basic "+Base64.getEncoder().encodeToString(("resource-client:"+app.config.resourceKey).getBytes(StandardCharsets.UTF_8))))).finish();
  assertTrue(text(app.introspect(introspect)).contains("\"active\":true"));
  assertEquals(401,app.introspect(request(app,HttpMethod.POST,"/introspect",form(Map.of("token",access)),null)).getStatusCode());
  assertEquals(400,redeem(app,"resource-client","invalid",app.config.resourceKey).getStatusCode());
  assertEquals(200,app.revoke(request(app,HttpMethod.POST,"/revoke",form(Map.of("client_id","demo-public","token",access)),null)).getStatusCode());
  assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,app.server.validateAccessTokenResult(bearer(access),app.config.resource.toString()));assertTrue(text(app.introspect(introspect)).contains("\"active\":false"));
 }
 @Test void actualFrameworkRoutesBindLoginCsrfConsentRotationAndPreparedRedirect() throws Exception {
  var app=app();SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->{
   var login=sim.performHttpRequest(request(app,HttpMethod.GET,"/authorize?"+query(app,"demo-public","mcp:discover mcp:whoami"),null,null));
   assertEquals(200,login.getMarshaledResponse().getStatusCode());var response=login.getMarshaledResponse();
   var cookie=response.getCookies().iterator().next();String old=cookie.getName()+"="+cookie.getValue().orElseThrow();var session=app.sessions.find(request(app,HttpMethod.GET,"/",null,old)).orElseThrow();String binding=session.binding;
   assertTrue(text(response).contains("Demo login"));assertFalse(text(response).contains(app.config.loginKey));assertFalse(text(response).contains(session.pending.get().handle));
   var post=request(app,HttpMethod.POST,"/login",form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"key",app.config.loginKey)),old);
   assertEquals(403,sim.performHttpRequest(post.copy().headers(h->h.remove("Origin")).finish()).getMarshaledResponse().getStatusCode());
   var rotated=sim.performHttpRequest(post).getMarshaledResponse();assertEquals(303,rotated.getStatusCode());
   var newCookie=rotated.getCookies().iterator().next();String current=newCookie.getName()+"="+newCookie.getValue().orElseThrow();var authenticated=app.sessions.find(request(app,HttpMethod.GET,"/",null,current)).orElseThrow();
   assertEquals(binding,authenticated.binding);assertNotEquals(session.id,authenticated.id);assertNotEquals(session.csrf,authenticated.csrf);assertTrue(app.sessions.find(request(app,HttpMethod.GET,"/",null,old)).isEmpty());
   var consent=request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",authenticated.csrf,"flow",authenticated.pending.get().nonce,"decision","approve")),current);
   assertEquals(403,sim.performHttpRequest(consent.copy().body(("csrf="+authenticated.csrf+"&decision=approve&subject=attacker").getBytes(StandardCharsets.UTF_8)).finish()).getMarshaledResponse().getStatusCode());
   var complete=sim.performHttpRequest(consent).getMarshaledResponse();assertEquals(303,complete.getStatusCode());String location=complete.getHeaders().get("Location").iterator().next();assertTrue(location.startsWith(app.config.redirect+"&code="));
   assertEquals(403,sim.performHttpRequest(consent).getMarshaledResponse().getStatusCode());
   String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));assertEquals(200,redeem(app,"demo-public",code,null).getStatusCode());
  });
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> hostileControlFormsCannotSelectAppIdentityOrBypassCsrf() {
  return Stream.of("csrf=x&csrf=x","%63srf=x&csrf=x","csrf=%FF","csrf=%C3%28","csrf=%","csrf=x&subject=other","csrf=x&resource=https%3A%2F%2Fother","csrf=x&decision=approve&","csrf=x&key="+"x".repeat(4097)).map(value->DynamicTest.dynamicTest("control length "+value.length(),()->{
   var app=app();var session=app.sessions.begin();String cookie="RevetsecIssuerDev="+session.id;
   assertEquals(403,app.login(request(app,HttpMethod.POST,"/login",value,cookie)).getStatusCode());assertFalse(session.authenticated);
  }));
 }
 @Test void sessionCapAndExpiryNeverEvictAuthenticatedStateToAdmitNewSession() {
  var clock=new MutableClock();var sessions=new BrowserSessions(clock,1,true);var first=sessions.begin();var rotated=sessions.login(first,new BrowserSessions.Pending("synthetic"));
  assertThrows(IllegalStateException.class,sessions::begin);var cookie=sessions.cookie(rotated);assertEquals("__Host-RevetsecIssuer",cookie.getName());assertTrue(cookie.getSecure());assertTrue(cookie.getHttpOnly());
  clock.now=clock.now.plusSeconds(601);assertDoesNotThrow(sessions::begin);assertEquals("IssuerSession{<redacted>}",rotated.toString());
 }
 @Test void fixedHostsOriginsMetadataHeadAndEscapingAreChecked() throws Exception {
  var app=app();assertEquals(403,app.index(request(app,HttpMethod.GET,"/",null,null).copy().headers(h->h.put("Host",Set.of("evil.example"))).finish()).getStatusCode());
  assertEquals(0,assertInstanceOf(MarshaledResponseBody.Bytes.class,app.metadata(request(app,HttpMethod.HEAD,"/",null,null)).getBody().orElseThrow()).getBytes().length);
  assertTrue(text(app.resourceMetadata(request(app,HttpMethod.GET,"/",null,null))).contains(app.config.resource.toString()));assertEquals("&lt;&amp;&quot;&#39;&gt;",LocalInputs.html("<&\"'>"));
 }
 @Test void failedStoreCapacityDoesNotDeletePermanentFencesAndCasIsAtomic() throws Exception {
  var clock=new MutableClock();var real=new VolatileStore(clock,2,4_194_304);var captured=new CapturingStore(real);var app=new IssuerResources(config(8089,8090),clock,captured);
  assertEquals(3,captured.commits.size());var issuer=captured.commits.get(0);assertEquals(OAuthStoreCommitStatus.CONFLICT,real.commit(issuer,Duration.ofSeconds(1)));
  assertThrows(OAuthServerException.class,()->code(app,"demo-public","mcp:discover"));
  clock.now=clock.now.plusSeconds(1000000);
  for(var tx:captured.commits.subList(0,2))for(var mutation:tx.getMutations())assertTrue(real.read(mutation.getKey(),Duration.ofSeconds(1)).isPresent());
  assertThrows(IllegalStateException.class,()->real.read(issuer.getConditions().get(0).getKey(),Duration.ZERO));
 }
 @Test void unavailableStoreRemains503AtMcpAdmission() throws Exception {
  var clock=new MutableClock();var captured=new CapturingStore(new VolatileStore(clock,2048,4_194_304));var app=new IssuerResources(config(8089,8090),clock,captured);String access=scalar(issued(app,"mcp:discover mcp:whoami"),"access_token");captured.fail=true;
  SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->assertEquals(503,call(sim,app,access,"tools/call","whoami","{}").getStatusCode()));
 }
 @Test void everyMcpMessageUsesOnlineStatusScopeAndObjectAuthorization() throws Exception {
  var app=app();String wide=scalar(issued(app,"mcp:discover mcp:whoami"),"access_token"),narrow=scalar(issued(app,"mcp:discover"),"access_token");
  SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->{
   assertEquals(401,call(sim,app,null,"tools/list",null,"{}").getStatusCode());
   assertEquals(200,call(sim,app,wide,"tools/list",null,"{}").getStatusCode());
   assertEquals(403,call(sim,app,narrow,"tools/call","whoami","{}").getStatusCode());
   var accepted=call(sim,app,wide,"tools/call","whoami","{}");assertEquals(200,accepted.getStatusCode());String body=new String(accepted.getBody().orElseThrow(),StandardCharsets.UTF_8);assertTrue(body.contains("Checked identity partition"));assertFalse(body.contains(IssuerConfig.SUBJECT));assertFalse(body.contains(wide));
   assertTrue(new String(call(sim,app,wide,"tools/call","whoami","{\"tenant\":\"other\"}").getBody().orElseThrow(),StandardCharsets.UTF_8).contains("isError"));
   app.revoke(request(app,HttpMethod.POST,"/revoke",form(Map.of("client_id","demo-public","token",wide)),null));assertEquals(401,call(sim,app,wide,"tools/call","whoami","{}").getStatusCode());
  });
 }
 @Test void expiresAndWrongResourceAreRejectedWithoutAnOfflineShortcut() throws Exception {
  var clock=new MutableClock();var app=new IssuerResources(config(8089,8090),clock);String token=scalar(issued(app,"mcp:discover mcp:whoami"),"access_token");
  assertThrows(IllegalArgumentException.class,()->app.server.validateAccessTokenResult(bearer(token),"https://wrong.example/mcp"));
  assertEquals(400,app.token(request(app,HttpMethod.POST,"/token",form(Map.of("grant_type","refresh_token","client_id","demo-public","resource","https://wrong.example/mcp","refresh_token","invalid")),null)).getStatusCode());
  clock.now=clock.now.plusSeconds(121);assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,app.server.validateAccessTokenResult(bearer(token),app.config.resource.toString()));
  SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->assertEquals(401,call(sim,app,token,"tools/list",null,"{}").getStatusCode()));
 }
 @Test void materializedHostOriginAndCookieAmbiguityFailClosed() throws Exception {
  var app=app();var session=app.sessions.begin();session.pending.set(new BrowserSessions.Pending("synthetic"));String cookie="RevetsecIssuerDev="+session.id;var valid=request(app,HttpMethod.POST,"/login",form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"key",app.config.loginKey)),cookie);
  for(String name:List.of("Host","Origin","Cookie","Content-Type"))assertEquals(403,app.login(valid.copy().headers(h->h.put(name,Set.of(h.get(name).iterator().next(),"different"))).finish()).getStatusCode());
  assertEquals(403,app.login(valid.copy().headers(h->h.put("Cookie",Set.of(cookie+"; "+cookie))).finish()).getStatusCode());
  assertEquals(403,app.login(valid.copy().headers(h->h.put("Content-Encoding",Set.of("gzip"))).finish()).getStatusCode());
  assertEquals(403,app.login(request(app,HttpMethod.POST,"/login?csrf="+session.csrf,form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"key",app.config.loginKey)),cookie)).getStatusCode());
 }
 @Test void malformedPrivateKeyFileAndMissingFreshNamespaceAreRejected() throws Exception {
  assertThrows(IllegalArgumentException.class,()->IssuerConfig.fromEnvironment(Map.of()));
  java.nio.file.Path folder=java.nio.file.Files.createTempDirectory("issuer-key-check-");
  java.nio.file.Path key=folder.resolve("key");
  try {
   java.nio.file.Files.writeString(key,LocalInputs.randomId()+"\n");java.nio.file.Files.setPosixFilePermissions(key,Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
   assertEquals(43,LocalInputs.keyFile(key.toString()).length());
   java.nio.file.Files.writeString(key,"x".repeat(45));assertThrows(java.io.IOException.class,()->LocalInputs.keyFile(key.toString()));
   java.nio.file.Files.writeString(key,LocalInputs.randomId());java.nio.file.Files.setPosixFilePermissions(key,Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,java.nio.file.attribute.PosixFilePermission.GROUP_READ));assertThrows(java.io.IOException.class,()->LocalInputs.keyFile(key.toString()));
  } finally {java.nio.file.Files.deleteIfExists(key);java.nio.file.Files.deleteIfExists(folder);}
 }
 @Test void staleConsentTabCannotApproveAReplacementClient() throws Exception {
  var app=app();var session=app.sessions.begin();String cookie="RevetsecIssuerDev="+session.id;session.authenticated=true;
  app.authorize(request(app,HttpMethod.GET,"/authorize?"+query(app,"demo-public","mcp:discover"),null,cookie));
  var first=session.pending.get();assertNotNull(first);String stale=form(Map.of("csrf",session.csrf,"flow",first.nonce,"decision","approve"));
  app.authorize(request(app,HttpMethod.GET,"/authorize?"+query(app,"demo-confidential","mcp:discover"),null,cookie));
  var replacement=session.pending.get();assertNotNull(replacement);assertNotEquals(first.nonce,replacement.nonce);
  assertEquals(403,app.complete(request(app,HttpMethod.POST,"/consent",stale,cookie)).getStatusCode());assertSame(replacement,session.pending.get());
  assertEquals(403,app.complete(request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",session.csrf,"decision","approve")),cookie)).getStatusCode());
  assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.resumeAuthorizationResult(first.handle,session.binding));
  assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.resumeAuthorizationResult(replacement.handle,session.binding));
  var completed=app.complete(request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",session.csrf,"flow",replacement.nonce,"decision","approve")),cookie));assertEquals(303,completed.getStatusCode());assertNull(session.pending.get());
 }
 @Test void replacementDuringResumeCannotChangeTheApprovedClientOrLoseTheNewInteraction() throws Exception {
  var clock=new MutableClock();var captured=new CapturingStore(new VolatileStore(clock,2048,4_194_304));var app=new IssuerResources(config(8089,8090),clock,captured);
  var session=app.sessions.begin();session.authenticated=true;String cookie="RevetsecIssuerDev="+session.id;
  app.authorize(request(app,HttpMethod.GET,"/authorize?"+query(app,"demo-public","mcp:discover"),null,cookie));var first=session.pending.get();assertNotNull(first);
  String binding=LocalInputs.randomId();var next=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.beginAuthorizationResult("GET",query(app,"demo-confidential","mcp:whoami"),new byte[0],Map.of(),binding));
  var replacement=new BrowserSessions.Pending(next.getInteraction().getInteractionValue());
  captured.beforeNextRead=()->session.pending.set(replacement);
  var completed=app.complete(request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",session.csrf,"flow",first.nonce,"decision","approve")),cookie));
  assertEquals(303,completed.getStatusCode());assertNull(captured.beforeNextRead);assertSame(replacement,session.pending.get());
  String location=completed.getHeaders().get("Location").iterator().next();String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
  assertEquals(400,redeem(app,"demo-confidential",code,app.config.clientKey).getStatusCode());
  var redeemed=redeem(app,"demo-public",code,null);assertEquals(200,redeemed.getStatusCode());assertTrue(text(redeemed).contains("mcp:discover"));assertFalse(text(redeemed).contains("mcp:whoami"));
  assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.resumeAuthorizationResult(replacement.handle,binding));
 }
 static @NonNull Request mcpRequest(@NonNull IssuerResources app,@Nullable String token,@NonNull String method,@Nullable String tool,@NonNull String args) {
  String params="{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}"+(tool==null?"":",\"name\":\""+tool+"\",\"arguments\":"+args)+"}";
  String body="{\"jsonrpc\":\"2.0\",\"id\":\"synthetic\",\"method\":\""+method+"\",\"params\":"+params+"}";
  Map<String,Set<String>> h=new LinkedHashMap<>(Map.of("Host",Set.of(app.config.resource.getRawAuthority()),"Content-Type",Set.of("application/json"),"Accept",Set.of("application/json, text/event-stream"),"MCP-Protocol-Version",Set.of("2026-07-28"),"Mcp-Method",Set.of(method)));
  if(token!=null)h.put("Authorization",Set.of("Bearer "+token));if(tool!=null)h.put("Mcp-Name",Set.of(tool));return Request.withRawUrl(HttpMethod.POST,"/mcp").headers(h).body(body.getBytes(StandardCharsets.UTF_8)).build();
 }
 static @NonNull McpSimulationResponse call(@NonNull Simulator sim,@NonNull IssuerResources app,@Nullable String token,@NonNull String method,@Nullable String tool,@NonNull String args) throws InterruptedException {
  try(var simulation=sim.startMcpRequest(mcpRequest(app,token,method,tool,args))) {return simulation.awaitResponse(Duration.ofSeconds(5)).orElseThrow();}
 }
 static final class MutableClock extends Clock {
  Instant now=Instant.parse("2026-10-06T12:00:00Z");
  @Override public @NonNull ZoneId getZone() {return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {return this;}
  @Override public @NonNull Instant instant() {return now;}
 }
 static final class CapturingStore implements OAuthAuthorizationServerStore {
  final VolatileStore store;final List<OAuthStoreTransaction> commits=new ArrayList<>();boolean fail;
  @Nullable Runnable beforeNextRead;
  CapturingStore(@NonNull VolatileStore store) {this.store=store;}
  @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {if(fail)throw new IllegalStateException("private-diagnostic");Runnable action=beforeNextRead;beforeNextRead=null;if(action!=null)action.run();return store.read(key,budget);}
  @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget) {commits.add(tx);return store.commit(tx,budget);}
 }
}
