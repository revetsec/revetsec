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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
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
 static @NonNull OAuthIssuerKeyProvider signingKeys(@NonNull Clock clock) throws Exception {
  var generator=java.security.KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();
  return OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair(
    LocalInputs.randomId(),pair.getPrivate(),pair.getPublic())).generation(LocalInputs.randomId()).publishedAt(clock.instant()).build());
 }
 static @NonNull StateSealer sealer() {
  return StateSealer.withActiveKey(SealingKey.fromBase64("test-seal",Base64.getEncoder().encodeToString(LocalInputs.randomBytes()))).build();
 }
 @Test void establishedStartupRetainsGrantAndRefreshAcrossApplicationInstances() throws Exception {
  var clock=Clock.systemUTC();var config=config(8089,8090);var store=new VolatileStore(clock,2048,4_194_304);
  var keys=signingKeys(clock);var sealing=sealer();
  var first=new IssuerResources(config,clock,store,keys,sealing,IssuerResources.StartupMode.FRESH);
  String firstPair=issued(first,"mcp:discover mcp:whoami");String access=scalar(firstPair,"access_token");
  String refresh=scalar(firstPair,"refresh_token");
  var established=new IssuerResources(config,clock,store,keys,sealing,IssuerResources.StartupMode.ESTABLISHED);
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,
    established.server.validateAccessTokenResult(bearer(access),config.resource.toString()));
  String refreshForm=form(Map.of("grant_type","refresh_token","client_id","demo-public",
    "resource",config.resource.toString(),"refresh_token",refresh));
  var rotated=established.token(request(established,HttpMethod.POST,"/token",refreshForm,null));
  assertEquals(200,rotated.getStatusCode());
  String next=scalar(text(rotated),"access_token");
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,
    first.server.validateAccessTokenResult(bearer(next),config.resource.toString()));
  assertThrows(IllegalStateException.class,
    ()->new IssuerResources(config,clock,store,keys,sealing,IssuerResources.StartupMode.FRESH));
 }
 @Test void establishedStartupRejectsMissingFenceAndWrongSealingKey() throws Exception {
  var clock=Clock.systemUTC();var config=config(8089,8090);var store=new VolatileStore(clock,2048,4_194_304);
  var keys=signingKeys(clock);var sealing=sealer();
  assertThrows(OAuthServerStoreException.class,
    ()->new IssuerResources(config,clock,store,keys,sealing,IssuerResources.StartupMode.ESTABLISHED));
  new IssuerResources(config,clock,store,keys,sealing,IssuerResources.StartupMode.FRESH);
  assertThrows(OAuthServerStoreException.class,
    ()->new IssuerResources(config,clock,store,keys,sealer(),IssuerResources.StartupMode.ESTABLISHED));
 }
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
   assertEquals(Set.of("same-origin"),response.getHeaders().get("Referrer-Policy"));
   var cookie=response.getCookies().iterator().next();String old=cookie.getName()+"="+cookie.getValue().orElseThrow();var session=app.sessions.find(request(app,HttpMethod.GET,"/",null,old)).orElseThrow();String binding=session.binding;
   assertTrue(text(response).contains("Demo login"));assertFalse(text(response).contains(app.config.loginKey));assertFalse(text(response).contains(session.pending.get().handle));
   var post=request(app,HttpMethod.POST,"/login",form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"key",app.config.loginKey)),old);
   assertEquals(403,sim.performHttpRequest(post.copy().headers(h->h.remove("Origin")).finish()).getMarshaledResponse().getStatusCode());
   assertEquals(403,sim.performHttpRequest(post.copy().headers(h->h.put("Origin",Set.of("null"))).finish()).getMarshaledResponse().getStatusCode());
   var rotated=sim.performHttpRequest(post).getMarshaledResponse();assertEquals(303,rotated.getStatusCode());
   var newCookie=rotated.getCookies().iterator().next();String current=newCookie.getName()+"="+newCookie.getValue().orElseThrow();var authenticated=app.sessions.find(request(app,HttpMethod.GET,"/",null,current)).orElseThrow();
   assertEquals(binding,authenticated.binding);assertNotEquals(session.id,authenticated.id);assertNotEquals(session.csrf,authenticated.csrf);assertTrue(app.sessions.find(request(app,HttpMethod.GET,"/",null,old)).isEmpty());
   var consentPage=sim.performHttpRequest(request(app,HttpMethod.GET,"/consent",null,current)).getMarshaledResponse();
   assertEquals(Set.of("same-origin"),consentPage.getHeaders().get("Referrer-Policy"));
   assertTrue(consentPage.getHeaders().get("Content-Security-Policy").iterator().next().contains("form-action 'self' https://client.example;"));
   var consent=request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",authenticated.csrf,"flow",authenticated.pending.get().nonce,"decision","approve")),current);
   assertEquals(403,sim.performHttpRequest(consent.copy().body(("csrf="+authenticated.csrf+"&decision=approve&subject=attacker").getBytes(StandardCharsets.UTF_8)).finish()).getMarshaledResponse().getStatusCode());
   assertEquals(403,sim.performHttpRequest(consent.copy().headers(h->h.put("Origin",Set.of("null"))).finish()).getMarshaledResponse().getStatusCode());
   var complete=sim.performHttpRequest(consent).getMarshaledResponse();assertEquals(303,complete.getStatusCode());assertEquals(Set.of("no-referrer"),complete.getHeaders().get("Referrer-Policy"));String location=complete.getHeaders().get("Location").iterator().next();assertTrue(location.startsWith(app.config.redirect+"&code="));
   assertEquals(403,sim.performHttpRequest(consent).getMarshaledResponse().getStatusCode());
   String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));assertEquals(200,redeem(app,"demo-public",code,null).getStatusCode());
  });
 }
 @Test void nativePortConsentUsesCheckedReturnAndCodeRedemptionKeepsExactPort() throws Exception {
  URI registered=URI.create("http://127.0.0.1:6273/oauth/callback"),actual=URI.create("http://127.0.0.1:6274/oauth/callback");
  var base=config(8089,8090);var config=new IssuerConfig(base.origin,base.resource,registered,URI.create("http://127.0.0.1:6274"),8089,8090,base.loginKey,base.clientKey,base.resourceKey,true);
  var app=new IssuerResources(config,Clock.systemUTC());var session=app.sessions.begin();session.authenticated=true;String cookie="RevetsecIssuerDev="+session.id;
  String selected=query(app,"demo-public","mcp:discover").replace(URLEncoder.encode(registered.toString(),StandardCharsets.UTF_8),URLEncoder.encode(actual.toString(),StandardCharsets.UTF_8));
  for(String invalid:List.of("http://localhost:6274/oauth/callback","http://127.0.0.1:6274/other","http://127.0.0.1:6274/oauth/callback?extra=1")) {
   var rejected=app.authorize(request(app,HttpMethod.GET,"/authorize?"+selected.replace(URLEncoder.encode(actual.toString(),StandardCharsets.UTF_8),URLEncoder.encode(invalid,StandardCharsets.UTF_8)),null,cookie));
   assertEquals(400,rejected.getStatusCode());assertFalse(rejected.getHeaders().containsKey("Location"));
  }
  var consent=app.authorize(request(app,HttpMethod.GET,"/authorize?"+selected,null,cookie));assertEquals(200,consent.getStatusCode());
  assertTrue(text(consent).contains(actual.toString()));String csp=consent.getHeaders().get("Content-Security-Policy").iterator().next();
  assertTrue(csp.contains("form-action 'self' http://127.0.0.1:6274;"));assertFalse(csp.contains(":6273"));
  var completed=app.complete(request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"decision","approve")),cookie));
  assertEquals(303,completed.getStatusCode());assertEquals(Set.of("no-referrer"),completed.getHeaders().get("Referrer-Policy"));
  String location=completed.getHeaders().get("Location").iterator().next();assertTrue(location.startsWith(actual+"?code="));
  String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));assertEquals(400,redeem(app,"demo-public",code,null).getStatusCode());
  var redeemed=app.token(request(app,HttpMethod.POST,"/token",form(Map.of("grant_type","authorization_code","client_id","demo-public","code",code,"code_verifier",VERIFIER,"redirect_uri",actual.toString(),"resource",app.config.resource.toString())),null));
  assertEquals(200,redeemed.getStatusCode());
 }
 @Test void ipv6NativeReturnUsesCheckedLinkAndKeepsConsentFormsSameOrigin() throws Exception {
  URI registered=URI.create("http://[::1]:6273/oauth/callback"),actual=URI.create("http://[::1]:43123/oauth/callback");
  for(String decision:List.of("approve","deny")) {
   var base=config(8089,8090);var config=new IssuerConfig(base.origin,base.resource,registered,base.origin,8089,8090,base.loginKey,base.clientKey,base.resourceKey,true);
   var app=new IssuerResources(config,Clock.systemUTC());var session=app.sessions.begin();session.authenticated=true;String cookie="RevetsecIssuerDev="+session.id;
   String selected=query(app,"demo-public","mcp:discover").replace(URLEncoder.encode(registered.toString(),StandardCharsets.UTF_8),URLEncoder.encode(actual.toString(),StandardCharsets.UTF_8));
   var consent=app.authorize(request(app,HttpMethod.GET,"/authorize?"+selected,null,cookie));assertEquals(200,consent.getStatusCode());assertTrue(text(consent).contains(actual.toString()));
   assertEquals(Set.of("default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),consent.getHeaders().get("Content-Security-Policy"));
   var post=request(app,HttpMethod.POST,"/consent",form(Map.of("csrf",session.csrf,"flow",session.pending.get().nonce,"decision",decision)),cookie);
   assertEquals(403,app.complete(post.copy().headers(h->h.put("Origin",Set.of(actual.getScheme()+"://"+actual.getRawAuthority()))).finish()).getStatusCode());
   var completed=app.complete(post);assertEquals(200,completed.getStatusCode());assertFalse(completed.getHeaders().containsKey("Location"));
   assertEquals(Set.of("no-referrer"),completed.getHeaders().get("Referrer-Policy"));assertEquals(Set.of("no-store"),completed.getHeaders().get("Cache-Control"));
   assertEquals(Set.of("default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),completed.getHeaders().get("Content-Security-Policy"));
   String body=text(completed),marker="id='native-return' rel='noreferrer' href='";assertTrue(body.contains(marker));
   String location=body.substring(body.indexOf(marker)+marker.length(),body.indexOf("'",body.indexOf(marker)+marker.length())).replace("&amp;","&");
   URI returned=URI.create(location);assertEquals(actual.getScheme(),returned.getScheme());assertEquals(actual.getRawAuthority(),returned.getRawAuthority());assertEquals(actual.getRawPath(),returned.getRawPath());
   assertTrue(location.contains("state=client-state"));assertFalse(body.contains(app.config.clientKey));assertFalse(body.contains(session.csrf));assertEquals(403,app.complete(post).getStatusCode());
   if(decision.equals("approve")) {
    assertTrue(location.startsWith(actual+"?code="));String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));assertEquals(400,redeem(app,"demo-public",code,null).getStatusCode());
    assertEquals(200,app.token(request(app,HttpMethod.POST,"/token",form(Map.of("grant_type","authorization_code","client_id","demo-public","code",code,"code_verifier",VERIFIER,"redirect_uri",actual.toString(),"resource",app.config.resource.toString())),null)).getStatusCode());
   }else {assertTrue(location.contains("error=access_denied"));assertFalse(location.contains("code="));}
  }
 }
 @Test void browserCorsOriginIsExplicitWithoutChangingControlPostOriginPolicy() throws Exception {
  var base=config(8089,8090);URI browser=URI.create("http://127.0.0.1:6274"),registered=URI.create("http://127.0.0.1:6273/oauth/callback");
  assertEquals(URI.create("https://client.example"),base.browserOrigin);
  for(String invalid:List.of("http://client.example","https://client.example/path","https://client.example?x=1","https://client.example#x","https://user@client.example","https://client.example:0"))
   assertThrows(IllegalArgumentException.class,()->new IssuerConfig(base.origin,base.resource,registered,URI.create(invalid),8089,8090,base.loginKey,base.clientKey,base.resourceKey,true));
  var app=new IssuerResources(new IssuerConfig(base.origin,base.resource,registered,browser,8089,8090,base.loginKey,base.clientKey,base.resourceKey,true),Clock.systemUTC());
  SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->{
   var metadata=request(app,HttpMethod.GET,"/.well-known/oauth-authorization-server",null,null);
   var allowed=sim.performHttpRequest(metadata.copy().headers(h->h.put("Origin",Set.of(browser.toString()))).finish()).getMarshaledResponse();
   assertEquals(200,allowed.getStatusCode());assertEquals(Set.of(browser.toString()),allowed.getHeaders().get("Access-Control-Allow-Origin"));
   var excluded=sim.performHttpRequest(metadata.copy().headers(h->h.put("Origin",Set.of("http://127.0.0.1:6273"))).finish()).getMarshaledResponse();
   assertFalse(excluded.getHeaders().containsKey("Access-Control-Allow-Origin"));
   assertEquals(403,sim.performHttpRequest(request(app,HttpMethod.POST,"/login","csrf=wrong&flow=wrong&key=wrong",null).copy().headers(h->h.put("Origin",Set.of(browser.toString()))).finish()).getMarshaledResponse().getStatusCode());
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
 @Test void configuredSecondResourceRequiresItsOwnGrantAndChallengesWithItsOwnMetadata() throws Exception {
  var base=config(8089,8090);var cfg=new IssuerConfig(base.origin,base.resource,base.redirect,base.browserOrigin,8089,8090,base.loginKey,base.clientKey,base.resourceKey,true,true);
  var app=new IssuerResources(cfg,Clock.systemUTC());URI second=cfg.resource.resolve("/mcp-second");
  assertEquals(Set.of(cfg.resource.toString(),second.toString()),cfg.resources().keySet());assertTrue(base.resourceForEndpoint("/mcp-second").isEmpty());
  assertEquals(404,new IssuerResources(base,Clock.systemUTC()).secondResourceMetadata(request(app,HttpMethod.GET,"/.well-known/oauth-protected-resource/mcp-second",null,null)).getStatusCode());
  assertTrue(text(app.secondResourceMetadata(request(app,HttpMethod.GET,"/.well-known/oauth-protected-resource/mcp-second",null,null))).contains(second.toString()));
  String firstToken=scalar(issued(app,"mcp:discover mcp:whoami"),"access_token"),binding=LocalInputs.randomId();
  String q=query(app,"demo-public","mcp:discover mcp:whoami").replace(URLEncoder.encode(cfg.resource.toString(),StandardCharsets.UTF_8),URLEncoder.encode(second.toString(),StandardCharsets.UTF_8));
  var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,app.server.beginAuthorizationResult("GET",q,new byte[0],Map.of(),binding)).getInteraction();
  assertEquals(Set.of(second.toString()),interaction.getRequestedScopesByResource().keySet());
  var completion=assertInstanceOf(OAuthAuthorizationResult.Completed.class,app.server.completeAuthorizationResult(interaction.getInteractionValue(),binding,OAuthAuthorizationDecision.withSubject(IssuerConfig.SUBJECT).authorizedScopesByResource(interaction.getRequestedScopesByResource()).refreshTokenPermitted(true).build()));
  String location=completion.getResponse().getLocationWithCredentials().orElseThrow().toString(),code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
  var redeemed=app.token(request(app,HttpMethod.POST,"/token",form(Map.of("grant_type","authorization_code","client_id","demo-public","code",code,"code_verifier",VERIFIER,"redirect_uri",cfg.redirect.toString(),"resource",second.toString())),null));
  assertEquals(200,redeemed.getStatusCode());String secondToken=scalar(text(redeemed),"access_token");
  SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->{
   for(String method:List.of("tools/list","tools/call"))for(String target:List.of("/mcp","/mcp-second"))for(String source:List.of("/mcp","/mcp-second")) {
    String token=source.equals("/mcp")?firstToken:secondToken;Request req=mcpRequest(app,token,method,method.equals("tools/call")?"whoami":null,"{}").copy().path(target).finish();
    try(var pending=sim.startMcpRequest(req)) {
     var response=pending.awaitResponse(Duration.ofSeconds(5)).orElseThrow();assertEquals(target.equals(source)?200:401,response.getStatusCode());
     if(!target.equals(source)) {String header=response.getHeaders().get("WWW-Authenticate").iterator().next();assertTrue(header.contains("error=\"invalid_token\""));assertTrue(header.contains("resource_metadata=\""+cfg.origin+"/.well-known/oauth-protected-resource"+target+"\""));}
    }
   }
  });
  assertEquals(List.of(second.toString()),assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,app.server.validateAccessTokenResult(bearer(secondToken),second.toString())).getAccessToken().getAudiences());
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
 @Test void metadataIsDefaultOffAndFixedMappingDoesNotResolveDns() throws Exception {
  assertFalse(IssuerConfig.metadataPolicy(Map.of()).getEnabled());
  var disabled=app();assertFalse(text(disabled.metadata(request(disabled,HttpMethod.GET,"/",null,null))).contains("client_id_metadata_document_supported"));
  URI origin=URI.create("https://cimd.example.com:6277");
  var policy=IssuerConfig.metadataPolicy(Map.of("REVETSEC_ISSUER_CIMD_ORIGIN",origin.toString(),"REVETSEC_ISSUER_CIMD_ADDRESS","8.8.8.8"));
  assertTrue(policy.getEnabled());assertEquals(Set.of(origin),policy.getAllowedOrigins().orElseThrow());assertTrue(policy.getCache().isEmpty());
  var resolver=policy.getAddressResolver().orElseThrow();
  assertEquals("8.8.8.8",resolver.resolve("CIMD.EXAMPLE.COM",Duration.ofSeconds(1)).get(0).getHostAddress());
  assertThrows(IllegalArgumentException.class,()->resolver.resolve("other.example.com",Duration.ofSeconds(1)));
  assertThrows(IllegalArgumentException.class,()->resolver.resolve("cimd.example.com",Duration.ZERO));
  var c=config(8089,8090);
  var enabled=new IssuerResources(new IssuerConfig(c.origin,c.resource,c.redirect,c.browserOrigin,c.httpPort,c.mcpPort,c.loginKey,c.clientKey,c.resourceKey,c.loopback,false,policy),Clock.systemUTC());
  assertTrue(text(enabled.metadata(request(enabled,HttpMethod.GET,"/",null,null))).contains("\"client_id_metadata_document_supported\":true"));
 }
 @Test void metadataRequiresPairedStrictTrustedConfiguration() {
  assertThrows(IllegalArgumentException.class,()->IssuerConfig.metadataPolicy(Map.of("REVETSEC_ISSUER_CIMD_ORIGIN","https://cimd.example.com:6277")));
  assertThrows(IllegalArgumentException.class,()->IssuerConfig.metadataPolicy(Map.of("REVETSEC_ISSUER_CIMD_ADDRESS","8.8.8.8")));
  for(String numeric:List.of("8.8.8","8.8.8.256","008.8.8.8","cimd.example.com","8.8.8.8 ","8.8.8.8:6277"))
   assertThrows(IllegalArgumentException.class,()->IssuerConfig.metadataPolicy(Map.of("REVETSEC_ISSUER_CIMD_ORIGIN","https://cimd.example.com:6277","REVETSEC_ISSUER_CIMD_ADDRESS",numeric)));
  for(String origin:List.of("http://cimd.example.com:6277","https://127.0.0.1:6277","https://cimd.example.com:6277/client.json"))
   assertThrows(IllegalArgumentException.class,()->IssuerConfig.metadataPolicy(Map.of("REVETSEC_ISSUER_CIMD_ORIGIN",origin,"REVETSEC_ISSUER_CIMD_ADDRESS","8.8.8.8")));
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
