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

import com.soklet.Soklet;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Actual numeric-loopback sockets, JDK client, pinned framework; no external browser/client qualification. */
final class IssuerSocketTests {
 private static int port() throws Exception {
  try(var socket=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {return socket.getLocalPort();}
 }
 @Test void localHttpClientPerformsBrowserCodeExchangeMcpAdmissionAndRevocation() throws Exception {
  int hp=port(),mp=port();while(mp==hp)mp=port();var config=IssuerApplicationTests.config(hp,mp);var app=new IssuerResources(config,Clock.systemUTC());
  var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
  try(var soklet=Soklet.fromConfig(IssuerPlayground.sokletConfig(app))) {
   soklet.start();
   var metadata=send(client,config.origin.resolve("/.well-known/oauth-authorization-server"),"GET",null,null,null);
   assertEquals(200,metadata.statusCode());assertTrue(metadata.body().contains(config.origin.toString()));
   var login=send(client,URI.create(config.origin+"/authorize?"+IssuerApplicationTests.query(app,"demo-public","mcp:discover mcp:whoami")),"GET",null,null,null);
   assertEquals(200,login.statusCode());String initial=login.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0],csrf=csrf(login.body());
   var signedIn=send(client,config.origin.resolve("/login"),"POST",IssuerApplicationTests.form(Map.of("csrf",csrf,"flow",flow(login.body()),"key",config.loginKey)),initial,config.origin.toString());
   assertEquals(303,signedIn.statusCode());String cookie=signedIn.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];assertNotEquals(initial,cookie);
   var consent=send(client,config.origin.resolve("/consent"),"GET",null,cookie,null);assertEquals(200,consent.statusCode());
   var complete=send(client,config.origin.resolve("/consent"),"POST",IssuerApplicationTests.form(Map.of("csrf",csrf(consent.body()),"flow",flow(consent.body()),"decision","approve")),cookie,config.origin.toString());
   assertEquals(303,complete.statusCode());String location=complete.headers().firstValue("Location").orElseThrow();assertTrue(location.startsWith(config.redirect+"&code="));
   String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
   String exchange=IssuerApplicationTests.form(Map.of("grant_type","authorization_code","client_id","demo-public","code",code,"code_verifier",IssuerApplicationTests.VERIFIER,"redirect_uri",config.redirect.toString(),"resource",config.resource.toString()));
   var tokens=send(client,config.origin.resolve("/token"),"POST",exchange,null,null);assertEquals(200,tokens.statusCode());assertEquals("no-store",tokens.headers().firstValue("Cache-Control").orElseThrow());
   String access=IssuerApplicationTests.scalar(tokens.body(),"access_token");
   var request=IssuerApplicationTests.mcpRequest(app,access,"tools/call","whoami","{}");
   var builder=HttpRequest.newBuilder(config.resource).timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofByteArray(request.getBody().orElseThrow()));
   request.getHeaders().forEach((name,values)->{if(!name.equalsIgnoreCase("Host"))values.forEach(value->builder.header(name,value));});
   var call=client.send(builder.build(),HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));assertEquals(200,call.statusCode());assertTrue(call.body().contains("Checked identity partition"));assertFalse(call.body().contains(access));assertFalse(call.body().contains(IssuerConfig.SUBJECT));
   assertEquals(200,send(client,config.origin.resolve("/revoke"),"POST",IssuerApplicationTests.form(Map.of("client_id","demo-public","token",access)),null,null).statusCode());
   assertEquals(401,client.send(builder.build(),HttpResponse.BodyHandlers.discarding()).statusCode());
  }
 }
 private static @NonNull String flow(@NonNull String html) {
  var match=Pattern.compile("name='flow' value='([A-Za-z0-9_-]{43})'").matcher(html);assertTrue(match.find());return match.group(1);
 }
 private static @NonNull String csrf(@NonNull String html) {
  var match=Pattern.compile("name='csrf' value='([A-Za-z0-9_-]{43})'").matcher(html);assertTrue(match.find());return match.group(1);
 }
 private static @NonNull HttpResponse<@NonNull String> send(@NonNull HttpClient client,@NonNull URI uri,@NonNull String method,@Nullable String body,@Nullable String cookie,@Nullable String origin) throws Exception {
  var builder=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5));
  if(body==null)builder.method(method,HttpRequest.BodyPublishers.noBody());else builder.header("Content-Type","application/x-www-form-urlencoded").method(method,HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8));
  if(cookie!=null)builder.header("Cookie",cookie);if(origin!=null)builder.header("Origin",origin);
  return client.send(builder.build(),HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
 }
}
