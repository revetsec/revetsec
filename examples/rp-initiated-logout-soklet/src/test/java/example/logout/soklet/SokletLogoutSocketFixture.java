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

package example.logout.soklet;
import example.logout.*;
import com.revetsec.json.*;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;

/** Private disposable raw-socket fixture; do not deploy its OP/bootstrap/clock/store controls. */
public final class SokletLogoutSocketFixture {
 private final @NonNull LogoutFixture fixture;private final @NonNull AtomicBoolean interruptObserved=new AtomicBoolean(),interruptLeftSet=new AtomicBoolean(),cancelSafe=new AtomicBoolean(),lastInterrupted=new AtomicBoolean();
 private SokletLogoutSocketFixture(@NonNull LogoutFixture fixture){this.fixture=fixture;}
 public static void main(@NonNull String @NonNull [] args)throws Exception {
  verify(com.revetsec.oidc.OidcClient.class,"CORE");verify(LocalFirstLogout.class,"COMMON");verify(LogoutFixture.class,"FIXTURE");verify(SokletLogoutRecipe.class,"CARRIER");verify(Soklet.class,"FRAMEWORK");
  int port=Integer.parseInt(args[0]);var mode=args.length>1&&args[1].equals("get")?LocalFirstLogout.Delivery.GET_REDIRECT:LocalFirstLogout.Delivery.FORM_POST;String padding=System.getenv().getOrDefault("REVETSEC_LOGOUT_PADDING","");LogoutFixture fixture=new LogoutFixture("logout-rp",padding);var controls=new SokletLogoutSocketFixture(fixture);var app=fixture.application(mode);var recipe=new SokletLogoutRecipe(app,true);var untrusted=new SokletLogoutRecipe(app,false);var base=recipe.configuration(port);
  var config=SokletConfig.withHttpServer(base.getHttpServer().orElseThrow()).lifecycleObservers(base.getLifecycleObservers()).resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(SokletLogoutRecipe.class,SokletLogoutSocketFixture.class))).instanceProvider(new InstanceProvider(){@Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type){if(type==SokletLogoutRecipe.class)return type.cast(recipe);if(type==SokletLogoutSocketFixture.class)return type.cast(controls);throw new IllegalArgumentException("Unknown fixture component");}}).requestInterceptor(new RequestInterceptor(){@Override public void interceptRequest(@NonNull ServerType type,@NonNull Request request,@Nullable ResourceMethod method,@NonNull Function<@NonNull Request,@NonNull MarshaledResponse> handler,@NonNull Consumer<@NonNull MarshaledResponse> writer){String expected=System.getenv().getOrDefault("REVETSEC_LOGOUT_FIXTURE_CREDENTIAL",""),actual=one(request,"X-Fixture-Credential");if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII))){writer.accept(MarshaledResponse.fromResponse(json(401,JsonObject.builder().put("error","Fixture denied").build())));return;}boolean application=request.getPath().equals("/logout")||request.getPath().equals("/logout/callback");MarshaledResponse response="insecure".equals(one(request,"X-Fixture-Carrier"))?MarshaledResponse.fromResponse(untrusted.handle(request)):handler.apply(request);if(application){boolean interrupted=Thread.currentThread().isInterrupted();controls.lastInterrupted.set(interrupted);if(fixture.takeInjectedInterrupt()){controls.interruptObserved.set(true);controls.interruptLeftSet.set(interrupted);controls.cancelSafe.set(response.getStatusCode()==503&&response.getHeaders().keySet().stream().noneMatch(n->n.equalsIgnoreCase("Location"))&&response.getCookies().stream().noneMatch(c->c.getName().equals(LocalFirstLogout.PENDING_COOKIE)&&c.getMaxAge().map(age->!age.isZero()).orElse(false)));Thread.interrupted();}}writer.accept(response);}}).build();
  Soklet.run(config,ShutdownCleanup.fromTimeoutAndAction(java.time.Duration.ofSeconds(5),result->fixture.close()),()->{
   System.out.println("READY");new CountDownLatch(1).await();
  });
 }
 @POST("/fixture/login") public @NonNull Response login(@NonNull Request request)throws Exception {if(request.getRawQuery().isPresent()||!request.getRawPath().equals(request.getPath()))return json(400,JsonObject.builder().put("error","Fixture denied").build());var browser=this.fixture.login();var cookie=ResponseCookie.fromSetCookieHeaderRepresentation(LocalFirstLogout.SESSION_COOKIE+'='+browser.session()+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1800").orElseThrow();return Response.withStatusCode(200).headers(Map.of("Cache-Control",List.of("no-store"),"Content-Type",List.of("application/json; charset=UTF-8"))).cookies(List.of(cookie)).body(JsonObject.builder().put("genuine_authentication",true).put("csrf",browser.csrf()).build().toJson().getBytes(StandardCharsets.UTF_8)).build();}
 @GET("/fixture/live") public @NonNull Response live(@NonNull Request request){String cookie=one(request,"Cookie");String prefix=LocalFirstLogout.SESSION_COOKIE+'=';boolean live=cookie!=null&&cookie.startsWith(prefix)&&cookie.indexOf(';')<0&&this.fixture.live(cookie.substring(prefix.length()));return json(200,JsonObject.builder().put("live",live).build());}
 @GET("/fixture/control/{command}") public @NonNull Response controlOne(@NonNull Request request){return control(request);}
 @GET("/fixture/control/{group}/{mode}") public @NonNull Response controlTwo(@NonNull Request request){return control(request);}
 private @NonNull Response control(@NonNull Request request){if(request.getRawQuery().isPresent()||!request.getRawPath().equals(request.getPath()))return json(400,JsonObject.builder().put("error","Fixture denied").build());try{JsonObject shared=this.fixture.control(request.getPath().substring("/fixture/control/".length()));return json(200,JsonObject.builder().put("shared",shared).put("origin_verified",true).put("interrupt_observed",this.interruptObserved.get()).put("handler_interrupt_left_set",this.interruptLeftSet.get()).put("handler_cancel_no_publication",this.cancelSafe.get()).put("last_handler_interrupt_set",this.lastInterrupted.get()).build());}catch(IllegalArgumentException unknown){return json(400,JsonObject.builder().put("error","Fixture denied").build());}}
 private static @Nullable String one(@NonNull Request request,@NonNull String name){List<String> values=new ArrayList<>();request.getHeaders().forEach((key,items)->{if(key.equalsIgnoreCase(name))values.addAll(items);});return values.size()==1?values.get(0):null;}
 private static @NonNull Response json(int status,@NonNull JsonObject value){return Response.withStatusCode(status).headers(Map.of("Content-Type",List.of("application/json; charset=UTF-8"),"Cache-Control",List.of("no-store"))).body(value.toJson().getBytes(StandardCharsets.UTF_8)).build();}
 private static void verify(@NonNull Class<?> type,@NonNull String label)throws Exception {String path=System.getenv("REVETSEC_LOGOUT_"+label+"_JAR"),expected=System.getenv("REVETSEC_LOGOUT_"+label+"_SHA256");if(path==null||expected==null)throw new AssertionError("Selected artifact unavailable");Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());if(!actual.toRealPath().equals(Path.of(path).toRealPath())||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(expected))throw new AssertionError("Selected artifact origin mismatch");}
}
