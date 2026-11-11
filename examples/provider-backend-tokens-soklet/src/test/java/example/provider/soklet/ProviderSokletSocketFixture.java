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

package example.provider.soklet;

import example.provider.ProviderFixture;
import com.revetsec.json.JsonObject;
import com.soklet.*;
import com.soklet.annotation.GET;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;
import java.util.function.Function;

/** Private synthetic localhost fixture. No fixture routes, signing keys or credential guard are application code. */
public final class ProviderSokletSocketFixture {
 private final @NonNull ProviderFixture fixture;
 private ProviderSokletSocketFixture(@NonNull ProviderFixture fixture){this.fixture=fixture;}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  int port=Integer.parseInt(args[0]);ProviderFixture fixture=new ProviderFixture();var control=new ProviderSokletSocketFixture(fixture);var recipe=new SokletProviderTokensRecipe(fixture.application(),true);var base=recipe.configuration(port);
  var config=SokletConfig.withHttpServer(base.getHttpServer().orElseThrow()).lifecycleObservers(base.getLifecycleObservers())
   .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(SokletProviderTokensRecipe.class,ProviderSokletSocketFixture.class)))
   .instanceProvider(new InstanceProvider(){@Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type){if(type==SokletProviderTokensRecipe.class)return type.cast(recipe);if(type==ProviderSokletSocketFixture.class)return type.cast(control);throw new IllegalArgumentException("Unknown fixture");}})
   .requestInterceptor(new RequestInterceptor(){@Override public void interceptRequest(@NonNull ServerType type,@NonNull Request request,@Nullable ResourceMethod method,@NonNull Function<@NonNull Request,@NonNull MarshaledResponse> handler,@NonNull Consumer<@NonNull MarshaledResponse> writer){
    String expected=System.getenv().getOrDefault("REVETSEC_PROVIDER_FIXTURE_CREDENTIAL","");String actual=one(request,"X-Fixture-Credential");
    if(expected.isEmpty()||actual==null||!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII)))writer.accept(MarshaledResponse.fromResponse(json(401,JsonObject.builder().put("error","Fixture denied").build())));else writer.accept(handler.apply(request));
   }}).build();
  Soklet.run(config,ShutdownCleanup.fromTimeoutAndAction(java.time.Duration.ofSeconds(5),result->fixture.close()),()->{
   System.out.println("READY");new CountDownLatch(1).await();
  });
 }
 @GET("/fixture/{command}") public @NonNull Response control(@NonNull Request request){
  String command=request.getPath().substring("/fixture/".length());if(request.getRawQuery().isPresent())return json(400,JsonObject.builder().put("error","Fixture denied").build());
  if(command.equals("health"))return json(200,JsonObject.builder().put("healthy",true).build());
  try{return json(200,this.fixture.control(command));}catch(IllegalArgumentException denied){return json(400,JsonObject.builder().put("error","Fixture denied").build());}
 }
 @GET("/fixture/token/{provider}/{mode}") public @NonNull Response token(@NonNull Request request){String nonce=one(request,"X-Fixture-Nonce");String[] paths=request.getPath().split("/",-1);if(nonce==null||paths.length!=5)return json(400,JsonObject.builder().put("error","Fixture denied").build());try{return json(200,this.fixture.token(paths[3],nonce,paths[4]));}catch(IllegalArgumentException denied){return json(400,JsonObject.builder().put("error","Fixture denied").build());}}
 private static @Nullable String one(@NonNull Request request,@NonNull String name){var values=new ArrayList<String>();request.getHeaders().forEach((key,items)->{if(key.equalsIgnoreCase(name))values.addAll(items);});return values.size()==1?values.get(0):null;}
 private static @NonNull Response json(int status,@NonNull JsonObject object){return Response.withStatusCode(status).headers(Map.of("Content-Type",List.of("application/json; charset=UTF-8"),"Cache-Control",List.of("no-store"))).body(object.toJson().getBytes(StandardCharsets.UTF_8)).build();}
}
