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

import example.provider.BackendApplication;
import com.revetsec.json.JsonObject;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static java.util.Objects.requireNonNull;

/**
 * Application-owned R9/R10 Soklet carrier. Supply a trusted TLS/query-free-edge decision at startup; it is never inferred
 * from forwarding headers. The supplied server binds IPv4 loopback and must be reachable only through that edge.
 * The pinned framework drops a bare trailing question mark; the edge must reject every query-bearing raw
 * request target (including an empty query) before constructing a Soklet request.
 * Real account/admission policy is injected into the common application. This adds no published core/adapter API.
 */
@ThreadSafe
public final class SokletProviderTokensRecipe {
 private final @NonNull BackendApplication application;
 private final boolean trustedHttpsAndQueryFreeEdge;
 /** Inject the common application and a trusted deployment decision about this listener's HTTPS and raw query-rejection edge. */
 public SokletProviderTokensRecipe(@NonNull BackendApplication application,boolean trustedHttpsAndQueryFreeEdge){this.application=requireNonNull(application);this.trustedHttpsAndQueryFreeEdge=trustedHttpsAndQueryFreeEdge;}
 /** Create the bounded private backend listener after configuring and authenticating its TLS edge. */
 public @NonNull SokletConfig configuration(int port){
  if(port<1024||port>65535)throw new IllegalArgumentException("Invalid private backend port");var recipe=this;
  return SokletConfig.withHttpServer(HttpServer.withPort(port).host("127.0.0.1")
   .maximumRequestSizeInBytes(49152).maximumRequestBodySizeInBytes(32768)
   .maximumHeadersSizeInBytes(8192).maximumHeaderCount(32).maximumRequestTargetLengthInBytes(2048)
   .concurrentConnectionLimit(64).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16)
   .requestHeaderTimeout(Duration.ofSeconds(3)).requestBodyTimeout(Duration.ofSeconds(3))
   .requestHandlerTimeout(Duration.ofSeconds(6)).responseWriteIdleTimeout(Duration.ofSeconds(3)).build())
   .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(SokletProviderTokensRecipe.class)))
   .instanceProvider(new InstanceProvider(){@Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type){if(type==SokletProviderTokensRecipe.class)return type.cast(recipe);throw new IllegalArgumentException("Unknown application component");}})
   .lifecycleObserver(new LifecycleObserver(){@Override public void didReceiveLogEvent(@NonNull LogEvent event){/* No request, token, body or exception logging. */}}).build();
 }
 /** Preserve raw multiplicity, complete body/discard status, exact path and the actual socket peer. */
 public @NonNull Response handle(@NonNull Request request){
  requireNonNull(request);BackendApplication.Reply reply;
  try{
   var remote=request.getRemoteAddress().orElseThrow(()->new IllegalArgumentException("Request denied"));
   var address=remote.getAddress();if(address==null||!request.getRawPath().equals(request.getPath()))return refusal(400);
   byte[] body=request.getBody().orElseGet(()->new byte[0]);
   if(request.isContentTooLarge()||request.getEncodedBodySizeInBytes()>32768||body.length>32768)return refusal(413);
   reply=this.application.handle(new BackendApplication.Request(request.getHttpMethod().name(),request.getRawPath(),request.getRawQuery().orElse(null),request.getHeaders(),body,false,this.trustedHttpsAndQueryFreeEdge,address.getHostAddress()));
  }catch(IllegalArgumentException malformed){return refusal(400);}catch(RuntimeException unavailable){return refusal(503);}
  Map<String,List<String>> headers=new LinkedHashMap<>();reply.headers().forEach((name,value)->headers.put(name,List.of(value)));JsonObject.Builder fields=JsonObject.builder();reply.fields().forEach(fields::put);
  List<ResponseCookie> cookies=new ArrayList<>();for(String cookie:reply.cookies())cookies.add(ResponseCookie.fromSetCookieHeaderRepresentation(cookie).orElseThrow(()->new IllegalStateException("Cookie encoding unavailable")));
  return Response.withStatusCode(reply.status()).headers(headers).cookies(cookies).body(fields.build().toJson().getBytes(StandardCharsets.UTF_8)).build();
 }
 private static @NonNull Response refusal(int status){return Response.withStatusCode(status).headers(Map.of("Cache-Control",List.of("no-store"),"Content-Type",List.of("application/json; charset=UTF-8"))).body("{\"error\":\"Request denied\"}".getBytes(StandardCharsets.UTF_8)).build();}
 @POST("/google/begin") public @NonNull Response googleBegin(@NonNull Request request){return handle(request);}
 @POST("/google/complete") public @NonNull Response googleComplete(@NonNull Request request){return handle(request);}
 @POST("/apple/begin") public @NonNull Response appleBegin(@NonNull Request request){return handle(request);}
 @POST("/apple/complete") public @NonNull Response appleComplete(@NonNull Request request){return handle(request);}
 @GET("/session") public @NonNull Response browserSession(@NonNull Request request){return handle(request);}
 @GET("/native/session") public @NonNull Response nativeSession(@NonNull Request request){return handle(request);}
 @GET("/account/{tenant}/{account}") public @NonNull Response browserAccount(@NonNull Request request){return handle(request);}
 @GET("/native/account/{tenant}/{account}") public @NonNull Response nativeAccount(@NonNull Request request){return handle(request);}
 @POST("/logout") public @NonNull Response browserLogout(@NonNull Request request){return handle(request);}
 @POST("/native/logout") public @NonNull Response nativeLogout(@NonNull Request request){return handle(request);}
 @Override public @NonNull String toString(){return "SokletProviderTokensRecipe{configuration=<redacted>}";}
}
