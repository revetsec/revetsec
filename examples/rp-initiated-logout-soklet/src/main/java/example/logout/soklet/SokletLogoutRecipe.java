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

import example.logout.LocalFirstLogout;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.util.*;
import static java.util.Objects.requireNonNull;

/**
 * Unpublished carrier for the common local-first logout application. The selected framework loses a bare trailing
 * question mark. Enable the startup capability only behind an authenticated/private HTTPS edge that rejects every
 * raw query delimiter on POST/logout before Soklet parsing, including an empty query. Return state queries remain
 * permitted on the fixed GET callback. Never infer edge trust from arbitrary forwarding request headers.
 */
@ThreadSafe
public final class SokletLogoutRecipe {
 private final @NonNull LocalFirstLogout application;private final boolean trustedHttpsAndQueryFreeStartEdge;
 public SokletLogoutRecipe(@NonNull LocalFirstLogout application,boolean trustedHttpsAndQueryFreeStartEdge){this.application=requireNonNull(application);this.trustedHttpsAndQueryFreeStartEdge=trustedHttpsAndQueryFreeStartEdge;}
 /** Bind only private IPv4loopback after qualifying the fixed HTTPS/raw-query edge and its own limits. */
 public @NonNull SokletConfig configuration(int port){if(port<1024||port>65535)throw new IllegalArgumentException("Private backend port required");var recipe=this;return SokletConfig.withHttpServer(HttpServer.withPort(port).host("127.0.0.1").maximumRequestSizeInBytes(24576).maximumRequestBodySizeInBytes(4096).maximumHeadersSizeInBytes(8192).maximumHeaderCount(32).maximumRequestTargetLengthInBytes(8192).concurrentConnectionLimit(64).requestHandlerConcurrency(16).requestHandlerQueueCapacity(16).requestHeaderTimeout(Duration.ofSeconds(3)).requestBodyTimeout(Duration.ofSeconds(3)).requestHandlerTimeout(Duration.ofSeconds(6)).responseWriteIdleTimeout(Duration.ofSeconds(3)).build()).resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(SokletLogoutRecipe.class))).instanceProvider(new InstanceProvider(){@Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type){if(type==SokletLogoutRecipe.class)return type.cast(recipe);throw new IllegalArgumentException("Unknown application component");}}).lifecycleObserver(new LifecycleObserver(){@Override public void didReceiveLogEvent(@NonNull LogEvent event){/* Do not log request, response, cookies, credentials or provider exceptions. */}}).build();}
 /** Preserve raw multiplicity, body/discard status, canonical path and actual socket peer before common handling. */
 public @NonNull Response handle(@NonNull Request request){requireNonNull(request);String path=request.getRawPath(),rejectionPath=path.equals("/logout/callback")||request.getPath().equals("/logout/callback")?"/logout/callback":path;LocalFirstLogout.Reply reply;try{var peer=request.getRemoteAddress().orElseThrow(()->new IllegalArgumentException("Missing socket peer"));var address=peer.getAddress();if(address==null||!path.equals(request.getPath()))return render(this.application.rejectCarrierRequest(rejectionPath,400));byte[] body=request.getBody().orElseGet(()->new byte[0]);if(request.isContentTooLarge()||request.getEncodedBodySizeInBytes()>4096||body.length>4096)return render(this.application.rejectCarrierRequest(rejectionPath,413));reply=this.application.handle(new LocalFirstLogout.Request(request.getHttpMethod().name(),path,request.getRawQuery().orElse(null),request.getHeaders(),body,false,this.trustedHttpsAndQueryFreeStartEdge,address.getHostAddress()));}catch(VirtualMachineError fatal){throw fatal;}catch(IllegalArgumentException malformed){reply=this.application.rejectCarrierRequest(rejectionPath,400);}catch(RuntimeException|Error unavailable){reply=this.application.rejectCarrierRequest(rejectionPath,503);}return render(reply);}
 private static @NonNull Response render(LocalFirstLogout.@NonNull Reply reply){Map<String,List<String>> headers=new LinkedHashMap<>();reply.headers().forEach((name,value)->headers.put(name,List.of(value)));List<ResponseCookie> cookies=new ArrayList<>();for(String cookie:reply.cookies())cookies.add(ResponseCookie.fromSetCookieHeaderRepresentation(cookie).orElseThrow(()->new IllegalStateException("Cookie representation unavailable")));return Response.withStatusCode(reply.status()).headers(headers).cookies(cookies).body(reply.body()).build();}
 @POST("/logout") public @NonNull Response begin(@NonNull Request request){return handle(request);}
 @GET("/logout/callback") public @NonNull Response complete(@NonNull Request request){return handle(request);}
 @Override public @NonNull String toString(){return "SokletLogoutRecipe{<redacted>}";}
}
