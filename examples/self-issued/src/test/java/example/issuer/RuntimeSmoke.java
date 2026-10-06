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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import org.jspecify.annotations.NonNull;

/** Standalone runtime check without JUnit or any annotation artifact. Emits booleans only. */
final class RuntimeSmoke {
 private RuntimeSmoke() {}
 private static int port() throws Exception {try(var s=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {return s.getLocalPort();}}
 public static void main(@NonNull String @NonNull [] args) throws Exception {
  if(args.length!=1)throw new IllegalArgumentException("Expected private capture destination.");
  int hp=port(),mp=port();while(mp==hp)mp=port();
  var config=new IssuerConfig(URI.create("http://127.0.0.1:"+hp),URI.create("http://127.0.0.1:"+mp+"/mcp"),URI.create("https://client.example/cb"),hp,mp,LocalInputs.randomId(),LocalInputs.randomId(),LocalInputs.randomId(),true);
  var app=new IssuerResources(config,Clock.systemUTC());
  try(var soklet=Soklet.fromConfig(IssuerPlayground.sokletConfig(app))) {
   soklet.start();var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
   var response=client.send(HttpRequest.newBuilder(config.origin.resolve("/.well-known/oauth-authorization-server")).timeout(Duration.ofSeconds(5)).GET().build(),HttpResponse.BodyHandlers.ofString());
   if(response.statusCode()!=200 || !response.body().contains(config.origin.toString()))throw new IllegalStateException("Runtime check failed.");
   Files.writeString(Path.of(args[0]),"{\"freshInitialization\":true,\"httpMetadata\":true,\"annotationFreeRuntime\":true,\"externalServices\":false}\n");
  }
 }
}
