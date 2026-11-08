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

package verification.oidcacr;

import org.jspecify.annotations.NonNull;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.oidc.OidcSessionReference;
import com.revetsec.oidc.OidcSessionReferenceParseResult;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class OidcAcrPolicy {
 private static int checks;
 private static void check(boolean value){checks++;if(!value)throw new AssertionError("ACR policy check "+checks);}
 private static OidcClient.@NonNull Builder client(){return OidcClient.withProviderMetadata(OidcProviderMetadata.withIssuer("https://issuer.example").authorizationEndpoint(URI.create("https://issuer.example/authorize")).tokenEndpoint(URI.create("https://issuer.example/token")).jwksUri(URI.create("https://issuer.example/jwks")).build()).clientId("client").redirectUri(URI.create("https://rp.example/callback"));}
 private static @NonNull List<@NonNull String> acr(@NonNull URI uri){List<String> result=new ArrayList<>();for(String pair:uri.getRawQuery().split("&")){String[] parts=pair.split("=",2);if(URLDecoder.decode(parts[0],StandardCharsets.UTF_8).equals("acr_values"))result.add(URLDecoder.decode(parts[1],StandardCharsets.UTF_8));}return result;}
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  String origin=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(OidcClient.class.getProtectionDomain().getCodeSource().getLocation().toURI()))));if(args.length!=1||!origin.equals(args[0]))throw new AssertionError("wrong core origin");
  var mutable=new ArrayList<>(List.of("urn:z","urn:a"));var builder=client().requiredAcrValues(Set.of("urn:required")).acrPreferences(mutable);mutable.clear();var configured=builder.build();
  check(acr(configured.beginAuthentication().getAuthorizationUri()).equals(List.of("urn:z urn:a")));
  check(acr(configured.beginAuthentication(OidcAuthenticationOptions.builder().acrPreferences(List.of("urn:y","urn:b")).build()).getAuthorizationUri()).equals(List.of("urn:y urn:b")));
  check(acr(configured.beginAuthentication(OidcAuthenticationOptions.builder().acrPreferences(List.of()).build()).getAuthorizationUri()).isEmpty());
  check(acr(configured.beginAuthentication(OidcAuthenticationOptions.builder().acrPreferences(List.of("urn:unused")).acrPreferences(null).build()).getAuthorizationUri()).equals(List.of("urn:z urn:a")));
  check(acr(client().requiredAcrValues(Set.of("urn:z","urn:a")).acrPreferences(null).build().beginAuthentication().getAuthorizationUri()).equals(List.of("urn:a urn:z")));
  check(acr(client().acrPreferences(List.of("urn:preference-only")).build().beginAuthentication().getAuthorizationUri()).equals(List.of("urn:preference-only")));
  var options=OidcAuthenticationOptions.builder().requiredAcrValues(Set.of("urn:required")).acrPreferences(List.of("urn:preferred")).build();check(options.getRequiredAcrValues().orElseThrow().equals(Set.of("urn:required")));check(options.getAcrPreferences().orElseThrow().equals(List.of("urn:preferred")));
  try{options.getAcrPreferences().orElseThrow().add("urn:mutated");throw new AssertionError();}catch(UnsupportedOperationException expected){check(true);}
  try{client().acrPreferences(List.of("urn:a","urn:a"));throw new AssertionError();}catch(IllegalArgumentException expected){check(true);}
  String fields="\"client_id\":\"client\",\"claims\":{\"iss\":\"https://issuer.example\",\"sub\":\"synthetic\",\"aud\":\"client\",\"iat\":1793894400},\"nonce_digest\":\""+"A".repeat(43)+"\"";
  check(OidcSessionReference.fromSerializedFormResult("{\"v\":1,"+fields+"}") instanceof OidcSessionReferenceParseResult.Rejected);
  var parsed=OidcSessionReference.fromSerializedFormResult("{\"v\":2,"+fields+",\"required_acr_values\":[\"urn:strong\"]}");if(!(parsed instanceof OidcSessionReferenceParseResult.Succeeded success))throw new AssertionError("v2");OidcSessionReference reference=success.getReference();check(reference.getRequiredAcrValues().equals(Set.of("urn:strong")));try{reference.getRequiredAcrValues().clear();throw new AssertionError();}catch(UnsupportedOperationException expected){check(true);}
  check(!reference.toString().contains("urn:strong"));if(checks!=14)throw new AssertionError(checks);System.out.println("PASS public OIDC ACR consumer: "+checks+" checks");
 }
}
