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
import com.soklet.*;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real signed provider validation through actual Soklet request/cookie types; socket matrix is separate. */
final class ProviderSokletCarrierTests {
 private static @NonNull Request request(@NonNull String path,@NonNull String body,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> extra){var headers=new HashMap<String,List<String>>();headers.put("Host",List.of("app.example"));headers.put("Content-Type",List.of("application/x-www-form-urlencoded"));headers.putAll(extra);return Request.withRawUrl(HttpMethod.POST,path).headers(headers).remoteAddress(new InetSocketAddress("127.0.0.1",12345)).body(body.getBytes(StandardCharsets.UTF_8)).build();}
 private static @NonNull String field(@NonNull Response response,@NonNull String field){String body=new String((byte[])response.getBody().orElseThrow(),StandardCharsets.UTF_8);var matcher=java.util.regex.Pattern.compile("\""+field+"\":\"([A-Za-z0-9_-]{43})\"").matcher(body);assertTrue(matcher.find());String value=matcher.group(1);assertFalse(matcher.find());return value;}
 @Test void realGoogleValidationPreservesBothSecurityCookies()throws Exception{
  try(var fixture=new ProviderFixture()){var recipe=new SokletProviderTokensRecipe(fixture.application(),true);var begin=recipe.handle(request("/google/begin","begin=1",Map.of("Origin",List.of("https://app.example"))));assertEquals(200,begin.getStatusCode());String nonce=field(begin,"nonce");String pending=begin.getCookies().get(0).getName()+"="+begin.getCookies().get(0).getValue().orElseThrow();String token=((JsonString)fixture.token("google",nonce,"valid").getMembers().get("token")).getValue();var done=recipe.handle(request("/google/complete","credential="+URLEncoder.encode(token,StandardCharsets.UTF_8)+"&g_csrf_token=TEST-ONLY-csrf",Map.of("Cookie",List.of(pending+"; g_csrf_token=TEST-ONLY-csrf"))));assertEquals(200,done.getStatusCode());assertEquals(2,done.getCookies().size());assertTrue(done.getCookies().stream().anyMatch(cookie->cookie.getName().equals("__Host-provider-session")&&cookie.getSecure()&&cookie.getHttpOnly()&&cookie.getPath().orElseThrow().equals("/")));assertTrue(done.getCookies().stream().anyMatch(cookie->cookie.getName().equals("__Host-provider-login")&&cookie.getMaxAge().orElseThrow().isZero()));}
 }
 @Test void discardedBodiesNeverBecomeSuccessfulPrefixes()throws Exception{try(var fixture=new ProviderFixture()){var recipe=new SokletProviderTokensRecipe(fixture.application(),true);var input=request("/google/begin","begin=1",Map.of("Origin",List.of("https://app.example"))).copy().contentTooLarge(true).finish();assertEquals(413,recipe.handle(input).getStatusCode());assertEquals(0L,((com.revetsec.json.JsonNumber)fixture.control("state").getMembers().get("attempts")).getLongValueExact().orElseThrow());}}
 @Test void trustedTransportDecisionIsIndependentOfForwardedHeaders()throws Exception{try(var fixture=new ProviderFixture()){var recipe=new SokletProviderTokensRecipe(fixture.application(),false);var input=request("/google/begin","begin=1",Map.of("Origin",List.of("https://app.example"),"X-Forwarded-Proto",List.of("https")));assertEquals(400,recipe.handle(input).getStatusCode());}}
 @Test void rawAliasesAndNonemptyQueriesDoNotSelectSuccessfulRoutes()throws Exception{try(var fixture=new ProviderFixture()){var recipe=new SokletProviderTokensRecipe(fixture.application(),true);for(String path:List.of("/google/%62egin","/google/begin?x=1"))assertEquals(400,recipe.handle(request(path,"begin=1",Map.of("Origin",List.of("https://app.example")))).getStatusCode());}}
 @Test void pinnedFrameworkDropsAnEmptyQueryAndRequiresTheDeclaredEdgePolicy()throws Exception{var input=request("/google/begin?","begin=1",Map.of("Origin",List.of("https://app.example")));assertTrue(input.getRawQuery().isEmpty());assertEquals("/google/begin",input.getRawPathAndQuery());try(var fixture=new ProviderFixture()){assertEquals(200,new SokletProviderTokensRecipe(fixture.application(),true).handle(input).getStatusCode());assertEquals(400,new SokletProviderTokensRecipe(fixture.application(),false).handle(input).getStatusCode());}}
 @Test void duplicateOriginValuesAreNotCollapsed()throws Exception{try(var fixture=new ProviderFixture()){var recipe=new SokletProviderTokensRecipe(fixture.application(),true);assertEquals(403,recipe.handle(request("/google/begin","begin=1",Map.of("Origin",List.of("https://app.example","https://app.example")))).getStatusCode());}}
}
