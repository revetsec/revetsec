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
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
final class SokletLogoutCarrierTests {
 private static @NonNull Request start(LogoutFixture.@NonNull Browser browser,@NonNull String path,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> extra){Map<String,List<String>> headers=new LinkedHashMap<>();headers.put("Host",List.of("app.example"));headers.put("Origin",List.of("https://app.example"));headers.put("X-CSRF-Token",List.of(browser.csrf()));headers.put("Cookie",List.of(LocalFirstLogout.SESSION_COOKIE+'='+browser.session()));headers.putAll(extra);return Request.withRawUrl(HttpMethod.POST,path).headers(headers).remoteAddress(new InetSocketAddress("127.0.0.1",12345)).body(new byte[0]).build();}
 private static @NonNull Request callback(@NonNull String query,@NonNull String binding,@Nullable String session){return Request.withRawUrl(HttpMethod.GET,"/logout/callback?"+query).headers(Map.of("Host",List.of("app.example"),"Cookie",List.of(LocalFirstLogout.PENDING_COOKIE+'='+binding+(session==null?"":"; "+LocalFirstLogout.SESSION_COOKIE+'='+session)))).remoteAddress(new InetSocketAddress("127.0.0.1",12345)).build();}
 private static @NonNull String body(@NonNull Response response){return new String((byte[])response.getBody().orElseThrow(),StandardCharsets.UTF_8);}
 private static @NonNull String state(@NonNull Response response){var matcher=Pattern.compile("name=\"state\" value=\"([A-Za-z0-9_-]{43})\"").matcher(body(response));assertTrue(matcher.find());return matcher.group(1);}
 private static @NonNull String binding(@NonNull Response response){return response.getCookies().stream().filter(c->c.getName().equals(LocalFirstLogout.PENDING_COOKIE)&&!c.getMaxAge().orElseThrow().isZero()).findFirst().orElseThrow().getValue().orElseThrow();}
 private static void cleared(@NonNull Response response,@NonNull String name){assertTrue(response.getCookies().stream().anyMatch(c->c.getName().equals(name)&&c.getMaxAge().orElseThrow().isZero()));}
 @Test void actualRequestResponseAndSeparateCookiesCarryGenuinePreparedForm()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true);var response=recipe.handle(start(browser,"/logout",Map.of()));assertEquals(200,response.getStatusCode());assertFalse(fixture.live(browser));assertEquals(2,response.getCookies().size());cleared(response,LocalFirstLogout.SESSION_COOKIE);assertEquals(43,binding(response).length());assertEquals(43,state(response).length());assertTrue(response.getCookies().stream().allMatch(c->c.getSecure()&&c.getHttpOnly()&&c.getPath().orElseThrow().equals("/")));assertTrue(body(response).contains("name=\"id_token_hint\""));}}
 @Test void callbackCorrelationDoesNotClearOrCloseANewerApplicationSession()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true);var prepared=recipe.handle(start(browser,"/logout",Map.of()));var newer=fixture.login();var response=recipe.handle(callback("state="+state(prepared),binding(prepared),newer.session()));assertEquals(200,response.getStatusCode());cleared(response,LocalFirstLogout.PENDING_COOKIE);assertEquals(1,response.getCookies().size());assertTrue(fixture.live(newer));assertEquals(400,recipe.handle(callback("state="+state(prepared),binding(prepared),null)).getStatusCode());}}
 @Test void transportCapabilityCannotBeSelectedByForwardingHeaders()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),false);assertEquals(400,recipe.handle(start(browser,"/logout",Map.of("X-Forwarded-Proto",List.of("https"),"Forwarded",List.of("proto=https")))).getStatusCode());assertTrue(fixture.live(browser));}}
 @Test void rawAliasesAndNonemptyStartQueriesFailBeforeClosing()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true);for(String path:List.of("/%6cogout","/logout?x=1")){assertEquals(400,recipe.handle(start(browser,path,Map.of())).getStatusCode());assertTrue(fixture.live(browser));}var malformed=callback("%73tate="+"A".repeat(43),"A".repeat(43),null);assertEquals(400,recipe.handle(malformed).getStatusCode());cleared(recipe.handle(malformed),LocalFirstLogout.PENDING_COOKIE);}}
 @Test void discardedCallbackBodiesStillClearPendingWithoutConsuming()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true);var input=callback("state="+"A".repeat(43),"A".repeat(43),null).copy().contentTooLarge(true).finish();var response=recipe.handle(input);assertEquals(413,response.getStatusCode());cleared(response,LocalFirstLogout.PENDING_COOKIE);}}
 @Test void duplicateRawOriginAndCookieFieldsRemainDenied()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var recipe=new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true);assertEquals(403,recipe.handle(start(browser,"/logout",Map.of("Origin",List.of("https://app.example","https://app.example")))).getStatusCode());String cookie=LocalFirstLogout.SESSION_COOKIE+'='+browser.session();assertEquals(400,recipe.handle(start(browser,"/logout",Map.of("Cookie",List.of(cookie,cookie)))).getStatusCode());assertTrue(fixture.live(browser));}}
 @Test void pinnedEmptyQueryLossRequiresARealDeclaredStartEdge()throws Exception{try(LogoutFixture fixture=new LogoutFixture()){var browser=fixture.login();var input=start(browser,"/logout?",Map.of());assertTrue(input.getRawQuery().isEmpty());assertEquals("/logout",input.getRawPathAndQuery());assertEquals(200,new SokletLogoutRecipe(fixture.application(LocalFirstLogout.Delivery.FORM_POST),true).handle(input).getStatusCode(),"framework information-loss component; actualedgegate remainsOPEN");assertFalse(fixture.live(browser));}}
}
