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

package example.logout;

import com.revetsec.BrowserBinding;
import com.revetsec.oidc.*;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;
import static java.util.Objects.requireNonNull;

/**
 * Unpublished application composition for an existing authenticated session. It creates no identity or account.
 * Authorize and close the local session atomically before any provider preparation. Never restore it on failure.
 * The application supplies current session/CSRF policy, trusted transport/peer context, protected hint storage and
 * a qualified confidential/integrity-protected atomic pending store. No arbitrary forwarding-header trust is used.
 */
@ThreadSafe
public final class LocalFirstLogout {
 public static final @NonNull String SESSION_COOKIE="__Host-app-session",PENDING_COOKIE="__Host-rp-logout";
 private static final int RESPONSE_LIMIT=131_072;
 public enum Delivery { FORM_POST, GET_REDIRECT }
 public record Configuration(@NonNull URI origin,@NonNull Delivery delivery) {
  public Configuration(@NonNull URI origin){this(origin,Delivery.FORM_POST);}
  public Configuration {requireNonNull(origin);requireNonNull(delivery);if(!"https".equals(origin.getScheme())||origin.getHost()==null||origin.getRawUserInfo()!=null||origin.getRawQuery()!=null||origin.getRawFragment()!=null||!origin.getRawPath().isEmpty()||origin.getPort()==0||origin.getPort()>65535||origin.toASCIIString().length()>2048)throw new IllegalArgumentException("A fixed HTTPS origin is required");}
  public @NonNull URI callback(){return this.origin.resolve("/logout/callback");}
  @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
 }
 /** No return value is authentication proof. A Detached value contains only trusted previously retained credentials. */
 public sealed interface CloseResult permits Denied,Unavailable,Detached { }
 /** The callback verified denial before any session effect. */
 public enum Denied implements CloseResult { INSTANCE }
 /** Authorization/effect is not established. The old cookie expires; no retry or provider work follows. */
 public enum Unavailable implements CloseResult { INSTANCE }
 public record Detached(@NonNull OidcSessionReference original,@NonNull OidcLogoutHint hint) implements CloseResult {
  public Detached {requireNonNull(original);requireNonNull(hint);}
  @Override public @NonNull String toString(){return "Detached{<redacted>}";}
 }
 /**
  * Under one application lock/transaction, verify the current session's stored CSRF then close that exact session
  * before returning Detached. Denied means no close. Unavailable/null/throw may have had an effect. Never retry,
  * reattach or return credentials for an unauthenticated/unapproved local session. Implementations honor remaining.
  */
 @FunctionalInterface public interface Sessions { @NonNull CloseResult closeAuthorized(@NonNull String sessionCookie,@NonNull String csrf,@NonNull Duration remaining)throws Exception; }
 public record Request(@NonNull String method,@NonNull String path,@Nullable String rawQuery,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,byte @NonNull [] body,boolean discarded,boolean trustedHttps,@NonNull String peer) {
  public Request {
   requireNonNull(method);requireNonNull(path);requireNonNull(headers);requireNonNull(body);ascii(peer,128);
   if(method.length()>16||path.length()>1024||rawQuery!=null&&rawQuery.length()>4096||headers.size()>32||body.length>4096)throw new IllegalArgumentException("Complete bounded request required");
   Map<String,List<String>> copy=new LinkedHashMap<>();int charged=0,count=0;
   for(var entry:headers.entrySet()){String rawName=requireNonNull(entry.getKey());if(rawName.length()>64)throw new IllegalArgumentException("Bounded header name required");String name=rawName.toLowerCase(Locale.ROOT);if(!name.matches("[a-z0-9-]{1,64}")||entry.getValue().size()>32)throw new IllegalArgumentException("Bounded headers required");List<String> values=copy.computeIfAbsent(name,key->new ArrayList<>());for(String value:entry.getValue()){if(value.length()>4096||!value.chars().allMatch(c->c>=0x20&&c<=0x7e))throw new IllegalArgumentException("Bounded ASCII headers required");charged+=name.length()+value.length();if(charged>8192||++count>32)throw new IllegalArgumentException("Header budget exceeded");values.add(value);}}
   Map<String,List<String>> immutable=new LinkedHashMap<>();copy.forEach((name,values)->immutable.put(name,List.copyOf(values)));headers=Map.copyOf(immutable);body=body.clone();
  }
  @Override public byte @NonNull [] body(){return this.body.clone();}
  @Override public @NonNull String toString(){return "Request{<redacted>}";}
 }
 /** Explicit body/Location getters may emit the retained credential on success; never log replies. */
 public record Reply(int status,@NonNull Map<@NonNull String,@NonNull String> headers,@NonNull List<@NonNull String> cookies,byte @NonNull [] body) {
  public Reply {headers=Map.copyOf(headers);cookies=List.copyOf(cookies);if(body.length>RESPONSE_LIMIT)throw new IllegalArgumentException("Response budget exceeded");body=body.clone();}
  @Override public byte @NonNull [] body(){return this.body.clone();}
  @Override public @NonNull String toString(){return "Reply{status="+this.status+", values=<redacted>}";}
 }
 private final @NonNull Configuration config;private final @NonNull OidcClient client;private final @NonNull PendingAuthorizationStore pending;private final @NonNull Sessions sessions;private final @NonNull SecureRandom random;private final @NonNull LongSupplier nanoTime;private final @NonNull Semaphore work=new Semaphore(8);
 private final @NonNull Map<@NonNull String,@NonNull RetainedBinding> retainedBindings=new LinkedHashMap<>();
 /**
  * The client must configure this origin's /logout/callback, a selected provider and a totalDeadline no greater
  * than three seconds. This handler retains its own original four-second budget. Configure bounded pending
  * capacity/expiry and a trusted protected session backend; in-memory fixtures are not a durable profile.
  */
 public LocalFirstLogout(@NonNull Configuration config,@NonNull OidcClient client,@NonNull PendingAuthorizationStore pending,@NonNull Sessions sessions){this(config,client,pending,sessions,new SecureRandom(),System::nanoTime);}
 LocalFirstLogout(@NonNull Configuration config,@NonNull OidcClient client,@NonNull PendingAuthorizationStore pending,@NonNull Sessions sessions,@NonNull SecureRandom random,@NonNull LongSupplier nanoTime){this.config=requireNonNull(config);this.client=requireNonNull(client);this.pending=requireNonNull(pending);this.sessions=requireNonNull(sessions);this.random=requireNonNull(random);this.nanoTime=requireNonNull(nanoTime);}
 /** Invoke once with complete raw carrier values. No store, session or provider operation is automatically retried. */
 public @NonNull Reply handle(@NonNull Request request){
  boolean callback=request.path().equals("/logout/callback"),possibleClose=false,closed=false,acquired=false;Budget budget=new Budget(this.nanoTime);
  try {
   budget.check();if(!request.trustedHttps()||request.discarded()||!one(request,"host").equalsIgnoreCase(this.config.origin().getRawAuthority())||!values(request,"authorization").isEmpty())throw new Refused(400);
   if(!callback&&!request.path().equals("/logout"))throw new Refused(404);
   if(request.body.length!=0)throw new Refused(400);
   if(callback){if(!request.method().equals("GET"))throw new Refused(405);String handle=cookieValue(request,PENDING_COOKIE);if(handle==null||!token(handle))throw new Refused(400);if(!this.work.tryAcquire())throw new Refused(503);acquired=true;BrowserBinding binding=claimBinding(handle);if(binding==null)throw new Refused(400);OidcLogoutResult result=this.client.completeLogoutResult(request.rawQuery()==null?"":request.rawQuery(),PendingOidcLogoutSource.fromStore(this.pending,binding),this.config.callback());budget.check();return fixed(result instanceof OidcLogoutResult.Returned?200:400,result instanceof OidcLogoutResult.Returned?"Provider return correlated; provider-session termination is not confirmed.":"Logout return not accepted.",List.of(clear(PENDING_COOKIE)));}
   if(!request.method().equals("POST"))throw new Refused(405);if(request.rawQuery()!=null)throw new Refused(400);if(!values(request,"origin").equals(List.of(this.config.origin().toString())))throw new Refused(403);
   List<String> contentTypes=values(request,"content-type");if(contentTypes.size()>1||contentTypes.size()==1&&!contentTypes.get(0).equalsIgnoreCase("application/x-www-form-urlencoded"))throw new Refused(415);
   String session=cookieValue(request,SESSION_COOKIE),csrf=one(request,"x-csrf-token");if(session==null||!token(session)||!token(csrf))throw new Refused(403);
   if(!this.work.tryAcquire())throw new Refused(503);acquired=true;budget.check();possibleClose=true;CloseResult outcome=this.sessions.closeAuthorized(session,csrf,budget.remaining());
   if(outcome instanceof Denied){possibleClose=false;budget.check();throw new Refused(403);}if(!(outcome instanceof Detached detached))throw new Refused(503);closed=true;budget.check();
   OidcLogoutRequest prepared=this.client.beginLogout(detached.original(),detached.hint());budget.check();return retainAndPrepare(prepared,budget);
  }catch(VirtualMachineError fatal){throw fatal;}
  catch(Refused refused){return fixed(refused.status,callback?"Logout return not accepted.":closed?"Local session closed; provider sign-out unavailable.":possibleClose?"The local sign-out outcome is unavailable.":"Request denied.",callback?List.of(clear(PENDING_COOKIE)):possibleClose?List.of(clear(SESSION_COOKIE),clear(PENDING_COOKIE)):List.of());}
  catch(Exception|Error unavailable){if(unavailable instanceof InterruptedException||unavailable instanceof java.io.InterruptedIOException&&!(unavailable instanceof java.net.SocketTimeoutException))Thread.currentThread().interrupt();return fixed(503,callback?"Logout return unavailable.":closed?"Local session closed; provider sign-out unavailable.":possibleClose?"The local sign-out outcome is unavailable.":"Request unavailable.",callback?List.of(clear(PENDING_COOKIE)):possibleClose?List.of(clear(SESSION_COOKIE),clear(PENDING_COOKIE)):List.of());}
  finally{if(acquired)this.work.release();}
 }
 /** A carrier that rejects malformed/oversized raw input still clears pending state on the fixed callback. */
 public @NonNull Reply rejectCarrierRequest(@NonNull String rawPath,int status){if(status!=400&&status!=413&&status!=503)throw new IllegalArgumentException("Fixed carrier rejection required");return fixed(status,"Request denied.",rawPath.equals("/logout/callback")?List.of(clear(PENDING_COOKIE)):List.of());}
 private @NonNull Reply prepared(@NonNull OidcLogoutRequest prepared,@NonNull String binding){
  long age=Duration.between(prepared.getPending().getCreatedAt(),prepared.getPending().getExpiresAt()).toSeconds();List<String> cookies=List.of(clear(SESSION_COOKIE),cookie(PENDING_COOKIE,binding,Math.min(3600,age)));
  if(this.config.delivery()==Delivery.GET_REDIRECT){String uri=prepared.getRedirectUri().toASCIIString();if(uri.length()>4096)throw new Refused(503);Map<String,String> headers=headers();headers.put("Location",uri);return new Reply(303,headers,cookies,new byte[0]);}
  StringBuilder html=new StringBuilder("<!doctype html><html><head><meta charset=\"UTF-8\"><title>Continue sign-out</title></head><body><p>Your local session is closed.</p><form method=\"post\" action=\"");escape(html,prepared.getFormAction().toASCIIString());html.append("\">");for(var field:prepared.getFormParameters().entrySet()){html.append("<input type=\"hidden\" name=\"");escape(html,field.getKey());html.append("\" value=\"");escape(html,field.getValue());html.append("\">");}html.append("<button type=\"submit\">Continue provider sign-out</button></form></body></html>");if(html.length()>RESPONSE_LIMIT)throw new Refused(503);Map<String,String> headers=headers();URI action=prepared.getFormAction();headers.put("Content-Security-Policy","default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action "+action.getScheme()+"://"+action.getRawAuthority());return new Reply(200,headers,cookies,html.toString().getBytes(StandardCharsets.US_ASCII));
 }
 private @NonNull Reply retainAndPrepare(@NonNull OidcLogoutRequest prepared,@NonNull Budget budget){
  BrowserBinding binding=BrowserBinding.fresh();String handle=freshToken();Duration lifetime=Duration.between(prepared.getPending().getCreatedAt(),prepared.getPending().getExpiresAt());
  if(!retainBinding(handle,binding,lifetime))throw new Refused(503);boolean published=false;
  try{budget.check();Reply response=prepared(prepared,handle);budget.check();if(prepared.getPending().saveToResult(this.pending,binding,budget.remaining())!=PendingAuthorizationSaveResult.SAVED)throw new Refused(503);budget.check();published=true;return response;}
  finally{if(!published)discardBinding(handle);}
 }
 private boolean retainBinding(@NonNull String handle,@NonNull BrowserBinding binding,@NonNull Duration lifetime){
  if(lifetime.isZero()||lifetime.isNegative()||lifetime.compareTo(Duration.ofHours(1))>0)return false;long now=this.nanoTime.getAsLong(),deadline=now+lifetime.toNanos();
  synchronized(this.retainedBindings){cleanupBindings(now);if(this.retainedBindings.size()>=128)return false;this.retainedBindings.put(handle,new RetainedBinding(binding,deadline));return true;}
 }
 private @Nullable BrowserBinding claimBinding(@NonNull String handle){long now=this.nanoTime.getAsLong();synchronized(this.retainedBindings){cleanupBindings(now);RetainedBinding retained=this.retainedBindings.remove(handle);return retained==null||retained.deadline-now<=0?null:retained.binding;}}
 private void discardBinding(@NonNull String handle){synchronized(this.retainedBindings){this.retainedBindings.remove(handle);}}
 private void cleanupBindings(long now){this.retainedBindings.values().removeIf(retained->retained.deadline-now<=0);}
 private record RetainedBinding(@NonNull BrowserBinding binding,long deadline){@Override public @NonNull String toString(){return "RetainedBinding{<redacted>}";}}
 private @NonNull String freshToken(){byte[] bytes=new byte[32];try{this.random.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}finally{Arrays.fill(bytes,(byte)0);}}
 private static boolean token(@NonNull String text){if(!text.matches("[A-Za-z0-9_-]{43}"))return false;byte[] decoded=null;try{decoded=Base64.getUrlDecoder().decode(text);return decoded.length==32&&Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(text);}catch(IllegalArgumentException malformed){return false;}finally{if(decoded!=null)Arrays.fill(decoded,(byte)0);}}
 private static void escape(@NonNull StringBuilder out,@NonNull String text){for(int i=0;i<text.length();){int c=text.codePointAt(i);i+=Character.charCount(c);String escaped=switch(c){case '&'->"&amp;";case '<'->"&lt;";case '>'->"&gt;";case '"'->"&quot;";case '\''->"&#39;";default->c<0x20||c>0x7e?"&#x"+Integer.toHexString(c)+";":Character.toString(c);};if(out.length()>RESPONSE_LIMIT-escaped.length())throw new Refused(503);out.append(escaped);}}
 private static @NonNull Map<@NonNull String,@NonNull String> headers(){return new LinkedHashMap<>(Map.of("Cache-Control","no-store","Pragma","no-cache","Content-Type","text/html; charset=UTF-8","Referrer-Policy","no-referrer","X-Content-Type-Options","nosniff","Content-Security-Policy","default-src 'none'; base-uri 'none'; frame-ancestors 'none'"));}
 private static @NonNull Reply fixed(int status,@NonNull String message,@NonNull List<@NonNull String> cookies){return new Reply(status,headers(),cookies,message.getBytes(StandardCharsets.US_ASCII));}
 private static @NonNull String cookie(@NonNull String name,@NonNull String value,long age){return name+'='+value+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="+age;}
 private static @NonNull String clear(@NonNull String name){return cookie(name,"",0);}
 private static @NonNull List<@NonNull String> values(@NonNull Request request,@NonNull String name){return request.headers().getOrDefault(name,List.of());}
 private static @NonNull String one(@NonNull Request request,@NonNull String name){List<String> values=values(request,name);if(values.size()!=1)throw new Refused(400);return values.get(0);}
 private static @Nullable String cookieValue(@NonNull Request request,@NonNull String name){String selected=null;int count=0;for(String line:values(request,"cookie"))for(String field:line.split(";",-1)){if(++count>32)throw new Refused(400);String pair=field.stripLeading();int equal=pair.indexOf('=');if(equal<1)throw new Refused(400);String key=pair.substring(0,equal),value=pair.substring(equal+1);if(!key.matches("[!#$%&'*+.^_`|~A-Za-z0-9-]+")||!value.chars().allMatch(c->c==0x21||c>=0x23&&c<=0x2b||c>=0x2d&&c<=0x3a||c>=0x3c&&c<=0x5b||c>=0x5d&&c<=0x7e))throw new Refused(400);if(key.equals(name)){if(selected!=null)throw new Refused(400);selected=value;}}return selected;}
 private static void ascii(@NonNull String value,int maximum){requireNonNull(value);if(value.isEmpty()||value.length()>maximum||!value.chars().allMatch(c->c>=0x21&&c<=0x7e))throw new IllegalArgumentException("Bounded ASCII value required");}
 private static final class Refused extends RuntimeException {private static final long serialVersionUID=1L;final int status;Refused(int status){super("Request denied",null,false,false);this.status=status;}}
 static final class Budget {private final @NonNull LongSupplier time;private final long end;Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(4).toNanos();}void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Refused(503);}@NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}}
 @Override public @NonNull String toString(){return "LocalFirstLogout{<redacted>}";}
}
