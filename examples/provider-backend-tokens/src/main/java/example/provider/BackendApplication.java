/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.provider;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;
import static java.util.Objects.requireNonNull;

/** Shared application recipe for R9/R10. Transport adapters retain raw multiplicity and input bounds. */
@ThreadSafe
public final class BackendApplication {
    public static final @NonNull String LOGIN_COOKIE="__Host-provider-login",SESSION_COOKIE="__Host-provider-session";
    private static final long LOGIN_NANOS=Duration.ofMinutes(5).toNanos(),SESSION_NANOS=Duration.ofMinutes(30).toNanos();
    public enum Provider { GOOGLE,APPLE }
    public record Configuration(@NonNull URI origin,@NonNull String googleClientId,@NonNull String appleAppId,
            @Nullable String googleHostedDomain,int maximumEntries,long maximumStateBytes){
        public Configuration{
            requireNonNull(origin);checked(googleClientId,255);checked(appleAppId,255);
            if(!"https".equals(origin.getScheme())||origin.getHost()==null||origin.getRawUserInfo()!=null||origin.getRawQuery()!=null||origin.getRawFragment()!=null
                    ||!(origin.getRawPath().isEmpty()||origin.getRawPath().equals("/"))||origin.getPort()==0||origin.getPort()>65535)throw new IllegalArgumentException("Trusted HTTPS origin required");
            origin=URI.create("https://"+origin.getRawAuthority().toLowerCase(Locale.ROOT));
            if(googleHostedDomain!=null&&!googleHostedDomain.matches("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"))throw new IllegalArgumentException("Exact hosted domain required");
            if(maximumEntries<1||maximumEntries>1024||maximumStateBytes<1||maximumStateBytes>1_048_576)throw new IllegalArgumentException("Invalid state bounds");
        }
        @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
    }
    public record Account(@NonNull String id,@NonNull String tenant){
        public Account{if(!id.matches("[A-Za-z0-9_-]{1,64}")||!tenant.matches("[A-Za-z0-9_-]{1,64}"))throw new IllegalArgumentException("Bounded local account IDs required");}
        @Override public @NonNull String toString(){return "Account{<redacted>}";}
    }
    /** Implement both callbacks against current account/tenant/ownership policy; never map by email. */
    public interface Accounts {
        @NonNull Optional<@NonNull Account> findAndAuthorizeLogin(@NonNull String issuer,@NonNull String subject,@NonNull Duration remaining)throws Exception;
        boolean authorize(@NonNull Account account,@NonNull String tenant,@NonNull String accountId,@NonNull Duration remaining)throws Exception;
    }
    /** Application abuse gate, using trusted transport peer context rather than forwarded request claims. */
    @FunctionalInterface public interface Admission { boolean allow(@NonNull Provider provider,@NonNull String peerKey,@NonNull Duration remaining)throws Exception; }
    public record Request(@NonNull String method,@NonNull String path,@Nullable String rawQuery,
            @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,byte @NonNull [] body,
            boolean discarded,boolean trustedHttps,@NonNull String peerKey){
        public Request{
            requireNonNull(method);requireNonNull(path);requireNonNull(headers);requireNonNull(body);checked(peerKey,128);
            if(body.length>32768||headers.size()>32||path.length()>1024)throw new IllegalArgumentException("Bounded complete request required");
            Map<String,List<String>> copy=new LinkedHashMap<>();long size=0;
            for(var item:headers.entrySet()){
                String name=item.getKey().toLowerCase(Locale.ROOT);if(!name.matches("[a-z0-9-]{1,64}"))throw new IllegalArgumentException("Invalid header");
                List<String> values=copy.computeIfAbsent(name,ignored->new ArrayList<>());
                for(String value:item.getValue()){if(value.length()>4096||!value.chars().allMatch(c->c>=0x20&&c<=0x7e))throw new IllegalArgumentException("Invalid header");size+=name.length()+value.length();values.add(value);}
            }
            if(size>8192||copy.values().stream().mapToInt(List::size).sum()>32)throw new IllegalArgumentException("Header budget exceeded");
            Map<String,List<String>> immutable=new LinkedHashMap<>();copy.forEach((name,values)->immutable.put(name,List.copyOf(values)));headers=Map.copyOf(immutable);body=body.clone();
        }
        @Override public byte @NonNull [] body(){return this.body.clone();}
        @Override public @NonNull String toString(){return "Request{<redacted>}";}
    }
    /** Only application session/challenge values are emitted; no provider token or claims are returned. */
    public record Reply(int status,@NonNull Map<@NonNull String,@NonNull String> fields,@NonNull List<@NonNull String> cookies){
        public Reply{fields=Map.copyOf(fields);cookies=List.copyOf(cookies);}
        public @NonNull Map<@NonNull String,@NonNull String> headers(){return Map.of("Cache-Control","no-store","Pragma","no-cache","Referrer-Policy","no-referrer","Content-Type","application/json; charset=UTF-8","X-Content-Type-Options","nosniff");}
        @Override public @NonNull String toString(){return "Reply{status="+status+", values=<redacted>}";}
    }
    private final @NonNull Configuration config;
    private final @NonNull Accounts accounts;
    private final @NonNull Admission admission;
    private final @NonNull Clock clock;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull ProviderTokens tokens;
    private final @NonNull SecureRandom random;
    private final @NonNull Semaphore work=new Semaphore(8);
    private final @NonNull Map<@NonNull String,@NonNull Attempt> attempts=new LinkedHashMap<>();
    private final @NonNull Map<@NonNull String,@NonNull Session> sessions=new LinkedHashMap<>();
    private long stateBytes;
    /** Production sources use only fixed published provider URLs and explicit RS256 policy. */
    public static @NonNull BackendApplication create(@NonNull Configuration config,@NonNull Accounts accounts,@NonNull Admission admission){
        Clock clock=Clock.systemUTC();return new BackendApplication(config,accounts,admission,clock,System::nanoTime,ProviderTokens.production(config,clock));
    }
    BackendApplication(@NonNull Configuration config,@NonNull Accounts accounts,@NonNull Admission admission,@NonNull Clock clock,
            @NonNull LongSupplier nanoTime,@NonNull ProviderTokens tokens){this(config,accounts,admission,clock,nanoTime,tokens,new SecureRandom());}
    BackendApplication(@NonNull Configuration config,@NonNull Accounts accounts,@NonNull Admission admission,@NonNull Clock clock,
            @NonNull LongSupplier nanoTime,@NonNull ProviderTokens tokens,@NonNull SecureRandom random){this.config=requireNonNull(config);this.accounts=requireNonNull(accounts);this.admission=requireNonNull(admission);this.clock=requireNonNull(clock);this.nanoTime=requireNonNull(nanoTime);this.tokens=requireNonNull(tokens);this.random=requireNonNull(random);}
    /** Invoke once per bounded request; failures do not retry provider or application operations. */
    public @NonNull Reply handle(@NonNull Request request){
        Budget budget=new Budget(this.nanoTime);boolean googleCompletion=request.path().equals("/google/complete");
        try{
            budget.check();
            if(!request.trustedHttps()||request.discarded()||request.rawQuery()!=null||!header(request,"host").equalsIgnoreCase(this.config.origin().getRawAuthority()))throw new Denied(400);
            return switch(request.path()){
                case "/google/begin"->begin(request,Provider.GOOGLE,budget);
                case "/apple/begin"->begin(request,Provider.APPLE,budget);
                case "/google/complete"->complete(request,Provider.GOOGLE,budget);
                case "/apple/complete"->complete(request,Provider.APPLE,budget);
                case "/session"->status(request,false);
                case "/native/session"->status(request,true);
                case "/logout"->logout(request,false);
                case "/native/logout"->logout(request,true);
                default->{if(request.path().startsWith("/account/")||request.path().startsWith("/native/account/"))yield account(request,budget);yield error(404,List.of());}
            };
        }catch(Denied denial){return error(denial.status,googleCompletion?List.of(cookie(LOGIN_COOKIE,"",0,true)):List.of());}
        catch(Exception failure){return error(503,googleCompletion?List.of(cookie(LOGIN_COOKIE,"",0,true)):List.of());}
    }
    private @NonNull Reply begin(@NonNull Request request,@NonNull Provider provider,@NonNull Budget budget)throws Exception{
        post(request);Map<String,String> form=form(request);if(!"1".equals(form.get("begin")))throw new Denied(400);
        boolean nativeFlow=provider==Provider.APPLE;if(nativeFlow)nativeRequest(request);else sameOrigin(request);
        Session old=session(request,nativeFlow,false);
        if(old!=null&&!nativeFlow&&!ProviderTokens.same(old.csrf,form.get("csrf")))throw new Denied(403);
        if(!this.admission.allow(provider,request.peerKey(),budget.remaining()))throw new Denied(429);budget.check();
        String id=token(),binding=token(),nonce=token();Instant now=this.clock.instant();long elapsed=this.nanoTime.getAsLong();
        synchronized(this.sessions){
            cleanup(now,elapsed);if(old!=null&&!current(old,now,elapsed))throw new Denied(401);
            Attempt attempt=new Attempt(id,binding,nonce,provider,old,now,elapsed+LOGIN_NANOS);
            if(this.attempts.size()>=this.config.maximumEntries()||attempt.charge>this.config.maximumStateBytes()-this.stateBytes||this.attempts.containsKey(id))throw new Denied(503);
            budget.check();this.attempts.put(id,attempt);this.stateBytes+=attempt.charge;
        }
        return nativeFlow?new Reply(200,Map.of("request_id",id,"request_binding",binding,"nonce",nonce),List.of())
                :new Reply(200,Map.of("nonce",nonce),List.of(cookie(LOGIN_COOKIE,id+'.'+binding,300,true)));
    }
    private @NonNull Reply complete(@NonNull Request request,@NonNull Provider provider,@NonNull Budget budget)throws Exception{
        post(request);Map<String,String> form=form(request);boolean nativeFlow=provider==Provider.APPLE;
        String id,binding,compact;
        if(nativeFlow){nativeRequest(request);id=field(form,"request_id",43);binding=field(form,"request_binding",43);compact=field(form,"identity_token",8192);}
        else{
            if(!values(request,"authorization").isEmpty())throw new Denied(400);
            List<String> origin=values(request,"origin");if(!origin.isEmpty()&&!origin.equals(List.of(this.config.origin().toString()))&&!origin.equals(List.of(ProviderTokens.GOOGLE)))throw new Denied(403);
            String csrfCookie=cookieValue(request,"g_csrf_token"),csrfBody=field(form,"g_csrf_token",512);
            if(csrfCookie==null||!ProviderTokens.same(csrfCookie,csrfBody))throw new Denied(403);
            String pending=cookieValue(request,LOGIN_COOKIE);if(pending==null||!pending.matches("[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}"))throw new Denied(401);
            id=pending.substring(0,43);binding=pending.substring(44);compact=field(form,"credential",8192);
        }
        if(!id.matches("[A-Za-z0-9_-]{43}")||!binding.matches("[A-Za-z0-9_-]{43}"))throw new Denied(401);
        if(!this.work.tryAcquire())throw new Denied(503);
        Attempt attempt=null;
        try{
            synchronized(this.sessions){
                Attempt selected=this.attempts.get(id);Instant now=this.clock.instant();long elapsed=this.nanoTime.getAsLong();
                if(selected==null||selected.claimed||selected.provider!=provider||!ProviderTokens.same(selected.binding,binding)||!selected.live(now,elapsed))throw new Denied(401);
                selected.claimed=true;attempt=selected;
            }
            ProviderTokens.Identity identity=this.tokens.validate(provider,compact,attempt.nonce,budget);if(identity==null)throw new Denied(401);
            Optional<Account> found=this.accounts.findAndAuthorizeLogin(identity.issuer(),identity.subject(),budget.remaining());budget.check();
            if(found.isEmpty())throw new Denied(403);Account account=found.orElseThrow();String sid=token(),csrf=token();
            synchronized(this.sessions){
                Instant now=this.clock.instant();long elapsed=this.nanoTime.getAsLong();
                if(this.attempts.get(id)!=attempt||!attempt.live(now,elapsed)||now.isBefore(identity.issued())||!now.isBefore(identity.expires())||(attempt.old!=null&&!current(attempt.old,now,elapsed)))throw new Denied(401);
                Session replacement=new Session(sid,csrf,account,nativeFlow,now,elapsed+SESSION_NANOS);
                long released=attempt.charge+(attempt.old==null?0:attempt.old.charge);
                int count=this.sessions.size()-(attempt.old==null?0:1)+1;
                if(count>this.config.maximumEntries()||replacement.charge>this.config.maximumStateBytes()-(this.stateBytes-released)||this.sessions.containsKey(sid)||sid.equals(id))throw new Denied(503);
                budget.check();discard(attempt);if(attempt.old!=null){this.sessions.remove(attempt.old.id);this.stateBytes-=attempt.old.charge;}
                this.sessions.put(sid,replacement);this.stateBytes+=replacement.charge;
            }
            return nativeFlow?new Reply(200,Map.of("session_token",sid,"expires_in","1800"),List.of())
                    :new Reply(200,Map.of("authenticated","true"),List.of(cookie(SESSION_COOKIE,sid,1800,false),cookie(LOGIN_COOKIE,"",0,true)));
        }finally{
            synchronized(this.sessions){if(attempt!=null)discard(attempt);}this.work.release();
        }
    }
    private @NonNull Reply status(@NonNull Request request,boolean nativeFlow){
        get(request);if(nativeFlow)nativeRequest(request);Session session=session(request,nativeFlow,false);
        return new Reply(200,session==null?Map.of("authenticated","false"):nativeFlow?Map.of("authenticated","true"):Map.of("authenticated","true","csrf",session.csrf),List.of());
    }
    private @NonNull Reply logout(@NonNull Request request,boolean nativeFlow){
        post(request);Map<String,String> body=form(request);if(nativeFlow)nativeRequest(request);else sameOrigin(request);
        Session session=session(request,nativeFlow,true);if(!nativeFlow&&!ProviderTokens.same(requireNonNull(session).csrf,body.get("csrf")))throw new Denied(403);
        synchronized(this.sessions){if(this.sessions.remove(requireNonNull(session).id,session))this.stateBytes-=session.charge;}
        return new Reply(200,Map.of("authenticated","false"),nativeFlow?List.of():List.of(cookie(SESSION_COOKIE,"",0,false),cookie(LOGIN_COOKIE,"",0,true)));
    }
    private @NonNull Reply account(@NonNull Request request,@NonNull Budget budget)throws Exception{
        get(request);boolean nativeFlow=request.path().startsWith("/native/");if(nativeFlow)nativeRequest(request);
        String[] path=request.path().split("/",-1);int offset=nativeFlow?3:2;if(path.length!=offset+2)throw new Denied(404);
        Session selected=requireNonNull(session(request,nativeFlow,true));String tenant=path[offset],id=path[offset+1];
        if(!selected.account.tenant().equals(tenant)||!selected.account.id().equals(id))throw new Denied(403);
        if(!this.work.tryAcquire())throw new Denied(503);
        try{
            if(!this.accounts.authorize(selected.account,tenant,id,budget.remaining()))throw new Denied(403);budget.check();
            synchronized(this.sessions){if(!current(selected,this.clock.instant(),this.nanoTime.getAsLong()))throw new Denied(401);}
            return new Reply(200,Map.of("access","permitted"),List.of());
        }finally{this.work.release();}
    }
    private @Nullable Session session(@NonNull Request request,boolean nativeFlow,boolean required){
        String id;
        if(nativeFlow){List<String> auth=values(request,"authorization");if(auth.isEmpty()){if(required)throw new Denied(401);return null;}if(auth.size()!=1||!auth.get(0).matches("Bearer [A-Za-z0-9_-]{43}"))throw new Denied(401);id=auth.get(0).substring(7);}
        else{if(!values(request,"authorization").isEmpty())throw new Denied(400);id=cookieValue(request,SESSION_COOKIE);if(id==null){if(required)throw new Denied(401);return null;}if(!id.matches("[A-Za-z0-9_-]{43}"))throw new Denied(401);}
        synchronized(this.sessions){Session selected=this.sessions.get(id);if(selected==null||selected.nativeFlow!=nativeFlow||!current(selected,this.clock.instant(),this.nanoTime.getAsLong())){if(required)throw new Denied(401);return null;}return selected;}
    }
    private boolean current(@NonNull Session selected,@NonNull Instant now,long elapsed){return this.sessions.get(selected.id)==selected&&!now.isBefore(selected.created)&&now.isBefore(selected.created.plusSeconds(1800))&&selected.expiresNanos-elapsed>0;}
    private void discard(@NonNull Attempt attempt){if(this.attempts.remove(attempt.id,attempt))this.stateBytes-=attempt.charge;}
    private void cleanup(@NonNull Instant now,long elapsed){
        List<Attempt> keepAttempts=new ArrayList<>();int inspected=0;
        for(var iterator=this.attempts.values().iterator();iterator.hasNext()&&inspected++<16;){Attempt value=iterator.next();iterator.remove();if(value.live(now,elapsed))keepAttempts.add(value);else this.stateBytes-=value.charge;}
        for(Attempt value:keepAttempts)this.attempts.put(value.id,value);
        List<Session> keepSessions=new ArrayList<>();inspected=0;
        for(var iterator=this.sessions.values().iterator();iterator.hasNext()&&inspected++<16;){Session value=iterator.next();iterator.remove();if(!now.isBefore(value.created.plusSeconds(1800))||value.expiresNanos-elapsed<=0)this.stateBytes-=value.charge;else keepSessions.add(value);}
        for(Session value:keepSessions)this.sessions.put(value.id,value);
    }
    private static final class Attempt{
        final @NonNull String id,binding,nonce;final @NonNull Provider provider;final @Nullable Session old;final @NonNull Instant created;final long expiresNanos,charge;boolean claimed;
        Attempt(@NonNull String id,@NonNull String binding,@NonNull String nonce,@NonNull Provider provider,@Nullable Session old,@NonNull Instant created,long expiresNanos){this.id=id;this.binding=binding;this.nonce=nonce;this.provider=provider;this.old=old;this.created=created;this.expiresNanos=expiresNanos;this.charge=129+(old==null?0:old.charge);}
        boolean live(@NonNull Instant now,long elapsed){return !now.isBefore(this.created)&&now.isBefore(this.created.plusSeconds(300))&&this.expiresNanos-elapsed>0;}
        @Override public @NonNull String toString(){return "Attempt{<redacted>}";}
    }
    private static final class Session{
        final @NonNull String id,csrf;final @NonNull Account account;final boolean nativeFlow;final @NonNull Instant created;final long expiresNanos,charge;
        Session(@NonNull String id,@NonNull String csrf,@NonNull Account account,boolean nativeFlow,@NonNull Instant created,long expiresNanos){this.id=id;this.csrf=csrf;this.account=account;this.nativeFlow=nativeFlow;this.created=created;this.expiresNanos=expiresNanos;this.charge=id.length()+csrf.length()+account.id().length()+account.tenant().length();}
        @Override public @NonNull String toString(){return "Session{<redacted>}";}
    }
    static final class Budget{
        private final @NonNull LongSupplier time;private final long end;
        Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(4).toNanos();}
        void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Denied(503);}
        void beforeKeyWork(){check();if(this.end-this.time.getAsLong()<Duration.ofSeconds(1).toNanos())throw new Denied(503);}
        @NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}
    }
    private static final class Denied extends RuntimeException{private static final long serialVersionUID=1L;final int status;Denied(int status){super("Request denied");this.status=status;}}
    private static @NonNull Reply error(int status,@NonNull List<@NonNull String> cookies){return new Reply(status,Map.of("error",status>=500?"Temporarily unavailable":"Request denied"),cookies);}
    private static void checked(@NonNull String value,int maximum){if(value.isEmpty()||value.length()>maximum||!value.chars().allMatch(c->c>=0x21&&c<=0x7e))throw new IllegalArgumentException("Bounded ASCII configuration required");}
    private static void post(@NonNull Request request){if(!request.method().equals("POST"))throw new Denied(405);String type=header(request,"content-type").replace(" ","");if(!type.equalsIgnoreCase("application/x-www-form-urlencoded")&&!type.equalsIgnoreCase("application/x-www-form-urlencoded;charset=UTF-8"))throw new Denied(415);}
    private static void get(@NonNull Request request){if(!request.method().equals("GET")||request.body.length!=0)throw new Denied(405);}
    private void sameOrigin(@NonNull Request request){if(!values(request,"origin").equals(List.of(this.config.origin().toString())))throw new Denied(403);}
    private static void nativeRequest(@NonNull Request request){if(!values(request,"origin").isEmpty()||!values(request,"cookie").isEmpty())throw new Denied(403);}
    private static @NonNull List<@NonNull String> values(@NonNull Request request,@NonNull String name){return request.headers().getOrDefault(name,List.of());}
    private static @NonNull String header(@NonNull Request request,@NonNull String name){List<String> values=values(request,name);if(values.size()!=1)throw new Denied(400);return values.get(0);}
    private static @Nullable String cookieValue(@NonNull Request request,@NonNull String name){
        String found=null;for(String line:values(request,"cookie"))for(String rawPair:line.split(";",-1)){
            String pair=rawPair.stripLeading();int equal=pair.indexOf('=');if(equal<=0)throw new Denied(400);String key=pair.substring(0,equal),value=pair.substring(equal+1);
            if(key.equals(name)){if(found!=null||value.length()>512||!value.chars().allMatch(c->c==0x21||(c>=0x23&&c<=0x2b)||(c>=0x2d&&c<=0x3a)||(c>=0x3c&&c<=0x5b)||(c>=0x5d&&c<=0x7e)))throw new Denied(400);found=value;}
        }return found;
    }
    private static @NonNull String field(@NonNull Map<@NonNull String,@NonNull String> form,@NonNull String name,int maximum){String value=form.get(name);if(value==null||value.isEmpty()||value.length()>maximum)throw new Denied(400);return value;}
    private static @NonNull Map<@NonNull String,@NonNull String> form(@NonNull Request request){
        for(byte value:request.body)if(value<0x20||value>0x7e)throw new Denied(400);
        String raw=new String(request.body,StandardCharsets.US_ASCII);if(raw.isEmpty())return Map.of();String[] parts=raw.split("&",-1);if(parts.length>16)throw new Denied(400);Map<String,String> result=new LinkedHashMap<>();
        for(String part:parts){int equal=part.indexOf('=');if(equal<1)throw new Denied(400);String name=decode(part.substring(0,equal)),value=decode(part.substring(equal+1));if(!name.matches("[A-Za-z0-9_]{1,64}")||value.length()>8192||result.putIfAbsent(name,value)!=null)throw new Denied(400);}
        return Map.copyOf(result);
    }
    private static @NonNull String decode(@NonNull String encoded){
        ByteArrayOutputStream bytes=new ByteArrayOutputStream(encoded.length());for(int i=0;i<encoded.length();i++){char value=encoded.charAt(i);if(value=='+')bytes.write(' ');else if(value=='%'){if(i+2>=encoded.length())throw new Denied(400);int high=Character.digit(encoded.charAt(++i),16),low=Character.digit(encoded.charAt(++i),16);if(high<0||low<0)throw new Denied(400);bytes.write(high*16+low);}else bytes.write(value);}
        try{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString();}catch(CharacterCodingException failure){throw new Denied(400);}
    }
    private @NonNull String token(){byte[] bytes=new byte[32];this.random.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static @NonNull String cookie(@NonNull String name,@NonNull String value,int age,boolean pending){return name+'='+value+"; Path=/; Secure; HttpOnly; SameSite="+(pending?"None":"Lax")+"; Max-Age="+age;}
    synchronized long retainedBytes(){synchronized(this.sessions){return this.stateBytes;}}
    int retainedSessions(){synchronized(this.sessions){return this.sessions.size();}}
    int retainedAttempts(){synchronized(this.sessions){return this.attempts.size();}}
    @Override public @NonNull String toString(){return "BackendApplication{<redacted>}";}
}
