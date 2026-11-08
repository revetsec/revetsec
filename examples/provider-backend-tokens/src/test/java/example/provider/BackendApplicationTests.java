/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.provider;

import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic synthetic signed tokens; no hosted Google/Apple account or native SDK run. */
public final class BackendApplicationTests {
    private static final @NonNull URI ORIGIN=URI.create("https://app.example");
    private static final @NonNull Instant NOW=Instant.parse("2026-11-05T12:00:00Z");
    private static final @NonNull KeyPair GOOGLE=key("TEST-ONLY-google-key"),APPLE=key("TEST-ONLY-apple-key"),OTHER=key("TEST-ONLY-untrusted-key");
    private static @NonNull SecureRandom random(@NonNull String seed){try{SecureRandom random=SecureRandom.getInstance("SHA1PRNG");random.setSeed(seed.getBytes(StandardCharsets.US_ASCII));return random;}catch(GeneralSecurityException failure){throw new AssertionError(failure);}}
    private static @NonNull KeyPair key(@NonNull String seed){try{KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048,random(seed));return generator.generateKeyPair();}catch(GeneralSecurityException failure){throw new AssertionError(failure);}}
    private static @NonNull String b64(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static @NonNull String unsigned(java.math.@NonNull BigInteger number){byte[] bytes=number.toByteArray();return b64(bytes.length>1&&bytes[0]==0?Arrays.copyOfRange(bytes,1,bytes.length):bytes);}
    private static @NonNull String jwks(@NonNull KeyPair pair,@NonNull String kid){RSAPublicKey key=(RSAPublicKey)pair.getPublic();return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\""+kid+"\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""+unsigned(key.getModulus())+"\",\"e\":\""+unsigned(key.getPublicExponent())+"\"}]}";}
    private static @NonNull String json(@NonNull Map<@NonNull String,@NonNull JsonValue> values){return JsonObject.fromMembers(values).toJson();}
    private static @NonNull JsonString str(@NonNull String value){return JsonString.fromValue(value);}
    private static @NonNull JsonNumber num(long value){return JsonNumber.fromValue(value);}
    private static @NonNull String signed(@NonNull KeyPair key,@NonNull String header,@NonNull String payload){try{String input=b64(header.getBytes(StandardCharsets.UTF_8))+'.'+b64(payload.getBytes(StandardCharsets.UTF_8));Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(key.getPrivate());signature.update(input.getBytes(StandardCharsets.US_ASCII));return input+'.'+b64(signature.sign());}catch(GeneralSecurityException failure){throw new AssertionError(failure);}}
    private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values){return values.entrySet().stream().map(e->URLEncoder.encode(e.getKey(),StandardCharsets.UTF_8)+'='+URLEncoder.encode(e.getValue(),StandardCharsets.UTF_8)).collect(java.util.stream.Collectors.joining("&"));}
    private static BackendApplication.@NonNull Request request(@NonNull String method,@NonNull String path,@NonNull String body,
            @Nullable String cookies,@Nullable String bearer,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> overrides){
        Map<String,List<String>> headers=new LinkedHashMap<>();headers.put("Host",List.of("app.example"));headers.put("Content-Type",List.of("application/x-www-form-urlencoded"));
        if(path.startsWith("/google/")||path.equals("/logout"))headers.put("Origin",List.of(ORIGIN.toString()));
        if(cookies!=null)headers.put("Cookie",List.of(cookies));if(bearer!=null)headers.put("Authorization",List.of("Bearer "+bearer));headers.putAll(overrides);
        return new BackendApplication.Request(method,path,null,headers,body.getBytes(StandardCharsets.UTF_8),false,true,"TEST-ONLY-peer");
    }
    private static @NonNull String cookie(BackendApplication.@NonNull Reply reply,@NonNull String name){return reply.cookies().stream().filter(v->v.startsWith(name+'=')).map(v->v.substring(0,v.indexOf(';'))).findFirst().orElseThrow();}
    private static final class Time extends Clock{
        private final @NonNull AtomicReference<@NonNull Instant> now=new AtomicReference<>(NOW);
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
        @Override public @NonNull Instant instant(){return this.now.get();}
    }
    private static final class Fixture implements AutoCloseable{
        final @NonNull Time clock=new Time();final @NonNull AtomicLong nanos=new AtomicLong(100_000);
        final @NonNull AtomicInteger googleFetches=new AtomicInteger(),appleFetches=new AtomicInteger(),attackerFetches=new AtomicInteger(),lookups=new AtomicInteger(),authorization=new AtomicInteger();
        final @NonNull AtomicBoolean admission=new AtomicBoolean(true),allowed=new AtomicBoolean(true),signIn=new AtomicBoolean(true);
        final @NonNull List<@NonNull Duration> budgets=new CopyOnWriteArrayList<>();
        final @NonNull Map<@NonNull String,BackendApplication.@NonNull Account> accounts=new ConcurrentHashMap<>();
        volatile @NonNull Runnable onLookup=()->{},onAuthorize=()->{};volatile int jwksStatus=200;volatile @NonNull String lastIssuer="",lastSubject="";
        final @NonNull HttpServer server;final @NonNull ExecutorService http=Executors.newFixedThreadPool(2);
        final BackendApplication.@NonNull Configuration config;final @NonNull BackendApplication app;
        Fixture()throws Exception{this(null,128,65536);}
        Fixture(@Nullable String domain,int entries,long bytes)throws Exception{
            this.server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);this.server.setExecutor(this.http);
            this.server.createContext("/google",exchange->{this.googleFetches.incrementAndGet();serve(exchange,jwks(GOOGLE,"google"));});
            this.server.createContext("/apple",exchange->{this.appleFetches.incrementAndGet();serve(exchange,jwks(APPLE,"apple"));});
            this.server.createContext("/attacker",exchange->{this.attackerFetches.incrementAndGet();serve(exchange,jwks(OTHER,"attacker"));});this.server.start();
            this.config=new BackendApplication.Configuration(ORIGIN,"web-client.apps.googleusercontent.com","com.example.native",domain,entries,bytes);
            this.accounts.put(ProviderTokens.GOOGLE+"|google-sub",new BackendApplication.Account("alice","tenant"));this.accounts.put(ProviderTokens.APPLE+"|apple-sub",new BackendApplication.Account("alice","tenant"));
            BackendApplication.Accounts backend=new BackendApplication.Accounts(){
                @Override public @NonNull Optional<BackendApplication.@NonNull Account> findAndAuthorizeLogin(@NonNull String issuer,@NonNull String subject,@NonNull Duration remaining){lookups.incrementAndGet();lastIssuer=issuer;lastSubject=subject;budgets.add(remaining);onLookup.run();return signIn.get()?Optional.ofNullable(accounts.get(issuer+'|'+subject)):Optional.empty();}
                @Override public boolean authorize(BackendApplication.@NonNull Account account,@NonNull String tenant,@NonNull String id,@NonNull Duration remaining){authorization.incrementAndGet();budgets.add(remaining);onAuthorize.run();return allowed.get()&&account.tenant().equals(tenant)&&account.id().equals(id);}
            };
            ProviderTokens tokens=new ProviderTokens(this.config,source("google"),source("google"),source("apple"),this.clock);
            this.app=new BackendApplication(this.config,backend,(provider,peer,remaining)->this.admission.get(),this.clock,this.nanos::get,tokens,random("TEST-ONLY-request-sequence"));
        }
        private void serve(com.sun.net.httpserver.@NonNull HttpExchange exchange,@NonNull String keys)throws java.io.IOException{byte[] body=keys.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json");exchange.getResponseHeaders().set("Cache-Control","max-age=60");exchange.getResponseHeaders().set("Date",DateTimeFormatter.RFC_1123_DATE_TIME.format(this.clock.instant().atZone(ZoneOffset.UTC)));exchange.sendResponseHeaders(this.jwksStatus,body.length);try(var stream=exchange.getResponseBody()){stream.write(body);}exchange.close();}
        private @NonNull RemoteJwksSource source(@NonNull String path){return RemoteJwksSource.withUri(uri(path)).allowInsecureLoopback(true).clock(this.clock).requestTimeout(Duration.ofSeconds(1)).maximumStaleness(Duration.ZERO).maximumKeys(8).build();}
        @NonNull URI uri(@NonNull String path){return URI.create("http://127.0.0.1:"+this.server.getAddress().getPort()+'/'+path);}
        BackendApplication.@NonNull Reply begin(BackendApplication.@NonNull Provider provider){return this.app.handle(request("POST",provider==BackendApplication.Provider.GOOGLE?"/google/begin":"/apple/begin","begin=1",null,null,Map.of()));}
        @NonNull Map<@NonNull String,@NonNull JsonValue> claims(BackendApplication.@NonNull Provider provider,BackendApplication.@NonNull Reply begin){
            Map<String,JsonValue> claims=new LinkedHashMap<>();boolean google=provider==BackendApplication.Provider.GOOGLE;
            claims.put("iss",str(google?ProviderTokens.GOOGLE:ProviderTokens.APPLE));claims.put("aud",str(google?this.config.googleClientId():this.config.appleAppId()));claims.put("sub",str(google?"google-sub":"apple-sub"));claims.put("iat",num(NOW.getEpochSecond()));claims.put("exp",num(NOW.plusSeconds(3600).getEpochSecond()));claims.put("nonce",str(begin.fields().get("nonce")));return claims;
        }
        @NonNull String token(BackendApplication.@NonNull Provider provider,BackendApplication.@NonNull Reply begin,@NonNull Consumer<@NonNull Map<@NonNull String,@NonNull JsonValue>> mutation){var claims=claims(provider,begin);mutation.accept(claims);return signed(provider==BackendApplication.Provider.GOOGLE?GOOGLE:APPLE,"{\"alg\":\"RS256\",\"kid\":\""+(provider==BackendApplication.Provider.GOOGLE?"google":"apple")+"\"}",json(claims));}
        BackendApplication.@NonNull Request completion(BackendApplication.@NonNull Provider provider,BackendApplication.@NonNull Reply begin,@NonNull String token){
            if(provider==BackendApplication.Provider.GOOGLE)return request("POST","/google/complete",form(Map.of("credential",token,"g_csrf_token","TEST-ONLY-csrf")),cookie(begin,BackendApplication.LOGIN_COOKIE)+"; g_csrf_token=TEST-ONLY-csrf",null,Map.of());
            return request("POST","/apple/complete",form(Map.of("request_id",begin.fields().get("request_id"),"request_binding",begin.fields().get("request_binding"),"identity_token",token)),null,null,Map.of());
        }
        BackendApplication.@NonNull Reply login(BackendApplication.@NonNull Provider provider)throws Exception{var begin=begin(provider);assertEquals(200,begin.status());return this.app.handle(completion(provider,begin,token(provider,begin,claims->{})));}
        @Override public void close(){this.server.stop(0);this.http.shutdownNow();try{assertTrue(this.http.awaitTermination(3,TimeUnit.SECONDS));}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}}
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> googleIssuerAliasesAndApplicationAuthorization(){
        List<DynamicTest> tests=new ArrayList<>();for(String issuer:List.of(ProviderTokens.GOOGLE,ProviderTokens.GOOGLE_LEGACY))tests.add(DynamicTest.dynamicTest(issuer,()->{try(Fixture f=new Fixture()){
            assertEquals(0,f.googleFetches.get());var start=f.begin(BackendApplication.Provider.GOOGLE);String jwt=f.token(BackendApplication.Provider.GOOGLE,start,c->c.put("iss",str(issuer)));var result=f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,start,jwt));assertEquals(200,result.status());assertEquals(ProviderTokens.GOOGLE,f.lastIssuer);assertEquals("google-sub",f.lastSubject);assertTrue(f.googleFetches.get()>0);
            String sid=cookie(result,BackendApplication.SESSION_COOKIE);assertTrue(result.cookies().stream().allMatch(c->c.contains("Secure")&&c.contains("HttpOnly")&&c.contains("Path=/")));assertEquals(200,f.app.handle(request("GET","/account/tenant/alice","",sid,null,Map.of())).status());assertEquals(403,f.app.handle(request("GET","/account/other/alice","",sid,null,Map.of())).status());assertEquals(403,f.app.handle(request("GET","/account/tenant/bob","",sid,null,Map.of())).status());f.allowed.set(false);assertEquals(403,f.app.handle(request("GET","/account/tenant/alice","",sid,null,Map.of())).status());assertTrue(f.budgets.stream().allMatch(d->!d.isNegative()&&!d.isZero()&&d.compareTo(Duration.ofSeconds(4))<=0));assertFalse(result.toString().contains(jwt));assertTrue(result.headers().get("Cache-Control").equals("no-store"));
        }}));return tests;
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> providerClaimPolicies(){
        Map<String,Consumer<Map<String,JsonValue>>> mutations=new LinkedHashMap<>();mutations.put("wrong-issuer",c->c.put("iss",str("https://attacker.invalid")));mutations.put("wrong-audience",c->c.put("aud",str("attacker-client")));mutations.put("multi-audience",c->c.put("aud",JsonArray.fromElements(List.of(c.get("aud"),str("other")))));mutations.put("wrong-presenter",c->c.put("azp",str("other-client")));mutations.put("nonstring-presenter",c->c.put("azp",num(1)));mutations.put("wrong-nonce",c->c.put("nonce",str("wrong")));mutations.put("missing-nonce",c->c.remove("nonce"));mutations.put("null-nonce",c->c.put("nonce",JsonNull.defaultInstance()));mutations.put("array-nonce",c->c.put("nonce",JsonArray.fromElements(List.of(str("bad")))));mutations.put("expired",c->c.put("exp",num(NOW.getEpochSecond())));mutations.put("future-issued",c->c.put("iat",num(NOW.plusSeconds(1).getEpochSecond())));mutations.put("not-yet-valid",c->c.put("nbf",num(NOW.plusSeconds(1).getEpochSecond())));mutations.put("missing-issued",c->c.remove("iat"));mutations.put("missing-subject",c->c.remove("sub"));mutations.put("oversized-subject",c->c.put("sub",str("s".repeat(256))));
        List<DynamicTest> result=new ArrayList<>();for(var provider:BackendApplication.Provider.values())for(var mutation:mutations.entrySet())result.add(DynamicTest.dynamicTest(provider+"/"+mutation.getKey(),()->{try(Fixture f=new Fixture()){
            var begin=f.begin(provider);String token=f.token(provider,begin,mutation.getValue());var input=f.completion(provider,begin,token);assertEquals(401,f.app.handle(input).status());assertEquals(0,f.lookups.get());assertEquals(0,f.app.retainedSessions());assertEquals(0,f.app.retainedAttempts());assertEquals(401,f.app.handle(input).status());
        }}));return result;
    }
    @Test void googleHostedDomainAndIdentityNeverComeFromEmail()throws Exception{
        try(Fixture f=new Fixture("company.example",128,65536)){
            for(String domain:List.of("missing","attacker.example")){var begin=f.begin(BackendApplication.Provider.GOOGLE);String token=f.token(BackendApplication.Provider.GOOGLE,begin,c->{c.put("email",str("alice@company.example"));if(!domain.equals("missing"))c.put("hd",str(domain));});assertEquals(401,f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,begin,token)).status());}
            var begin=f.begin(BackendApplication.Provider.GOOGLE);assertEquals(200,f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{c.put("hd",str("company.example"));c.put("email",str("unrelated@elsewhere.example"));c.put("azp",str(f.config.googleClientId()));}))).status());assertEquals("google-sub",f.lastSubject);
            begin=f.begin(BackendApplication.Provider.GOOGLE);assertEquals(403,f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{c.put("hd",str("company.example"));c.put("sub",str("new-unmapped-sub"));c.put("email",str("alice@company.example"));}))).status());assertEquals("new-unmapped-sub",f.lastSubject);
        }
    }
    @Test void appleNonceSupportAndNativeSessionBinding()throws Exception{
        try(Fixture f=new Fixture()){
            for(JsonValue supported:List.of(JsonBoolean.falseInstance(),str("true"))){var begin=f.begin(BackendApplication.Provider.APPLE);assertEquals(401,f.app.handle(f.completion(BackendApplication.Provider.APPLE,begin,f.token(BackendApplication.Provider.APPLE,begin,c->c.put("nonce_supported",supported)))).status());}
            var begin=f.begin(BackendApplication.Provider.APPLE);String token=f.token(BackendApplication.Provider.APPLE,begin,c->c.put("nonce_supported",JsonBoolean.trueInstance()));var input=f.completion(BackendApplication.Provider.APPLE,begin,token);var result=f.app.handle(input);assertEquals(200,result.status());assertTrue(result.cookies().isEmpty());String session=result.fields().get("session_token");assertEquals(200,f.app.handle(request("GET","/native/account/tenant/alice","",null,session,Map.of())).status());assertEquals(401,f.app.handle(input).status());assertEquals(401,f.app.handle(request("GET","/native/account/tenant/alice","",null,token,Map.of())).status());assertEquals(400,f.app.handle(request("GET","/account/tenant/alice","",null,session,Map.of())).status());assertEquals(403,f.app.handle(request("GET","/native/account/tenant/alice","","g_csrf_token=x",session,Map.of())).status());
            var fresh=f.begin(BackendApplication.Provider.APPLE);assertEquals(401,f.app.handle(f.completion(BackendApplication.Provider.APPLE,fresh,token)).status());
        }
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> googleRequestProtectionPrecedesKeys(){
        List<DynamicTest> result=new ArrayList<>();for(String bad:List.of("missing-cookie","missing-body","mismatch","duplicate-cookie","cookie-leading-space","cookie-trailing-space","duplicate-body","percent-duplicate","query","discarded","wrong-origin","duplicate-origin","wrong-host","duplicate-host","wrong-type","wrong-method","not-https","malformed-utf8"))result.add(DynamicTest.dynamicTest(bad,()->{try(Fixture f=new Fixture()){
            var begin=f.begin(BackendApplication.Provider.GOOGLE);String jwt=f.token(BackendApplication.Provider.GOOGLE,begin,c->{});var good=f.completion(BackendApplication.Provider.GOOGLE,begin,jwt);Map<String,List<String>> headers=new LinkedHashMap<>(good.headers());String body=new String(good.body(),StandardCharsets.US_ASCII),method="POST",query=null;boolean discarded=false,https=true;
            switch(bad){case "missing-cookie"->headers.put("cookie",List.of(cookie(begin,BackendApplication.LOGIN_COOKIE)));case "missing-body"->body=form(Map.of("credential",jwt));case "mismatch"->body=form(Map.of("credential",jwt,"g_csrf_token","different"));case "duplicate-cookie"->headers.put("cookie",List.of(headers.get("cookie").get(0)+"; g_csrf_token=TEST-ONLY-csrf"));case "cookie-leading-space"->headers.put("cookie",List.of(cookie(begin,BackendApplication.LOGIN_COOKIE)+"; g_csrf_token= TEST-ONLY-csrf"));case "cookie-trailing-space"->headers.put("cookie",List.of(cookie(begin,BackendApplication.LOGIN_COOKIE)+"; g_csrf_token=TEST-ONLY-csrf "));case "duplicate-body"->body+="&credential="+jwt;case "percent-duplicate"->body+="&g%5Fcsrf_token=TEST-ONLY-csrf";case "query"->query="credential=ignored";case "discarded"->discarded=true;case "wrong-origin"->headers.put("origin",List.of("https://attacker.invalid"));case "duplicate-origin"->headers.put("origin",List.of(ORIGIN.toString(),ORIGIN.toString()));case "wrong-host"->headers.put("host",List.of("attacker.invalid"));case "duplicate-host"->headers.put("HOST",List.of("app.example"));case "wrong-type"->headers.put("content-type",List.of("text/plain"));case "wrong-method"->method="GET";case "not-https"->https=false;case "malformed-utf8"->body+="&extra=%C3%28";default->throw new AssertionError();}
            var rejected=f.app.handle(new BackendApplication.Request(method,good.path(),query,headers,body.getBytes(StandardCharsets.US_ASCII),discarded,https,"peer"));assertTrue(rejected.status()>=400&&rejected.status()<500);assertEquals(0,f.googleFetches.get());assertEquals(0,f.lookups.get());assertEquals(0,f.app.retainedSessions());
        }}));return result;
    }
    @Test void nativeRequestBindingAndFixedAudienceCannotBeOverridden()throws Exception{
        try(Fixture f=new Fixture()){
            var begin=f.begin(BackendApplication.Provider.APPLE);String jwt=f.token(BackendApplication.Provider.APPLE,begin,c->{});var good=f.completion(BackendApplication.Provider.APPLE,begin,jwt);
            var body=new LinkedHashMap<>(Map.of("request_id",begin.fields().get("request_id"),"request_binding","x".repeat(43),"identity_token",jwt));assertEquals(401,f.app.handle(request("POST","/apple/complete",form(body),null,null,Map.of())).status());assertEquals(0,f.appleFetches.get());
            assertEquals(403,f.app.handle(request("POST","/apple/complete",new String(good.body(),StandardCharsets.US_ASCII),null,null,Map.of("Origin",List.of(ORIGIN.toString())))).status());assertEquals(0,f.appleFetches.get());
            body.put("request_binding",begin.fields().get("request_binding"));body.put("client_id","attacker-client");assertEquals(200,f.app.handle(request("POST","/apple/complete",form(body),null,null,Map.of())).status());
            begin=f.begin(BackendApplication.Provider.APPLE);String wrong=f.token(BackendApplication.Provider.APPLE,begin,c->c.put("aud",str("attacker-client")));body=new LinkedHashMap<>(Map.of("request_id",begin.fields().get("request_id"),"request_binding",begin.fields().get("request_binding"),"identity_token",wrong,"client_id",f.config.appleAppId()));assertEquals(401,f.app.handle(request("POST","/apple/complete",form(body),null,null,Map.of())).status());
        }
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> signatureAlgorithmsAndTokenKeyReferences(){
        List<DynamicTest> tests=new ArrayList<>();for(var provider:BackendApplication.Provider.values())for(String bad:List.of("signature","algorithm","jku","x5u","embedded-key","critical","duplicate-claims"))tests.add(DynamicTest.dynamicTest(provider+"/"+bad,()->{try(Fixture f=new Fixture()){
            var begin=f.begin(provider);String kid=provider==BackendApplication.Provider.GOOGLE?"google":"apple";Map<String,JsonValue> header=new LinkedHashMap<>(Map.of("alg",str("RS256"),"kid",str(kid)));String payload=json(f.claims(provider,begin));KeyPair pair=provider==BackendApplication.Provider.GOOGLE?GOOGLE:APPLE;
            switch(bad){case "signature"->pair=OTHER;case "algorithm"->header.put("alg",str("HS256"));case "jku"->header.put("jku",str(f.uri("attacker").toString()));case "x5u"->header.put("x5u",str(f.uri("attacker").toString()));case "embedded-key"->header.put("jwk",JsonObject.emptyInstance());case "critical"->header.put("crit",JsonArray.fromElements(List.of(str("other"))));case "duplicate-claims"->payload=payload.substring(0,payload.length()-1)+",\"iss\":\""+(provider==BackendApplication.Provider.GOOGLE?ProviderTokens.GOOGLE:ProviderTokens.APPLE)+"\"}";default->throw new AssertionError();}
            assertEquals(401,f.app.handle(f.completion(provider,begin,signed(pair,json(header),payload))).status());assertEquals(0,f.attackerFetches.get());assertEquals(0,f.lookups.get());assertEquals(0,f.app.retainedSessions());
        }}));return tests;
    }
    @Test void unavailableKeysAreNotInvalidTokensAndNeverRetryTheAttempt()throws Exception{
        try(Fixture f=new Fixture()){
            f.jwksStatus=503;var begin=f.begin(BackendApplication.Provider.GOOGLE);var input=f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{}));assertEquals(503,f.app.handle(input).status());assertEquals(1,f.googleFetches.get());assertEquals(0,f.lookups.get());assertEquals(401,f.app.handle(input).status());assertEquals(1,f.googleFetches.get());assertEquals(0,f.app.retainedAttempts());
        }
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> nonceRacesHaveExactlyOneWinner(){
        List<DynamicTest> tests=new ArrayList<>();for(var provider:BackendApplication.Provider.values())tests.add(DynamicTest.dynamicTest(provider.toString(),()->{try(Fixture f=new Fixture()){
            var begin=f.begin(provider);var input=f.completion(provider,begin,f.token(provider,begin,c->{}));ExecutorService workers=Executors.newFixedThreadPool(2);CountDownLatch start=new CountDownLatch(1);
            try{List<Future<Integer>> attempts=new ArrayList<>();for(int i=0;i<2;i++)attempts.add(workers.submit(()->{start.await();return f.app.handle(input).status();}));start.countDown();List<Integer> outcomes=List.of(attempts.get(0).get(4,TimeUnit.SECONDS),attempts.get(1).get(4,TimeUnit.SECONDS));assertEquals(1,outcomes.stream().filter(s->s==200).count());assertEquals(1,outcomes.stream().filter(s->s==401).count());assertEquals(1,f.lookups.get());assertEquals(1,f.app.retainedSessions());assertEquals(0,f.app.retainedAttempts());}finally{workers.shutdownNow();assertTrue(workers.awaitTermination(2,TimeUnit.SECONDS));}
        }}));return tests;
    }
    @Test void statusAdmissionCapsAndBoundedStateAccounting()throws Exception{
        try(Fixture f=new Fixture(null,1,65536)){
            for(int i=0;i<100;i++)assertEquals(200,f.app.handle(request("GET","/session","",null,null,Map.of())).status());assertEquals(0,f.app.retainedAttempts());assertEquals(0,f.app.retainedBytes());
            f.admission.set(false);assertEquals(429,f.begin(BackendApplication.Provider.GOOGLE).status());assertEquals(0,f.app.retainedBytes());f.admission.set(true);assertEquals(200,f.begin(BackendApplication.Provider.GOOGLE).status());assertEquals(129,f.app.retainedBytes());assertEquals(503,f.begin(BackendApplication.Provider.APPLE).status());assertEquals(129,f.app.retainedBytes());
            f.clock.now.set(NOW.plusSeconds(300));f.nanos.addAndGet(Duration.ofMinutes(5).toNanos());assertEquals(200,f.begin(BackendApplication.Provider.APPLE).status());assertEquals(129,f.app.retainedBytes());assertEquals(1,f.app.retainedAttempts());
        }
        try(Fixture f=new Fixture(null,1,128)){assertEquals(503,f.begin(BackendApplication.Provider.GOOGLE).status());assertEquals(0,f.app.retainedBytes());}
        try(Fixture f=new Fixture(null,1,129)){f.accounts.put(ProviderTokens.GOOGLE+"|google-sub",new BackendApplication.Account("a".repeat(64),"t".repeat(64)));var begin=f.begin(BackendApplication.Provider.GOOGLE);assertEquals(503,f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{}))).status());assertEquals(0,f.app.retainedSessions());assertEquals(0,f.app.retainedBytes());}
    }
    @Test void googleSessionRotationWorksAtFullEntryCapacityAndLogoutRevokesIt()throws Exception{
        try(Fixture f=new Fixture(null,1,65536)){
            var first=f.login(BackendApplication.Provider.GOOGLE);String old=cookie(first,BackendApplication.SESSION_COOKIE);var status=f.app.handle(request("GET","/session","",old,null,Map.of()));String csrf=status.fields().get("csrf");
            var begin=f.app.handle(request("POST","/google/begin",form(Map.of("begin","1","csrf",csrf)),old,null,Map.of()));assertEquals(200,begin.status());var second=f.app.handle(f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{})));assertEquals(200,second.status());String current=cookie(second,BackendApplication.SESSION_COOKIE);assertNotEquals(old,current);assertEquals(1,f.app.retainedSessions());assertEquals("false",f.app.handle(request("GET","/session","",old,null,Map.of())).fields().get("authenticated"));assertEquals(401,f.app.handle(request("GET","/account/tenant/alice","",old,null,Map.of())).status());status=f.app.handle(request("GET","/session","",current,null,Map.of()));
            assertEquals(403,f.app.handle(request("POST","/logout","csrf=wrong",current,null,Map.of())).status());assertEquals(200,f.app.handle(request("POST","/logout",form(Map.of("csrf",status.fields().get("csrf"))),current,null,Map.of())).status());assertEquals("false",f.app.handle(request("GET","/session","",current,null,Map.of())).fields().get("authenticated"));assertEquals(0,f.app.retainedBytes());
        }
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> delayedOrUnavailableAccountPolicyWithholdsSessions(){
        List<DynamicTest> tests=new ArrayList<>();for(String mode:List.of("deadline","expiry","future-iat-after-rollback","failure","disabled"))tests.add(DynamicTest.dynamicTest(mode,()->{try(Fixture f=new Fixture()){
            var begin=f.begin(BackendApplication.Provider.APPLE);String token=f.token(BackendApplication.Provider.APPLE,begin,c->{});
            switch(mode){case "deadline"->f.onLookup=()->f.nanos.addAndGet(Duration.ofSeconds(4).toNanos());case "expiry"->f.onLookup=()->f.clock.now.set(NOW.plusSeconds(3600));case "future-iat-after-rollback"->{f.clock.now.set(NOW.plusSeconds(2));token=f.token(BackendApplication.Provider.APPLE,begin,c->c.put("iat",num(NOW.plusSeconds(2).getEpochSecond())));f.onLookup=()->f.clock.now.set(NOW.plusSeconds(1));}case "failure"->f.onLookup=()->{throw new IllegalStateException("TEST-ONLY-secret-detail");};case "disabled"->f.signIn.set(false);default->throw new AssertionError();}
            var input=f.completion(BackendApplication.Provider.APPLE,begin,token);var reply=f.app.handle(input);assertEquals(mode.equals("deadline")||mode.equals("failure")?503:mode.equals("disabled")?403:401,reply.status());assertTrue(reply.cookies().isEmpty());assertFalse(reply.fields().containsKey("session_token"));assertEquals(0,f.app.retainedSessions());assertEquals(0,f.app.retainedBytes());assertEquals(1,f.lookups.get());assertEquals(401,f.app.handle(input).status());assertFalse(reply.toString().contains("secret-detail"));
        }}));return tests;
    }
    @Test void sessionExpiryCannotReviveWhenWallClockRollsBack()throws Exception{
        try(Fixture f=new Fixture()){
            var result=f.login(BackendApplication.Provider.APPLE);String token=result.fields().get("session_token");f.clock.now.set(NOW.plusSeconds(1800));f.nanos.addAndGet(Duration.ofMinutes(30).toNanos());assertEquals("false",f.app.handle(request("GET","/native/session","",null,token,Map.of())).fields().get("authenticated"));f.clock.now.set(NOW);assertEquals("false",f.app.handle(request("GET","/native/session","",null,token,Map.of())).fields().get("authenticated"));assertEquals(1,f.app.retainedSessions());
        }
    }
    @Test void payloadAndSecretBearingObjectsStayRedactedAndBounded()throws Exception{
        try(Fixture f=new Fixture()){
            var begin=f.begin(BackendApplication.Provider.APPLE);String jwt=f.token(BackendApplication.Provider.APPLE,begin,c->{});var request=f.completion(BackendApplication.Provider.APPLE,begin,jwt);var reply=f.app.handle(request);
            for(Object value:List.of(begin,request,reply,f.app,f.config,new BackendApplication.Account("alice","tenant")))for(String secret:List.of(jwt,begin.fields().get("nonce"),begin.fields().get("request_binding"),reply.fields().get("session_token")))assertFalse(value.toString().contains(secret));
            assertThrows(IllegalArgumentException.class,()->new BackendApplication.Request("POST","/google/complete",null,Map.of(),new byte[32769],false,true,"peer"));assertThrows(IllegalArgumentException.class,()->new BackendApplication.Configuration(URI.create("http://app.example"),"google","apple",null,1,1));
        }
    }
    @Test void workAdmissionBoundsConcurrentValidationAndAlwaysReturnsPermits()throws Exception{
        try(Fixture f=new Fixture()){
            List<BackendApplication.Request> requests=new ArrayList<>();for(int i=0;i<9;i++){var begin=f.begin(BackendApplication.Provider.APPLE);requests.add(f.completion(BackendApplication.Provider.APPLE,begin,f.token(BackendApplication.Provider.APPLE,begin,c->{})));}
            CountDownLatch entered=new CountDownLatch(8),release=new CountDownLatch(1);f.onLookup=()->{entered.countDown();try{assertTrue(release.await(3,TimeUnit.SECONDS));}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}};
            ExecutorService workers=Executors.newFixedThreadPool(8);List<Future<Integer>> results=new ArrayList<>();
            try{for(int i=0;i<8;i++){var input=requests.get(i);results.add(workers.submit(()->f.app.handle(input).status()));}assertTrue(entered.await(2,TimeUnit.SECONDS));assertEquals(503,f.app.handle(requests.get(8)).status());assertEquals(8,f.lookups.get());release.countDown();for(var result:results)assertEquals(200,result.get(4,TimeUnit.SECONDS));assertEquals(8,f.app.retainedSessions());assertEquals(1,f.app.retainedAttempts());}
            finally{release.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
            f.onLookup=()->{};assertEquals(200,f.app.handle(requests.get(8)).status());assertEquals(9,f.lookups.get());assertEquals(0,f.app.retainedAttempts());
        }
    }
    @Test void logoutDuringAccountLookupCannotPublishAReplacementSession()throws Exception{
        try(Fixture f=new Fixture()){
            var first=f.login(BackendApplication.Provider.GOOGLE);String old=cookie(first,BackendApplication.SESSION_COOKIE);var status=f.app.handle(request("GET","/session","",old,null,Map.of()));String csrf=status.fields().get("csrf");var begin=f.app.handle(request("POST","/google/begin",form(Map.of("begin","1","csrf",csrf)),old,null,Map.of()));var input=f.completion(BackendApplication.Provider.GOOGLE,begin,f.token(BackendApplication.Provider.GOOGLE,begin,c->{}));
            CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);f.onLookup=()->{entered.countDown();try{assertTrue(release.await(3,TimeUnit.SECONDS));}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}};ExecutorService worker=Executors.newSingleThreadExecutor();
            try{Future<BackendApplication.Reply> pending=worker.submit(()->f.app.handle(input));assertTrue(entered.await(2,TimeUnit.SECONDS));assertEquals(200,f.app.handle(request("POST","/logout",form(Map.of("csrf",csrf)),old,null,Map.of())).status());release.countDown();var result=pending.get(4,TimeUnit.SECONDS);assertEquals(401,result.status());assertFalse(result.fields().containsKey("session_token"));assertTrue(result.cookies().stream().noneMatch(c->c.startsWith(BackendApplication.SESSION_COOKIE+'=')));assertEquals(0,f.app.retainedSessions());assertEquals(0,f.app.retainedBytes());assertEquals(401,f.app.handle(input).status());}
            finally{release.countDown();worker.shutdownNow();assertTrue(worker.awaitTermination(3,TimeUnit.SECONDS));}
        }
    }
    @Test void cancelledRequestCannotAllocateLoginState()throws Exception{
        try(Fixture f=new Fixture()){
            try{Thread.currentThread().interrupt();assertEquals(503,f.begin(BackendApplication.Provider.GOOGLE).status());assertTrue(Thread.currentThread().isInterrupted());assertEquals(0,f.app.retainedAttempts());assertEquals(0,f.app.retainedBytes());assertEquals(0,f.googleFetches.get());}
            finally{Thread.interrupted();}
        }
    }
    @Test void nativeRotationAndLogoutUseOnlyTheApplicationSession()throws Exception{
        try(Fixture f=new Fixture(null,1,65536)){
            String old=f.login(BackendApplication.Provider.APPLE).fields().get("session_token");var begin=f.app.handle(request("POST","/apple/begin","begin=1",null,old,Map.of()));assertEquals(200,begin.status());var done=f.app.handle(f.completion(BackendApplication.Provider.APPLE,begin,f.token(BackendApplication.Provider.APPLE,begin,c->{})));assertEquals(200,done.status());String current=done.fields().get("session_token");assertNotEquals(old,current);assertEquals(1,f.app.retainedSessions());assertEquals(401,f.app.handle(request("GET","/native/account/tenant/alice","",null,old,Map.of())).status());assertEquals(200,f.app.handle(request("POST","/native/logout","",null,current,Map.of())).status());assertEquals(401,f.app.handle(request("GET","/native/account/tenant/alice","",null,current,Map.of())).status());assertEquals(0,f.app.retainedBytes());
        }
    }
    @Test void providerAttemptCannotBeReinterpretedByAnotherProviderEndpoint()throws Exception{
        try(Fixture f=new Fixture()){
            var apple=f.begin(BackendApplication.Provider.APPLE);String pending=BackendApplication.LOGIN_COOKIE+'='+apple.fields().get("request_id")+'.'+apple.fields().get("request_binding");String googleToken=f.token(BackendApplication.Provider.GOOGLE,apple,c->{});assertEquals(401,f.app.handle(request("POST","/google/complete",form(Map.of("credential",googleToken,"g_csrf_token","csrf")),pending+"; g_csrf_token=csrf",null,Map.of())).status());assertEquals(0,f.googleFetches.get());assertEquals(0,f.lookups.get());assertEquals(200,f.app.handle(f.completion(BackendApplication.Provider.APPLE,apple,f.token(BackendApplication.Provider.APPLE,apple,c->{}))).status());
        }
    }
    @Test void protectedAccountWorkSharesTheSameBoundedWorkGate()throws Exception{
        try(Fixture f=new Fixture()){
            String session=f.login(BackendApplication.Provider.APPLE).fields().get("session_token");var input=request("GET","/native/account/tenant/alice","",null,session,Map.of());
            CountDownLatch entered=new CountDownLatch(8),release=new CountDownLatch(1);f.onAuthorize=()->{if(f.authorization.get()>8)return;entered.countDown();try{assertTrue(release.await(3,TimeUnit.SECONDS));}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}};
            ExecutorService workers=Executors.newFixedThreadPool(8);List<Future<Integer>> results=new ArrayList<>();
            try{for(int i=0;i<8;i++)results.add(workers.submit(()->f.app.handle(input).status()));assertTrue(entered.await(2,TimeUnit.SECONDS));assertEquals(503,f.app.handle(input).status());assertEquals(8,f.authorization.get());release.countDown();for(var result:results)assertEquals(200,result.get(4,TimeUnit.SECONDS));}
            finally{release.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
            f.onAuthorize=()->{};assertEquals(200,f.app.handle(input).status());assertEquals(9,f.authorization.get());
        }
    }
}
