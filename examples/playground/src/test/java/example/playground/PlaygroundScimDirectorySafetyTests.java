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
package example.playground;

import com.revetsec.json.*;
import com.revetsec.password.*;
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import example.playground.PlaygroundScimDirectory.*;

/** Actual directory policy, KDF, publication and bounded admission paths; no network claims. */
final class PlaygroundScimDirectorySafetyTests {
    private static final @NonNull String ADMIN="synthetic-alpha-admin-private-credential-0000";
    private static final @NonNull String READER="synthetic-alpha-reader-private-credential-0000";
    private static final @NonNull String BETA="synthetic-beta-admin-private-credential-0000";
    private static final @NonNull Identity ID=new Identity("private-scim","admin","service-client");
    private static final @NonNull Principal PRINCIPAL=new Principal("admin","alpha",Role.PROVISIONER,null,1,true);
    private static final @NonNull PasswordHasher HASHER=PasswordHasher.withArgon2id(Argon2idParameters.fromCosts(19_456,2,1))
            .workGate(PasswordWorkGate.fromInMemoryLimits(2,38_912)).build();
    private static @NonNull Request request(@NonNull HttpMethod method,@NonNull String path,@NonNull String token,@NonNull String body){
        var builder=Request.withRawUrl(method,path).headers(Map.of("Host",List.of("app.example"),"Authorization",List.of("Bearer "+token),"Content-Type",List.of("application/scim+json")));
        if(!body.isEmpty())builder.body(body.getBytes(StandardCharsets.UTF_8));return builder.build();
    }
    private static @NonNull String user(@NonNull String name,@NonNull String fields){return "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"externalId\":\""+name+"\",\"userName\":\""+name+"\",\"active\":true"+fields+"}";}
    private static @NonNull String text(@NonNull MarshaledResponse response){return response.getBody().map(body->new String(((MarshaledResponseBody.Bytes)body).getBytes(),StandardCharsets.UTF_8)).orElse("");}
    private static @NonNull Request patch(@NonNull String fields,@NonNull String version){return request(HttpMethod.PATCH,"/scim/alpha/v2/Users/u1",ADMIN,
            "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":["+fields+"]}").copy().headers(headers->headers.put("If-Match",List.of(version))).finish();}
    private static long number(@NonNull JsonObject object,@NonNull String key){return ((JsonNumber)Objects.requireNonNull(object.getMembers().get(key))).getValue().longValueExact();}

    private static final class Fixture {
        final @NonNull Directory directory;
        final @NonNull PlaygroundScimDirectory app;
        final @NonNull AtomicReference<@NonNull Instant> now=new AtomicReference<>(Instant.parse("2026-11-06T00:00:00Z"));
        final @NonNull AtomicLong nanos=new AtomicLong();
        final @NonNull AtomicInteger policies=new AtomicInteger(),kdf=new AtomicInteger();
        final @NonNull AtomicReference<char @Nullable []> borrowed=new AtomicReference<>();
        final @NonNull AtomicReference<@NonNull Probe> probe=new AtomicReference<>((stage,remaining)->{});
        final @NonNull AtomicBoolean admitted=new AtomicBoolean(true);
        Fixture(){
            var readerId=new Identity("private-scim","reader","service-client");
            var betaId=new Identity("private-scim","beta","service-client");
            var reader=new Principal("reader","alpha",Role.READER,null,1,false);
            var beta=new Principal("beta","beta",Role.PROVISIONER,null,1,true);
            this.directory=new Directory(Set.of("alpha","beta"),Map.of(ID,PRINCIPAL,readerId,reader,betaId,beta));
            Clock clock=new Clock(){
                @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!ZoneOffset.UTC.equals(zone))throw new IllegalArgumentException("Fixture UTC only");return this;}
                @Override public @NonNull Instant instant(){return Objects.requireNonNull(now.get());}
            };
            this.app=new PlaygroundScimDirectory(new Configuration(URI.create("https://app.example"),Set.of("alpha","beta")),
                    List.of(new Registration(ADMIN,ID,PRINCIPAL),new Registration(READER,readerId,reader),new Registration(BETA,betaId,beta)),
                    this.directory,HASHER,(principal,password,remaining)->{this.policies.incrementAndGet();this.borrowed.set(password);return password.length>=8;},
                    (peer,remaining)->this.admitted.get(),clock,this.nanos::get,(stage,remaining)->{if(stage==Stage.BEFORE_KDF)this.kdf.incrementAndGet();Objects.requireNonNull(this.probe.get()).visit(stage,remaining);},65_536);
        }
        @NonNull MarshaledResponse create(@NonNull String name,@NonNull String fields){return this.app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user(name,fields)));}
        long writes(){return number(this.directory.snapshotCounts(),"writes");}
        void reader(){this.directory.replacePrincipal(ID,new Principal("admin","alpha",Role.READER,null,2,false));}
        void assertBorrowedWiped(){char[] value=this.borrowed.get();assertNotNull(value);for(char c:value)assertEquals('\0',c);}
    }

    @Test void attemptedAndEffectivePrivilegeFieldsCannotHideInPatchOrReplace(){
        var f=new Fixture();assertEquals(201,f.create("alice","").getStatusCode());
        for(String field:List.of("roles","entitlements","groups","userType")){
            String value=field.equals("userType")?"\"administrator\"":"[]";
            var denied=f.app.handle(patch("{\"op\":\"replace\",\"path\":\""+field+"\",\"value\":"+value+"}","W/\"u1:1\""));
            assertTrue(Set.of(400,403).contains(denied.getStatusCode()),field);
        }
        var denied=f.app.handle(request(HttpMethod.PUT,"/scim/alpha/v2/Users/u1",ADMIN,user("alice",",\"roles\":[]")).copy().headers(headers->headers.put("If-Match",List.of("W/\"u1:1\""))).finish());
        assertEquals(403,denied.getStatusCode());assertEquals(1,f.writes());assertEquals(0,f.kdf.get());
        assertEquals(200,f.app.handle(patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Allowed\"}","W/\"u1:1\"")).getStatusCode());
        assertTrue(text(f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users/u1",READER,""))).contains("Allowed"));
    }

    @Test void currentPrincipalAndOriginalBudgetAreCheckedAtEveryExposedBoundary(){
        for(Stage stage:Stage.values()){
            for(String mode:List.of("reader","rollback","late")){
                var f=new Fixture();f.probe.set((actual,remaining)->{if(actual==stage){switch(mode){case "reader"->f.reader();case "rollback"->f.now.updateAndGet(now->now.minusSeconds(1));case "late"->f.nanos.addAndGet(Duration.ofSeconds(9).toNanos());default->throw new AssertionError();}}});
                int status=f.create("alice",",\"password\":\"synthetic-private-password\"").getStatusCode();
                assertEquals(mode.equals("reader")?403:503,status,stage+":"+mode);assertEquals(0,f.writes(),stage+":"+mode);
                if(f.borrowed.get()!=null)f.assertBorrowedWiped();
            }
        }
    }

    @Test void preparedReadIsWithheldWhenItsSnapshotOrPrincipalChanges(){
        for(boolean principalChange:List.of(false,true)){
            var f=new Fixture();assertEquals(201,f.create("alice","").getStatusCode());
            AtomicBoolean once=new AtomicBoolean();f.probe.set((stage,remaining)->{if(stage==Stage.BEFORE_PUBLISH&&once.compareAndSet(false,true)){
                if(principalChange)f.reader();else assertEquals(201,f.create("bob","").getStatusCode());
            }});
            var read=f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users",ADMIN,""));
            assertEquals(principalChange?403:503,read.getStatusCode());assertFalse(text(read).contains("alice"));
            assertEquals(principalChange?1:2,f.writes());
        }
    }

    @Test void restoringAuthorityCannotReuseAnEarlierPrincipalGeneration(){
        var f=new Fixture();f.reader();assertThrows(IllegalArgumentException.class,()->f.directory.replacePrincipal(ID,PRINCIPAL));
        assertThrows(IllegalArgumentException.class,()->f.directory.replacePrincipal(ID,new Principal("admin","alpha",Role.PROVISIONER,null,2,true)));
        assertEquals(403,f.create("alice","").getStatusCode());
        f.directory.replacePrincipal(ID,new Principal("admin","alpha",Role.PROVISIONER,null,3,true));assertEquals(201,f.create("alice","").getStatusCode());
    }

    @Test void knownNoEffectAndUnknownAppliedRemainDistinctWithoutReplay(){
        for(boolean unknown:List.of(false,true)){
            var f=new Fixture();f.directory.failNext(unknown);assertEquals(503,f.create("alice","").getStatusCode());
            assertEquals(unknown?1:0,f.writes());
            var later=f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users/u1",READER,""));assertEquals(unknown?200:404,later.getStatusCode());
            if(unknown){assertTrue(text(later).contains("alice"));assertEquals(409,f.create("alice","").getStatusCode());assertEquals(1,f.writes());}
        }
    }

    @Test void passwordWorkRunsOutsideProtectionAndNeverPublishesCleartext()throws Exception{
        var f=new Fixture();ExecutorService worker=Executors.newSingleThreadExecutor();
        try{
            f.probe.set((stage,remaining)->{if(stage==Stage.BEFORE_KDF)assertEquals(0,worker.submit(()->number(f.directory.snapshotCounts(),"rows")).get(2,TimeUnit.SECONDS));});
            assertEquals(201,f.create("alice",",\"password\":\"synthetic-private-password\"").getStatusCode());assertEquals(1,f.policies.get());assertEquals(1,f.kdf.get());f.assertBorrowedWiped();
            String stored=Objects.requireNonNull(f.directory.credential("alpha","u1"));assertTrue(stored.startsWith("$argon2id$"));
            char[] secret="synthetic-private-password".toCharArray();try{assertInstanceOf(PasswordVerificationResult.Matched.class,HASHER.verifyResult(secret,stored));}finally{Arrays.fill(secret,'\0');}
            String response=text(f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users/u1?attributes=password,userName",READER,"")));assertFalse(response.contains("synthetic-private-password"));assertFalse(response.contains("$argon2id$"));
            assertEquals(403,f.app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",READER,"not-json")).getStatusCode());assertEquals(1,f.kdf.get());
        }finally{worker.shutdownNow();assertTrue(worker.awaitTermination(3,TimeUnit.SECONDS));}
    }

    @Test void sameSnapshotRacingWritesPublishExactlyOneWholeReplacement()throws Exception{
        var f=new Fixture();assertEquals(201,f.create("alice","").getStatusCode());CountDownLatch entered=new CountDownLatch(2),release=new CountDownLatch(1);
        f.probe.set((stage,remaining)->{if(stage==Stage.BEFORE_PUBLISH){entered.countDown();if(!release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("Fixture wait");}});
        ExecutorService workers=Executors.newFixedThreadPool(2);
        try{
            Callable<Integer> action=()->f.app.handle(patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Winner\"}","W/\"u1:1\"")).getStatusCode();
            Future<Integer> first=workers.submit(action),second=workers.submit(action);assertTrue(entered.await(2,TimeUnit.SECONDS));release.countDown();
            assertEquals(Set.of(200,412),new HashSet<>(List.of(first.get(3,TimeUnit.SECONDS),second.get(3,TimeUnit.SECONDS))));assertEquals(2,f.writes());assertEquals(1,number(f.directory.snapshotCounts(),"conflicts"));
        }finally{release.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
    }

    @Test void admissionIsBoundedAndRecoveredWithoutBlockingUnrelatedTenant()throws Exception{
        var f=new Fixture();CountDownLatch entered=new CountDownLatch(8),release=new CountDownLatch(1);
        f.probe.set((stage,remaining)->{if(stage==Stage.VALIDATED){entered.countDown();if(!release.await(4,TimeUnit.SECONDS))throw new IllegalStateException("Fixture wait");}});
        ExecutorService workers=Executors.newFixedThreadPool(8);List<Future<Integer>> requests=new ArrayList<>();
        try{
            for(int i=0;i<8;i++)requests.add(workers.submit(()->f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users",READER,"")).getStatusCode()));
            assertTrue(entered.await(2,TimeUnit.SECONDS));assertEquals(503,f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users",READER,"")).getStatusCode());release.countDown();
            for(Future<Integer> result:requests)assertEquals(200,result.get(3,TimeUnit.SECONDS));f.probe.set((stage,remaining)->{});
            assertEquals(201,f.app.handle(request(HttpMethod.POST,"/scim/beta/v2/Users",BETA,user("bob",""))).getStatusCode());
            f.admitted.set(false);assertEquals(403,f.create("alice","").getStatusCode());assertEquals(1,f.writes());f.admitted.set(true);assertEquals(201,f.create("alice","").getStatusCode());
        }finally{release.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
    }

    @Test void hostileIngressAndQueryBudgetsRefuseBeforeAnyWrite(){
        var f=new Fixture();
        for(String query:List.of("access_token=x","%61ccess_token=x","ACCESS_TOKEN=x","filter=roles.value%20eq%20%22admin%22","filter=userName%20co%20%22a%22","sortBy=roles","attributes="+ "x".repeat(1025))){
            int status=f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users?"+query,READER,"")).getStatusCode();assertTrue(Set.of(400,413).contains(status),query+":"+status);
        }
        for(Request hostile:List.of(
                request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,"x".repeat(16_385)),
                request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice","")).copy().headers(headers->headers.put("Authorization",List.of("Bearer "+ADMIN,"Bearer "+ADMIN))).finish(),
                request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice","")).copy().headers(headers->headers.put("Host",List.of("foreign.example"))).finish(),
                request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice","")).copy().headers(headers->headers.put("Content-Type",List.of("text/plain"))).finish())){
            assertTrue(hostile.getBody().orElseThrow().length>16_384?f.app.handle(hostile).getStatusCode()==413:Set.of(400,415).contains(f.app.handle(hostile).getStatusCode()));
        }
        assertEquals(0,f.writes());assertEquals(0,f.kdf.get());
        for(int i=0;i<21;i++)assertEquals(201,f.create("user"+i,"").getStatusCode());
        var capped=f.app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users?count=21",READER,""));assertEquals(200,capped.getStatusCode());assertTrue(text(capped).contains("\"itemsPerPage\":20"));
    }
}
