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

package verification.store;

import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.*;
import java.util.*;

/** Independent JVM caller. Output is structural only; keys/credentials/control state remain ephemeral. */
public final class Worker {
    private Worker() { }
    private static @NonNull String value(@NonNull Properties p,@NonNull String key) {return Objects.requireNonNull(p.getProperty(key));}
    private static void gate(@NonNull Path directory) throws Exception {
        Files.writeString(directory.resolve("ready"),"ready");long until=System.nanoTime()+Duration.ofSeconds(15).toNanos();
        while (!Files.exists(directory.resolve("go"))) {if(System.nanoTime()>until)throw new IllegalStateException("Gate expired");Thread.sleep(10);}
    }
    private static boolean admitted(@Nullable DeploymentGate gate) {return gate==null || gate.isOpen();}
    private static boolean traffic(@NonNull String command) {return Set.of("prepare","begin","complete","active","redeem","refresh").contains(command);}
    public static void main(@NonNull String @NonNull [] args) throws Exception {
        String command=args[0];Path config=Path.of(args[1]),dir=Path.of(args[2]);
        Properties p=new Properties();try(var in=Files.newInputStream(config)){p.load(in);}
        if(command.equals("keys")) {
            var g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);var pair=g.generateKeyPair();
            Files.write(dir.resolve("private.der"),pair.getPrivate().getEncoded());Files.write(dir.resolve("public.der"),pair.getPublic().getEncoded());
            byte[] key=new byte[32];var random=new java.security.SecureRandom();random.nextBytes(key);
            Files.writeString(dir.resolve("sealer.txt"),Base64.getEncoder().encodeToString(key));random.nextBytes(key);
            Files.writeString(dir.resolve("sealer-next.txt"),Base64.getEncoder().encodeToString(key));System.out.println("KEYS");return;
        }
        String mode=p.getProperty("mode","normal");int[] calls={0};
        PostgresStore store=new PostgresStore(value(p,"url"),p,Integer.parseInt(p.getProperty("capacity","1000")));
        OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore() {
            @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return store.read(key,budget);}
            @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction txn,@NonNull Duration budget){
                calls[0]++;
                if(calls[0]==1 && mode.equals("race")){try{gate(dir);}catch(Exception e){throw new IllegalStateException("Gate failed");}}
                return store.commit(txn,budget);
            }
        };
        if(mode.startsWith("pause-"))store.probe=(stage,txn)->{
            if(stage.equals(mode.substring(6))){try{gate(dir);}catch(Exception e){throw new java.sql.SQLException("Fixture gate failed");}}
        };
        String issuer=value(p,"issuer");Instant now=Instant.parse(p.getProperty("now","2026-10-06T12:00:00Z"));
        String gatePath=p.getProperty("gate");DeploymentGate deployment=gatePath==null?null:new DeploymentGate(Path.of(gatePath),value(p,"generation"));
        IssuerFixture f=new IssuerFixture(wrapper,Path.of(value(p,"secrets")),issuer,now,p.getProperty("sealing","old"));
        // Management/diagnostic commands are explicit trusted fixture operations, not request routes.
        if(command.equals("contract")) {
            RecordingStore recording=new RecordingStore(store);
            IssuerFixture fixture=new IssuerFixture(recording,Path.of(value(p,"secrets")),issuer,now);
            StoreContract.run(recording,fixture,
                ()->store.probe=(stage,txn)->{if(stage.equals("mutation"))throw new java.sql.SQLException("Injected SQL failure");},
                ()->store.probe=null);return;
        }
        if(command.equals("init")){System.out.println(f.server.initializeFreshIssuer().name());f.server.establishNewSubject("subject");return;}
        if(command.equals("budget")) {
            long start=System.nanoTime();boolean failed=false;
            try{store.read(OAuthStoreKey.fromStoredForm(value(p,"key")),Duration.ofMillis(300));}catch(IllegalStateException e){failed=true;}
            System.out.println(failed && System.nanoTime()-start<Duration.ofSeconds(2).toNanos()?"BOUNDED":"BAD-BUDGET");return;
        }
        if(mode.equals("wait"))gate(dir); // engine already built, before route admission
        if(traffic(command) && !admitted(deployment)){System.out.println("GATED");return;}
        try {
            switch(command) {
                case "warm"-> {f.server.warmUp();System.out.println("READY");return;}
                case "fence"-> {f.server.revokeAllGrants();System.out.println("FENCED");return;}
                case "subject-fence"-> {f.server.revokeSubject("subject");System.out.println("FENCED");return;}
                case "reseal"-> {System.out.println(f.server.resealStoreEntry(OAuthStoreKey.fromStoredForm(value(p,"key"))).name());return;}
                case "prepare"-> {String code=f.code();if(!admitted(deployment)){System.out.println("GATED");return;}Files.writeString(dir.resolve("code"),code);System.out.println("PREPARED");return;}
                case "begin"-> {String handle=f.begin();if(!admitted(deployment)){System.out.println("GATED");return;}Files.writeString(dir.resolve("interaction"),handle);System.out.println("PREPARED");return;}
                case "complete"-> {var result=f.complete(Files.readString(dir.resolve("interaction")));System.out.println(!admitted(deployment)?"GATED":result instanceof OAuthAuthorizationResult.Completed?"COMPLETED":"REJECTED");return;}
                case "active"-> {boolean active=f.active(Files.readString(dir.resolve("access")));System.out.println(!admitted(deployment)?"GATED":active?"ACTIVE":"INACTIVE");return;}
                default-> { }
            }
            if(!Set.of("redeem","refresh").contains(command))throw new IllegalArgumentException("Unknown fixture command");
            OAuthTokenResult result=command.equals("refresh")?f.refresh(Files.readString(dir.resolve("refresh"))):f.redeem(Files.readString(dir.resolve("code")));
            if(!admitted(deployment)){System.out.println("GATED");return;}
            if(result instanceof OAuthTokenResult.Succeeded success) {
                Files.writeString(dir.resolve("access"),IssuerFixture.tokenField(success.getResponse(),"access_token"));
                Files.writeString(dir.resolve("refresh"),IssuerFixture.tokenField(success.getResponse(),"refresh_token"));System.out.println("SUCCEEDED "+calls[0]);
            }else System.out.println("REJECTED "+calls[0]);
        }catch(OAuthServerException e){System.out.println(e.getReason().name()+(Set.of("redeem","refresh","fence","subject-fence","reseal").contains(command)?" "+calls[0]:""));}
    }
}
