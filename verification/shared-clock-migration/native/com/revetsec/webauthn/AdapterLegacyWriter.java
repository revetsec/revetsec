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

package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import example.pending.PostgresqlWebAuthnStore;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.PooledConnection;
import org.postgresql.ds.PGConnectionPoolDataSource;
import org.jspecify.annotations.NonNull;

/** Genuine frozen-old engine + adapter writer, including an actually pooled SQL session. */
public final class AdapterLegacyWriter {
    private AdapterLegacyWriter() { }
    public static void main(@NonNull String @NonNull [] args) {
        try { run(args); }
        catch (Throwable failure) {System.err.println("LEGACY_WRITER_FAILED");System.exit(1);}
    }
    private static void run(@NonNull String @NonNull [] args) throws Exception {
        if(args.length!=2)throw new IllegalArgumentException();
        if(!Path.of(WebAuthnStore.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().equals(Path.of(System.getenv("OLD_CORE_JAR")).toRealPath()))throw new AssertionError();
        String namespace=args[1];Duration budget=Duration.ofSeconds(10);Properties properties=new Properties();
        properties.setProperty("user",System.getenv("DB_USER"));properties.setProperty("password",System.getenv("DB_PASSWORD"));properties.setProperty("sslmode","disable");properties.setProperty("gssEncMode","disable");properties.setProperty("socketTimeout","10");
        PGConnectionPoolDataSource pool=new PGConnectionPoolDataSource();pool.setUrl(System.getenv("DB_URL"));pool.setUser(System.getenv("DB_USER"));pool.setPassword(System.getenv("DB_PASSWORD"));
        PooledConnection pooled=args[0].equals("pooled")?pool.getPooledConnection():null;
        Connection held=pooled==null?DriverManager.getConnection(System.getenv("DB_URL"),properties):pooled.getConnection();
        try {
            Connection lease=(Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,arguments)->{
                if(method.getName().equals("close"))return null;
                try{return method.invoke(held,arguments);}catch(InvocationTargetException failure){throw failure.getCause();}
            });
            var store=new PostgresqlWebAuthnStore(namespace,remaining->lease,512);
            AtomicReference<WebAuthnStoreWrite> captured=new AtomicReference<>();
            WebAuthnStore capture=new WebAuthnStore(){
                @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration remaining){return store.read(keys,remaining);}
                @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration remaining){captured.set(write);return WebAuthnStoreCommitResult.UNAVAILABLE;}
            };
            Clock clock=Clock.fixed(Instant.ofEpochSecond(Long.parseLong(System.getenv("OLD_WORKER_SECONDS"))),ZoneOffset.UTC);
            StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64(System.getenv("SEAL_KEY_ID"),System.getenv("SEAL_KEY"))).clock(clock).build();
            WebAuthnRecoveryGate gate=remaining->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){ }};
            var party=WebAuthnRelyingParty.withRelyingPartyId("login.example.com").relyingPartyName("Private migration writer").allowedOrigins(Set.of("https://login.example.com"))
                .credentialNamespace(namespace).store(capture).stateSealer(sealer).recoveryGate(gate).clockForTesting(clock).build();
            var result=party.beginAuthenticationResult(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
            if(!(result instanceof WebAuthnAuthenticationRequestResult.Unavailable)||captured.get()==null)throw new AssertionError();
            System.out.println("READY "+args[0]);System.out.flush();
            if(!new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII)).readLine().equals("CONTINUE"))throw new AssertionError();
            boolean sessionRefused=false;
            try {var outcome=store.compareAndCommit(captured.get(),budget);sessionRefused=outcome!=WebAuthnStoreCommitResult.COMMITTED;}
            catch(RuntimeException expected){sessionRefused=true;}
            if(!sessionRefused)throw new AssertionError();
            System.out.println("PASS old-engine-"+args[0]+"-cannot-commit");
            boolean loginRefused=false;
            try(Connection next=DriverManager.getConnection(System.getenv("DB_URL"),properties)){next.getAutoCommit();}catch(SQLException expected){loginRefused=true;}
            if(!loginRefused)throw new AssertionError();
            System.out.println("PASS old-credential-"+args[0]+"-cannot-login");
        } finally {try{held.close();}catch(SQLException ignored){ }if(pooled!=null)pooled.close();}
    }
}
