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
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.oauth.server.QualificationIssuerCarrier;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Owned multi-JVM structural adapter actor. Records are opaque fixtures, not authenticated service state. */
public final class NativeContentionActor {
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(20);
    private static final @NonNull Instant NOW=Instant.ofEpochSecond(1800000000);
    private static final @NonNull AtomicInteger SAMPLES=new AtomicInteger();
    private static final @NonNull AtomicLong MAX_AUTHORITY_NANOS=new AtomicLong();
    private static volatile @NonNull String stage="START",envelope="NONE";
    private static @Nullable StoreTimeObservation fixedPoint;
    private NativeContentionActor() { }
    private static @NonNull String env(@NonNull String name){return java.util.Objects.requireNonNull(System.getenv(name));}
    private static @NonNull String nonce(@NonNull String value)throws Exception{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
    private static @NonNull String encode(byte @NonNull [] value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value);}
    private static int bucket(@NonNull String value)throws Exception{return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII))[0]&255;}
    private static @NonNull String key(@NonNull String family,@NonNull String namespace,@NonNull String name,boolean root)throws Exception{
        return switch(family){
            case "TOTP" -> root?TotpStoreKey.forNamespace(namespace,"epoch").getStorageKey():TotpStoreKey.forAccount(namespace,"epoch",name).getStorageKey();
            case "WEBAUTHN" -> root?WebAuthnStoreKey.forNamespaceClock(namespace,"example.com").getStorageKey():WebAuthnStoreKey.forAccountFence(namespace,"example.com",name.getBytes(StandardCharsets.UTF_8)).getStorageKey();
            case "ISSUER" -> "revetsec:as:1:"+nonce(namespace)+":"+(root?"ISSUER_STATE":"SUBJECT_STATE")+":"+nonce(root?namespace:name);
            default -> throw new IllegalArgumentException("Unsupported structural family");
        };
    }
    private static void keys(@NonNull String family,@NonNull String namespace)throws Exception{
        System.out.println("ROOT\t"+key(family,namespace,"",true));
        Set<Integer> distinct=new HashSet<>();List<String> collisions=new ArrayList<>();
        for(int i=0;i<100000 && (distinct.size()<16||collisions.size()<16);i++){
            String value=key(family,namespace,"fixture-"+i,false);int bucket=bucket(value);
            if(distinct.size()<16&&distinct.add(bucket))System.out.println("DISTINCT\t"+bucket+"\t"+value);
            if(bucket==0&&collisions.size()<16){collisions.add(value);System.out.println("COLLISION\t"+bucket+"\t"+value);}
        }
        if(distinct.size()!=16||collisions.size()!=16)throw new IllegalStateException("Bounded structural key search failed");
    }
    private static @NonNull WebAuthnStoreKey waTarget(@NonNull String namespace,@NonNull String stored){
        for(int i=0;i<100000;i++){
            WebAuthnStoreKey key=WebAuthnStoreKey.forAccountFence(namespace,"example.com",("fixture-"+i).getBytes(StandardCharsets.UTF_8));
            if(key.getStorageKey().equals(stored))return key;
        }
        throw new IllegalArgumentException("Unknown bounded structural address");
    }
    private static @NonNull Connection connection(@NonNull Duration budget)throws Exception{
        if(budget.isZero()||budget.isNegative())throw new IllegalStateException("Structural actor budget");
        Properties p=new Properties();p.setProperty("user",env("DB_USER"));p.setProperty("password",env("DB_PASSWORD"));
        p.setProperty("sslmode","disable");p.setProperty("gssEncMode","disable");p.setProperty("socketTimeout","25");p.setProperty("ApplicationName",env("ACTOR_ID"));
        return DriverManager.getConnection(env("DB_URL"),p);
    }
    private static @NonNull Connection source(@NonNull Duration budget)throws java.sql.SQLException{
        try{return connection(budget);}catch(java.sql.SQLException failed){throw failed;}catch(Exception failed){throw new java.sql.SQLException("Structural actor source",failed);}
    }
    private static @NonNull StoreTimeObservation point(@NonNull String scope,@NonNull Duration budget)throws Exception{
        if(!scope.equals(env("PHYSICAL"))||budget.compareTo(Duration.ofMillis(1))<=0)throw new IllegalStateException("Structural authority scope/budget");
        long started=System.nanoTime();Thread.sleep(1);SAMPLES.incrementAndGet();
        StoreTimeObservation point=java.util.Objects.requireNonNull(fixedPoint);
        MAX_AUTHORITY_NANOS.accumulateAndGet(System.nanoTime()-started,Math::max);return point;
    }
    private static byte @NonNull [] totpBytes(){byte[] raw=new byte[55];raw[0]=1;raw[1]=1;raw[2]='k';return encode(raw).getBytes(StandardCharsets.US_ASCII);}
    @FunctionalInterface private interface Commit { @NonNull String run(); }
    private static @NonNull Commit prepare()throws Exception{
        String family=env("FAMILY"),namespace=env("NAMESPACE"),root=env("ROOT_KEY"),key=env("TARGET_KEY"),version=nonce(env("ACTOR_ID")+key);
        return switch(family){
            case "TOTP" -> {
                var store=new PostgresqlTotpStore(namespace,env("PHYSICAL"),NativeContentionActor::source,65536,268435456,NativeContentionActor::point);
                var rkey=TotpStoreKey.fromStoredForm(root);var target=TotpStoreKey.fromStoredForm(key);
                stage="TOTP_READ";var envelopeValue=store.read(Set.of(rkey,target),BUDGET);envelope=envelopeValue.getClass().getSimpleName();var read=(TotpStoreReadResult.Available)envelopeValue;var snapshot=read.getSnapshot();
                var condition=StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(),NOW,NOW.plusSeconds(60));
                var record=TotpStoreRecord.fromStoredForm(target,version,totpBytes());
                var mutation=snapshot.getEntry(target) instanceof TotpStoreEntry.Absent?TotpStoreWrite.Mutation.insert(record):TotpStoreWrite.Mutation.replace(record);
                var write=TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE,snapshot,List.of(mutation),condition);
                yield ()->store.compareAndCommit(write,BUDGET).getStatus().name();
            }
            case "WEBAUTHN" -> {
                var store=new PostgresqlWebAuthnStore(namespace,env("PHYSICAL"),NativeContentionActor::source,1000000,NativeContentionActor::point);
                var rkey=WebAuthnStoreKey.forNamespaceClock(namespace,"example.com");var target=waTarget(namespace,key);
                stage="WEBAUTHN_READ";var envelopeValue=store.read(Set.of(rkey,target),BUDGET);envelope=envelopeValue.getClass().getSimpleName();var read=(WebAuthnStoreReadResult.Available)envelopeValue;var snapshot=read.getSnapshot();
                var condition=StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(),NOW,NOW.plusSeconds(60));
                var mutation=snapshot.getEntry(target) instanceof WebAuthnStoreEntry.Absent?WebAuthnStoreWrite.Mutation.insert(target,new byte[]{1,2,3,4}):WebAuthnStoreWrite.Mutation.replace(target,new byte[]{1,2,3,4});
                var write=WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,List.of(mutation),condition);
                yield ()->store.compareAndCommit(write,BUDGET).getStatus().name();
            }
            case "ISSUER" -> {
                var store=new PostgresqlIssuerStore(namespace,env("PHYSICAL"),NativeContentionActor::source,1000000,NativeContentionActor::point);
                var rkey=OAuthStoreKey.fromStoredForm(root);var target=OAuthStoreKey.fromStoredForm(key);
                stage="ISSUER_ROOT_READ";var rootValue=store.read(rkey,BUDGET);envelope=rootValue.getClass().getSimpleName();var rootRead=(OAuthStoreReadResult.Available)rootValue;
                stage="ISSUER_TARGET_READ";var targetValue=store.read(target,BUDGET);envelope=targetValue.getClass().getSimpleName();var targetRead=(OAuthStoreReadResult.Available)targetValue;
                var transaction=QualificationIssuerCarrier.insert(rootRead,targetRead,target,version,NOW);
                yield ()->store.commit(transaction,BUDGET).getStatus().name();
            }
            default -> throw new IllegalArgumentException("Unsupported structural family");
        };
    }
    private static void hold(boolean bucketHold)throws Exception{
        try(Connection c=connection(BUDGET)){
            c.setAutoCommit(false);
            if(bucketHold)try(PreparedStatement s=c.prepareStatement("SELECT bucket FROM "+env("FAMILY").toLowerCase(java.util.Locale.ROOT)+"_store_escrow WHERE namespace=? AND bucket=? FOR UPDATE")){
                s.setString(1,env("PHYSICAL"));s.setInt(2,Integer.parseInt(env("BUCKET")));try(var rows=s.executeQuery()){if(!rows.next())throw new IllegalStateException("Missing structural bucket");}
            }
            else {
                long deadline=System.nanoTime()+BUDGET.toNanos();String scope=env("PHYSICAL"),key=env("TARGET_KEY");
                switch(env("FAMILY")){
                    case "TOTP" -> {var physical=TotpPgScope.from("TOTP",scope);TotpPgLocks.sharedAdmission(c,physical,deadline);TotpPgLocks.entities(c,List.of(TotpPgLocks.entity(physical,key,true)),deadline);}
                    case "WEBAUTHN" -> {var physical=WebAuthnPgScope.from("WEBAUTHN",scope);WebAuthnPgLocks.sharedAdmission(c,physical,deadline);WebAuthnPgLocks.entities(c,List.of(WebAuthnPgLocks.entity(physical,key,true)),deadline);}
                    case "ISSUER" -> {var physical=IssuerPgScope.from("ISSUER",scope);IssuerPgLocks.sharedAdmission(c,physical,deadline);IssuerPgLocks.entities(c,List.of(IssuerPgLocks.entity(physical,key,true)),deadline);}
                    default -> throw new IllegalArgumentException("Unsupported structural holder");
                }
            }
            System.out.println("HELD");System.out.flush();
            if(!"RELEASE".equals(new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII)).readLine()))throw new IllegalStateException("Structural hold command");
            c.rollback();System.out.println("RELEASED");
        }
    }
    public static void main(@NonNull String @NonNull [] args){
        try{
            java.nio.file.Path origin=java.nio.file.Path.of(com.revetsec.StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            String coreHash=java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(origin)));
            if(!coreHash.equals("b23109a3434703a40ce5a9795ae18b46265c9f07b73901c3b3c4c54dcbbe3b38"))throw new IllegalStateException("Selected core origin mismatch");
            if(args.length==3&&args[0].equals("keys")){keys(args[1],args[2]);return;}
            if(args.length==1&&args[0].startsWith("hold-")){hold(args[0].equals("hold-bucket"));return;}
            fixedPoint=StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(env("AUTHORITY"),env("RECOVERY")),env("CLOCK"),NOW,Duration.ZERO);
            Commit commit=prepare();System.out.println("READY");System.out.flush();
            if(!"GO".equals(new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII)).readLine()))throw new IllegalStateException("Structural start command");
            long started=System.nanoTime();String status=commit.run();long elapsed=System.nanoTime()-started;
            System.out.println("RESULT "+status+" "+elapsed+" "+SAMPLES.get()+" "+MAX_AUTHORITY_NANOS.get());
        }catch(Exception failure){System.err.println("STRUCTURAL_ACTOR_FAILED "+stage+" "+failure.getClass().getSimpleName()+" "+envelope+" "+MAX_AUTHORITY_NANOS.get());System.exit(1);}
    }
}
