/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Actual adapter SPI timing with structural values and scripted UTC; no service/profile proof. */
public final class TemporalMatrixChecks {
    private static final @NonNull String NS="temporal",EPOCH="one";
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(8);
    private static final @NonNull Instant N=Instant.ofEpochSecond(1700000010,123456789),E=N.plusSeconds(10);
    private static final @NonNull StoreAdmission ADMISSION=StoreAdmission.fromIdentifiers(id("authority"),id("recovery"));
    private static final @NonNull AtomicReference<@NonNull StoreTimeObservation> POINT=new AtomicReference<>(healthy(N));
    private static final @NonNull AtomicReference<@NonNull String> LAST=new AtomicReference<>("NONE");
    private static final @NonNull AtomicInteger SAMPLES=new AtomicInteger(),PID=new AtomicInteger();
    private static @NonNull String family="TOTP",operation="origin";
    private TemporalMatrixChecks() { }
    private static @NonNull String id(@NonNull String input){try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.US_ASCII)));}catch(Exception failure){throw new AssertionError(failure);}}
    private static @NonNull String env(@NonNull String name){return Objects.requireNonNull(System.getenv(name));}
    private static @NonNull String physical(){return id("physical:"+env("DB_SCHEMA"));}
    private static @NonNull String table(@NonNull String suffix){return family.toLowerCase(Locale.ROOT)+"_store_"+suffix;}
    private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull Instant instant){return StoreTimeObservation.Healthy.fromObservation(ADMISSION,id("clock"),instant,Duration.ZERO);}
    private static @NonNull StoreTimeObservation observe(@NonNull String scope,@NonNull Duration budget){
        if(!scope.equals(physical())||budget.isZero()||budget.isNegative())throw new IllegalStateException("Temporal authority scope/budget");
        StoreTimeObservation value=POINT.get();LAST.set(value instanceof StoreTimeObservation.Healthy point?point.getObservedAt().toString():"UNAVAILABLE");SAMPLES.incrementAndGet();return value;
    }
    private static @NonNull Connection connection(@NonNull Duration budget)throws SQLException{
        if(budget.isZero()||budget.isNegative())throw new SQLException("Temporal fixture budget");
        String schema=env("DB_SCHEMA");if(!schema.matches("temporal_[a-z0-9_]+"))throw new SQLException("Invalid owned schema");
        Properties properties=new Properties();properties.setProperty("user",env("DB_USER"));properties.setProperty("password",env("DB_PASSWORD"));properties.setProperty("sslmode","disable");properties.setProperty("gssEncMode","disable");properties.setProperty("connectTimeout","2");properties.setProperty("socketTimeout","8");properties.setProperty("ApplicationName",schema+":"+operation);
        Connection connection=DriverManager.getConnection(env("DB_URL"),properties);
        try(Statement statement=connection.createStatement()){statement.execute("SET search_path TO "+schema);try(ResultSet r=statement.executeQuery("SELECT pg_backend_pid()")){if(!r.next())throw new SQLException("Missing owned backend PID");PID.set(r.getInt(1));}}
        return connection;
    }
    private static @NonNull String key(){return switch(family){
        case "TOTP"->TotpStoreKey.forAccount(NS,EPOCH,"target").getStorageKey();
        case "WEBAUTHN"->WebAuthnStoreKey.forCeremony(NS,"example.invalid",Base64.getUrlDecoder().decode(id("ceremony"))).getStorageKey();
        case "ISSUER"->"revetsec:as:1:"+id("issuer")+":INTERACTION:"+id("target");
        default->throw new IllegalArgumentException("Unknown family");
    };}
    private static int bucket(@NonNull String key){try{return Byte.toUnsignedInt(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.US_ASCII))[0]);}catch(Exception failure){throw new AssertionError(failure);}}
    private static byte @NonNull [] payload(){byte[] raw=new byte[55];raw[0]=1;raw[1]=1;raw[2]='k';return family.equals("TOTP")?Base64.getUrlEncoder().withoutPadding().encode(raw):raw;}
    private record Outcome(@NonNull String status,boolean timing,@NonNull String validatedAt) { }
    @FunctionalInterface private interface Commit { @NonNull Outcome run(); }
    private static @NonNull Commit prepare(){
        StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)POINT.get(),N,E);
        if(family.equals("TOTP")){
            var root=TotpStoreKey.forNamespace(NS,EPOCH);var target=TotpStoreKey.fromStoredForm(key());
            var store=new PostgresqlTotpStore(NS,physical(),TemporalMatrixChecks::connection,4096,4_000_000L,TemporalMatrixChecks::observe);
            var result=store.read(Set.of(root,target),BUDGET);if(!(result instanceof TotpStoreReadResult.Available available))throw new AssertionError("TOTP prepare unavailable");
            var write=TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE,available.getSnapshot(),List.of(TotpStoreWrite.Mutation.insert(TotpStoreRecord.fromStoredForm(target,id("version"),payload()))),condition);
            return ()->{var receipt=store.compareAndCommit(write,BUDGET);return new Outcome(receipt.getStatus().name(),receipt.getTiming().isPresent(),receipt.getTiming().map(t->t.getValidatedTime().getObservedAt().toString()).orElse("-"));};
        }
        if(family.equals("WEBAUTHN")){
            var target=WebAuthnStoreKey.fromStoredForm(key());var store=new PostgresqlWebAuthnStore(NS,physical(),TemporalMatrixChecks::connection,4096,TemporalMatrixChecks::observe);
            var result=store.read(Set.of(target),BUDGET);if(!(result instanceof WebAuthnStoreReadResult.Available available))throw new AssertionError("WebAuthn prepare unavailable");
            var write=WebAuthnStoreWrite.fromSnapshotAndMutations(available.getSnapshot(),List.of(WebAuthnStoreWrite.Mutation.insertExpiring(target,payload(),E)),condition);
            return ()->{var receipt=store.compareAndCommit(write,BUDGET);return new Outcome(receipt.getStatus().name(),receipt.getTiming().isPresent(),receipt.getTiming().map(t->t.getValidatedTime().getObservedAt().toString()).orElse("-"));};
        }
        var target=OAuthStoreKey.fromStoredForm(key());var store=new PostgresqlIssuerStore(NS,physical(),TemporalMatrixChecks::connection,4096,TemporalMatrixChecks::observe);
        var result=store.read(target,BUDGET);if(!(result instanceof OAuthStoreReadResult.Available available))throw new AssertionError("Issuer prepare unavailable");
        var write=TemporalIssuerCarrier.insert(available,target,id("version"),Base64.getUrlEncoder().withoutPadding().encodeToString(payload()),Instant.ofEpochSecond(E.getEpochSecond()+1),condition);
        return ()->{var receipt=store.commit(write,BUDGET);return new Outcome(receipt.getStatus().name(),receipt.getTiming().isPresent(),receipt.getTiming().map(t->t.getValidatedTime().getObservedAt().toString()).orElse("-"));};
    }
    private static void setup()throws Exception{
        long[] entries=new long[256],bytes=new long[256],bootstrapEntries=new long[256],bootstrapBytes=new long[256];
        if(family.equals("TOTP")){int root=bucket(TotpStoreKey.forNamespace(NS,EPOCH).getStorageKey());bootstrapEntries[root]=1;bootstrapBytes[root]=158;}
        // Closed fixture allocation, before the normal initialization or target transaction.
        TotpPgCapacity.Allocation allocation=TotpPgCapacity.allocate(family,4096,family.equals("TOTP")?4_000_000L:0,entries,bytes,bootstrapEntries,bootstrapBytes);
        try(Connection c=connection(BUDGET);Statement s=c.createStatement()){
            if(family.equals("TOTP")){
                s.executeUpdate("INSERT INTO totp_store_namespace(namespace,physical_namespace,active_epoch,activation_state,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,maximum_reserved_bytes) VALUES ('temporal','"+physical()+"','one','NEW','"+ADMISSION.getAuthorityId()+"','"+ADMISSION.getRecoveryGeneration()+"','"+id("clock")+"',0,'"+id("allocation")+"',3,4096,4000000)");
                s.executeUpdate("INSERT INTO totp_store_epoch(namespace,recovery_epoch) VALUES ('temporal','one')");
            }else s.executeUpdate("INSERT INTO "+table("namespace")+"(namespace,physical_namespace,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,admission_open) VALUES ('temporal','"+physical()+"','"+ADMISSION.getAuthorityId()+"','"+ADMISSION.getRecoveryGeneration()+"','"+id("clock")+"',0,'"+id("allocation")+"',2,4096,true)");
            long[] limits=allocation.getEntryLimits(),byteLimits=allocation.getByteLimits();
            try(PreparedStatement row=c.prepareStatement("INSERT INTO "+table("escrow")+"(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) VALUES (?,?,?,?,?,0,?,0)")){
                for(int i=0;i<256;i++){row.setString(1,family);row.setString(2,physical());row.setInt(3,i);row.setString(4,id("allocation"));row.setLong(5,limits[i]);row.setLong(6,byteLimits[i]);row.addBatch();}row.executeBatch();
            }
        }
        if(family.equals("TOTP")){
            var root=TotpStoreKey.forNamespace(NS,EPOCH);var store=new PostgresqlTotpStore(NS,physical(),TemporalMatrixChecks::connection,4096,4_000_000L,TemporalMatrixChecks::observe);
            var read=(TotpStoreReadResult.Available)store.read(Set.of(root),BUDGET);var condition=StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)read.getSnapshot().getTimeObservation(),N,E);
            var receipt=store.compareAndCommit(TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE,read.getSnapshot(),List.of(TotpStoreWrite.Mutation.insert(TotpStoreRecord.fromStoredForm(root,id("root-version"),payload()))),condition),BUDGET);
            if(!receipt.getStatus().name().equals("COMMITTED"))throw new AssertionError("TOTP root setup failed");
        }
        System.out.println("SETUP ready");
    }
    private static void hold(@NonNull String kind)throws Exception{
        try(Connection c=connection(BUDGET)){
            c.setAutoCommit(false);c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);long end=System.nanoTime()+20_000_000_000L;
            switch(family){
                case "TOTP"->{var scope=TotpPgScope.from(family,physical());TotpPgLocks.sharedAdmission(c,scope,end);if(kind.equals("entity"))TotpPgLocks.entities(c,List.of(TotpPgLocks.entity(scope,key(),true)),end);}
                case "WEBAUTHN"->{var scope=WebAuthnPgScope.from(family,physical());WebAuthnPgLocks.sharedAdmission(c,scope,end);if(kind.equals("entity"))WebAuthnPgLocks.entities(c,List.of(WebAuthnPgLocks.entity(scope,key(),true)),end);}
                case "ISSUER"->{var scope=IssuerPgScope.from(family,physical());IssuerPgLocks.sharedAdmission(c,scope,end);if(kind.equals("entity"))IssuerPgLocks.entities(c,List.of(IssuerPgLocks.entity(scope,key(),true)),end);}
                default->throw new IllegalArgumentException("Unknown family");
            }
            if(kind.equals("quota"))try(PreparedStatement s=c.prepareStatement("SELECT bucket FROM "+table("escrow")+" WHERE namespace=? AND bucket=? FOR UPDATE")){s.setString(1,physical());s.setInt(2,bucket(key()));try(ResultSet r=s.executeQuery()){if(!r.next())throw new AssertionError("Missing target quota");}}
            System.out.println("HELD "+PID.get());System.out.flush();if(!"RELEASE".equals(new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII)).readLine()))throw new AssertionError("Owned holder release protocol");c.rollback();System.out.println("RELEASED");
        }
    }
    private static void selectPoint(@NonNull String name){POINT.set(switch(name){
        case "below","N-1"->healthy(N.minusNanos(1));case "N","catchup"->healthy(N);case "E-1"->healthy(E.minusNanos(1));case "expired","E"->healthy(E);case "E+1"->healthy(E.plusNanos(1));case "unavailable"->StoreTimeObservation.Unavailable.fromAdmission(ADMISSION);default->throw new IllegalArgumentException("Unknown scripted point");
    });}
    private static void worker(boolean catchup)throws Exception{
        if(catchup)selectPoint("below");Commit work=prepare();int before=SAMPLES.get();PID.set(0);
        System.out.println("PLAN\t"+key()+"\t"+id("version")+"\t"+Base64.getUrlEncoder().withoutPadding().encodeToString(payload()));
        System.out.println("READY "+bucket(key())+" "+before);System.out.flush();
        BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII));ExecutorService executor=Executors.newSingleThreadExecutor();Future<Outcome> pending=CompletableFuture.completedFuture(new Outcome("NOT_STARTED",false,"-"));boolean started=false;
        try{
            for(String command;(command=input.readLine())!=null;){
                if(command.equals("GO")){if(started)throw new AssertionError("Duplicate target attempt");pending=executor.submit(work::run);started=true;System.out.println("STARTED");}
                else if(command.equals("STATUS"))System.out.println("STATE "+before+" "+SAMPLES.get()+" "+pending.isDone()+" "+PID.get());
                else if(command.startsWith("SET ")){selectPoint(command.substring(4));System.out.println("POINT SET");}
                else if(command.equals("FINISH")){if(!started)throw new AssertionError("Target never started");Outcome outcome=pending.get(12,TimeUnit.SECONDS);System.out.println("RESULT "+outcome.status()+" "+outcome.timing()+" "+before+" "+SAMPLES.get()+" "+LAST.get()+" "+outcome.validatedAt());break;}
                else throw new AssertionError("Unknown owned worker command");
                System.out.flush();
            }
        }finally{executor.shutdownNow();if(!executor.awaitTermination(2,TimeUnit.SECONDS))throw new AssertionError("Owned worker did not terminate");}
    }
    public static void main(@NonNull String @NonNull [] args)throws Exception{
        if(args.length<2||!List.of("TOTP","WEBAUTHN","ISSUER").contains(args[0]))throw new IllegalArgumentException("Expected family/operation");family=args[0];operation=args[1];
        var origin=java.nio.file.Path.of(com.revetsec.StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI());String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(origin)));if(!hash.equals(env("PG_QUALIFICATION_CORE_SHA256")))throw new IllegalStateException("Selected core origin mismatch");
        switch(operation){case "origin"->System.out.println("ORIGIN "+hash);case "setup"->setup();case "hold"->{if(args.length!=3||!List.of("entity","quota").contains(args[2]))throw new IllegalArgumentException("Expected lock kind");hold(args[2]);}case "worker"->worker(args.length==3&&args[2].equals("catchup"));default->throw new IllegalArgumentException("Unknown operation");}
    }
}
