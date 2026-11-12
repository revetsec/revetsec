/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package example.pending;

import org.jspecify.annotations.NonNull;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

/** Real adapter commits across JVMs, with a held assigned escrow row and ordered SQL transcript. */
public final class ScBound04AdapterChecks {
    private ScBound04AdapterChecks() { }
    @FunctionalInterface public interface Commit { @NonNull String run(Cap09ContentionChecks.@NonNull Connections connections)throws Exception; }
    private record Quota(long limit,long used,long byteLimit,long bytes) { }
    private record Event(@NonNull String category,@NonNull String sql,@NonNull String bindings) { }
    private record Outcome(@NonNull String status,@NonNull String xid,@NonNull List<@NonNull Event> events) { }

    public static void run(Cap09ContentionChecks.@NonNull Harness harness,@NonNull Path config,@NonNull Clock workerClock)throws Exception {
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER"))caseFor(harness,config,workerClock,family);
    }
    private static void caseFor(Cap09ContentionChecks.@NonNull Harness harness,@NonNull Path config,@NonNull Clock workerClock,@NonNull String family)throws Exception {
        System.out.println("SC_BOUND04_STAGE "+family+" select");
        Quota[] quotas=quotas(harness,family);
        Cap09ContentionChecks.Plan held=find(harness,family,0,quotas,-1);
        Cap09ContentionChecks.Plan other=find(harness,family,held.index()+1,quotas,bucket(held.key()));
        check(family+"/distinct-keys-and-capacity-buckets",!held.key().equals(other.key())&&bucket(held.key())!=bucket(other.key()));
        ExecutorService readers=Executors.newCachedThreadPool();Process pending=null,independent=null;
        try(Connection blocker=harness.open(Duration.ofSeconds(8))){
            blocker.setAutoCommit(false);
            pending=worker(config,family,held.index());prepared(readers,pending,workerClock);
            independent=worker(config,family,other.index());prepared(readers,independent,workerClock);
            System.out.println("SC_BOUND04_STAGE "+family+" block");
            int blockerPid;String blockerXid;
            try(Statement statement=blocker.createStatement();ResultSet result=statement.executeQuery("SELECT pg_backend_pid(),txid_current()")){
                result.next();blockerPid=result.getInt(1);blockerXid=result.getString(2);
            }
            try(PreparedStatement statement=blocker.prepareStatement("SELECT namespace FROM "+table(family,"namespace")+" WHERE namespace='migration' FOR NO KEY UPDATE");ResultSet result=statement.executeQuery()){
                if(!result.next())throw new AssertionError("Missing namespace row");
            }
            try(PreparedStatement statement=blocker.prepareStatement("SELECT bucket FROM "+table(family,"escrow")+" WHERE namespace=? AND bucket=? FOR UPDATE")){
                statement.setString(1,harness.scope(family));statement.setInt(2,bucket(held.key()));
                try(ResultSet result=statement.executeQuery()){if(!result.next())throw new AssertionError("Missing held bucket");}
            }
            try{
                System.out.println("SC_BOUND04_STAGE "+family+" held-worker");
                start(pending);int pendingPid=ready(readers,pending);
                String waitXid=awaitCapacityWait(harness,pendingPid,blockerPid,family);
                check(family+"/held-adapter-waits-on-actual-capacity-row",pending.isAlive());
                start(independent);int independentPid=ready(readers,independent);
                Outcome completed=outcome(readers,independent,family,"independent");
                check(family+"/other-jvm-commits-before-holder-release",completed.status().equals("COMMITTED")&&pending.isAlive()&&!completed.xid().equals("UNASSIGNED"));
                assertTrace(family,"independent",completed.events(),bucket(other.key()));
                check(family+"/held-still-waiting-after-independent-commit",isCapacityWait(harness,pendingPid,blockerPid,family));
                System.out.println("SC_BOUND04_WAIT "+family+" blockerPid="+blockerPid+" blockerXid="+blockerXid+" waiterPid="+pendingPid+" waiterXid="+waitXid+" independentPid="+independentPid+" independentXid="+completed.xid()+" heldBucket="+bucket(held.key())+" independentBucket="+bucket(other.key()));
                blocker.rollback();
                Outcome released=outcome(readers,pending,family,"held");
                check(family+"/held-jvm-commits-after-release",released.status().equals("COMMITTED")&&!released.xid().equals("UNASSIGNED"));
                check(family+"/separate-commit-transactions",!released.xid().equals(completed.xid())&&!released.xid().equals(blockerXid));
                System.out.println("SC_BOUND04_COMMIT "+family+" heldPid="+pendingPid+" heldXid="+released.xid()+" independentPid="+independentPid+" independentXid="+completed.xid());
                assertTrace(family,"held",released.events(),bucket(held.key()));
                check(family+"/both-jvms-exit",pending.waitFor(3,TimeUnit.SECONDS)&&pending.exitValue()==0&&independent.waitFor(3,TimeUnit.SECONDS)&&independent.exitValue()==0);
            }finally{blocker.rollback();}
        }finally{
            for(Process process:new Process[]{pending,independent})if(process!=null){process.destroyForcibly();process.waitFor(3,TimeUnit.SECONDS);}
            readers.shutdownNow();readers.awaitTermination(3,TimeUnit.SECONDS);
        }
    }
    private static @NonNull Process worker(@NonNull Path config,@NonNull String family,int index)throws Exception {
        return new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",System.getProperty("java.class.path"),AdapterJoinProbe.class.getName(),config.toString(),"capacity-worker",family,Integer.toString(index)).redirectErrorStream(true).start();
    }
    private static void start(@NonNull Process worker)throws Exception {worker.getOutputStream().write(10);worker.getOutputStream().flush();}
    private static void prepared(@NonNull ExecutorService readers,@NonNull Process worker,@NonNull Clock workerClock)throws Exception {
        String stage="start";
        for(int i=0;i<8;i++){
            String row=line(readers,worker);
            if(row.equals("SYNC_READY")){Instant now=workerClock.instant();String sync=now.getEpochSecond()+" "+now.getNano()+"\n";worker.getOutputStream().write(sync.getBytes(StandardCharsets.US_ASCII));worker.getOutputStream().flush();continue;}
            if(row.startsWith("SC_BOUND04_WORKER_STAGE ")){stage=row.substring("SC_BOUND04_WORKER_STAGE ".length());continue;}
            if(row.equals("PREPARED"))return;
            if(row.startsWith("ADAPTER_PROBE_FAILED")){String detail=line(readers,worker);throw new AssertionError("SC-BOUND-04/worker-"+stage+"-"+detail.replace(' ','_'));}
            throw new AssertionError("SC-BOUND-04/worker-"+stage+"-unexpected-"+row.replace(' ','_'));
        }
        throw new AssertionError("SC-BOUND-04/worker-preparation-over-bound");
    }
    private static int ready(@NonNull ExecutorService readers,@NonNull Process worker)throws Exception {
        String stage="start";
        for(int i=0;i<8;i++){
            String row=line(readers,worker);
            if(row.startsWith("SC_BOUND04_WORKER_STAGE ")){stage=row.substring("SC_BOUND04_WORKER_STAGE ".length());continue;}
            if(row.startsWith("READY "))return Integer.parseInt(row.substring(6));
            if(row.startsWith("ADAPTER_PROBE_FAILED")){String detail=line(readers,worker);throw new AssertionError("SC-BOUND-04/worker-"+stage+"-"+detail.replace(' ','_'));}
            throw new AssertionError("SC-BOUND-04/worker-"+stage+"-unexpected-"+row.replace(' ','_'));
        }
        throw new AssertionError("SC-BOUND-04/worker-readiness-over-bound");
    }
    private static @NonNull Outcome outcome(@NonNull ExecutorService readers,@NonNull Process worker,@NonNull String family,@NonNull String actor)throws Exception {
        String first=line(readers,worker);String[] parts=first.split(" ",3);
        if(parts.length!=3||!parts[0].equals("RESULT"))throw new AssertionError("SC-BOUND-04 adapter worker outcome: "+first);
        List<Event> events=new ArrayList<>();
        for(int i=0;i<128;i++){
            String row=line(readers,worker);if(row.equals("END"))return new Outcome(parts[1],parts[2],List.copyOf(events));
            String[] fields=row.split(" ",4);
            if(fields.length!=4||!fields[0].equals("TRACE"))throw new AssertionError("SC-BOUND-04 adapter trace protocol: "+row);
            String sql=new String(Base64.getUrlDecoder().decode(fields[2]),StandardCharsets.UTF_8);
            events.add(new Event(fields[1],sql,fields[3]));
            System.out.println("SC_BOUND04_SQL "+family+" "+actor+" "+events.size()+" "+fields[1]+" "+fields[2]+" "+fields[3]);
        }
        throw new AssertionError("SC-BOUND-04 adapter trace over bound");
    }
    private static @NonNull String line(@NonNull ExecutorService readers,@NonNull Process process)throws Exception {
        Future<String> read=readers.submit(()->{InputStream stream=process.getInputStream();StringBuilder result=new StringBuilder();int next;
            while((next=stream.read())>=0&&next!='\n')result.append((char)next);
            return next<0&&result.length()==0?null:result.toString();});
        return Objects.requireNonNull(read.get(6,TimeUnit.SECONDS),"SC-BOUND-04 adapter worker ended before protocol line");
    }
    private static @NonNull String awaitCapacityWait(Cap09ContentionChecks.@NonNull Harness harness,int waiter,int blocker,@NonNull String family)throws Exception {
        long end=System.nanoTime()+Duration.ofSeconds(3).toNanos();
        try(Connection connection=harness.open(Duration.ofSeconds(5));PreparedStatement statement=connection.prepareStatement(
                "SELECT a.backend_xid::text FROM pg_stat_activity a WHERE a.pid=? AND a.wait_event_type='Lock' AND ?=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE ? AND a.query LIKE '%FOR UPDATE%'")){
            while(System.nanoTime()<end){statement.setInt(1,waiter);statement.setInt(2,blocker);statement.setString(3,"%"+table(family,"escrow")+"%");
                try(ResultSet result=statement.executeQuery()){if(result.next())return Objects.toString(result.getString(1),"UNASSIGNED");}
                LockSupport.parkNanos(1_000_000);
            }
        }
        throw new AssertionError("SC-BOUND-04/"+family+"/capacity-wait-not-observed");
    }
    private static boolean isCapacityWait(Cap09ContentionChecks.@NonNull Harness harness,int waiter,int blocker,@NonNull String family)throws Exception {
        try(Connection connection=harness.open(Duration.ofSeconds(5));PreparedStatement statement=connection.prepareStatement(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.pid=? AND a.wait_event_type='Lock' AND ?=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE ? AND a.query LIKE '%FOR UPDATE%')")){
            statement.setInt(1,waiter);statement.setInt(2,blocker);statement.setString(3,"%"+table(family,"escrow")+"%");
            try(ResultSet result=statement.executeQuery()){result.next();return result.getBoolean(1);}
        }
    }
    private static void assertTrace(@NonNull String family,@NonNull String actor,@NonNull List<@NonNull Event> events,int bucket){
        int admission=first(events,"ADMISSION"),entity=first(events,"ENTITY"),capacity=first(events,"CAPACITY_LOCK"),data=first(events,"DATA_WRITE"),quota=first(events,"CAPACITY_WRITE");
        check(family+"/"+actor+"-admission-entity-capacity-write-order",admission>=0&&entity>admission&&capacity>entity&&data>capacity&&quota>data);
        check(family+"/"+actor+"-assigned-bucket-only",events.stream().filter(e->e.category().equals("CAPACITY_LOCK")).count()==1&&events.get(capacity).bindings().contains("3="+bucket));
        check(family+"/"+actor+"-no-namespace-write",events.stream().noneMatch(e->e.category().equals("NAMESPACE_WRITE")));
    }
    private static int first(@NonNull List<@NonNull Event> events,@NonNull String category){for(int i=0;i<events.size();i++)if(events.get(i).category().equals(category))return i;return -1;}
    private static @NonNull Quota @NonNull [] quotas(Cap09ContentionChecks.@NonNull Harness harness,@NonNull String family)throws Exception {
        Quota[] values=new Quota[256];try(Connection connection=harness.open(Duration.ofSeconds(8));PreparedStatement statement=connection.prepareStatement(
                "SELECT bucket,entry_limit,used_entries,byte_limit,used_bytes FROM "+table(family,"escrow")+" WHERE namespace=?")){
            statement.setString(1,harness.scope(family));try(ResultSet result=statement.executeQuery()){
                while(result.next()){int bucket=result.getInt(1);values[bucket]=new Quota(result.getLong(2),result.getLong(3),result.getLong(4),result.getLong(5));}
            }
        }
        for(Quota quota:values)Objects.requireNonNull(quota,"Incomplete escrow census");return values;
    }
    private static Cap09ContentionChecks.@NonNull Plan find(Cap09ContentionChecks.@NonNull Harness harness,@NonNull String family,int start,@NonNull Quota @NonNull [] quotas,int avoid)throws Exception {
        for(int index=start;index<start+10000;index++){
            int bucket=bucket(harness.key(family,index,false));Quota quota=quotas[bucket];
            if(bucket==avoid||quota.used()>=quota.limit()||(family.equals("TOTP")&&quota.byteLimit()-quota.bytes()<1000)||!absent(harness,family,harness.key(family,index,false)))continue;
            System.out.println("SC_BOUND04_SELECT "+family+" index="+index+" bucket="+bucket+" freeEntries="+(quota.limit()-quota.used())+" freeBytes="+(quota.byteLimit()-quota.bytes()));
            Cap09ContentionChecks.Plan plan=harness.capture(family,index,false);
            System.out.println("SC_BOUND04_CHARGE "+family+" index="+index+" reservedBytes="+plan.bytes());
            if(!family.equals("TOTP")||plan.bytes()<=quota.byteLimit()-quota.bytes())return plan;
        }
        throw new AssertionError("No assigned candidate for cross-JVM regression");
    }
    private static boolean absent(Cap09ContentionChecks.@NonNull Harness harness,@NonNull String family,@NonNull String key)throws Exception {
        try(Connection connection=harness.open(Duration.ofSeconds(5));PreparedStatement statement=connection.prepareStatement(
                "SELECT NOT EXISTS(SELECT 1 FROM "+table(family,"entry")+" WHERE namespace='migration' AND storage_key=?)")){
            statement.setString(1,key);try(ResultSet result=statement.executeQuery()){result.next();return result.getBoolean(1);}
        }
    }
    private static int bucket(@NonNull String key)throws Exception{return Byte.toUnsignedInt(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.US_ASCII))[0]);}
    private static @NonNull String table(@NonNull String family,@NonNull String suffix){return family.toLowerCase(Locale.ROOT)+"_store_"+suffix;}
    private static void check(@NonNull String label,boolean passed){if(!passed)throw new AssertionError("SC-BOUND-04/"+label);System.out.println("PASS SC-BOUND-04/"+label);}

    public static void worker(@NonNull String family,Cap09ContentionChecks.@NonNull Connections open,@NonNull Commit commit)throws Exception {
        AtomicInteger count=new AtomicInteger();Traced[] selected=new Traced[1];
        String status=commit.run(budget->{if(count.incrementAndGet()!=1)throw new java.sql.SQLException("Unexpected repeated connection");
            Connection physical=open.open(budget);Traced trace=new Traced(physical);selected[0]=trace;
            try(Statement statement=physical.createStatement();ResultSet result=statement.executeQuery("SELECT pg_backend_pid()")){result.next();System.out.println("READY "+result.getInt(1));System.out.flush();}
            return trace.connection();});
        if(count.get()!=1||selected[0]==null)throw new AssertionError("Missing traced transaction");
        System.out.println("RESULT "+status+" "+selected[0].xid());
        for(Event event:selected[0].events())System.out.println("TRACE "+event.category()+" "+Base64.getUrlEncoder().withoutPadding().encodeToString(event.sql().getBytes(StandardCharsets.UTF_8))+" "+event.bindings());
        System.out.println("END");System.out.flush();
    }
    private static @NonNull String category(@NonNull String sql){String normalized=sql.toUpperCase(Locale.ROOT).replaceAll("\\s+"," ").trim();
        if(normalized.contains("PG_ADVISORY_XACT_LOCK")&&normalized.contains("(?, ?)"))return "ADMISSION";
        if(normalized.contains("PG_ADVISORY_XACT_LOCK")&&normalized.contains("(?)"))return "ENTITY";
        if(normalized.contains("_STORE_ESCROW")&&normalized.contains("FOR UPDATE"))return "CAPACITY_LOCK";
        if(normalized.startsWith("UPDATE ")&&normalized.contains("_STORE_ESCROW"))return "CAPACITY_WRITE";
        if(normalized.matches("(?s)^(INSERT INTO|UPDATE|DELETE FROM) [A-Z]+_STORE_ENTRY\\b.*"))return "DATA_WRITE";
        if(normalized.matches("(?s)^(INSERT INTO|UPDATE|DELETE FROM) [A-Z]+_STORE_NAMESPACE\\b.*"))return "NAMESPACE_WRITE";
        return "SQL_OTHER";
    }
    private static final class Traced {
        private final @NonNull Connection physical;private final @NonNull List<@NonNull Event> events=new ArrayList<>();private @NonNull String xid="UNASSIGNED";
        private Traced(@NonNull Connection physical){this.physical=physical;}
        private @NonNull String xid(){return this.xid;}
        private @NonNull List<@NonNull Event> events(){return List.copyOf(this.events);}
        private @NonNull Connection connection(){return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            try{
                if(method.getName().equals("commit"))try(Statement statement=this.physical.createStatement();ResultSet result=statement.executeQuery("SELECT txid_current_if_assigned()")){
                    if(result.next())this.xid=Objects.toString(result.getString(1),"UNASSIGNED");
                }
                Object value=method.invoke(this.physical,args);
                if(method.getName().equals("createStatement")&&value instanceof Statement statement){
                    return Proxy.newProxyInstance(Statement.class.getClassLoader(),new Class<?>[]{Statement.class},(p,m,a)->{
                        try{
                            if(m.getName().startsWith("execute")&&a!=null&&a.length>0&&a[0] instanceof String sql)this.events.add(new Event(category(sql),sql,"{}"));
                            return m.invoke(statement,a);
                        }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
                    });
                }
                if(method.getName().equals("prepareStatement")&&args!=null&&args[0] instanceof String sql&&value instanceof PreparedStatement statement){
                    Map<Integer,String> bindings=new TreeMap<>();
                    return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{
                        try{
                            if(m.getName().startsWith("set")&&a!=null&&a.length>=2&&a[0] instanceof Integer index)bindings.put(index,bind(a[1]));
                            if(m.getName().startsWith("execute"))this.events.add(new Event(category(sql),sql,bindings.toString().replace(' ', '_')));
                            return m.invoke(statement,a);
                        }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
                    });
                }
                return value;
            }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
        });}
        private static @NonNull String bind(@org.jspecify.annotations.Nullable Object value)throws Exception {
            if(value instanceof Integer||value instanceof Long)return value.toString();
            if(value==null)return "NULL";
            byte[] bytes=value instanceof byte[] binary?binary:value.toString().getBytes(StandardCharsets.UTF_8);
            return value.getClass().getSimpleName()+"#"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes),0,4);
        }
    }
}
