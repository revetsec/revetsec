/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations.
 */
package example.pending;

import org.jspecify.annotations.NonNull;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

/** Bounded real-adapter contention; no throughput SLO or deployment-profile claim. */
public final class Cap09ContentionChecks {
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(8);
    private Cap09ContentionChecks() { }
    public record Plan(@NonNull String family,int index,boolean large,@NonNull String key,long bytes,@NonNull Object write){
        @Override public @NonNull String toString(){return "Plan{<redacted>}";}
    }
    public record PublicResult(@NonNull String outcome,@NonNull String status,int calls) { }
    @FunctionalInterface public interface Connections { @NonNull Connection open(@NonNull Duration budget)throws SQLException; }
    public interface Harness {
        @NonNull String key(@NonNull String family,int index,boolean large);
        @NonNull String scope(@NonNull String family);
        @NonNull Plan capture(@NonNull String family,int index,boolean large)throws Exception;
        @NonNull String commit(@NonNull Plan plan,@NonNull Connections source)throws Exception;
        @NonNull PublicResult execute(@NonNull Plan plan,@NonNull Stats trace)throws Exception;
        @NonNull Connection open(@NonNull Duration budget)throws SQLException;
        @NonNull AutoCloseable permit(@NonNull String family)throws Exception;
    }
    public static final class Stats {
        private final @NonNull Set<@NonNull String> sql=ConcurrentHashMap.newKeySet();
        private final @NonNull AtomicInteger namespaceWrites=new AtomicInteger(),globalInventoryQueries=new AtomicInteger();
        private void executed(@NonNull String query){
            String normalized=query.toUpperCase(Locale.ROOT).replaceAll("\\s+"," ").trim();this.sql.add(normalized);
            if(normalized.matches("(?s)^(UPDATE|INSERT INTO|DELETE FROM|TRUNCATE(?: TABLE)?) (?:PUBLIC\\.)?(TOTP|WEBAUTHN|ISSUER)_STORE_NAMESPACE\\b.*"))this.namespaceWrites.incrementAndGet();
            if((normalized.contains("SUM(")||normalized.contains("COUNT("))&&normalized.matches("(?s).*FROM (?:PUBLIC\\.)?(TOTP|WEBAUTHN|ISSUER)_STORE_(ENTRY|ESCROW)\\b.*"))this.globalInventoryQueries.incrementAndGet();
        }
    }
    public static @NonNull Connection track(@NonNull Connection physical,@NonNull Stats trace,@NonNull AtomicInteger pid)throws SQLException{
        try(Statement s=physical.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){if(!r.next())throw new SQLException("Missing owned PID");pid.set(r.getInt(1));}
        return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            try{
                Object value=method.invoke(physical,args);
                if(method.getName().equals("prepareStatement")&&args!=null&&args.length>0&&args[0] instanceof String query&&value instanceof PreparedStatement statement)
                    return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{try{if(m.getName().startsWith("execute"))trace.executed(query);return m.invoke(statement,a);}catch(InvocationTargetException wrapped){throw wrapped.getCause();}});
                return value;
            }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
        });
    }
    private record Quota(int bucket,long limit,long used,long byteLimit,long bytes) { }
    public static void run(@NonNull Harness h)throws Exception{
        Stats trace=new Stats();
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER")){
            String namespace=namespaceFingerprint(h,family);int cursor=0;
            for(int round=0;round<2;round++){
                List<Quota> quotas=quotas(h,family);Plan held=find(h,family,cursor,false,quotas,-1,-1,true);cursor=held.index()+1;
                Plan other=find(h,family,cursor,false,quotas,-1,bucket(held.key()),true);cursor=other.index()+1;
                check(family+"/disjoint-canonical-account-and-capacity-buckets/"+round,!held.key().equals(other.key())&&bucket(held.key())!=bucket(other.key()));
                ExecutorService workers=Executors.newFixedThreadPool(2);AtomicInteger pendingPid=new AtomicInteger();
                try(AutoCloseable permit=h.permit(family);Connection blocker=h.open(BUDGET)){
                    Objects.requireNonNull(permit);
                    blocker.setAutoCommit(false);int blockerPid;
                    try(Statement s=blocker.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();blockerPid=r.getInt(1);}
                    try(PreparedStatement s=blocker.prepareStatement("SELECT namespace FROM "+table(family,"namespace")+" WHERE namespace='migration' FOR NO KEY UPDATE")){try(ResultSet r=s.executeQuery()){if(!r.next())throw new AssertionError("Missing namespace");}}
                    try(PreparedStatement s=blocker.prepareStatement("SELECT bucket FROM "+table(family,"escrow")+" WHERE namespace=? AND bucket=? FOR UPDATE")){s.setString(1,h.scope(family));s.setInt(2,bucket(held.key()));try(ResultSet r=s.executeQuery()){if(!r.next())throw new AssertionError("Missing held bucket");}}
                    Future<String> pending=workers.submit(()->h.commit(held,budget->track(h.open(budget),trace,pendingPid)));
                    try{
                        boolean waited=false;long end=System.nanoTime()+3_000_000_000L;
                        try(Connection observer=h.open(BUDGET);PreparedStatement s=observer.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE pid=? AND wait_event_type='Lock' AND ?=ANY(pg_blocking_pids(a.pid)) AND query LIKE ? AND query LIKE '%FOR UPDATE%')")){
                            while(end-System.nanoTime()>0){s.setInt(1,pendingPid.get());s.setInt(2,blockerPid);s.setString(3,"%"+table(family,"escrow")+"%");try(ResultSet r=s.executeQuery()){r.next();if(r.getBoolean(1)){waited=true;break;}}LockSupport.parkNanos(1_000_000);}
                        }
                        check(family+"/actual-selected-escrow-lock-wait/"+round,waited&&!pending.isDone());
                        Future<String> independent=workers.submit(()->h.commit(other,budget->track(h.open(budget),trace,new AtomicInteger())));
                        String status=independent.get(3,TimeUnit.SECONDS);
                        check(family+"/unrelated-account-commits-before-holder-release/"+round,status.equals("COMMITTED")&&!pending.isDone());
                        blocker.rollback();check(family+"/held-account-commits-after-explicit-release/"+round,pending.get(5,TimeUnit.SECONDS).equals("COMMITTED"));
                    }finally{blocker.rollback();pending.cancel(true);}
                }finally{workers.shutdownNow();check(family+"/owned-workers-terminated/"+round,workers.awaitTermination(3,TimeUnit.SECONDS));}
            }
            List<Quota> available=quotas(h,family);int target=available.stream().filter(q->q.used()==0&&q.limit()>0&&(family.equals("TOTP")?q.limit()==1&&q.byteLimit()>1000:true)).mapToInt(Quota::bucket).findFirst().orElseThrow();
            while(true){Quota quota=quotas(h,family).get(target);if(quota.used()==quota.limit())break;Plan fill=find(h,family,cursor,false,quotas(h,family),target,-1,true);cursor=fill.index()+1;PublicResult result=h.execute(fill,trace);check(family+"/genuine-public-collision-bucket-fill",result.outcome().equals("SUCCESS")&&result.status().equals("COMMITTED")&&result.calls()==1);}
            Plan refused=find(h,family,cursor,false,quotas(h,family),target,-1,false);cursor=refused.index()+1;
            List<Quota> full=quotas(h,family);check(family+"/collision-full-assigned-bucket-with-global-spare",full.get(target).used()==full.get(target).limit()&&full.stream().mapToLong(q->q.limit()-q.used()).sum()>0);
            String before=fingerprint(h,family);
            try(AutoCloseable permit=h.permit(family)){Objects.requireNonNull(permit);check(family+"/raw-collision-is-capacity-not-CAS",capacity(family).equals(h.commit(refused,budget->track(h.open(budget),trace,new AtomicInteger()))));}
            PublicResult result=h.execute(refused,trace);
            check(family+"/public-collision-unavailable-with-one-capacity-call",result.outcome().equals(family.equals("TOTP")?"CAPACITY":"UNAVAILABLE")&&result.status().equals(capacity(family))&&result.calls()==1);
            check(family+"/collision-zero-data-quota-version-effects-no-borrowing",before.equals(fingerprint(h,family)));
            if(family.equals("TOTP")){
                Plan oversized=find(h,family,cursor,true,quotas(h,family),-1,-1,false);Quota q=quotas(h,family).get(bucket(oversized.key()));
                check("TOTP/byte-stranding-has-entry-room-and-global-byte-spare",q.used()<q.limit()&&q.byteLimit()-q.bytes()<oversized.bytes()&&quotas(h,family).stream().mapToLong(x->x.byteLimit()-x.bytes()).sum()>oversized.bytes());before=fingerprint(h,family);
                try(AutoCloseable permit=h.permit(family)){Objects.requireNonNull(permit);check("TOTP/raw-byte-stranding-is-capacity",h.commit(oversized,budget->track(h.open(budget),trace,new AtomicInteger())).equals("CAPACITY_REFUSED"));}
                result=h.execute(oversized,trace);check("TOTP/public-byte-stranding-no-retry-or-invalid-credential",result.outcome().equals("CAPACITY")&&result.status().equals("CAPACITY_REFUSED")&&result.calls()==1);
                check("TOTP/byte-stranding-preserves-all-state-and-assigned-limits",before.equals(fingerprint(h,family)));
            }
            check(family+"/namespace-capacity-metadata-is-unchanged",namespace.equals(namespaceFingerprint(h,family)));
        }
        check("all-families/no-ordinary-namespace-capacity-write",trace.namespaceWrites.get()==0);
        check("all-families/no-ordinary-global-count-sum-or-borrow-query",trace.globalInventoryQueries.get()==0);
        List<String> hashes=new ArrayList<>();for(String sql:trace.sql)hashes.add(hex(sql));Collections.sort(hashes);
        System.out.println("CAP09_SQL_FINGERPRINTS "+String.join(",",hashes));
    }
    private static @NonNull Plan find(@NonNull Harness h,@NonNull String family,int start,boolean large,@NonNull List<@NonNull Quota> quotas,int wanted,int avoid,boolean mustFit)throws Exception{
        for(int i=start;i<start+100000;i++){
            String key=h.key(family,i,large);int bucket=bucket(key);Quota q=quotas.get(bucket);
            if((wanted>=0&&wanted!=bucket)||bucket==avoid)continue;
            if(mustFit&&(q.used()>=q.limit()||(family.equals("TOTP")&&q.byteLimit()-q.bytes()<1000)))continue;
            if(large&&(q.used()>=q.limit()||q.byteLimit()-q.bytes()>2500))continue;
            Plan plan=h.capture(family,i,large);check(family+"/captured-genuine-single-account-shape",plan.key().equals(key));
            if(mustFit&&plan.bytes()>q.byteLimit()-q.bytes())continue;
            if(large&&plan.bytes()<=q.byteLimit()-q.bytes())continue;
            return plan;
        }
        throw new AssertionError("No bounded canonical candidate");
    }
    private static @NonNull String capacity(@NonNull String family){return family.equals("TOTP")?"CAPACITY_REFUSED":"CAPACITY";}
    private static @NonNull String table(@NonNull String family,@NonNull String suffix){return family.toLowerCase(Locale.ROOT)+"_store_"+suffix;}
    private static int bucket(@NonNull String key)throws Exception{return Integer.parseInt(hex(key).substring(0,2),16);}
    private static @NonNull String hex(@NonNull String value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));}
    private static @NonNull List<@NonNull Quota> quotas(@NonNull Harness h,@NonNull String family)throws Exception{
        List<Quota> values=new ArrayList<>();try(Connection c=h.open(BUDGET);PreparedStatement s=c.prepareStatement("SELECT bucket,entry_limit,used_entries,byte_limit,used_bytes FROM "+table(family,"escrow")+" WHERE namespace=? ORDER BY bucket")){s.setString(1,h.scope(family));try(ResultSet r=s.executeQuery()){while(r.next())values.add(new Quota(r.getInt(1),r.getLong(2),r.getLong(3),r.getLong(4),r.getLong(5)));}}if(values.size()!=256)throw new AssertionError("Incomplete quota census");return values;
    }
    private static @NonNull String namespaceFingerprint(@NonNull Harness h,@NonNull String family)throws Exception{return query(h,"SELECT md5(row_to_json(n)::text) FROM "+table(family,"namespace")+" n WHERE namespace='migration'");}
    private static @NonNull String fingerprint(@NonNull Harness h,@NonNull String family)throws Exception{
        String result=namespaceFingerprint(h,family);
        for(String suffix:List.of("entry","escrow"))result+=query(h,"SELECT md5(coalesce(jsonb_agg(to_jsonb(n) ORDER BY "+(suffix.equals("entry")?"storage_key":"bucket")+")::text,'')) FROM "+table(family,suffix)+" n");
        return result;
    }
    private static @NonNull String query(@NonNull Harness h,@NonNull String sql)throws Exception{try(Connection c=h.open(BUDGET);Statement s=c.createStatement();ResultSet r=s.executeQuery(sql)){if(!r.next())throw new AssertionError("Missing metadata");return Objects.requireNonNull(r.getString(1));}}
    private static void check(@NonNull String label,boolean passed){if(!passed)throw new AssertionError("CAP09/"+label);System.out.println("PASS CAP09/"+label);}
}
