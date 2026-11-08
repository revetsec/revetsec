/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import com.revetsec.oauth.server.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/** Isolated SPI mechanics with structural opaque values, never authenticated engine proofs. */
public final class Cap10AtomicityChecks {
    private static final String NS="cap10",EPOCH="one";
    private static final Duration BUDGET=Duration.ofSeconds(8);
    private static final Instant NOW=Instant.ofEpochSecond(1700000010),END=NOW.plusSeconds(60);
    private static final StoreAdmission ADMISSION=StoreAdmission.fromIdentifiers(id("authority"),id("recovery"));
    private static final StoreTimeObservation.Healthy POINT=StoreTimeObservation.Healthy.fromObservation(ADMISSION,id("clock"),NOW,Duration.ZERO);
    private static final StoreTemporalCondition CONDITION=StoreTimeAccess.get().fromObservation(POINT,NOW,END);
    private static String family,mode,shape;
    private static int dataDml,quotaDml,commits,opens;
    private Cap10AtomicityChecks() { }
    private static String id(String input){try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.US_ASCII)));}catch(Exception e){throw new AssertionError(e);}}
    private static String physical(){return id("physical:"+System.getenv("DB_SCHEMA"));}
    private static String table(String suffix){return family.toLowerCase(Locale.ROOT)+"_store_"+suffix;}
    private static Connection connection(Duration ignored)throws SQLException {
        opens++;
        Connection physical=DriverManager.getConnection(System.getenv("DB_URL"),System.getenv("DB_USER"),System.getenv("DB_PASSWORD"));
        String schema=System.getenv("DB_SCHEMA");if(!schema.matches("cap10_[a-z0-9_]+"))throw new SQLException("Invalid owned schema");
        try(Statement statement=physical.createStatement()){statement.execute("SET search_path TO "+schema);}
        return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            try{
                Object value=method.invoke(physical,args);
                if(method.getName().equals("commit")&&dataDml>0){
                    commits++;
                    if(mode.equals("halt_after")){System.out.println("BOUNDARY committed-before-receipt");System.out.flush();Runtime.getRuntime().halt(79);}
                    if(mode.equals("lost"))throw new SQLException("Injected lost COMMIT acknowledgement","08006");
                }
                if(method.getName().equals("prepareStatement")&&args!=null&&args[0] instanceof String sql&&value instanceof PreparedStatement statement)
                    return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{
                        try{
                            Object result=m.invoke(statement,a);
                            if(m.getName().equals("executeUpdate")){
                                String normalized=sql.toLowerCase(Locale.ROOT);
                                boolean quota=normalized.startsWith("update "+table("escrow"));
                                boolean data=normalized.startsWith("insert into "+table("entry"))||normalized.startsWith("update "+table("entry"))||normalized.startsWith("delete from "+table("entry"));
                                if(data)dataDml++;if(quota)quotaDml++;
                                String boundary=data&&dataDml==1?"data":quota&&quotaDml==1?"quota":"none";
                                if(mode.equals("fail_"+boundary))throw new SQLException("Injected after actual "+boundary+" DML","P0001");
                                if(mode.equals("halt_"+boundary)){System.out.println("BOUNDARY after-first-"+boundary+"-dml");System.out.flush();Runtime.getRuntime().halt(78);}
                            }
                            return result;
                        }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
                    });
                return value;
            }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
        });
    }
    private static String key(int index){
        if(family.equals("TOTP"))return TotpStoreKey.forAccount(NS,EPOCH,"account-"+index).getStorageKey();
        if(family.equals("WEBAUTHN"))return WebAuthnStoreKey.forCeremony(NS,"example.invalid",Base64.getUrlDecoder().decode(id("ceremony-"+index))).getStorageKey();
        return "revetsec:as:1:"+id("issuer")+":INTERACTION:"+id("interaction-"+index);
    }
    private static int bucket(String key){try{return Byte.toUnsignedInt(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.US_ASCII))[0]);}catch(Exception e){throw new AssertionError(e);}}
    private static List<String> keys(){
        List<String> keys=new ArrayList<>();keys.add(key(0));int target=bucket(keys.get(0)),cursor=1;
        // a,b,e share a bucket; c,d,f,g each use a different bucket.
        Set<Integer> used=new HashSet<>();used.add(target);
        while(keys.size()<7){String candidate=key(cursor++);int b=bucket(candidate),position=keys.size();boolean same=position==1||position==4;
            if(same?b==target:!used.contains(b)){keys.add(candidate);used.add(b);}if(cursor>100000)throw new AssertionError("Candidate search exhausted");}
        return keys;
    }
    private record Change(String key,boolean remove,int size,int version) { }
    private static byte[] payload(int size,int version){
        byte[] raw=new byte[55+size*3];Arrays.fill(raw,(byte)version);raw[0]=1;raw[1]=1;raw[2]='k';
        return family.equals("TOTP")?Base64.getUrlEncoder().withoutPadding().encode(raw):raw;
    }
    private static List<Change> changes(boolean seed){
        List<String> k=keys();List<Change> out=new ArrayList<>();int[] sizes={128,256,384,32};
        if(seed){for(int i=0;i<4;i++)out.add(new Change(k.get(i),false,sizes[i],1));return out;}
        if(family.equals("TOTP")){
            out.add(new Change(k.get(0),false,256,2));out.add(new Change(k.get(1),false,128,2));
            out.add(new Change(k.get(2),false,shape.equals("negative")?64:128,2));out.add(new Change(k.get(3),false,288,2));
            if(shape.equals("positive"))out.add(new Change(k.get(4),false,64,2));
        }else{
            // Insert before delete deliberately: capacity must check merged net, not transient order.
            out.add(new Change(k.get(4),false,64,2));out.add(new Change(k.get(0),false,256,2));out.add(new Change(k.get(1),true,0,2));out.add(new Change(k.get(2),true,0,2));
            if(!shape.equals("negative"))out.add(new Change(k.get(5),false,32,2));
            if(shape.equals("positive"))out.add(new Change(k.get(6),false,32,2));
        }
        return out;
    }
    private static String version(Change c){return id("version:"+c.key()+":"+c.version());}
    private static String commit(List<Change> changes,boolean initialize)throws Exception{
        Set<TotpStoreKey> totpKeys=new HashSet<>();Set<WebAuthnStoreKey> waKeys=new HashSet<>();
        if(family.equals("TOTP")){
            TotpStoreKey root=TotpStoreKey.forNamespace(NS,EPOCH);totpKeys.add(root);for(Change c:changes)totpKeys.add(TotpStoreKey.fromStoredForm(c.key()));
            PostgresqlTotpStore store=new PostgresqlTotpStore(NS,physical(),Cap10AtomicityChecks::connection,4096,4_000_000L,(scope,left)->POINT);
            TotpStoreReadResult result=store.read(totpKeys,BUDGET);if(!(result instanceof TotpStoreReadResult.Available read))throw new AssertionError("TOTP read unavailable");
            List<TotpStoreWrite.Mutation> mutations=new ArrayList<>();
            for(Change c:changes){TotpStoreKey key=TotpStoreKey.fromStoredForm(c.key());TotpStoreRecord record=TotpStoreRecord.fromStoredForm(key,version(c),payload(c.size(),c.version()));mutations.add(read.getSnapshot().getEntry(key) instanceof TotpStoreEntry.Absent?TotpStoreWrite.Mutation.insert(record):TotpStoreWrite.Mutation.replace(record));}
            var receipt=store.compareAndCommit(TotpStoreWrite.fromSnapshotAndMutations(initialize?TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE:TotpStoreWrite.Purpose.UPDATE,read.getSnapshot(),mutations,CONDITION),BUDGET);
            System.out.println("TIMING "+receipt.getTiming().isPresent());return receipt.getStatus().name();
        }
        if(family.equals("WEBAUTHN")){
            for(Change c:changes)waKeys.add(WebAuthnStoreKey.fromStoredForm(c.key()));
            PostgresqlWebAuthnStore store=new PostgresqlWebAuthnStore(NS,physical(),Cap10AtomicityChecks::connection,4096,(scope,left)->POINT);
            WebAuthnStoreReadResult result=store.read(waKeys,BUDGET);if(!(result instanceof WebAuthnStoreReadResult.Available read))throw new AssertionError("WebAuthn read unavailable");
            List<WebAuthnStoreWrite.Mutation> mutations=new ArrayList<>();
            for(Change c:changes){WebAuthnStoreKey key=WebAuthnStoreKey.fromStoredForm(c.key());mutations.add(c.remove()?WebAuthnStoreWrite.Mutation.delete(key):read.getSnapshot().getEntry(key) instanceof WebAuthnStoreEntry.Absent?WebAuthnStoreWrite.Mutation.insertExpiring(key,payload(c.size(),c.version()),END):WebAuthnStoreWrite.Mutation.replaceExpiring(key,payload(c.size(),c.version()),END));}
            var receipt=store.compareAndCommit(WebAuthnStoreWrite.fromSnapshotAndMutations(read.getSnapshot(),mutations,CONDITION),BUDGET);
            System.out.println("TIMING "+receipt.getTiming().isPresent());return receipt.getStatus().name();
        }
        PostgresqlIssuerStore store=new PostgresqlIssuerStore(NS,physical(),Cap10AtomicityChecks::connection,4096,(scope,left)->POINT);
        List<OAuthStoreTransaction.Condition> conditions=new ArrayList<>();List<OAuthStoreTransaction.Mutation> mutations=new ArrayList<>();
        for(Change c:changes){OAuthStoreKey key=OAuthStoreKey.fromStoredForm(c.key());OAuthStoreReadResult result=store.read(key,BUDGET);if(!(result instanceof OAuthStoreReadResult.Available read))throw new AssertionError("Issuer read unavailable");
            conditions.add(read.getEntry().isEmpty()?(OAuthStoreTransaction.Condition)call(OAuthStoreTransaction.Condition.class,"fromAbsent",new Class<?>[]{OAuthStoreKey.class},key):(OAuthStoreTransaction.Condition)call(OAuthStoreTransaction.Condition.class,"fromVersion",new Class<?>[]{OAuthStoreKey.class,String.class},key,read.getEntry().orElseThrow().getVersion()));
            mutations.add(c.remove()?(OAuthStoreTransaction.Mutation)call(OAuthStoreTransaction.Mutation.class,"fromRemove",new Class<?>[]{OAuthStoreKey.class},key):(OAuthStoreTransaction.Mutation)call(OAuthStoreTransaction.Mutation.class,"fromPut",new Class<?>[]{OAuthStoreEntry.class},OAuthStoreEntry.fromStoredForm(key,version(c),END,Base64.getUrlEncoder().withoutPadding().encodeToString(payload(c.size(),c.version())))));
        }
        OAuthStoreTransaction transaction=(OAuthStoreTransaction)call(OAuthStoreTransaction.class,"fromConditions",new Class<?>[]{OAuthStoreTransaction.Purpose.class,StoreAdmission.class,StoreTemporalCondition.class,List.class,List.class},OAuthStoreTransaction.Purpose.TIMED,ADMISSION,CONDITION,conditions,mutations);
        var receipt=store.commit(transaction,BUDGET);System.out.println("TIMING "+receipt.getTiming().isPresent());return receipt.getStatus().name();
    }
    private static Object call(Class<?> type,String name,Class<?>[] parameters,Object... arguments)throws Exception{Method method=type.getDeclaredMethod(name,parameters);method.setAccessible(true);try{return method.invoke(null,arguments);}catch(InvocationTargetException wrapped){throw new AssertionError("Invalid structural issuer fixture",wrapped.getCause());}}
    private static void provision()throws Exception{
        try(Connection c=connection(BUDGET);Statement s=c.createStatement()){
            String ids="'"+physical()+"','"+ADMISSION.getAuthorityId()+"','"+ADMISSION.getRecoveryGeneration()+"','"+id("clock")+"',0,'"+id("allocation")+"'";
            if(family.equals("TOTP")){
                s.executeUpdate("INSERT INTO totp_store_namespace(namespace,physical_namespace,active_epoch,activation_state,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,maximum_reserved_bytes) VALUES ('cap10','"+physical()+"','one','NEW','"+ADMISSION.getAuthorityId()+"','"+ADMISSION.getRecoveryGeneration()+"','"+id("clock")+"',0,'"+id("allocation")+"',3,4096,4000000)");
                s.executeUpdate("INSERT INTO totp_store_epoch(namespace,recovery_epoch) VALUES ('cap10','one')");
            }else s.executeUpdate("INSERT INTO "+table("namespace")+"(namespace,physical_namespace,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,admission_open) VALUES ('cap10',"+ids+",2,4096,true)");
            s.executeUpdate("INSERT INTO "+table("escrow")+"(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) SELECT '"+family+"','"+physical()+"',n,'"+id("allocation")+"',16,0,"+(family.equals("TOTP")?15625:0)+",0 FROM generate_series(0,255) n");
        }
        if(family.equals("TOTP")){String status=commit(List.of(new Change(TotpStoreKey.forNamespace(NS,EPOCH).getStorageKey(),false,0,1)),true);if(!status.equals("COMMITTED"))throw new AssertionError("Root setup: "+status);}
        String status=commit(changes(true),false);if(!status.equals("COMMITTED"))throw new AssertionError("Seed setup: "+status);
        System.out.println("SETUP ready");
    }
    private static void fill()throws Exception{
        int target=bucket(keys().get(mode.equals("fill_cancel")?0:family.equals("TOTP")?4:5));
        if(mode.equals("fill_bytes"))target=bucket(keys().get(3));
        long freeEntries,freeBytes;
        try(Connection c=connection(BUDGET);PreparedStatement s=c.prepareStatement("SELECT entry_limit-used_entries,byte_limit-used_bytes FROM "+table("escrow")+" WHERE bucket=?")){s.setInt(1,target);try(ResultSet r=s.executeQuery()){if(!r.next())throw new AssertionError("Missing fill bucket");freeEntries=r.getLong(1);freeBytes=r.getLong(2);}}
        boolean bytes=mode.equals("fill_bytes")||(mode.equals("fill_cancel")&&family.equals("TOTP"));
        long count=bytes?1:freeEntries;int size=bytes?(int)((freeBytes-158)/4):0;if(count<=0||size<0)throw new AssertionError("Invalid fill");
        List<Change> pending=new ArrayList<>();
        for(int i=100001;count>0&&i<200000;i++)if(bucket(key(i))==target){pending.add(new Change(key(i),false,size,1));count--;if(pending.size()==8||count==0){if(!commit(pending,false).equals("COMMITTED"))throw new AssertionError("Fill refused");pending.clear();}}
        if(count!=0)throw new AssertionError("Fill search exhausted");System.out.println("FILL ready");
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3||!Set.of("TOTP","WEBAUTHN","ISSUER").contains(args[0])||!Set.of("setup","fill_entry","fill_bytes","fill_cancel","normal","fail_data","fail_quota","lost","halt_data","halt_quota","halt_after").contains(args[1])||!Set.of("positive","zero","negative").contains(args[2]))throw new IllegalArgumentException("Expected family/mode/shape");
        family=args[0];mode=args[1];shape=args[2];
        if(mode.equals("setup")){provision();return;}
        if(mode.startsWith("fill_")){fill();return;}
        List<Change> changes=changes(false);
        for(Change c:changes)System.out.println("PLAN\t"+c.key()+"\t"+(c.remove()?"REMOVE":"PUT")+"\t"+version(c)+"\t"+(c.remove()?"-":Base64.getUrlEncoder().withoutPadding().encodeToString(payload(c.size(),c.version()))));
        System.out.flush();String status=commit(changes,false);
        System.out.println("STATUS "+status);System.out.println("TRACE "+dataDml+" "+quotaDml+" "+commits+" "+opens);
    }
}
