/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Actual helper calls and recorded requested SQL only; no native deadlock/profile claim. */
public final class ActualLockHelperChecks {
    private static final @NonNull String PHYSICAL="A".repeat(43);
    private static int assertions;
    private ActualLockHelperChecks() { }
    private record Row(long id,boolean exclusive) { }
    private record Pair(int first,int second) { }
    private record Scope(@NonNull String family,@NonNull String namespace) { }
    private record Hash(@NonNull Pair admission,long entity) { }
    @FunctionalInterface private interface Checked { void run()throws Exception; }
    private static void check(@NonNull String label,boolean value){if(!value)throw new AssertionError(label);assertions++;System.out.println("PASS "+label);}
    private static void reject(@NonNull String label,@NonNull Checked operation)throws Exception{boolean rejected=false;try{operation.run();}catch(IllegalArgumentException expected){rejected=true;}check(label,rejected);}
    private static @NonNull List<@NonNull Row> merge(@NonNull String implementation,@NonNull List<@NonNull Row> values){
        return switch(implementation){
            case "TOTP"->TotpPgLocks.merge(values.stream().map(r->TotpPgLocks.Entity.fromId(r.id(),r.exclusive())).toList()).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            case "WEBAUTHN"->WebAuthnPgLocks.merge(values.stream().map(r->WebAuthnPgLocks.Entity.fromId(r.id(),r.exclusive())).toList()).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            case "ISSUER"->IssuerPgLocks.merge(values.stream().map(r->IssuerPgLocks.Entity.fromId(r.id(),r.exclusive())).toList()).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            default->throw new IllegalArgumentException("Unknown helper");
        };
    }
    private static @NonNull List<@NonNull Row> entitySet(@NonNull String implementation,@NonNull Scope scope,@NonNull Map<@NonNull String,@NonNull Boolean> keys){
        return switch(implementation){
            case "TOTP"->TotpPgLocks.entitySet(TotpPgScope.from(scope.family(),scope.namespace()),keys).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            case "WEBAUTHN"->WebAuthnPgLocks.entitySet(WebAuthnPgScope.from(scope.family(),scope.namespace()),keys).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            case "ISSUER"->IssuerPgLocks.entitySet(IssuerPgScope.from(scope.family(),scope.namespace()),keys).stream().map(r->new Row(r.getId(),r.isExclusive())).toList();
            default->throw new IllegalArgumentException("Unknown helper");
        };
    }
    private static @NonNull Hash hash(@NonNull String implementation,@NonNull Scope scope,@NonNull String key){
        return switch(implementation){
            case "TOTP"->{var s=TotpPgScope.from(scope.family(),scope.namespace());var a=TotpPgLocks.admission(s);yield new Hash(new Pair(a.getFirst(),a.getSecond()),TotpPgLocks.entity(s,key,false).getId());}
            case "WEBAUTHN"->{var s=WebAuthnPgScope.from(scope.family(),scope.namespace());var a=WebAuthnPgLocks.admission(s);yield new Hash(new Pair(a.getFirst(),a.getSecond()),WebAuthnPgLocks.entity(s,key,false).getId());}
            case "ISSUER"->{var s=IssuerPgScope.from(scope.family(),scope.namespace());var a=IssuerPgLocks.admission(s);yield new Hash(new Pair(a.getFirst(),a.getSecond()),IssuerPgLocks.entity(s,key,false).getId());}
            default->throw new IllegalArgumentException("Unknown helper");
        };
    }
    private static @NonNull List<@NonNull Pair> admissions(@NonNull String implementation,@NonNull List<@NonNull Scope> scopes){
        return switch(implementation){
            case "TOTP"->TotpPgLocks.allAdmission(scopes.stream().map(s->TotpPgScope.from(s.family(),s.namespace())).toList()).stream().map(a->new Pair(a.getFirst(),a.getSecond())).toList();
            case "WEBAUTHN"->WebAuthnPgLocks.allAdmission(scopes.stream().map(s->WebAuthnPgScope.from(s.family(),s.namespace())).toList()).stream().map(a->new Pair(a.getFirst(),a.getSecond())).toList();
            case "ISSUER"->IssuerPgLocks.allAdmission(scopes.stream().map(s->IssuerPgScope.from(s.family(),s.namespace())).toList()).stream().map(a->new Pair(a.getFirst(),a.getSecond())).toList();
            default->throw new IllegalArgumentException("Unknown helper");
        };
    }
    private static void acquire(@NonNull String implementation,@NonNull Connection connection,@NonNull List<@NonNull Row> rows,long deadline)throws SQLException{
        switch(implementation){
            case "TOTP"->TotpPgLocks.entities(connection,rows.stream().map(r->TotpPgLocks.Entity.fromId(r.id(),r.exclusive())).toList(),deadline);
            case "WEBAUTHN"->WebAuthnPgLocks.entities(connection,rows.stream().map(r->WebAuthnPgLocks.Entity.fromId(r.id(),r.exclusive())).toList(),deadline);
            case "ISSUER"->IssuerPgLocks.entities(connection,rows.stream().map(r->IssuerPgLocks.Entity.fromId(r.id(),r.exclusive())).toList(),deadline);
            default->throw new IllegalArgumentException("Unknown helper");
        }
    }
    private static final class Recorder {
        private final @NonNull List<@NonNull Row> locks=new ArrayList<>();
        private int timeouts;
        private @NonNull Connection connection(boolean autoCommit,int isolation){
            return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->switch(method.getName()){
                case "getAutoCommit"->autoCommit;
                case "getTransactionIsolation"->isolation;
                case "prepareStatement"->statement((String)Objects.requireNonNull(args)[0]);
                case "close"->null;
                default->throw new AssertionError("Unexpected recorder connection call: "+method.getName());
            });
        }
        private @NonNull PreparedStatement statement(@NonNull String sql){
            long[] id={0};String[] timeout={"",""};
            return (PreparedStatement)Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(proxy,method,args)->{
                switch(method.getName()){
                    case "setLong"->{if(((Integer)Objects.requireNonNull(args)[0])!=1)throw new AssertionError("Wrong advisory ID parameter");id[0]=(Long)args[1];return null;}
                    case "setString"->{timeout[(Integer)Objects.requireNonNull(args)[0]-1]=(String)args[1];return null;}
                    case "close"->{return null;}
                    case "execute"->{
                        if(sql.equals("SELECT set_config('statement_timeout', ?, true), set_config('lock_timeout', ?, true)")){
                            if(!timeout[0].equals(timeout[1])||!timeout[0].matches("[1-9][0-9]*ms"))throw new AssertionError("Missing original deadline bound");this.timeouts++;
                        }else if(sql.equals("SELECT pg_advisory_xact_lock(?)"))this.locks.add(new Row(id[0],true));
                        else if(sql.equals("SELECT pg_advisory_xact_lock_shared(?)"))this.locks.add(new Row(id[0],false));
                        else throw new AssertionError("Unexpected helper SQL");
                        return false;
                    }
                    default->throw new AssertionError("Unexpected recorder statement call: "+method.getName());
                }
            });
        }
    }
    private static void permutation(@NonNull String implementation,@NonNull List<@NonNull Row> input,int start,@NonNull AtomicInteger index)throws Exception{
        if(start==input.size()){
            List<Row> expected=List.of(new Row(Long.MIN_VALUE,false),new Row(-1,true),new Row(0,true),new Row(1,false),new Row(Long.MAX_VALUE,true));
            int cell=index.getAndIncrement();check(implementation+"/merge-permutation/"+cell,merge(implementation,input).equals(expected));
            Recorder recorder=new Recorder();try(Connection c=recorder.connection(false,Connection.TRANSACTION_READ_COMMITTED)){acquire(implementation,c,input,System.nanoTime()+10_000_000_000L);}
            check(implementation+"/SQL-once-sorted-strongest/"+cell,recorder.locks.equals(expected)&&recorder.timeouts==expected.size());return;
        }
        for(int i=start;i<input.size();i++){Collections.swap(input,start,i);permutation(implementation,input,start+1,index);Collections.swap(input,start,i);}
    }
    private static void grammar(@NonNull String implementation)throws Exception{
        List<String> namespaces=List.of("a",PHYSICAL,"scope-µ","é".repeat(128),"😀".repeat(64),"a:b","ab:c");
        List<String> keys=List.of("x","record:a","a:b:c","ab:c","x".repeat(640),"line\nkey");
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER"))for(int n=0;n<namespaces.size();n++)for(int k=0;k<keys.size();k++){
            String namespace=namespaces.get(n),key=keys.get(k);Hash actual=hash(implementation,new Scope(family,namespace),key);
            System.out.println("HASH\t"+implementation+'\t'+family+'\t'+Base64.getEncoder().encodeToString(namespace.getBytes(StandardCharsets.UTF_8))+'\t'+Base64.getEncoder().encodeToString(key.getBytes(StandardCharsets.US_ASCII))+'\t'+actual.admission().first()+'\t'+actual.admission().second()+'\t'+actual.entity());
        }
        Hash fixed=hash(implementation,new Scope("ISSUER","scope-µ"),"record:a");check(implementation+"/fixed-independent-UTF8-vector",fixed.admission().first()==817153383&&fixed.admission().second()==-1070715098&&fixed.entity()==9076332401462940645L);
        List<String> invalidNamespaces=List.of("","x".repeat(257),"é".repeat(129),"😀".repeat(65),"embedded\0zero","\ud800","\udc00");
        for(int i=0;i<invalidNamespaces.size();i++){String ns=invalidNamespaces.get(i);reject(implementation+"/invalid-UTF8-scope/"+i,()->hash(implementation,new Scope("TOTP",ns),"key"));}
        for(String family:List.of("totp","TOTP ","OTHER",""))reject(implementation+"/invalid-family/"+family,()->hash(implementation,new Scope(family,PHYSICAL),"key"));
        List<String> invalidKeys=List.of("","x".repeat(641),"embedded\0zero","é","\ud800");
        for(int i=0;i<invalidKeys.size();i++){String key=invalidKeys.get(i);reject(implementation+"/invalid-exact-ASCII-key/"+i,()->hash(implementation,new Scope("TOTP",PHYSICAL),key));}
        List<Scope> scopeSet=List.of(new Scope("TOTP",PHYSICAL),new Scope("ISSUER","scope-µ"),new Scope("WEBAUTHN","different"));
        List<Pair> expected=new ArrayList<>();for(Scope s:scopeSet)expected.add(hash(implementation,s,"key").admission());
        expected.sort((a,b)->{int first=Integer.compare(a.first(),b.first());return first==0?Integer.compare(a.second(),b.second()):first;});
        check(implementation+"/all-scope-signed-order",admissions(implementation,scopeSet).equals(expected));
        List<Scope> reverse=new ArrayList<>(scopeSet);Collections.reverse(reverse);check(implementation+"/all-scope-reversed-input",admissions(implementation,reverse).equals(expected));
        reject(implementation+"/empty-allowlist",()->admissions(implementation,List.of()));
        reject(implementation+"/duplicate-family-namespace",()->admissions(implementation,List.of(new Scope("TOTP","a"),new Scope("TOTP","b"))));
        reject(implementation+"/four-scope-allowlist",()->admissions(implementation,List.of(scopeSet.get(0),scopeSet.get(1),scopeSet.get(2),scopeSet.get(0))));
    }
    private static void constructor(@NonNull String implementation,@NonNull String physical,@NonNull AtomicInteger calls){
        StoreTimeObservation point=StoreTimeObservation.Unavailable.fromAdmission(StoreAdmission.fromIdentifiers(PHYSICAL,PHYSICAL));
        switch(implementation){
            case "TOTP"->new PostgresqlTotpStore("fixture",physical,left->{calls.incrementAndGet();throw new SQLException("Constructor performed I/O");},1,1,(scope,left)->point);
            case "WEBAUTHN"->new PostgresqlWebAuthnStore("fixture",physical,left->{calls.incrementAndGet();throw new SQLException("Constructor performed I/O");},1,(scope,left)->point);
            case "ISSUER"->new PostgresqlIssuerStore("fixture",physical,left->{calls.incrementAndGet();throw new SQLException("Constructor performed I/O");},1,(scope,left)->point);
            default->throw new IllegalArgumentException("Unknown helper");
        }
    }
    private static void canonical(@NonNull String implementation)throws Exception{
        AtomicInteger calls=new AtomicInteger();constructor(implementation,PHYSICAL,calls);byte[] other=new byte[32];Arrays.fill(other,(byte)0xff);constructor(implementation,Base64.getUrlEncoder().withoutPadding().encodeToString(other),calls);
        List<String> invalid=List.of("","A".repeat(42),"A".repeat(44),"A".repeat(42)+"B","é".repeat(43),"A".repeat(43)+"=");
        for(int i=0;i<invalid.size();i++){String value=invalid.get(i);reject(implementation+"/noncanonical-physical-store-ID/"+i,()->constructor(implementation,value,calls));}
        check(implementation+"/store-constructor-canonical-ID-zero-I/O",calls.get()==0);
    }
    private static void matrix(@NonNull String implementation)throws Exception{
        check(implementation+"/empty-lock-set",merge(implementation,List.of()).isEmpty());
        for(int modes=0;modes<8;modes++){
            List<Row> input=new ArrayList<>();for(int i=0;i<3;i++)input.add(new Row(42,(modes&(1<<i))!=0));
            check(implementation+"/forced-collision-strongest/"+modes,merge(implementation,input).equals(List.of(new Row(42,modes!=0))));
        }
        List<Row> sixteen=new ArrayList<>();for(int i=0;i<16;i++)sixteen.add(new Row(i,i%2==0));
        check(implementation+"/sixteen-logical-locks",merge(implementation,sixteen).equals(sixteen));
        List<Row> seventeen=new ArrayList<>(sixteen);seventeen.add(new Row(0,false));reject(implementation+"/seventeen-inputs-before-collision-merge",()->merge(implementation,seventeen));
        Map<String,Boolean> keys=new LinkedHashMap<>();for(int i=0;i<16;i++)keys.put("key:"+i,i%2==0);
        Scope scope=new Scope("TOTP",PHYSICAL);List<Row> ordered=entitySet(implementation,scope,keys);Map<String,Boolean> reversed=new LinkedHashMap<>();List<String> names=new ArrayList<>(keys.keySet());Collections.reverse(names);for(String key:names)reversed.put(key,keys.get(key));
        check(implementation+"/actual-key-order-independent",ordered.equals(entitySet(implementation,scope,reversed)));
        for(int i=1;i<ordered.size();i++)check(implementation+"/actual-key-signed-order/"+i,ordered.get(i-1).id()<ordered.get(i).id());
        keys.put("key:16",false);reject(implementation+"/seventeen-logical-keys",()->entitySet(implementation,scope,keys));
        AtomicInteger count=new AtomicInteger();permutation(implementation,new ArrayList<>(List.of(new Row(-1,false),new Row(Long.MAX_VALUE,true),new Row(0,true),new Row(Long.MIN_VALUE,false),new Row(-1,true),new Row(1,false))),0,count);check(implementation+"/all-720-input-permutations",count.get()==720);
        for(int invalid=0;invalid<2;invalid++){
            Recorder recorder=new Recorder();boolean refused=false;try(Connection c=recorder.connection(invalid==0,invalid==0?Connection.TRANSACTION_READ_COMMITTED:Connection.TRANSACTION_SERIALIZABLE)){try{acquire(implementation,c,List.of(new Row(1,true)),System.nanoTime()+10_000_000_000L);}catch(SQLException expected){refused=true;}}
            check(implementation+"/transaction-guard/"+invalid,refused&&recorder.locks.isEmpty()&&recorder.timeouts==0);
        }
        Recorder expired=new Recorder();boolean refused=false;try(Connection c=expired.connection(false,Connection.TRANSACTION_READ_COMMITTED)){try{acquire(implementation,c,List.of(new Row(1,true)),System.nanoTime()-1);}catch(SQLException expected){refused="57014".equals(expected.getSQLState());}}
        check(implementation+"/expired-original-deadline-zero-requested-SQL",refused&&expired.locks.isEmpty()&&expired.timeouts==0);
    }
    public static void main(@NonNull String @NonNull [] args)throws Exception{
        if(args.length!=1||!List.of("TOTP","WEBAUTHN","ISSUER").contains(args[0]))throw new IllegalArgumentException("Expected actual helper family");
        var origin=java.nio.file.Path.of(com.revetsec.StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        String expected=Objects.requireNonNull(System.getenv("PG_QUALIFICATION_CORE_SHA256"));String actual=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(origin)));if(!actual.equals(expected))throw new IllegalStateException("Selected core origin mismatch");
        grammar(args[0]);canonical(args[0]);matrix(args[0]);System.out.println("SUMMARY "+args[0]+" "+assertions);
    }
}
