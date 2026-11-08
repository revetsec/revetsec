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

import com.revetsec.json.*;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.oauth.server.OAuthStoreKey;
import example.migration.CodecSupport;
import org.jspecify.annotations.NonNull;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Private CAP-08 source/SQL component controls; never serving admission or trusted time. */
public final class Cap08CapacityChecks {
    private Cap08CapacityChecks() { }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    public static void main(@NonNull String @NonNull [] args)throws Exception { CodecSupport.main(args,Cap08CapacityChecks::process); }
    private static @NonNull JsonArray process(@NonNull JsonObject config)throws Exception {
        var output=new ArrayList<@NonNull JsonValue>();
        if(text(config,"operation").equals("native")){nativeChecks(config,output);return JsonArray.fromElements(output);}
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER")){
            Native impl=new Native(family);List<JsonObject> retained=rows(config,"prepared").stream().filter(d->text((JsonObject)d.find("source").orElseThrow(),"family").equals(family)).toList();
            JsonObject root=retained.stream().filter(d->Set.of("NAMESPACE_STATE","NAMESPACE_CLOCK","ISSUER_STATE").contains(text(d,"kind"))).findFirst().orElseThrow();
            long charge=family.equals("TOTP")?number(root,"reservationBytes"):0;
            JsonObject example=(JsonObject)retained.stream().filter(d->!Set.of("NAMESPACE_STATE","NAMESPACE_CLOCK","ISSUER_STATE").contains(text(d,"kind"))).findFirst().orElseThrow().find("source").orElseThrow();
            Map<Integer,String> addresses=new TreeMap<>();
            for(int i=0;addresses.size()<256&&i<100000;i++){String key=address(family,text(example,"key"),i);addresses.putIfAbsent(oracleBucket(key),key);}
            check(addresses.size()==256,"bucket corpus incomplete");
            for(int bucket=0;bucket<256;bucket++){
                int b=bucket;String key=Objects.requireNonNull(addresses.get(b));
                cell(output,family+"/hash/"+b,()->check(impl.bucket(key)==b,"ASCII SHA-256 bucket mismatch"));
                cell(output,family+"/tiny-bootstrap/"+b,()->{
                    long[] zero=new long[256],planned=new long[256],plannedBytes=new long[256];planned[b]=1;plannedBytes[b]=charge;
                    Object a=impl.allocate(1,charge,zero,zero,planned,plannedBytes);
                    verify(impl,a,1,charge,zero,zero,planned,plannedBytes);
                    check(impl.values(a,"getEntryLimits")[b]==1&&Arrays.stream(impl.values(a,"getUsedEntries")).sum()==0,"bootstrap must not be counted as present");
                    long[] actual=planned.clone();reject(()->impl.allocate(1,charge,actual,plannedBytes,planned,plannedBytes));
                    if(charge>0)reject(()->impl.allocate(1,charge-1,zero,zero,planned,plannedBytes));
                });
            }
            for(int remainder=0;remainder<256;remainder++){
                int r=remainder;
                cell(output,family+"/retained-and-bootstrap-remainder/"+r,()->{
                    long[] actual=new long[256],usedBytes=new long[256],bootstrap=new long[256],bootstrapBytes=new long[256];
                    for(int i=0;i<256;i++){actual[i]=1+i%3;usedBytes[i]=family.equals("TOTP")?actual[i]*(1000+i):0;}
                    bootstrap[(r+137)%256]=1;bootstrapBytes[(r+137)%256]=charge;
                    long entries=Arrays.stream(actual).sum()+1+512+r,bytes=family.equals("TOTP")?Arrays.stream(usedBytes).sum()+charge+768+255-r:0;
                    long[] original=actual.clone(),originalBytes=usedBytes.clone();Object a=impl.allocate(entries,bytes,actual,usedBytes,bootstrap,bootstrapBytes);
                    verify(impl,a,entries,bytes,actual,usedBytes,bootstrap,bootstrapBytes);
                    check(Arrays.equals(original,actual)&&Arrays.equals(originalBytes,usedBytes),"input inventory changed");
                });
            }
            cell(output,family+"/genuine-complete-retained-histogram",()->{
                long[] actual=new long[256],usedBytes=new long[256],zero=new long[256];
                for(JsonObject d:retained){JsonObject source=(JsonObject)d.find("source").orElseThrow();int b=oracleBucket(text(source,"key"));actual[b]++;usedBytes[b]+=family.equals("TOTP")?number(d,"reservationBytes"):0;}
                long entries=retained.size()+513,bytes=family.equals("TOTP")?Arrays.stream(usedBytes).sum()+1025:0;
                verify(impl,impl.allocate(entries,bytes,actual,usedBytes,zero,zero),entries,bytes,actual,usedBytes,zero,zero);
            });
            cell(output,family+"/genuine-root-before-spare-distribution",()->{
                JsonObject target=(JsonObject)root.find("target").orElseThrow();int b=oracleBucket(text(target,"key"));long[] zero=new long[256],planned=new long[256],plannedBytes=new long[256];planned[b]=1;plannedBytes[b]=charge;
                if(family.equals("TOTP"))check(TotpPgCapacity.totpReservation(bytes(text(target,"ciphertext"))).getReservedBytes()==charge,"genuine root K64 charge");
                verify(impl,impl.allocate(1,charge,zero,zero,planned,plannedBytes),1,charge,zero,zero,planned,plannedBytes);
            });
            cell(output,family+"/hard-bounds-invalid-shapes-and-overflow",()->{
                long[] zero=new long[256],one=new long[256];one[255]=1;long hard=family.equals("TOTP")?65536:1000000,byteHard=family.equals("TOTP")?268435456:0;
                impl.allocate(hard,byteHard,zero,zero,zero,zero);
                reject(()->impl.allocate(0,charge,zero,zero,one,zero));reject(()->impl.allocate(hard+1,byteHard,zero,zero,zero,zero));
                reject(()->impl.allocate(1,byteHard+1,zero,zero,zero,zero));reject(()->impl.allocate(1,charge,new long[255],zero,zero,zero));reject(()->impl.allocate(1,charge,new long[257],zero,zero,zero));
                long[] invalid=new long[256];invalid[255]=-1;reject(()->impl.allocate(1,charge,invalid,zero,zero,zero));invalid[255]=Long.MAX_VALUE;reject(()->impl.allocate(1,charge,invalid,zero,one,zero));
            });
            cell(output,family+"/allocation-copies-inputs-and-outputs",()->{
                long[] actual=new long[256],zero=new long[256];actual[255]=1;Object a=impl.allocate(513,charge,actual,zero,zero,zero);long[] expected=impl.values(a,"getEntryLimits");
                actual[255]=99;long[] leaked=impl.values(a,"getEntryLimits");leaked[255]=-1;
                check(Arrays.equals(expected,impl.values(a,"getEntryLimits"))&&impl.values(a,"getUsedEntries")[255]==1,"allocation aliases caller arrays");
            });
        }
        return JsonArray.fromElements(output);
    }
    private static void cell(@NonNull List<@NonNull JsonValue> out,@NonNull String name,@NonNull Action action){
        boolean passed=false;String error="";try{action.run();passed=true;}catch(AssertionError failure){error="ASSERTION";}catch(Exception failure){error=failure.getClass().getSimpleName();}
        out.add(JsonObject.builder().put("id",name).put("passed",passed).put("error",error).build());
    }
    private static void check(boolean condition,@NonNull String message){if(!condition)throw new AssertionError(message);}
    private static void reject(@NonNull Action action)throws Exception{boolean refused=false;try{action.run();}catch(IllegalArgumentException expected){refused=true;}check(refused,"invalid allocation accepted");}
    private static int oracleBucket(@NonNull String address)throws Exception{return Integer.parseInt(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(address.getBytes(StandardCharsets.US_ASCII))).substring(0,2),16);}
    private static @NonNull String address(@NonNull String family,@NonNull String example,int i){return switch(family){
        case "TOTP"->TotpStoreKey.forAccount("migration",i%2==0?"old-one":"old-two","cap08-account-"+i).getStorageKey();
        case "WEBAUTHN"->WebAuthnStoreKey.forCredential("migration",i%2==0?"login.example.com":"retained.example.net",ByteBuffer.allocate(4).putInt(i).array()).getStorageKey();
        default->OAuthStoreKey.fromStoredForm(example.substring(0,example.lastIndexOf(':')+1)+b64(ByteBuffer.allocate(32).putInt(i).array())).getStorageKey();};}
    private static void verify(@NonNull Native impl,@NonNull Object a,long entries,long byteCap,long @NonNull [] actual,long @NonNull [] actualBytes,long @NonNull [] bootstrap,long @NonNull [] bootstrapBytes)throws Exception{
        check(Arrays.equals(oracle(entries,actual,bootstrap),impl.values(a,"getEntryLimits")),"entry quota/remainder mismatch");
        check(Arrays.equals(oracle(byteCap,actualBytes,bootstrapBytes),impl.values(a,"getByteLimits")),"byte quota/remainder mismatch");
        check(Arrays.equals(actual,impl.values(a,"getUsedEntries"))&&Arrays.equals(actualBytes,impl.values(a,"getUsedBytes")),"bootstrap incorrectly charged as retained");
    }
    private static long @NonNull [] oracle(long cap,long @NonNull [] actual,long @NonNull [] bootstrap){
        long[] result=new long[256];long left=cap;for(int i=0;i<256;i++){result[i]=actual[i]+bootstrap[i];left-=result[i];}
        // Independent round-robin distribution, rather than repeating the helper's quotient/remainder expression.
        long rounds=left/256;for(int i=0;i<256;i++)result[i]+=rounds;for(long i=rounds*256;i<left;i++)result[(int)(i-rounds*256)]++;
        return result;
    }
    private static final class Native {
        private final @NonNull String family;private final @NonNull Class<?> type;
        private Native(@NonNull String family){this.family=family;this.type=switch(family){case "TOTP"->TotpPgCapacity.class;case "WEBAUTHN"->WebAuthnPgCapacity.class;default->IssuerPgCapacity.class;};}
        private @NonNull Object allocate(long cap,long bytes,long @NonNull [] actual,long @NonNull [] usedBytes,long @NonNull [] planned,long @NonNull [] plannedBytes)throws Exception{
            try{return Objects.requireNonNull(this.type.getDeclaredMethod("allocate",String.class,long.class,long.class,long[].class,long[].class,long[].class,long[].class).invoke(null,this.family,cap,bytes,actual,usedBytes,planned,plannedBytes));}
            catch(InvocationTargetException wrapper){if(wrapper.getCause() instanceof IllegalArgumentException expected)throw expected;throw new IllegalStateException("Native allocation error",wrapper);}
        }
        private long @NonNull [] values(@NonNull Object a,@NonNull String name)throws Exception{return (long[])Objects.requireNonNull(a.getClass().getDeclaredMethod(name).invoke(a));}
        private int bucket(@NonNull String key)throws Exception{return (Integer)Objects.requireNonNull(this.type.getDeclaredMethod("bucket",String.class).invoke(null,key));}
    }
    private static void nativeChecks(@NonNull JsonObject config,@NonNull List<@NonNull JsonValue> out)throws Exception{
        try(Connection connection=DriverManager.getConnection(Objects.requireNonNull(System.getenv("DB_URL")),Objects.requireNonNull(System.getenv("DB_USER")),Objects.requireNonNull(System.getenv("DB_PASSWORD")))){
            connection.setAutoCommit(false);
            for(String family:List.of("TOTP","WEBAUTHN","ISSUER")){
                String table=family.toLowerCase(Locale.ROOT)+"_store_escrow";Native impl=new Native(family);
                JsonObject root=rows(config,"prepared").stream().filter(d->text((JsonObject)d.find("source").orElseThrow(),"family").equals(family)&&Set.of("NAMESPACE_STATE","NAMESPACE_CLOCK","ISSUER_STATE").contains(text(d,"kind"))).findFirst().orElseThrow();
                String scope=text((JsonObject)root.find("source").orElseThrow(),"scope"),generation=text(config,"allocationGeneration");int bucket=oracleBucket(text((JsonObject)root.find("target").orElseThrow(),"key"));long charge=family.equals("TOTP")?number(root,"reservationBytes"):0;
                long[] zero=new long[256],planned=new long[256],plannedBytes=new long[256];planned[bucket]=1;plannedBytes[bucket]=charge;Object allocation=impl.allocate(1,charge,zero,zero,planned,plannedBytes);
                try(Statement statement=connection.createStatement()){statement.execute("CREATE TEMP TABLE "+table+" (LIKE public."+table+" INCLUDING ALL)");}
                try(PreparedStatement statement=connection.prepareStatement("INSERT INTO "+table+"(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) VALUES(?,?,?,?,?,?,?,?)")){
                    long[] entry=impl.values(allocation,"getEntryLimits"),bytes=impl.values(allocation,"getByteLimits");for(int i=0;i<256;i++){statement.setString(1,family);statement.setString(2,scope);statement.setInt(3,i);statement.setString(4,generation);statement.setLong(5,entry[i]);statement.setLong(6,0);statement.setLong(7,bytes[i]);statement.setLong(8,0);statement.addBatch();}statement.executeBatch();
                }
                cell(out,family+"/sql-fresh-256-planned-not-present",()->{try(Statement statement=connection.createStatement();ResultSet rs=statement.executeQuery("SELECT count(*),sum(entry_limit),sum(used_entries),sum(byte_limit),sum(used_bytes) FROM "+table)){check(rs.next()&&rs.getInt(1)==256&&rs.getLong(2)==1&&rs.getLong(3)==0&&rs.getLong(4)==charge&&rs.getLong(5)==0,"fresh persisted allocation");}});
                cell(out,family+"/sql-unassigned-bucket-refuses-without-effects",()->{Savepoint point=connection.setSavepoint();boolean refused=false;try{apply(connection,family,scope,generation,(bucket+1)%256,1,charge);}catch(SQLException expected){refused=expected.getClass().getSimpleName().equals("CapacityRefused");}finally{connection.rollback(point);}check(refused,"unassigned bucket accepted");});
                if(family.equals("TOTP"))cell(out,family+"/sql-one-byte-under-root-reservation-refuses",()->{Savepoint point=connection.setSavepoint();try(Statement statement=connection.createStatement()){statement.executeUpdate("UPDATE "+table+" SET byte_limit="+(charge-1)+" WHERE bucket="+bucket);}boolean refused=false;try{apply(connection,family,scope,generation,bucket,1,charge);}catch(SQLException expected){refused=expected.getClass().getSimpleName().equals("CapacityRefused");}finally{connection.rollback(point);}check(refused,"underfunded root accepted");});
                cell(out,family+"/sql-root-charge-and-rollback-are-atomic",()->{Savepoint point=connection.setSavepoint();apply(connection,family,scope,generation,bucket,1,charge);try(Statement statement=connection.createStatement();ResultSet rs=statement.executeQuery("SELECT used_entries,used_bytes FROM "+table+" WHERE bucket="+bucket)){check(rs.next()&&rs.getLong(1)==1&&rs.getLong(2)==charge,"root charge missing");}connection.rollback(point);try(Statement statement=connection.createStatement();ResultSet rs=statement.executeQuery("SELECT sum(used_entries),sum(used_bytes) FROM "+table)){check(rs.next()&&rs.getLong(1)==0&&rs.getLong(2)==0,"rollback leaked root charge");}});
                cell(out,family+"/sql-root-exact-charge-commits",()->{apply(connection,family,scope,generation,bucket,1,charge);connection.commit();try(Statement statement=connection.createStatement();ResultSet rs=statement.executeQuery("SELECT sum(used_entries),sum(used_bytes) FROM "+table)){check(rs.next()&&rs.getLong(1)==1&&rs.getLong(2)==charge,"committed root charge missing");}});
            }
            connection.rollback();
        }
    }
    private static void apply(@NonNull Connection connection,@NonNull String family,@NonNull String scope,@NonNull String generation,int bucket,long entries,long bytes)throws SQLException{
        long end=System.nanoTime()+5_000_000_000L;
        switch(family){
            case "TOTP"->{var plan=TotpPgCapacity.lockAndCheck(connection,TotpPgScope.from(family,scope),generation,List.of(TotpPgCapacity.Delta.from(bucket,entries,bytes)),end);plan.apply(connection,end);}
            case "WEBAUTHN"->{var plan=WebAuthnPgCapacity.lockAndCheck(connection,WebAuthnPgScope.from(family,scope),generation,List.of(WebAuthnPgCapacity.Delta.from(bucket,entries,bytes)),end);plan.apply(connection,end);}
            default->{var plan=IssuerPgCapacity.lockAndCheck(connection,IssuerPgScope.from(family,scope),generation,List.of(IssuerPgCapacity.Delta.from(bucket,entries,bytes)),end);plan.apply(connection,end);}
        }
    }
}
