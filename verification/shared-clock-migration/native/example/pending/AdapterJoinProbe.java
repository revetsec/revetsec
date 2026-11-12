/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package example.pending;

import com.revetsec.OperationBinding;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.oauth.server.*;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import example.migration.CodecSupport;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPairGenerator;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import static example.migration.CodecSupport.*;

/** Actual current adapters and public services over the migrated disposable database. */
public final class AdapterJoinProbe {
    private final @NonNull JsonObject config;
    private final @NonNull Clock worker;
    private final @NonNull StateSealer sealer;
    private final @NonNull StateSealer webauthnSealer;
    private final @NonNull PostgresqlTotpStore totpStore;
    private final @NonNull PostgresqlWebAuthnStore webauthnStore;
    private final @NonNull PostgresqlIssuerStore issuerStore;

    private AdapterJoinProbe(@NonNull JsonObject config){this(config,null);}
    private AdapterJoinProbe(@NonNull JsonObject config,@Nullable Instant workerOverride) {
        this.config=config;
        Instant workerBase=workerOverride==null?instant((JsonObject)config.find("workerNow").orElseThrow()):workerOverride;
        long workerStarted=System.nanoTime();
        this.worker=new Clock(){
            @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone){if(!zone.equals(ZoneOffset.UTC))throw new IllegalArgumentException("Private UTC worker only");return this;}
            @Override public @NonNull Instant instant(){return workerBase.plusNanos(Math.multiplyExact(System.nanoTime()-workerStarted,2L));}
        };
        String active=text(config,"activeKeyId");
        JsonObject keys=(JsonObject)config.find("keys").orElseThrow();
        List<SealingKey> previous=new ArrayList<>();
        SealingKey selected=null;
        for(var entry:keys.getMembers().entrySet()){
            SealingKey key=SealingKey.fromBase64(entry.getKey(),((JsonString)entry.getValue()).getValue());
            if(entry.getKey().equals(active))selected=key;else previous.add(key);
        }
        this.sealer=StateSealer.withActiveKey(java.util.Objects.requireNonNull(selected))
                .verificationKeys(previous).maximumSealedLength(16384).clock(this.worker).build();
        this.webauthnSealer=StateSealer.withActiveKey(java.util.Objects.requireNonNull(selected)).verificationKeys(previous)
                .maximumSealedLength(Math.toIntExact(number(config,"webauthnMaximumSealedLength",16384))).clock(this.worker).build();
        this.totpStore=new PostgresqlTotpStore("migration",text(config,"totpScope"),this::connection,cap09Entries("TOTP"),number(config,"cap09TotpByteCap",268435456L),
                (scope,budget)->observe("TOTP",scope,budget));
        this.webauthnStore=new PostgresqlWebAuthnStore("migration",text(config,"webauthnScope"),this::connection,cap09Entries("WEBAUTHN"),
                (scope,budget)->observe("WEBAUTHN",scope,budget));
        this.issuerStore=new PostgresqlIssuerStore("migration",text(config,"issuerScope"),this::connection,cap09Entries("ISSUER"),
                (scope,budget)->observe("ISSUER",scope,budget));
    }

    public static void main(@NonNull String @NonNull [] args) {
        try {
            if(args.length!=2&&!(args.length==4&&args[1].equals("capacity-worker")))throw new IllegalArgumentException("Expected protected config and command");
            JsonObject config=(JsonObject)com.revetsec.internal.json.JsonCodec.parse(Files.readAllBytes(Path.of(args[0])),
                    com.revetsec.internal.json.JsonLimits.protocolDocument(4194304));
            if(!hash(Files.readAllBytes(Path.of(StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI())))
                    .equals(text(config,"expectedCoreSha256")))throw new AssertionError("Exact current artifact origin");
            AdapterJoinProbe probe;
            if(args[1].equals("capacity-worker")){
                System.out.println("SYNC_READY");System.out.flush();
                String[] parts=readWorkerSync().split(" ");
                if(parts.length!=2)throw new IllegalArgumentException("Invalid worker sync");
                probe=new AdapterJoinProbe(config,Instant.ofEpochSecond(Long.parseLong(parts[0]),Integer.parseInt(parts[1])));
            }else probe=new AdapterJoinProbe(config);
            switch(args[1]){
                case "raw" -> probe.raw();
                case "query" -> probe.query();
                case "mutate" -> probe.mutate();
                case "retained-issuer" -> probe.retainedIssuer();
                case "fence-outage" -> probe.fenceOutage();
                case "floor-timing" -> probe.floorTiming();
                case "bootstrap-denied" -> probe.bootstrapDenied();
                case "totp-capacity" -> probe.totpCapacity();
                case "webauthn-capacity" -> probe.webauthnCapacity();
                case "capacity-contention" -> probe.cap09Contention(Path.of(args[0]));
                case "capacity-worker" -> probe.cap09Worker(args[2],Integer.parseInt(args[3]));
                case "fence-denied" -> probe.fenceDenied();
                case "closed" -> probe.closed(true);
                case "skew" -> probe.closed(false);
                case "hold-status" -> probe.holdStatus();
                default -> throw new IllegalArgumentException("Unknown private command");
            }
        } catch(Throwable failure) {
            System.err.println("ADAPTER_PROBE_FAILED "+failure.getClass().getSimpleName());
            if(failure instanceof SQLException sql&&sql.getSQLState()!=null&&sql.getSQLState().matches("[A-Z0-9]{5}"))System.err.println("FIXTURE_SQLSTATE "+sql.getSQLState());
            if(failure instanceof AssertionError&&failure.getMessage()!=null&&failure.getMessage().matches("[A-Za-z0-9/_-]{1,180}"))System.err.println("FIXTURE_ASSERTION "+failure.getMessage());
            if(failure instanceof AssertionError&&failure.getMessage()!=null&&failure.getMessage().startsWith("SC-BOUND-04/")){String diagnostic=failure.getMessage().replaceAll("\\s+","_");System.err.println("SC_BOUND04_DIAGNOSTIC "+diagnostic.substring(0,Math.min(240,diagnostic.length())));}
            System.exit(1);
        }
    }

    private static @NonNull String readWorkerSync()throws Exception{
        StringBuilder line=new StringBuilder();int next;
        while((next=System.in.read())>=0&&next!='\n'&&line.length()<80)line.append((char)next);
        if(next!='\n')throw new IllegalArgumentException("Missing worker sync");
        return line.toString();
    }

    private void check(@NonNull String name,boolean condition){
        if(!condition)throw new AssertionError(name);
        System.out.println("PASS "+name);
    }

    private @NonNull String scope(@NonNull String family){
        return text(this.config,switch(family){case "TOTP"->"totpScope";case "WEBAUTHN"->"webauthnScope";case "ISSUER"->"issuerScope";default->throw new IllegalArgumentException();});
    }

    private @NonNull String @NonNull [] rpc(@NonNull String operation,@NonNull String family,@NonNull String scope,@NonNull Duration budget)throws Exception{
        int millis=(int)Math.min(1000,Math.max(1,budget.toMillis()));
        try(Socket socket=new Socket()){
            socket.connect(new InetSocketAddress("127.0.0.1",(int)number(this.config,"authorityPort")),millis);
            socket.setSoTimeout(millis);
            var out=new OutputStreamWriter(socket.getOutputStream(),StandardCharsets.US_ASCII);
            out.write(text(this.config,"authorityToken")+'\t'+operation+'\t'+family+'\t'+scope+'\t'+millis+'\n');out.flush();
            String line=new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII)).readLine();
            if(line==null||line.length()>1024)throw new IllegalStateException("Closed authority response");
            String[] result=line.split("\\t",-1);
            if(result.length!=8||!(result[0].equals("OK")||result[0].equals("ADMITTED")||result[0].equals("UTC_UNAVAILABLE")))throw new IllegalStateException("Current external admission closed");
            if(!result[1].equals(text(this.config,"authorityId"))||!result[2].equals(text(this.config,"recoveryGeneration"))||(result[0].equals("OK")&&!result[3].equals(text(this.config,"clockGeneration"))))throw new IllegalStateException("Authority identities differ");
            return result;
        }
    }

    private @NonNull StoreTimeObservation observe(@NonNull String family,@NonNull String scope,@NonNull Duration budget)throws Exception{
        String[] point=rpc("OBSERVE",family,scope,budget);
        if(point[0].equals("UTC_UNAVAILABLE"))return StoreTimeObservation.Unavailable.fromAdmission(StoreAdmission.fromIdentifiers(point[1],point[2]));
        if(!point[0].equals("OK"))throw new IllegalStateException("Missing authority time");
        return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(point[1],point[2]),point[3],
                Instant.ofEpochSecond(Long.parseLong(point[4]),Long.parseLong(point[5])),Duration.ofNanos(Long.parseLong(point[6])));
    }

    private boolean current(@NonNull String family){
        try{return rpc("ADMIT",family,scope(family),Duration.ofSeconds(1))[0].equals("ADMITTED");}catch(Exception closed){return false;}
    }

    private @NonNull Connection connection(@NonNull Duration budget)throws SQLException{
        if(budget.isZero()||budget.isNegative()||!current("ISSUER"))throw new SQLException("Private external gate closed");
        Properties properties=new Properties();
        properties.setProperty("user",System.getenv("DB_USER"));properties.setProperty("password",System.getenv("DB_PASSWORD"));
        properties.setProperty("sslmode","disable");properties.setProperty("gssEncMode","disable");properties.setProperty("socketTimeout","10");
        return DriverManager.getConnection(System.getenv("DB_URL"),properties);
    }

    private final class Lease implements AutoCloseable {
        private final @NonNull String family;
        private final @NonNull FileChannel channel;
        private final @NonNull FileLock lock;
        private boolean closed;
        private Lease(@NonNull String family)throws Exception{
            this.family=family;this.channel=FileChannel.open(Path.of(text(config,"runtimeLock")),StandardOpenOption.READ,StandardOpenOption.WRITE);
            this.lock=this.channel.lock(0,Long.MAX_VALUE,true);
            if(!current(family)){close();throw new IllegalStateException("Private runtime admission closed");}
        }
        private @NonNull Boolean isCurrent(){return !this.closed&&this.lock.isValid()&&current(this.family);}
        @Override public void close(){if(!this.closed){this.closed=true;try{this.lock.close();this.channel.close();}catch(Exception failure){throw new IllegalStateException("Private permit close failed");}}}
    }

    private @Nullable Lease acquire(@NonNull String family,@NonNull Duration budget){
        if(budget.isZero()||budget.isNegative())return null;
        try{return new Lease(family);}catch(Exception closed){return null;}
    }

    private @NonNull TotpAuthenticator totp(@NonNull TotpStore selected){
        TotpRecoveryGate gate=(context,budget)->{
            Lease lease=acquire("TOTP",budget);
            if(lease==null)return null;
            return new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return lease.isCurrent();}@Override public void close(){lease.close();}};
        };
        return TotpAuthenticator.withIssuer("Fixture").credentialNamespace("migration").recoveryEpoch("old-one")
                .store(selected).stateSealer(this.sealer).recoveryGate(gate).clock(this.worker).build();
    }

    private @NonNull WebAuthnRelyingParty party(){return party(this.webauthnStore);}

    private @NonNull WebAuthnRelyingParty party(@NonNull WebAuthnStore selected){
        WebAuthnRecoveryGate gate=budget->{Lease lease=acquire("WEBAUTHN",budget);if(lease==null)return null;
            return new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return lease.isCurrent();}@Override public void close(){lease.close();}};};
        return com.revetsec.webauthn.AdapterJoinWorker.configure(WebAuthnRelyingParty.withRelyingPartyId("login.example.com"),this.worker)
                .relyingPartyName("Migration fixture").allowedOrigins(Set.of("https://login.example.com"))
                .credentialNamespace("migration").store(selected).stateSealer(this.webauthnSealer).recoveryGate(gate).build();
    }

    private @NonNull OAuthAuthorizationServer issuer()throws Exception{return issuer(this.issuerStore);}

    private @NonNull OAuthAuthorizationServer issuer(@NonNull OAuthAuthorizationServerStore selected)throws Exception{
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);var pair=generator.generateKeyPair();
        var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("fixture",pair.getPrivate(),pair.getPublic()))
                .generation("migration-probe").publishedAt(this.worker.instant().minusSeconds(1)).build();
        return OAuthAuthorizationServer.withIssuer(text(this.config,"issuer"))
                .authorizationEndpoint(URI.create("https://issuer.example/authorize")).tokenEndpoint(URI.create("https://issuer.example/token"))
                .jwksEndpoint(URI.create("https://issuer.example/jwks")).clientRepository((id,budget)->Optional.empty())
                .resources(Map.of("https://resource.example/mcp",Set.of("read"))).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance()).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys))
                .store(selected).stateSealer(this.sealer).clock(this.worker).maximumStoreRecordBytes(16384).build();
    }

    private void raw()throws Exception{
        try(Lease lease=new Lease("TOTP")){
            Map<String,Set<TotpStoreKey>> keys=new HashMap<>();Set<WebAuthnStoreKey> wa=new HashSet<>();int issuer=0;
            for(JsonObject row:rows(this.config,"rows")){
                String family=text(row,"family"),address=text(row,"key");
                if(family.equals("TOTP")){TotpStoreKey key=TotpStoreKey.fromStoredForm(address);keys.computeIfAbsent(key.getRecoveryEpoch(),unused->new HashSet<>()).add(key);}
                else if(family.equals("WEBAUTHN")){wa.add(WebAuthnStoreKey.fromStoredForm(address));}
                else{var result=this.issuerStore.read(OAuthStoreKey.fromStoredForm(address),Duration.ofSeconds(5));
                    if(!(result instanceof OAuthStoreReadResult.Available available)||available.getEntry().isEmpty()){System.err.println("FIXTURE_RAW_ISSUER_READ "+result.getClass().getSimpleName());throw new AssertionError("current-issuer-retained-read");}issuer++;}
            }
            var active=this.totpStore.read(java.util.Objects.requireNonNull(keys.get("old-one")),Duration.ofSeconds(5));
            check("current-totp-adapter-loads-active-retained-epoch",active instanceof TotpStoreReadResult.Available a&&a.getSnapshot().getEntries().size()==number(this.config,"expectedTotpActiveRecords",5)&&a.getSnapshot().getEntries().values().stream().allMatch(TotpStoreEntry.Present.class::isInstance));
            check("current-totp-adapter-fences-retained-old-epoch",this.totpStore.read(java.util.Objects.requireNonNull(keys.get("old-two")),Duration.ofSeconds(5)) instanceof TotpStoreReadResult.Fenced);
            var groups=new java.util.TreeMap<String,List<WebAuthnStoreKey>>();for(var key:wa)groups.computeIfAbsent(key.getStorageKey().split(":")[2],unused->new ArrayList<>()).add(key);int loaded=0;
            for(var ordered:groups.values()){ordered.sort(java.util.Comparator.comparing(WebAuthnStoreKey::getStorageKey));
                for(int start=0;start<ordered.size();start+=16){var requested=Set.copyOf(ordered.subList(start,Math.min(ordered.size(),start+16)));var read=this.webauthnStore.read(requested,Duration.ofSeconds(5));
                    if(!(read instanceof WebAuthnStoreReadResult.Available a)||a.getSnapshot().getEntries().size()!=requested.size()||!a.getSnapshot().getEntries().values().stream().allMatch(WebAuthnStoreEntry.Present.class::isInstance))throw new AssertionError("Incomplete bounded WebAuthn read");loaded+=requested.size();}
            }
            check("current-wa-adapter-loads-all-retained-kinds",loaded==number(this.config,"expectedWebauthnRecords",8));
            check("current-issuer-adapter-loads-all-retained-kinds",issuer==14);
            check("raw-read-keeps-current-external-permit",lease.isCurrent());
        }
    }

    private void query()throws Exception{
        var status=totp(this.totpStore).getStatusResult("account-1-0");
        check("totp-public-status-retains-factor-batch-pending",status instanceof TotpStatusResult.Present p&&p.getStatus().getActiveFactor().isPresent()&&p.getStatus().getPendingEnrollment().isPresent()&&p.getStatus().getRemainingRecoveryCodeCount()==2);
        var list=party().listCredentialsResult(new byte[]{4,5,6});
        check("wa-public-list-retains-active-credential",list instanceof WebAuthnCredentialListResult.Listed l&&l.getCredentialIds().size()==1&&Arrays.equals(l.getCredentialIds().get(0),new byte[]{1,2,3}));
        var empty=party().listCredentialsResult(new byte[]{10,11,12});
        check("wa-public-list-retains-disabled-empty-account",empty instanceof WebAuthnCredentialListResult.Listed l&&l.getCredentialIds().isEmpty());
        try(Lease lease=new Lease("ISSUER")){issuer().warmUp();check("issuer-public-warmup-uses-migrated-root",lease.isCurrent());}
    }

    private long @NonNull [] totpReservation(@NonNull TotpStoreKey key)throws Exception{
        int bucket=Byte.toUnsignedInt(bytes(hash(key.getStorageKey()))[0]);
        try(var connection=connection(Duration.ofSeconds(5));var statement=connection.prepareStatement(
                "SELECT e.sealed_form,e.sealed_size,e.reserved_size,b.used_bytes,b.byte_limit FROM totp_store_entry e JOIN totp_store_escrow b ON b.namespace=? AND b.bucket=? WHERE e.namespace='migration' AND e.recovery_epoch=? AND e.storage_key=?")){
            statement.setString(1,text(this.config,"totpScope"));statement.setInt(2,bucket);
            statement.setString(3,key.getRecoveryEpoch());statement.setString(4,key.getStorageKey());
            try(var result=statement.executeQuery()){
                if(!result.next())throw new AssertionError("Missing rotation reservation");
                byte[] sealed=bytes(result.getString(1));
                check("totp-sql-actual-size-is-truthful",sealed.length==result.getLong(2));
                return new long[]{sealed.length,result.getLong(3),result.getLong(4),result.getLong(5),asciiKey(sealed).length()};
            }
        }
    }

    private void retainedIssuer()throws Exception{
        try(Lease lease=new Lease("ISSUER")){
            OAuthStoreKey key=OAuthStoreKey.fromStoredForm(text(this.config,"maintenanceKey"));
            var read=this.issuerStore.read(key,Duration.ofSeconds(5));if(!(read instanceof OAuthStoreReadResult.Available available))throw new AssertionError("Retained read");
            var before=available.getEntry().orElseThrow();var receipt=issuer().resealStoreEntry(key);
            check("MIG12-expired-credential-still-retained-maintenance-commits",receipt.getStatus()==OAuthStoreCommitStatus.COMMITTED);
            Instant authority=receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt();
            check("MIG12-authority-past-credential-expiry-before-full-retention",!authority.isBefore(Instant.ofEpochSecond(number(this.config,"maintenanceExpiresSeconds")))&&authority.isBefore(before.getRetainUntil()));
            var after=this.issuerStore.read(key,Duration.ofSeconds(5));if(!(after instanceof OAuthStoreReadResult.Available actual))throw new AssertionError("Retained postread");
            var value=actual.getEntry().orElseThrow();check("MIG12-exact-retention-and-current-permit-preserved",value.getRetainUntil().equals(before.getRetainUntil())&&!value.getVersion().equals(before.getVersion())&&lease.isCurrent());
        }
    }

    private void mutate()throws Exception{
        TotpAuthenticator totp=totp(this.totpStore);TotpStoreKey account=TotpStoreKey.forAccount("migration","old-one","account-1-0");
        long[] before=totpReservation(account);
        check("totp-public-reseal-commits-on-current-adapter",totp.resealStoreEntryResult(account) instanceof TotpStoreResealResult.Resealed);
        long[] after=totpReservation(account);
        check("totp-runtime-key-growth-uses-existing-reservation",before[4]==1&&after[4]==text(this.config,"activeKeyId").length()
                &&after[0]>before[0]&&after[0]<=before[1]&&after[1]==before[1]&&after[2]==before[2]&&after[3]==before[3]);
        if(after[4]==64)check("totp-runtime-k64-exactly-reaches-prepared-reservation",after[0]==before[1]);
        byte[] syntheticSecret=new byte[20];for(int i=0;i<syntheticSecret.length;i++)syntheticSecret[i]=(byte)(i+7);
        javax.crypto.Mac mac=javax.crypto.Mac.getInstance("HmacSHA1");mac.init(new javax.crypto.spec.SecretKeySpec(syntheticSecret,"HmacSHA1"));
        byte[] digest=mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(this.worker.instant().getEpochSecond()/30L).array());int offset=digest[digest.length-1]&15;
        int binary=((digest[offset]&127)<<24)|((digest[offset+1]&255)<<16)|((digest[offset+2]&255)<<8)|(digest[offset+3]&255);
        String code=String.format(java.util.Locale.ROOT,"%06d",binary%1000000);Arrays.fill(syntheticSecret,(byte)0);Arrays.fill(digest,(byte)0);
        check("totp-original-secret-verifies-after-migration",totp.verifyResult("account-1-0",code,OperationBinding.fromTrustedPersistence("adapter-verify")) instanceof TotpVerificationResult.Succeeded);
        check("totp-committed-step-replay-remains-rejected",totp.verifyResult("account-1-0",code,OperationBinding.fromTrustedPersistence("adapter-replay")) instanceof TotpVerificationResult.Rejected);
        var status=totp.getStatusResult("account-1-0");String factor=((TotpStatusResult.Present)status).getStatus().getActiveFactor().orElseThrow().getFactorId();
        var removal=totp.removeFactorResult("account-1-0",factor);
        if(!(removal instanceof TotpFactorRemovalResult.Succeeded))System.err.println("FIXTURE_REMOVAL_OUTCOME "+removal.getClass().getSimpleName()+" "+(removal instanceof TotpFactorRemovalResult.Unavailable unavailable?unavailable.getReason().name():"NO_INFRASTRUCTURE_REASON"));
        check("totp-public-factor-removal-commits",removal instanceof TotpFactorRemovalResult.Succeeded);
        var removed=totp.getStatusResult("account-1-0");check("totp-removal-observed-by-following-query",removed instanceof TotpStatusResult.Present p&&p.getStatus().getActiveFactor().isEmpty());
        WebAuthnRelyingParty party=party();WebAuthnStoreKey key=WebAuthnStoreKey.forCredential("migration","login.example.com",new byte[]{1,2,3});
        check("wa-public-raw-reseal-current-receipt",party.resealStoreEntry(key).getStatus()==WebAuthnStoreCommitResult.COMMITTED);
        check("wa-public-credential-removal-commits",party.removeCredentialResult(new byte[]{4,5,6},new byte[]{1,2,3}) instanceof WebAuthnCredentialRemovalResult.Removed);
        var list=party.listCredentialsResult(new byte[]{4,5,6});check("wa-removal-observed-by-following-query",list instanceof WebAuthnCredentialListResult.Listed l&&l.getCredentialIds().isEmpty());
        try(Lease lease=new Lease("ISSUER")){
            OAuthAuthorizationServer server=issuer();OAuthStoreKey root=rows(this.config,"rows").stream().filter(r->text(r,"family").equals("ISSUER")&&text(r,"key").contains(":ISSUER_STATE:")).map(r->OAuthStoreKey.fromStoredForm(text(r,"key"))).findFirst().orElseThrow();
            check("issuer-public-raw-reseal-current-receipt",server.resealStoreEntry(root).getStatus()==OAuthStoreCommitStatus.COMMITTED);
            server.revokeSubject("álîçè");check("issuer-public-subject-fence-advances",lease.isCurrent());
            server.revokeAllGrants();check("issuer-public-issuer-fence-advances",lease.isCurrent());
            server.warmUp();check("issuer-current-adapter-remains-readable",lease.isCurrent());
        }
    }

    private @NonNull OAuthStoreKey issuerRootKey(){return rows(this.config,"rows").stream().filter(r->text(r,"family").equals("ISSUER")&&text(r,"key").contains(":ISSUER_STATE:")).map(r->OAuthStoreKey.fromStoredForm(text(r,"key"))).findFirst().orElseThrow();}

    private void fenceOutage()throws Exception{
        OAuthStoreKey root=issuerRootKey();var read=this.issuerStore.read(root,Duration.ofSeconds(5));
        check("MIG13-current-adapter-available-root-with-unavailable-UTC",read instanceof OAuthStoreReadResult.Available a&&a.getEntry().isPresent()&&a.getTimeObservation() instanceof StoreTimeObservation.Unavailable);
        try(Lease lease=new Lease("ISSUER")){
            OAuthAuthorizationServer server=issuer();
            for(String purpose:List.of("WARMUP","INITIALIZE","REGISTER","RESEAL")){
                boolean refused=false;try{switch(purpose){case "WARMUP"->server.warmUp();case "INITIALIZE"->server.initializeFreshIssuer();case "REGISTER"->server.establishNewSubject("new-outage-subject");case "RESEAL"->server.resealStoreEntry(root);default->throw new AssertionError();}}catch(OAuthServerStoreException expected){refused=true;}
                check("MIG13-timed-purpose-refuses-"+purpose,refused);
            }
            server.revokeSubject("álîçè");check("MIG13-subject-fence-under-UTC-outage",lease.isCurrent());
            server.revokeAllGrants();check("MIG13-issuer-fence-under-UTC-outage",lease.isCurrent());
        }
        check("MIG13-totp-cannot-borrow-fence-admission",totp(this.totpStore).getStatusResult("account-1-0") instanceof TotpStatusResult.Unavailable);
        check("MIG13-wa-cannot-borrow-fence-admission",party().listCredentialsResult(new byte[]{4,5,6}) instanceof WebAuthnCredentialListResult.Unavailable);
    }

    private void fenceDenied()throws Exception{
        OAuthAuthorizationServer server=issuer();
        for(boolean all:List.of(false,true)){
            boolean refused=false;try{if(all)server.revokeAllGrants();else server.revokeSubject("álîçè");}catch(OAuthServerStoreException expected){refused=true;}
            check("MIG13-fence-denied-"+(all?"issuer":"subject"),refused);
        }
    }

    private void totpCapacity()throws Exception{
        TotpAuthenticator auth=totp(this.totpStore);int active=0,retained=0;
        for(JsonObject row:rows(this.config,"rows")){
            if(!text(row,"family").equals("TOTP"))continue;TotpStoreKey key=TotpStoreKey.fromStoredForm(text(row,"key"));
            if(!key.getRecoveryEpoch().equals("old-one")){
                check("CAP06-inactive-retained-epoch-remains-fenced",this.totpStore.read(Set.of(key),Duration.ofSeconds(5)) instanceof TotpStoreReadResult.Fenced);retained++;continue;
            }
            long[] before=totpReservation(key);var result=auth.resealStoreEntryResult(key);long[] after=totpReservation(key);
            check("CAP06-active-epoch-K64-maintenance-admitted",result instanceof TotpStoreResealResult.Resealed||result instanceof TotpStoreResealResult.AlreadyCurrent);
            check("CAP06-active-epoch-exact-K64-reservation",after[4]==64&&after[0]==before[1]&&after[0]<=65536&&after[1]==before[1]&&after[2]==before[2]&&after[3]==before[3]);active++;
        }
        check("CAP06-complete-retained-TOTP-population-covered",active==13&&retained==4);
    }

    private void webauthnCapacity()throws Exception{
        int permanent=0,ceremonies=0;var party=party();
        for(JsonObject row:rows(this.config,"rows")){
            if(!text(row,"family").equals("WEBAUTHN"))continue;var key=WebAuthnStoreKey.fromStoredForm(text(row,"key"));
            if(key.getKind()==WebAuthnStoreKey.Kind.CEREMONY){boolean refused=false;try{party.resealStoreEntry(key);}catch(IllegalArgumentException expected){refused=true;}check("CAP07-ceremony-public-maintenance-remains-ineligible",refused);ceremonies++;continue;}
            check("CAP07-permanent-K64-maintenance-commits",party.resealStoreEntry(key).getStatus()==WebAuthnStoreCommitResult.COMMITTED);
            try(Lease lease=new Lease("WEBAUTHN")){
                var read=this.webauthnStore.read(Set.of(key),Duration.ofSeconds(5));
                if(!(read instanceof WebAuthnStoreReadResult.Available available)||!(available.getSnapshot().getEntry(key) instanceof WebAuthnStoreEntry.Present present))throw new AssertionError("Capacity read");
                byte[] frame=present.getSealedBytes();var buffer=ByteBuffer.wrap(frame);buffer.position(4);int chunks=Short.toUnsignedInt(buffer.getShort()),size=Short.toUnsignedInt(buffer.getShort());buffer.position(24);
                check("CAP07-selected-recipe-chunk-size",size==2029);
                for(int i=0;i<chunks;i++){int length=Short.toUnsignedInt(buffer.getShort());byte[] sealed=new byte[length];buffer.get(sealed);byte[] wire=java.util.Base64.getUrlDecoder().decode(sealed);check("CAP07-every-current-chunk-K64-and-within-recipe-cap",wire[1]==64&&length<=3800);Arrays.fill(wire,(byte)0);Arrays.fill(sealed,(byte)0);}
                check("CAP07-public-row-and-SQL-caps",!buffer.hasRemaining()&&frame.length<=262144&&java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(frame).length()<=350000&&lease.isCurrent());Arrays.fill(frame,(byte)0);
            }
            permanent++;
        }
        check("CAP07-complete-native-population-covered",permanent==12&&ceremonies==7);
    }

    private int cap09Entries(@NonNull String family){return Math.toIntExact(number(this.config,"cap09EntryCap",family.equals("TOTP")?65536:1000000));}
    private static @NonNull String cap09Name(int index,boolean large){String name="cap09-account-"+index;return large?name+"x".repeat(1024-name.length()):name;}
    private static byte @NonNull [] cap09Handle(int index){return ByteBuffer.allocate(16).putLong(0x09090909L).putLong(index).array();}
    private @NonNull String cap09Key(@NonNull String family,int index,boolean large){
        return switch(family){case "TOTP"->TotpStoreKey.forAccount("migration","old-one",cap09Name(index,large)).getStorageKey();
            case "WEBAUTHN"->WebAuthnStoreKey.forAccountFence("migration","login.example.com",cap09Handle(index)).getStorageKey();
            default->{String root=issuerRootKey().getStorageKey();yield root.substring(0,root.indexOf(":ISSUER_STATE:"))+":SUBJECT_STATE:"+hash(cap09Name(index,false));}};
    }
    private Cap09ContentionChecks.@NonNull Plan cap09Plan(@NonNull String family,int index,boolean large,@NonNull Object write){
        String key;long charge=0;
        if(family.equals("TOTP")){var tx=(TotpStoreWrite)write;if(tx.getMutations().size()!=1)throw new AssertionError("CAP09 shape");var record=tx.getMutations().get(0).getRecord();key=record.getKey().getStorageKey();charge=TotpPgCapacity.totpReservation(record.getSealedBytes()).getReservedBytes();}
        else if(family.equals("WEBAUTHN")){var tx=(WebAuthnStoreWrite)write;if(tx.getMutations().size()!=1)throw new AssertionError("CAP09 shape");key=tx.getMutations().get(0).getKey().getStorageKey();}
        else{var tx=(OAuthStoreTransaction)write;if(tx.getMutations().size()!=1)throw new AssertionError("CAP09 shape");key=tx.getMutations().get(0).getKey().getStorageKey();}
        if(!key.equals(cap09Key(family,index,large)))throw new AssertionError("CAP09 wrong captured account");return new Cap09ContentionChecks.Plan(family,index,large,key,charge,write);
    }
    private @NonNull Object cap09Receipt(Cap09ContentionChecks.@NonNull Plan plan,Cap09ContentionChecks.@NonNull Connections source)throws Exception{
        return switch(plan.family()){
            case "TOTP"->new PostgresqlTotpStore("migration",scope("TOTP"),source::open,cap09Entries("TOTP"),number(this.config,"cap09TotpByteCap",268435456L),(physical,budget)->observe("TOTP",physical,budget)).compareAndCommit((TotpStoreWrite)plan.write(),Duration.ofSeconds(8));
            case "WEBAUTHN"->new PostgresqlWebAuthnStore("migration",scope("WEBAUTHN"),source::open,cap09Entries("WEBAUTHN"),(physical,budget)->observe("WEBAUTHN",physical,budget)).compareAndCommit((WebAuthnStoreWrite)plan.write(),Duration.ofSeconds(8));
            default->new PostgresqlIssuerStore("migration",scope("ISSUER"),source::open,cap09Entries("ISSUER"),(physical,budget)->observe("ISSUER",physical,budget)).commit((OAuthStoreTransaction)plan.write(),Duration.ofSeconds(8));
        };
    }
    private @NonNull String cap09Commit(Cap09ContentionChecks.@NonNull Plan plan,Cap09ContentionChecks.@NonNull Connections source)throws Exception{
        Object receipt=cap09Receipt(plan,source);return receipt instanceof TotpStoreCommitReceipt t?t.getStatus().name():receipt instanceof WebAuthnStoreCommitReceipt w?w.getStatus().name():((OAuthStoreCommitReceipt)receipt).getStatus().name();
    }
    private Cap09ContentionChecks.@NonNull PublicResult cap09Attempt(@NonNull String family,int index,boolean large,boolean capture,Cap09ContentionChecks.@NonNull Stats trace,java.util.concurrent.atomic.@NonNull AtomicReference<@NonNull Object> written)throws Exception{
        var calls=new java.util.concurrent.atomic.AtomicInteger();var status=new java.util.concurrent.atomic.AtomicReference<>("NONE");String outcome;
        Cap09ContentionChecks.Connections source=budget->Cap09ContentionChecks.track(connection(budget),trace,new java.util.concurrent.atomic.AtomicInteger());
        if(family.equals("TOTP")){
            var selected=new TotpStore(){
                @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){return new PostgresqlTotpStore("migration",scope("TOTP"),source::open,cap09Entries("TOTP"),number(config,"cap09TotpByteCap",268435456L),(physical,left)->observe("TOTP",physical,left)).read(keys,budget);}
                @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite tx,@NonNull Duration budget){written.set(tx);calls.incrementAndGet();try{if(capture){status.set("UNAVAILABLE");return TotpStoreCommitReceipt.fromRefusal(TotpStoreCommitResult.UNAVAILABLE);}var receipt=(TotpStoreCommitReceipt)cap09Receipt(cap09Plan(family,index,large,tx),source);status.set(receipt.getStatus().name());return receipt;}catch(Exception failure){throw new IllegalStateException(failure);}}
            };
            var result=totp(selected).beginEnrollmentResult(TotpEnrollmentOptions.withAccountId(cap09Name(index,large)).accountName("Synthetic").build(),OperationBinding.fromTrustedPersistence("cap09-browser"));
            if(capture&&calls.get()==0&&result instanceof TotpEnrollmentRequestResult.Unavailable unavailable)status.set("EARLY_"+unavailable.getReason().name());
            outcome=result instanceof TotpEnrollmentRequestResult.Prepared?"SUCCESS":result instanceof TotpEnrollmentRequestResult.Unavailable u&&u.getReason()==TotpUnavailableReason.CAPACITY_REFUSED?"CAPACITY":result instanceof TotpEnrollmentRequestResult.Unavailable?"UNAVAILABLE":"OTHER";
        }else if(family.equals("WEBAUTHN")){
            var selected=new WebAuthnStore(){
                @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){return new PostgresqlWebAuthnStore("migration",scope("WEBAUTHN"),source::open,cap09Entries("WEBAUTHN"),(physical,left)->observe("WEBAUTHN",physical,left)).read(keys,budget);}
                @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite tx,@NonNull Duration budget){written.set(tx);calls.incrementAndGet();try{if(capture){status.set("UNAVAILABLE");return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);}var receipt=(WebAuthnStoreCommitReceipt)cap09Receipt(cap09Plan(family,index,large,tx),source);status.set(receipt.getStatus().name());return receipt;}catch(Exception failure){throw new IllegalStateException(failure);}}
            };
            var result=party(selected).disableAccountResult(cap09Handle(index));outcome=result instanceof WebAuthnAccountDisableResult.Disabled?"SUCCESS":result instanceof WebAuthnAccountDisableResult.Unavailable?"UNAVAILABLE":"OTHER";
        }else{
            var selected=new OAuthAuthorizationServerStore(){
                @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return new PostgresqlIssuerStore("migration",scope("ISSUER"),source::open,cap09Entries("ISSUER"),(physical,left)->observe("ISSUER",physical,left)).read(key,budget);}
                @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){written.set(tx);calls.incrementAndGet();try{if(capture){status.set("UNAVAILABLE");return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.UNAVAILABLE);}var receipt=(OAuthStoreCommitReceipt)cap09Receipt(cap09Plan(family,index,large,tx),source);status.set(receipt.getStatus().name());return receipt;}catch(Exception failure){throw new IllegalStateException(failure);}}
            };
            try(Lease lease=new Lease("ISSUER")){try{issuer(selected).establishNewSubject(cap09Name(index,false));outcome="SUCCESS";}catch(OAuthServerStoreException failure){if(failure.getReason()!=OAuthServerException.Reason.STORE_UNAVAILABLE)throw failure;outcome="UNAVAILABLE";}if(!lease.isCurrent())throw new AssertionError("CAP09 permit lost");}
        }
        return new Cap09ContentionChecks.PublicResult(outcome,status.get(),calls.get());
    }
    private void cap09Worker(@NonNull String family,int index)throws Exception{
        System.out.println("SC_BOUND04_WORKER_STAGE capture");System.out.flush();
        try(Lease probe=new Lease(family)){if(!probe.isCurrent())throw new AssertionError("SC-BOUND-04/preflight-not-current");}
        catch(Exception failure){throw new AssertionError("SC-BOUND-04/preflight-"+failure.getClass().getSimpleName());}
        var written=new java.util.concurrent.atomic.AtomicReference<Object>();
        var result=cap09Attempt(family,index,false,true,new Cap09ContentionChecks.Stats(),written);
        if(!result.outcome().equals("UNAVAILABLE")||result.calls()!=1)throw new AssertionError("SC-BOUND-04/capture-"+result.outcome()+"-"+result.status()+"-"+result.calls());
        var plan=cap09Plan(family,index,false,java.util.Objects.requireNonNull(written.get()));
        System.out.println("PREPARED");System.out.flush();
        if(System.in.read()<0)throw new IllegalStateException("SC-BOUND-04 worker start missing");
        System.out.println("SC_BOUND04_WORKER_STAGE permit");System.out.flush();
        try(Lease lease=new Lease(family)){
            System.out.println("SC_BOUND04_WORKER_STAGE commit");System.out.flush();
            ScBound04AdapterChecks.worker(family,this::connection,source->{String status=cap09Commit(plan,source);
                if(!lease.isCurrent())throw new AssertionError("SC-BOUND-04 permit lost");return status;});
        }
    }
    private void cap09Contention(@NonNull Path configPath)throws Exception{
        var harness=new Cap09ContentionChecks.Harness(){
            @Override public @NonNull String key(@NonNull String family,int index,boolean large){return cap09Key(family,index,large);}
            @Override public @NonNull String scope(@NonNull String family){return AdapterJoinProbe.this.scope(family);}
            @Override public Cap09ContentionChecks.@NonNull Plan capture(@NonNull String family,int index,boolean large)throws Exception{var written=new java.util.concurrent.atomic.AtomicReference<Object>();var result=cap09Attempt(family,index,large,true,new Cap09ContentionChecks.Stats(),written);if(!result.outcome().equals("UNAVAILABLE")||result.calls()!=1)throw new AssertionError("CAP09 capture failed");return cap09Plan(family,index,large,java.util.Objects.requireNonNull(written.get()));}
            @Override public @NonNull String commit(Cap09ContentionChecks.@NonNull Plan plan,Cap09ContentionChecks.@NonNull Connections source)throws Exception{return cap09Commit(plan,source);}
            @Override public Cap09ContentionChecks.@NonNull PublicResult execute(Cap09ContentionChecks.@NonNull Plan plan,Cap09ContentionChecks.@NonNull Stats trace)throws Exception{return cap09Attempt(plan.family(),plan.index(),plan.large(),false,trace,new java.util.concurrent.atomic.AtomicReference<>());}
            @Override public @NonNull Connection open(@NonNull Duration budget)throws SQLException{return connection(budget);}
            @Override public @NonNull AutoCloseable permit(@NonNull String family)throws Exception{return new Lease(family);}
        };
        ScBound04LockOrderChecks.run(harness);
        Cap09ContentionChecks.run(harness);
        ScBound04AdapterChecks.run(harness,configPath,this.worker);
    }

    private void bootstrapDenied()throws Exception{
        String family=text(this.config,"bootstrapFamily");
        if(family.equals("TOTP")){
            var root=TotpStoreKey.forNamespace("migration","old-one");check("MIG15-TOTP-missing-or-closed-root-is-unavailable",this.totpStore.read(Set.of(root),Duration.ofSeconds(5)) instanceof TotpStoreReadResult.Unavailable);
            check("MIG15-TOTP-account-read-cannot-hide-root-loss",this.totpStore.read(Set.of(TotpStoreKey.forAccount("migration","old-one","account-1-0")),Duration.ofSeconds(5)) instanceof TotpStoreReadResult.Unavailable);
            check("MIG15-TOTP-bootstrap-refuses",totp(this.totpStore).initializeNamespaceResult() instanceof TotpNamespaceInitializationResult.Unavailable);
        }else if(family.equals("WEBAUTHN")){
            var root=WebAuthnStoreKey.forNamespaceClock("migration","login.example.com");check("MIG15-WA-missing-or-closed-root-is-unavailable",this.webauthnStore.read(Set.of(root),Duration.ofSeconds(5)) instanceof WebAuthnStoreReadResult.Unavailable);
            check("MIG15-WA-bootstrap-refuses",party().beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(new byte[]{95,96,97}).userName("Synthetic").userDisplayName("Synthetic").build(),OperationBinding.fromTrustedPersistence("A".repeat(43))) instanceof WebAuthnRegistrationRequestResult.Unavailable);
        }else if(family.equals("ISSUER")){
            check("MIG15-ISSUER-missing-or-closed-root-is-unavailable",this.issuerStore.read(issuerRootKey(),Duration.ofSeconds(5)) instanceof OAuthStoreReadResult.Unavailable);
            boolean refused=false;try{issuer().initializeFreshIssuer();}catch(OAuthServerStoreException expected){refused=true;}check("MIG15-ISSUER-bootstrap-refuses",refused);
        }else throw new IllegalArgumentException("Unknown bootstrap family");
    }

    private void floorReceipt(@NonNull String family,@NonNull String key,@NonNull StoreTemporalCondition condition,@NonNull StoreCommitTiming timing){
        Instant floor=condition.getNotBeforeInclusive(),validated=timing.getValidatedTime().getObservedAt();
        check("MIG14-"+family+"-validated-after-prepared-floor",validated.isAfter(floor));
        check("MIG14-"+family+"-absent-completion-is-not-invented",timing.getCompletedTime().isEmpty());
        System.out.println("MIG14_FLOOR\t"+family+"\t"+b64(key.getBytes(StandardCharsets.UTF_8))+"\t"+floor.getEpochSecond()+"\t"+floor.getNano()+"\t"+validated.getEpochSecond()+"\t"+validated.getNano());
    }

    private void floorTiming()throws Exception{
        TotpStore capturedTotp=new TotpStore(){
            @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){return totpStore.read(keys,budget);}
            @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){
                var receipt=totpStore.compareAndCommit(write,budget);check("MIG14-TOTP-actual-commit",receipt.getStatus()==TotpStoreCommitResult.COMMITTED);
                for(var mutation:write.getMutations()){
                    var input=mutation.getRecord();var actual=totpStore.read(Set.of(input.getKey()),budget);if(!(actual instanceof TotpStoreReadResult.Available available)||!(available.getSnapshot().getEntry(input.getKey()) instanceof TotpStoreEntry.Present present))throw new AssertionError("TOTP stored input");
                    check("MIG14-TOTP-opaque-input-preserved",input.getVersion().equals(present.getRecord().getVersion())&&Arrays.equals(input.getSealedBytes(),present.getRecord().getSealedBytes()));
                    floorReceipt("TOTP",input.getKey().getStorageKey(),write.getTemporalCondition(),receipt.getTiming().orElseThrow());
                }return receipt;
            }
        };
        check("MIG14-TOTP-public-normal-transition",totp(capturedTotp).beginEnrollmentResult(TotpEnrollmentOptions.withAccountId("mig14-new-account").accountName("Synthetic").build(),OperationBinding.fromTrustedPersistence("mig14-browser")) instanceof TotpEnrollmentRequestResult.Prepared);
        WebAuthnStore capturedWa=new WebAuthnStore(){
            @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){return webauthnStore.read(keys,budget);}
            @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){
                var receipt=webauthnStore.compareAndCommit(write,budget);check("MIG14-WEBAUTHN-actual-commit",receipt.getStatus()==WebAuthnStoreCommitResult.COMMITTED);
                for(var mutation:write.getMutations()){
                    var actual=webauthnStore.read(Set.of(mutation.getKey()),budget);if(!(actual instanceof WebAuthnStoreReadResult.Available available)||!(available.getSnapshot().getEntry(mutation.getKey()) instanceof WebAuthnStoreEntry.Present present))throw new AssertionError("WA stored input");
                    check("MIG14-WEBAUTHN-opaque-input-preserved",Arrays.equals(mutation.getSealedBytes().orElseThrow(),present.getSealedBytes()));
                    floorReceipt("WEBAUTHN",mutation.getKey().getStorageKey(),write.getTemporalCondition(),receipt.getTiming().orElseThrow());
                }return receipt;
            }
        };
        check("MIG14-WEBAUTHN-public-normal-transition",party(capturedWa).beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(new byte[]{90,91,92}).userName("Synthetic").userDisplayName("Synthetic").build(),OperationBinding.fromTrustedPersistence(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]))) instanceof WebAuthnRegistrationRequestResult.Prepared);
        OAuthAuthorizationServerStore capturedIssuer=new OAuthAuthorizationServerStore(){
            @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return issuerStore.read(key,budget);}
            @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){
                var receipt=issuerStore.commit(tx,budget);check("MIG14-ISSUER-actual-commit",receipt.getStatus()==OAuthStoreCommitStatus.COMMITTED);
                for(var mutation:tx.getMutations()){
                    var input=mutation.getEntry().orElseThrow();var actual=issuerStore.read(input.getKey(),budget);if(!(actual instanceof OAuthStoreReadResult.Available available))throw new AssertionError("Issuer stored input");var stored=available.getEntry().orElseThrow();
                    check("MIG14-ISSUER-opaque-input-preserved",input.getVersion().equals(stored.getVersion())&&input.toSealedForm().equals(stored.toSealedForm()));floorReceipt("ISSUER",input.getKey().getStorageKey(),tx.getTemporalCondition().orElseThrow(),receipt.getTiming().orElseThrow());
                }return receipt;
            }
        };
        try(Lease lease=new Lease("ISSUER")){issuer(capturedIssuer).establishNewSubject("mig14-new-subject");check("MIG14-ISSUER-public-normal-transition",lease.isCurrent());}
    }

    private void closed(boolean externalClosed)throws Exception{
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER"))check(externalClosed?"direct-external-admission-closed-"+family:"direct-external-admission-current-despite-worker-skew-"+family,current(family)!=externalClosed);
        check("totp-public-service-closed-without-current-external-admission",totp(this.totpStore).getStatusResult("account-1-0") instanceof TotpStatusResult.Unavailable);
        check("wa-public-service-closed-without-current-external-admission",party().listCredentialsResult(new byte[]{4,5,6}) instanceof WebAuthnCredentialListResult.Unavailable);
        boolean refused=false;try{issuer().warmUp();}catch(OAuthServerStoreException expected){refused=true;}
        check("issuer-public-service-closed-without-current-external-admission",refused);
    }

    private void holdStatus()throws Exception{
        TotpStore held=new TotpStore(){private boolean first=true;
            @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration remaining){
                var result=totpStore.read(keys,remaining);if(this.first){this.first=false;System.out.println("READY HELD_PUBLIC_STATUS");System.out.flush();try{if(!"CONTINUE".equals(new BufferedReader(new InputStreamReader(System.in,StandardCharsets.US_ASCII)).readLine()))throw new IllegalStateException();}catch(Exception failed){throw new IllegalStateException("Private held operation failed");}}return result;
            }
            @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration remaining){return totpStore.compareAndCommit(write,remaining);}
        };
        check("held-public-operation-finishes-before-exclusive-restore",totp(held).getStatusResult("account-1-0") instanceof TotpStatusResult.Present);
    }

    private static @NonNull Set<@NonNull WebAuthnStoreKey> waKeys(){
        byte[] ceremony=new byte[32];for(int i=0;i<32;i++)ceremony[i]=(byte)(i+1);
        return Set.of(WebAuthnStoreKey.forNamespaceClock("migration","login.example.com"),
                WebAuthnStoreKey.forCredential("migration","login.example.com",new byte[]{1,2,3}),
                WebAuthnStoreKey.forCredential("migration","login.example.com",new byte[]{7,8,9}),
                WebAuthnStoreKey.forAccountCredentialIndex("migration","login.example.com",new byte[]{4,5,6}),
                WebAuthnStoreKey.forAccountCredentialIndex("migration","login.example.com",new byte[]{10,11,12}),
                WebAuthnStoreKey.forAccountFence("migration","login.example.com",new byte[]{4,5,6}),
                WebAuthnStoreKey.forAccountFence("migration","login.example.com",new byte[]{10,11,12}),
                WebAuthnStoreKey.forCeremony("migration","login.example.com",ceremony));
    }
}
