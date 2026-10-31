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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
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
    private final @NonNull PostgresqlTotpStore totpStore;
    private final @NonNull PostgresqlWebAuthnStore webauthnStore;
    private final @NonNull PostgresqlIssuerStore issuerStore;

    private AdapterJoinProbe(@NonNull JsonObject config) {
        this.config=config;
        Instant workerBase=instant((JsonObject)config.find("workerNow").orElseThrow());
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
        this.totpStore=new PostgresqlTotpStore("migration",text(config,"totpScope"),this::connection,65536,268435456L,
                (scope,budget)->observe("TOTP",scope,budget));
        this.webauthnStore=new PostgresqlWebAuthnStore("migration",text(config,"webauthnScope"),this::connection,1000000,
                (scope,budget)->observe("WEBAUTHN",scope,budget));
        this.issuerStore=new PostgresqlIssuerStore("migration",text(config,"issuerScope"),this::connection,1000000,
                (scope,budget)->observe("ISSUER",scope,budget));
    }

    public static void main(@NonNull String @NonNull [] args) {
        try {
            if(args.length!=2)throw new IllegalArgumentException("Expected protected config and command");
            JsonObject config=(JsonObject)com.revetsec.internal.json.JsonCodec.parse(Files.readAllBytes(Path.of(args[0])),
                    com.revetsec.internal.json.JsonLimits.protocolDocument(4194304));
            if(!hash(Files.readAllBytes(Path.of(StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI())))
                    .equals(text(config,"expectedCoreSha256")))throw new AssertionError("Exact current artifact origin");
            AdapterJoinProbe probe=new AdapterJoinProbe(config);
            switch(args[1]){
                case "raw" -> probe.raw();
                case "query" -> probe.query();
                case "mutate" -> probe.mutate();
                case "closed" -> probe.closed(true);
                case "skew" -> probe.closed(false);
                case "hold-status" -> probe.holdStatus();
                default -> throw new IllegalArgumentException("Unknown private command");
            }
        } catch(Throwable failure) {
            System.err.println("ADAPTER_PROBE_FAILED "+failure.getClass().getSimpleName());
            System.exit(1);
        }
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
            if(result.length!=8||!result[0].equals("OK"))throw new IllegalStateException("Current external admission closed");
            if(!result[1].equals(text(this.config,"authorityId"))||!result[2].equals(text(this.config,"recoveryGeneration"))||!result[3].equals(text(this.config,"clockGeneration")))throw new IllegalStateException("Authority identities differ");
            return result;
        }
    }

    private @NonNull StoreTimeObservation observe(@NonNull String family,@NonNull String scope,@NonNull Duration budget)throws Exception{
        String[] point=rpc("OBSERVE",family,scope,budget);
        return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(point[1],point[2]),point[3],
                Instant.ofEpochSecond(Long.parseLong(point[4]),Long.parseLong(point[5])),Duration.ofNanos(Long.parseLong(point[6])));
    }

    private boolean current(@NonNull String family){
        try{rpc("ADMIT",family,scope(family),Duration.ofSeconds(1));return true;}catch(Exception closed){return false;}
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

    private @NonNull WebAuthnRelyingParty party(){
        WebAuthnRecoveryGate gate=budget->{Lease lease=acquire("WEBAUTHN",budget);if(lease==null)return null;
            return new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return lease.isCurrent();}@Override public void close(){lease.close();}};};
        return com.revetsec.webauthn.AdapterJoinWorker.configure(WebAuthnRelyingParty.withRelyingPartyId("login.example.com"),this.worker)
                .relyingPartyName("Migration fixture").allowedOrigins(Set.of("https://login.example.com"))
                .credentialNamespace("migration").store(this.webauthnStore).stateSealer(this.sealer).recoveryGate(gate).build();
    }

    private @NonNull OAuthAuthorizationServer issuer()throws Exception{
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);var pair=generator.generateKeyPair();
        var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("fixture",pair.getPrivate(),pair.getPublic()))
                .generation("migration-probe").publishedAt(this.worker.instant().minusSeconds(1)).build();
        return OAuthAuthorizationServer.withIssuer(text(this.config,"issuer"))
                .authorizationEndpoint(URI.create("https://issuer.example/authorize")).tokenEndpoint(URI.create("https://issuer.example/token"))
                .jwksEndpoint(URI.create("https://issuer.example/jwks")).clientRepository((id,budget)->Optional.empty())
                .resources(Map.of("https://resource.example/mcp",Set.of("read"))).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance()).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys))
                .store(this.issuerStore).stateSealer(this.sealer).clock(this.worker).maximumStoreRecordBytes(16384).build();
    }

    private void raw()throws Exception{
        try(Lease lease=new Lease("TOTP")){
            Map<String,Set<TotpStoreKey>> keys=new HashMap<>();Set<WebAuthnStoreKey> wa=new HashSet<>();int issuer=0;
            for(JsonObject row:rows(this.config,"rows")){
                String family=text(row,"family"),address=text(row,"key");
                if(family.equals("TOTP")){TotpStoreKey key=TotpStoreKey.fromStoredForm(address);keys.computeIfAbsent(key.getRecoveryEpoch(),unused->new HashSet<>()).add(key);}
                else if(family.equals("WEBAUTHN")){WebAuthnStoreKey found=waKeys().stream().filter(k->k.getStorageKey().equals(address)).findFirst().orElseThrow();wa.add(found);}
                else{var result=this.issuerStore.read(OAuthStoreKey.fromStoredForm(address),Duration.ofSeconds(5));
                    if(!(result instanceof OAuthStoreReadResult.Available available)||available.getEntry().isEmpty())throw new AssertionError("Current issuer retained read");issuer++;}
            }
            var active=this.totpStore.read(java.util.Objects.requireNonNull(keys.get("old-one")),Duration.ofSeconds(5));
            check("current-totp-adapter-loads-active-retained-epoch",active instanceof TotpStoreReadResult.Available a&&a.getSnapshot().getEntries().size()==5&&a.getSnapshot().getEntries().values().stream().allMatch(TotpStoreEntry.Present.class::isInstance));
            check("current-totp-adapter-fences-retained-old-epoch",this.totpStore.read(java.util.Objects.requireNonNull(keys.get("old-two")),Duration.ofSeconds(5)) instanceof TotpStoreReadResult.Fenced);
            var read=this.webauthnStore.read(wa,Duration.ofSeconds(5));check("current-wa-adapter-loads-all-retained-kinds",read instanceof WebAuthnStoreReadResult.Available a&&a.getSnapshot().getEntries().size()==8&&a.getSnapshot().getEntries().values().stream().allMatch(WebAuthnStoreEntry.Present.class::isInstance));
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

    private void mutate()throws Exception{
        TotpAuthenticator totp=totp(this.totpStore);TotpStoreKey account=TotpStoreKey.forAccount("migration","old-one","account-1-0");
        check("totp-public-reseal-commits-on-current-adapter",totp.resealStoreEntryResult(account) instanceof TotpStoreResealResult.Resealed);
        byte[] syntheticSecret=new byte[20];for(int i=0;i<syntheticSecret.length;i++)syntheticSecret[i]=(byte)(i+7);
        javax.crypto.Mac mac=javax.crypto.Mac.getInstance("HmacSHA1");mac.init(new javax.crypto.spec.SecretKeySpec(syntheticSecret,"HmacSHA1"));
        byte[] digest=mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(this.worker.instant().getEpochSecond()/30L).array());int offset=digest[digest.length-1]&15;
        int binary=((digest[offset]&127)<<24)|((digest[offset+1]&255)<<16)|((digest[offset+2]&255)<<8)|(digest[offset+3]&255);
        String code=String.format(java.util.Locale.ROOT,"%06d",binary%1000000);Arrays.fill(syntheticSecret,(byte)0);Arrays.fill(digest,(byte)0);
        check("totp-original-secret-verifies-after-migration",totp.verifyResult("account-1-0",code,"adapter-verify") instanceof TotpVerificationResult.Succeeded);
        check("totp-committed-step-replay-remains-rejected",totp.verifyResult("account-1-0",code,"adapter-replay") instanceof TotpVerificationResult.Rejected);
        var status=totp.getStatusResult("account-1-0");String factor=((TotpStatusResult.Present)status).getStatus().getActiveFactor().orElseThrow().getFactorId();
        check("totp-public-factor-removal-commits",totp.removeFactorResult("account-1-0",factor) instanceof TotpFactorRemovalResult.Succeeded);
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
