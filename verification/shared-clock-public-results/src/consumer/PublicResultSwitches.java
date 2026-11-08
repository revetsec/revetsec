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


package consumer;

import com.revetsec.OperationBinding;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NonNull;

/** Public packaged-client switches; Java21 consumer, unchanged Java17 core. */
public final class PublicResultSwitches {
    private PublicResultSwitches() { }
    static @NonNull String route(@NonNull RecoveryCodeRotationResult result) {
        return switch (result) {
            case RecoveryCodeRotationResult.Succeeded ignored -> "RecoveryCodeRotationResult.Succeeded";
            case RecoveryCodeRotationResult.Rejected ignored -> "RecoveryCodeRotationResult.Rejected";
            case RecoveryCodeRotationResult.Unavailable ignored -> "RecoveryCodeRotationResult.Unavailable";
            case RecoveryCodeRotationResult.Indeterminate ignored -> "RecoveryCodeRotationResult.Indeterminate";
            case RecoveryCodeRotationResult.ReconciliationRequired ignored -> "RecoveryCodeRotationResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull RecoveryCodeUseResult result) {
        return switch (result) {
            case RecoveryCodeUseResult.Succeeded ignored -> "RecoveryCodeUseResult.Succeeded";
            case RecoveryCodeUseResult.Rejected ignored -> "RecoveryCodeUseResult.Rejected";
            case RecoveryCodeUseResult.Throttled ignored -> "RecoveryCodeUseResult.Throttled";
            case RecoveryCodeUseResult.Unavailable ignored -> "RecoveryCodeUseResult.Unavailable";
            case RecoveryCodeUseResult.Indeterminate ignored -> "RecoveryCodeUseResult.Indeterminate";
            case RecoveryCodeUseResult.ReconciliationRequired ignored -> "RecoveryCodeUseResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpEnrollmentCancellationResult result) {
        return switch (result) {
            case TotpEnrollmentCancellationResult.Succeeded ignored -> "TotpEnrollmentCancellationResult.Succeeded";
            case TotpEnrollmentCancellationResult.Rejected ignored -> "TotpEnrollmentCancellationResult.Rejected";
            case TotpEnrollmentCancellationResult.Unavailable ignored -> "TotpEnrollmentCancellationResult.Unavailable";
            case TotpEnrollmentCancellationResult.Indeterminate ignored -> "TotpEnrollmentCancellationResult.Indeterminate";
            case TotpEnrollmentCancellationResult.ReconciliationRequired ignored -> "TotpEnrollmentCancellationResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpEnrollmentRequestResult result) {
        return switch (result) {
            case TotpEnrollmentRequestResult.Prepared ignored -> "TotpEnrollmentRequestResult.Prepared";
            case TotpEnrollmentRequestResult.Rejected ignored -> "TotpEnrollmentRequestResult.Rejected";
            case TotpEnrollmentRequestResult.Throttled ignored -> "TotpEnrollmentRequestResult.Throttled";
            case TotpEnrollmentRequestResult.Unavailable ignored -> "TotpEnrollmentRequestResult.Unavailable";
            case TotpEnrollmentRequestResult.Indeterminate ignored -> "TotpEnrollmentRequestResult.Indeterminate";
            case TotpEnrollmentRequestResult.ReconciliationRequired ignored -> "TotpEnrollmentRequestResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpEnrollmentResult result) {
        return switch (result) {
            case TotpEnrollmentResult.Succeeded ignored -> "TotpEnrollmentResult.Succeeded";
            case TotpEnrollmentResult.Rejected ignored -> "TotpEnrollmentResult.Rejected";
            case TotpEnrollmentResult.Throttled ignored -> "TotpEnrollmentResult.Throttled";
            case TotpEnrollmentResult.Unavailable ignored -> "TotpEnrollmentResult.Unavailable";
            case TotpEnrollmentResult.Indeterminate ignored -> "TotpEnrollmentResult.Indeterminate";
            case TotpEnrollmentResult.ReconciliationRequired ignored -> "TotpEnrollmentResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpFactorRemovalResult result) {
        return switch (result) {
            case TotpFactorRemovalResult.Succeeded ignored -> "TotpFactorRemovalResult.Succeeded";
            case TotpFactorRemovalResult.Rejected ignored -> "TotpFactorRemovalResult.Rejected";
            case TotpFactorRemovalResult.Unavailable ignored -> "TotpFactorRemovalResult.Unavailable";
            case TotpFactorRemovalResult.Indeterminate ignored -> "TotpFactorRemovalResult.Indeterminate";
            case TotpFactorRemovalResult.ReconciliationRequired ignored -> "TotpFactorRemovalResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpNamespaceInitializationResult result) {
        return switch (result) {
            case TotpNamespaceInitializationResult.Initialized ignored -> "TotpNamespaceInitializationResult.Initialized";
            case TotpNamespaceInitializationResult.AlreadyInitialized ignored -> "TotpNamespaceInitializationResult.AlreadyInitialized";
            case TotpNamespaceInitializationResult.Unavailable ignored -> "TotpNamespaceInitializationResult.Unavailable";
            case TotpNamespaceInitializationResult.Indeterminate ignored -> "TotpNamespaceInitializationResult.Indeterminate";
            case TotpNamespaceInitializationResult.ReconciliationRequired ignored -> "TotpNamespaceInitializationResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpStoreResealResult result) {
        return switch (result) {
            case TotpStoreResealResult.Resealed ignored -> "TotpStoreResealResult.Resealed";
            case TotpStoreResealResult.AlreadyCurrent ignored -> "TotpStoreResealResult.AlreadyCurrent";
            case TotpStoreResealResult.Absent ignored -> "TotpStoreResealResult.Absent";
            case TotpStoreResealResult.Unavailable ignored -> "TotpStoreResealResult.Unavailable";
            case TotpStoreResealResult.Indeterminate ignored -> "TotpStoreResealResult.Indeterminate";
            case TotpStoreResealResult.ReconciliationRequired ignored -> "TotpStoreResealResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull TotpVerificationResult result) {
        return switch (result) {
            case TotpVerificationResult.Succeeded ignored -> "TotpVerificationResult.Succeeded";
            case TotpVerificationResult.Rejected ignored -> "TotpVerificationResult.Rejected";
            case TotpVerificationResult.Throttled ignored -> "TotpVerificationResult.Throttled";
            case TotpVerificationResult.Unavailable ignored -> "TotpVerificationResult.Unavailable";
            case TotpVerificationResult.Indeterminate ignored -> "TotpVerificationResult.Indeterminate";
            case TotpVerificationResult.ReconciliationRequired ignored -> "TotpVerificationResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnAccountDisableResult result) {
        return switch (result) {
            case WebAuthnAccountDisableResult.Disabled ignored -> "WebAuthnAccountDisableResult.Disabled";
            case WebAuthnAccountDisableResult.Unavailable ignored -> "WebAuthnAccountDisableResult.Unavailable";
            case WebAuthnAccountDisableResult.Indeterminate ignored -> "WebAuthnAccountDisableResult.Indeterminate";
            case WebAuthnAccountDisableResult.ReconciliationRequired ignored -> "WebAuthnAccountDisableResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnAuthenticationRequestResult result) {
        return switch (result) {
            case WebAuthnAuthenticationRequestResult.Prepared ignored -> "WebAuthnAuthenticationRequestResult.Prepared";
            case WebAuthnAuthenticationRequestResult.Rejected ignored -> "WebAuthnAuthenticationRequestResult.Rejected";
            case WebAuthnAuthenticationRequestResult.Unavailable ignored -> "WebAuthnAuthenticationRequestResult.Unavailable";
            case WebAuthnAuthenticationRequestResult.Indeterminate ignored -> "WebAuthnAuthenticationRequestResult.Indeterminate";
            case WebAuthnAuthenticationRequestResult.ReconciliationRequired ignored -> "WebAuthnAuthenticationRequestResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnAuthenticationResult result) {
        return switch (result) {
            case WebAuthnAuthenticationResult.Succeeded ignored -> "WebAuthnAuthenticationResult.Succeeded";
            case WebAuthnAuthenticationResult.Rejected ignored -> "WebAuthnAuthenticationResult.Rejected";
            case WebAuthnAuthenticationResult.Unavailable ignored -> "WebAuthnAuthenticationResult.Unavailable";
            case WebAuthnAuthenticationResult.Indeterminate ignored -> "WebAuthnAuthenticationResult.Indeterminate";
            case WebAuthnAuthenticationResult.ReconciliationRequired ignored -> "WebAuthnAuthenticationResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnCredentialRemovalResult result) {
        return switch (result) {
            case WebAuthnCredentialRemovalResult.Removed ignored -> "WebAuthnCredentialRemovalResult.Removed";
            case WebAuthnCredentialRemovalResult.Absent ignored -> "WebAuthnCredentialRemovalResult.Absent";
            case WebAuthnCredentialRemovalResult.Unavailable ignored -> "WebAuthnCredentialRemovalResult.Unavailable";
            case WebAuthnCredentialRemovalResult.Indeterminate ignored -> "WebAuthnCredentialRemovalResult.Indeterminate";
            case WebAuthnCredentialRemovalResult.ReconciliationRequired ignored -> "WebAuthnCredentialRemovalResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnRegistrationRequestResult result) {
        return switch (result) {
            case WebAuthnRegistrationRequestResult.Prepared ignored -> "WebAuthnRegistrationRequestResult.Prepared";
            case WebAuthnRegistrationRequestResult.Rejected ignored -> "WebAuthnRegistrationRequestResult.Rejected";
            case WebAuthnRegistrationRequestResult.Unavailable ignored -> "WebAuthnRegistrationRequestResult.Unavailable";
            case WebAuthnRegistrationRequestResult.Indeterminate ignored -> "WebAuthnRegistrationRequestResult.Indeterminate";
            case WebAuthnRegistrationRequestResult.ReconciliationRequired ignored -> "WebAuthnRegistrationRequestResult.ReconciliationRequired";
        };
    }
    static @NonNull String route(@NonNull WebAuthnRegistrationResult result) {
        return switch (result) {
            case WebAuthnRegistrationResult.Succeeded ignored -> "WebAuthnRegistrationResult.Succeeded";
            case WebAuthnRegistrationResult.Rejected ignored -> "WebAuthnRegistrationResult.Rejected";
            case WebAuthnRegistrationResult.Unavailable ignored -> "WebAuthnRegistrationResult.Unavailable";
            case WebAuthnRegistrationResult.Indeterminate ignored -> "WebAuthnRegistrationResult.Indeterminate";
            case WebAuthnRegistrationResult.ReconciliationRequired ignored -> "WebAuthnRegistrationResult.ReconciliationRequired";
        };
    }
    private static void require(boolean condition, @NonNull String label) {
        if (!condition) throw new AssertionError(label);
    }
    private static int audit(@NonNull Class<?> family, @NonNull Set<@NonNull String> variants,
                             @NonNull Path expectedJar, @NonNull String expectedSha) throws Exception {
        require(family.isSealed(), "sealed public result");
        Path origin=Path.of(family.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        require(origin.equals(expectedJar) && Files.isRegularFile(origin), "exact packaged core origin");
        require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(origin))).equals(expectedSha), "exact packaged core bytes");
        Set<String> actual=new HashSet<>();
        for(Class<?> variant:family.getPermittedSubclasses()) {
            actual.add(variant.getSimpleName());
            require(Modifier.isPublic(variant.getModifiers()) && Modifier.isFinal(variant.getModifiers()), "public final permitted variant");
            require(variant.getSuperclass()==family && variant.getProtectionDomain().getCodeSource().getLocation().equals(family.getProtectionDomain().getCodeSource().getLocation()), "variant exact family/JAR");
            if(variant.getSimpleName().equals("ReconciliationRequired")) {
                require(variant.getConstructors().length==0 && variant.getDeclaredFields().length==0 && variant.getDeclaredMethods().length==0, "restricted payload-free reconciliation shape");
                require(Arrays.stream(variant.getDeclaredConstructors()).allMatch(c->Modifier.isPrivate(c.getModifiers())), "private reconciliation construction");
            }
        }
        require(actual.equals(variants), "all permitted variants match explicit switch cases");
        return actual.size();
    }
    static @NonNull String route(@NonNull WebAuthnReauthenticationResult result) {
        return switch (result) {
            case WebAuthnReauthenticationResult.Succeeded ignored -> "WebAuthnReauthenticationResult.Succeeded";
            case WebAuthnReauthenticationResult.Rejected ignored -> "WebAuthnReauthenticationResult.Rejected";
            case WebAuthnReauthenticationResult.Unavailable ignored -> "WebAuthnReauthenticationResult.Unavailable";
            case WebAuthnReauthenticationResult.Indeterminate ignored -> "WebAuthnReauthenticationResult.Indeterminate";
            case WebAuthnReauthenticationResult.ReconciliationRequired ignored -> "WebAuthnReauthenticationResult.ReconciliationRequired";
        };
    }

    public static void main(@NonNull String @NonNull [] args) throws Exception {
        require(args.length==2 && args[1].matches("[0-9a-f]{64}"), "expected JAR path and SHA256");
        Path jar=Path.of(args[0]).toRealPath();int variants=0;
        variants+=audit(RecoveryCodeRotationResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(RecoveryCodeUseResult.class,Set.of("Succeeded","Rejected","Throttled","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpEnrollmentCancellationResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpEnrollmentRequestResult.class,Set.of("Prepared","Rejected","Throttled","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpEnrollmentResult.class,Set.of("Succeeded","Rejected","Throttled","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpFactorRemovalResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpNamespaceInitializationResult.class,Set.of("Initialized","AlreadyInitialized","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpStoreResealResult.class,Set.of("Resealed","AlreadyCurrent","Absent","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(TotpVerificationResult.class,Set.of("Succeeded","Rejected","Throttled","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnAccountDisableResult.class,Set.of("Disabled","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnAuthenticationRequestResult.class,Set.of("Prepared","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnAuthenticationResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnCredentialRemovalResult.class,Set.of("Removed","Absent","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnRegistrationRequestResult.class,Set.of("Prepared","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnRegistrationResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        variants+=audit(WebAuthnReauthenticationResult.class,Set.of("Succeeded","Rejected","Unavailable","Indeterminate","ReconciliationRequired"),jar,args[1]);
        require(variants==84, "sixteen-family permitted count");
        // Public engine calls may legally supply ordinary variants. No private
        // constructor/factory, internal class or fabricated proof is used.
        AtomicInteger gates=new AtomicInteger();
        TotpStore inaccessibleStore=new TotpStore() {
            @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget) {throw new AssertionError("Store must remain behind closed recovery admission");}
            @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget) {throw new AssertionError("Store must remain behind closed recovery admission");}
        };
        byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+1);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",Base64.getEncoder().encodeToString(key))).build();
        Arrays.fill(key,(byte)0);
        TotpAuthenticator auth=TotpAuthenticator.withIssuer("Public fixture").credentialNamespace("public-fixture").recoveryEpoch("one")
            .store(inaccessibleStore).stateSealer(sealer).recoveryGate((context,budget)->{gates.incrementAndGet();return null;}).build();
        String account="fixture-account",id="fixture-id";
        OperationBinding binding=OperationBinding.fromTrustedPersistence("fixture-binding");
        require(route(auth.beginEnrollmentResult(TotpEnrollmentOptions.withAccountId(account).accountName("Fixture").build(),binding)).equals("TotpEnrollmentRequestResult.Unavailable"), "public enrollment preparation unavailable route");
        require(route(auth.confirmEnrollmentResult(account,id,"123456",binding)).equals("TotpEnrollmentResult.Unavailable"), "public enrollment unavailable route");
        require(route(auth.verifyResult(account,"123456",binding)).equals("TotpVerificationResult.Unavailable"), "public verification unavailable route");
        require(route(auth.consumeRecoveryCodeResult(account,"invalid",binding)).equals("RecoveryCodeUseResult.Unavailable"), "public recovery-code unavailable route");
        require(route(auth.rotateRecoveryCodesResult(account,id,id)).equals("RecoveryCodeRotationResult.Unavailable"), "public recovery rotation unavailable route");
        require(route(auth.removeFactorResult(account,id)).equals("TotpFactorRemovalResult.Unavailable"), "public factor removal unavailable route");
        require(route(auth.cancelEnrollmentResult(account,id,binding)).equals("TotpEnrollmentCancellationResult.Unavailable"), "public enrollment cancellation unavailable route");
        require(route(auth.initializeNamespaceResult()).equals("TotpNamespaceInitializationResult.Unavailable"), "public namespace initialization unavailable route");
        require(route(auth.resealStoreEntryResult(TotpStoreKey.forNamespace("public-fixture","one"))).equals("TotpStoreResealResult.Unavailable"), "public reseal unavailable route");
        require(route(auth.confirmEnrollmentResult(account,id,"x".repeat(129),binding)).equals("TotpEnrollmentResult.Rejected"), "public oversized enrollment rejection route");
        require(route(auth.verifyResult(account,"x".repeat(129),binding)).equals("TotpVerificationResult.Rejected"), "public oversized verification rejection route");
        require(gates.get()==9, "no storage/proof callbacks and early rejections skip recovery admission");
        PublicServiceChecks.run(PublicSwitchRouter::route,jar,args[1]);
        System.out.println("SWITCH_FAMILIES 16");System.out.println("PERMITTED_VARIANTS "+variants);
        System.out.println("PUBLIC_RUNTIME_ROUTES 11");System.out.println("RUNTIME_RECONCILIATION_ROUTES "+PublicServiceChecks.reconciliationRoutes());
        System.out.println("CORE_ORIGIN_SHA256 "+args[1]);
    }
}
