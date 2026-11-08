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

import com.revetsec.StoreAdmission;
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Pure public consumer/service join. No result or proof is manufactured. */
final class PublicServiceChecks {
 private PublicServiceChecks() { }
 enum Mode { ELIGIBLE, KNOWN_TIME_OUTAGE, KNOWN_CLOSE_FAILURE, UNKNOWN_APPLIED, UNKNOWN_ABSENT, UNAVAILABLE }
 @FunctionalInterface interface Router { @NonNull String route(@NonNull Object value); }
 private static @Nullable Router router;
 private static @Nullable Path core;
 private static final @NonNull Set<@NonNull String> seen=new HashSet<>(),reconciliation=new HashSet<>(),unknown=new HashSet<>(),unavailable=new HashSet<>(),eligible=new HashSet<>();
 private static int cases,reconciliationRoutes;
 private static @NonNull String context="UNSET";
 private static final @NonNull List<@NonNull String> caseRows=new java.util.ArrayList<>(),countRows=new java.util.ArrayList<>();
 static void context(@NonNull String value){context=value;}
 static void counts(@NonNull String family,@NonNull Mode mode,int reads,int callbacks,int applied,int closes){countsScenario(family,mode.name(),reads,callbacks,applied,closes);}
 static void countsScenario(@NonNull String family,@NonNull String scenario,int reads,int callbacks,int applied,int closes){countRows.add(family+"\t"+scenario+"\t"+reads+"\t"+callbacks+"\t"+applied+"\t"+closes);}
 static int reconciliationRoutes(){return reconciliationRoutes;}
 private static final @NonNull List<@NonNull Class<?>> FAMILIES=List.of(
  TotpEnrollmentRequestResult.class,TotpEnrollmentResult.class,TotpVerificationResult.class,RecoveryCodeUseResult.class,
  RecoveryCodeRotationResult.class,TotpFactorRemovalResult.class,TotpEnrollmentCancellationResult.class,
  TotpNamespaceInitializationResult.class,TotpStoreResealResult.class,WebAuthnRegistrationRequestResult.class,
  WebAuthnAuthenticationRequestResult.class,WebAuthnRegistrationResult.class,WebAuthnAuthenticationResult.class,
  WebAuthnCredentialRemovalResult.class,WebAuthnAccountDisableResult.class,WebAuthnReauthenticationResult.class);
 static void require(boolean value,@NonNull String label){if(!value)throw new AssertionError(label);}
 static <T> @NonNull T expect(@NonNull Class<@NonNull T> type,@Nullable Object value){require(type.isInstance(value),"Unexpected public service variant for "+type.getSimpleName());return Objects.requireNonNull(type.cast(value));}
 static boolean sameAdmission(@NonNull StoreAdmission a,@NonNull StoreAdmission b){return a.getAuthorityId().equals(b.getAuthorityId())&&a.getRecoveryGeneration().equals(b.getRecoveryGeneration());}
 static @NonNull String expected(@NonNull Mode mode,@NonNull String success){return switch(mode){case ELIGIBLE->success;case KNOWN_TIME_OUTAGE,KNOWN_CLOSE_FAILURE->"ReconciliationRequired";case UNKNOWN_APPLIED,UNKNOWN_ABSENT->"Indeterminate";case UNAVAILABLE->"Unavailable";};}
 static void record(@NonNull String family,@NonNull String leaf,@NonNull Object value){
  Class<?> actual=value.getClass();require(actual.getSimpleName().equals(leaf)&&actual.getEnclosingClass()!=null&&actual.getEnclosingClass().getSimpleName().equals(family),"Public family/leaf mismatch: "+family+"/"+leaf);
  try{require(Path.of(actual.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().equals(Objects.requireNonNull(core)),"Result class did not originate in exact selected JAR");}catch(java.net.URISyntaxException|java.io.IOException fault){throw new AssertionError("Public result origin unavailable",fault);}
  require(Objects.requireNonNull(router).route(value).equals(family+"."+leaf),"Consumer dispatched to the wrong explicit result arm: "+family+"/"+leaf);seen.add(family+"."+leaf);caseRows.add(family+"\t"+leaf+"\t"+context);cases++;
  Object payload=payload(value);boolean carries=Set.of("TotpEnrollmentRequestResult.Prepared","TotpEnrollmentResult.Succeeded","TotpVerificationResult.Succeeded","RecoveryCodeUseResult.Succeeded","RecoveryCodeRotationResult.Succeeded","WebAuthnRegistrationRequestResult.Prepared","WebAuthnAuthenticationRequestResult.Prepared","WebAuthnRegistrationResult.Succeeded","WebAuthnAuthenticationResult.Succeeded","WebAuthnReauthenticationResult.Succeeded").contains(family+"."+leaf);
  require(carries?payload!=null:payload==null,"Payload access outside eligible restricted variant");
  if(leaf.equals("ReconciliationRequired")){reconciliationRoutes++;reconciliation.add(family);require(value.toString().equals(family+"{<redacted>}"),"Reconciliation result retained detail");}
  if(leaf.equals("Indeterminate"))unknown.add(family);if(leaf.equals("Unavailable"))unavailable.add(family);if(carries||Set.of("Initialized","Resealed","Succeeded","Disabled","Removed").contains(leaf))eligible.add(family);
 }
 private static @Nullable Object payload(@NonNull Object value){
  if(value instanceof TotpEnrollmentRequestResult.Prepared result)return result.getEnrollment();
  if(value instanceof TotpEnrollmentResult.Succeeded result)return result.getRecoveryCodes();
  if(value instanceof TotpVerificationResult.Succeeded result)return result.getVerification();
  if(value instanceof RecoveryCodeUseResult.Succeeded result)return result.getUse();
  if(value instanceof RecoveryCodeRotationResult.Succeeded result)return result.getRecoveryCodes();
  if(value instanceof WebAuthnRegistrationRequestResult.Prepared result)return result.getRequest();
  if(value instanceof WebAuthnAuthenticationRequestResult.Prepared result)return result.getRequest();
  if(value instanceof WebAuthnRegistrationResult.Succeeded result)return result.getRegistration();
  if(value instanceof WebAuthnAuthenticationResult.Succeeded result)return result.getAuthentication();
  if(value instanceof WebAuthnReauthenticationResult.Succeeded result)return result.getReauthentication();return null;
 }
 static void run(@NonNull Router selected,@NonNull Path jar,@NonNull String digest)throws Exception{
  require(cases==0,"Fixture must run in a fresh process");router=selected;core=jar.toRealPath();require(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(core))).equals(digest),"Selected JAR bytes changed");Set<String> all=new HashSet<>();
  for(Class<?> family:FAMILIES){require(family.isSealed(),"Public family must remain sealed");for(Class<?> leaf:family.getPermittedSubclasses()){
   require(Modifier.isPublic(leaf.getModifiers())&&Modifier.isFinal(leaf.getModifiers()),"Result leaf is not public/final");all.add(family.getSimpleName()+"."+leaf.getSimpleName());
   if(leaf.getSimpleName().equals("ReconciliationRequired")){
    require(leaf.getConstructors().length==0&&leaf.getDeclaredFields().length==0&&leaf.getDeclaredMethods().length==0,"Reconciliation leaf must retain no payload or detail");
    for(var method:leaf.getMethods())require(method.getDeclaringClass()==Object.class||method.getName().equals("toString"),"Inherited reconciliation payload getter");
    for(Class<?> parent=leaf;parent!=Object.class;parent=parent.getSuperclass())for(var field:parent.getDeclaredFields())require(Modifier.isStatic(field.getModifiers())||field.isSynthetic(),"Inherited reconciliation instance payload");
   }
  }}require(all.size()==84,"Explicit sixteen-family result inventory changed");
  TotpServiceCases.run();WebAuthnServiceCases.run();TypedReauthenticationServiceCases.run();require(seen.equals(all),"Public producers did not execute every permitted result leaf");require(cases==120,"Exact finite public service case count changed");require(reconciliation.size()==16&&unknown.size()==16&&unavailable.size()==16&&eligible.size()==16,"A public mutation family is missing a required effect/outcome class");
  String evidence=System.getProperty("consumer.evidence.directory");if(evidence!=null){Path out=Path.of(evidence);Files.writeString(out.resolve("public-service-cases.tsv"),"family\tleaf\tcontext\n"+String.join("\n",caseRows)+"\n");Files.writeString(out.resolve("public-service-counts.tsv"),"family\tmode\treads\tcallbacks\tapplied\tcloses\n"+String.join("\n",countRows)+"\n");}
  System.out.println("PUBLIC_SERVICE_RUNTIME_CASES "+cases);System.out.println("PUBLIC_SERVICE_UNIQUE_VARIANTS "+seen.size());System.out.println("PUBLIC_SERVICE_RECONCILIATION_FAMILIES "+reconciliation.size());System.out.println("PUBLIC_SERVICE_UNKNOWN_FAMILIES "+unknown.size());System.out.println("PUBLIC_SERVICE_PREWRITE_UNAVAILABLE_FAMILIES "+unavailable.size());System.out.println("PUBLIC_SERVICE_ELIGIBLE_FAMILIES "+eligible.size());System.out.println("WA_FIXTURE_MAX_DRIFT_MILLIS "+WebAuthnServiceCases.maximumDriftMillis());
 }
}
