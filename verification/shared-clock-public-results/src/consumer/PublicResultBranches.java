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
import com.revetsec.totp.*;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
/** Java17-compatible explicit public leaf consumer; no pattern-switch syntax. */
public final class PublicResultBranches {
 private PublicResultBranches(){}
 static @NonNull String route(@NonNull Object value){
  if(value instanceof RecoveryCodeRotationResult.Succeeded ignored)return "RecoveryCodeRotationResult.Succeeded";
  if(value instanceof RecoveryCodeRotationResult.Rejected ignored)return "RecoveryCodeRotationResult.Rejected";
  if(value instanceof RecoveryCodeRotationResult.Unavailable ignored)return "RecoveryCodeRotationResult.Unavailable";
  if(value instanceof RecoveryCodeRotationResult.Indeterminate ignored)return "RecoveryCodeRotationResult.Indeterminate";
  if(value instanceof RecoveryCodeRotationResult.ReconciliationRequired ignored)return "RecoveryCodeRotationResult.ReconciliationRequired";
  if(value instanceof RecoveryCodeUseResult.Succeeded ignored)return "RecoveryCodeUseResult.Succeeded";
  if(value instanceof RecoveryCodeUseResult.Rejected ignored)return "RecoveryCodeUseResult.Rejected";
  if(value instanceof RecoveryCodeUseResult.Throttled ignored)return "RecoveryCodeUseResult.Throttled";
  if(value instanceof RecoveryCodeUseResult.Unavailable ignored)return "RecoveryCodeUseResult.Unavailable";
  if(value instanceof RecoveryCodeUseResult.Indeterminate ignored)return "RecoveryCodeUseResult.Indeterminate";
  if(value instanceof RecoveryCodeUseResult.ReconciliationRequired ignored)return "RecoveryCodeUseResult.ReconciliationRequired";
  if(value instanceof TotpEnrollmentCancellationResult.Succeeded ignored)return "TotpEnrollmentCancellationResult.Succeeded";
  if(value instanceof TotpEnrollmentCancellationResult.Rejected ignored)return "TotpEnrollmentCancellationResult.Rejected";
  if(value instanceof TotpEnrollmentCancellationResult.Unavailable ignored)return "TotpEnrollmentCancellationResult.Unavailable";
  if(value instanceof TotpEnrollmentCancellationResult.Indeterminate ignored)return "TotpEnrollmentCancellationResult.Indeterminate";
  if(value instanceof TotpEnrollmentCancellationResult.ReconciliationRequired ignored)return "TotpEnrollmentCancellationResult.ReconciliationRequired";
  if(value instanceof TotpEnrollmentRequestResult.Prepared ignored)return "TotpEnrollmentRequestResult.Prepared";
  if(value instanceof TotpEnrollmentRequestResult.Rejected ignored)return "TotpEnrollmentRequestResult.Rejected";
  if(value instanceof TotpEnrollmentRequestResult.Throttled ignored)return "TotpEnrollmentRequestResult.Throttled";
  if(value instanceof TotpEnrollmentRequestResult.Unavailable ignored)return "TotpEnrollmentRequestResult.Unavailable";
  if(value instanceof TotpEnrollmentRequestResult.Indeterminate ignored)return "TotpEnrollmentRequestResult.Indeterminate";
  if(value instanceof TotpEnrollmentRequestResult.ReconciliationRequired ignored)return "TotpEnrollmentRequestResult.ReconciliationRequired";
  if(value instanceof TotpEnrollmentResult.Succeeded ignored)return "TotpEnrollmentResult.Succeeded";
  if(value instanceof TotpEnrollmentResult.Rejected ignored)return "TotpEnrollmentResult.Rejected";
  if(value instanceof TotpEnrollmentResult.Throttled ignored)return "TotpEnrollmentResult.Throttled";
  if(value instanceof TotpEnrollmentResult.Unavailable ignored)return "TotpEnrollmentResult.Unavailable";
  if(value instanceof TotpEnrollmentResult.Indeterminate ignored)return "TotpEnrollmentResult.Indeterminate";
  if(value instanceof TotpEnrollmentResult.ReconciliationRequired ignored)return "TotpEnrollmentResult.ReconciliationRequired";
  if(value instanceof TotpFactorRemovalResult.Succeeded ignored)return "TotpFactorRemovalResult.Succeeded";
  if(value instanceof TotpFactorRemovalResult.Rejected ignored)return "TotpFactorRemovalResult.Rejected";
  if(value instanceof TotpFactorRemovalResult.Unavailable ignored)return "TotpFactorRemovalResult.Unavailable";
  if(value instanceof TotpFactorRemovalResult.Indeterminate ignored)return "TotpFactorRemovalResult.Indeterminate";
  if(value instanceof TotpFactorRemovalResult.ReconciliationRequired ignored)return "TotpFactorRemovalResult.ReconciliationRequired";
  if(value instanceof TotpNamespaceInitializationResult.Initialized ignored)return "TotpNamespaceInitializationResult.Initialized";
  if(value instanceof TotpNamespaceInitializationResult.AlreadyInitialized ignored)return "TotpNamespaceInitializationResult.AlreadyInitialized";
  if(value instanceof TotpNamespaceInitializationResult.Unavailable ignored)return "TotpNamespaceInitializationResult.Unavailable";
  if(value instanceof TotpNamespaceInitializationResult.Indeterminate ignored)return "TotpNamespaceInitializationResult.Indeterminate";
  if(value instanceof TotpNamespaceInitializationResult.ReconciliationRequired ignored)return "TotpNamespaceInitializationResult.ReconciliationRequired";
  if(value instanceof TotpStoreResealResult.Resealed ignored)return "TotpStoreResealResult.Resealed";
  if(value instanceof TotpStoreResealResult.AlreadyCurrent ignored)return "TotpStoreResealResult.AlreadyCurrent";
  if(value instanceof TotpStoreResealResult.Absent ignored)return "TotpStoreResealResult.Absent";
  if(value instanceof TotpStoreResealResult.Unavailable ignored)return "TotpStoreResealResult.Unavailable";
  if(value instanceof TotpStoreResealResult.Indeterminate ignored)return "TotpStoreResealResult.Indeterminate";
  if(value instanceof TotpStoreResealResult.ReconciliationRequired ignored)return "TotpStoreResealResult.ReconciliationRequired";
  if(value instanceof TotpVerificationResult.Succeeded ignored)return "TotpVerificationResult.Succeeded";
  if(value instanceof TotpVerificationResult.Rejected ignored)return "TotpVerificationResult.Rejected";
  if(value instanceof TotpVerificationResult.Throttled ignored)return "TotpVerificationResult.Throttled";
  if(value instanceof TotpVerificationResult.Unavailable ignored)return "TotpVerificationResult.Unavailable";
  if(value instanceof TotpVerificationResult.Indeterminate ignored)return "TotpVerificationResult.Indeterminate";
  if(value instanceof TotpVerificationResult.ReconciliationRequired ignored)return "TotpVerificationResult.ReconciliationRequired";
  if(value instanceof WebAuthnAccountDisableResult.Disabled ignored)return "WebAuthnAccountDisableResult.Disabled";
  if(value instanceof WebAuthnAccountDisableResult.Unavailable ignored)return "WebAuthnAccountDisableResult.Unavailable";
  if(value instanceof WebAuthnAccountDisableResult.Indeterminate ignored)return "WebAuthnAccountDisableResult.Indeterminate";
  if(value instanceof WebAuthnAccountDisableResult.ReconciliationRequired ignored)return "WebAuthnAccountDisableResult.ReconciliationRequired";
  if(value instanceof WebAuthnAuthenticationRequestResult.Prepared ignored)return "WebAuthnAuthenticationRequestResult.Prepared";
  if(value instanceof WebAuthnAuthenticationRequestResult.Rejected ignored)return "WebAuthnAuthenticationRequestResult.Rejected";
  if(value instanceof WebAuthnAuthenticationRequestResult.Unavailable ignored)return "WebAuthnAuthenticationRequestResult.Unavailable";
  if(value instanceof WebAuthnAuthenticationRequestResult.Indeterminate ignored)return "WebAuthnAuthenticationRequestResult.Indeterminate";
  if(value instanceof WebAuthnAuthenticationRequestResult.ReconciliationRequired ignored)return "WebAuthnAuthenticationRequestResult.ReconciliationRequired";
  if(value instanceof WebAuthnAuthenticationResult.Succeeded ignored)return "WebAuthnAuthenticationResult.Succeeded";
  if(value instanceof WebAuthnAuthenticationResult.Rejected ignored)return "WebAuthnAuthenticationResult.Rejected";
  if(value instanceof WebAuthnAuthenticationResult.Unavailable ignored)return "WebAuthnAuthenticationResult.Unavailable";
  if(value instanceof WebAuthnAuthenticationResult.Indeterminate ignored)return "WebAuthnAuthenticationResult.Indeterminate";
  if(value instanceof WebAuthnAuthenticationResult.ReconciliationRequired ignored)return "WebAuthnAuthenticationResult.ReconciliationRequired";
  if(value instanceof WebAuthnCredentialRemovalResult.Removed ignored)return "WebAuthnCredentialRemovalResult.Removed";
  if(value instanceof WebAuthnCredentialRemovalResult.Absent ignored)return "WebAuthnCredentialRemovalResult.Absent";
  if(value instanceof WebAuthnCredentialRemovalResult.Unavailable ignored)return "WebAuthnCredentialRemovalResult.Unavailable";
  if(value instanceof WebAuthnCredentialRemovalResult.Indeterminate ignored)return "WebAuthnCredentialRemovalResult.Indeterminate";
  if(value instanceof WebAuthnCredentialRemovalResult.ReconciliationRequired ignored)return "WebAuthnCredentialRemovalResult.ReconciliationRequired";
  if(value instanceof WebAuthnRegistrationRequestResult.Prepared ignored)return "WebAuthnRegistrationRequestResult.Prepared";
  if(value instanceof WebAuthnRegistrationRequestResult.Rejected ignored)return "WebAuthnRegistrationRequestResult.Rejected";
  if(value instanceof WebAuthnRegistrationRequestResult.Unavailable ignored)return "WebAuthnRegistrationRequestResult.Unavailable";
  if(value instanceof WebAuthnRegistrationRequestResult.Indeterminate ignored)return "WebAuthnRegistrationRequestResult.Indeterminate";
  if(value instanceof WebAuthnRegistrationRequestResult.ReconciliationRequired ignored)return "WebAuthnRegistrationRequestResult.ReconciliationRequired";
  if(value instanceof WebAuthnRegistrationResult.Succeeded ignored)return "WebAuthnRegistrationResult.Succeeded";
  if(value instanceof WebAuthnRegistrationResult.Rejected ignored)return "WebAuthnRegistrationResult.Rejected";
  if(value instanceof WebAuthnRegistrationResult.Unavailable ignored)return "WebAuthnRegistrationResult.Unavailable";
  if(value instanceof WebAuthnRegistrationResult.Indeterminate ignored)return "WebAuthnRegistrationResult.Indeterminate";
  if(value instanceof WebAuthnRegistrationResult.ReconciliationRequired ignored)return "WebAuthnRegistrationResult.ReconciliationRequired";
  if(value instanceof WebAuthnReauthenticationResult.Succeeded ignored)return "WebAuthnReauthenticationResult.Succeeded";
  if(value instanceof WebAuthnReauthenticationResult.Rejected ignored)return "WebAuthnReauthenticationResult.Rejected";
  if(value instanceof WebAuthnReauthenticationResult.Unavailable ignored)return "WebAuthnReauthenticationResult.Unavailable";
  if(value instanceof WebAuthnReauthenticationResult.Indeterminate ignored)return "WebAuthnReauthenticationResult.Indeterminate";
  if(value instanceof WebAuthnReauthenticationResult.ReconciliationRequired ignored)return "WebAuthnReauthenticationResult.ReconciliationRequired";
  throw new AssertionError("Unreviewed public result leaf");
 }
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  PublicServiceChecks.require(args.length==2&&args[1].matches("[0-9a-f]{64}"),"Expected exact JAR path and SHA256");
  PublicServiceChecks.run(PublicResultBranches::route,java.nio.file.Path.of(args[0]),args[1]);
  System.out.println("BRANCH_FAMILIES 16");System.out.println("PERMITTED_VARIANTS 84");System.out.println("RUNTIME_RECONCILIATION_ROUTES "+PublicServiceChecks.reconciliationRoutes());System.out.println("CORE_ORIGIN_SHA256 "+args[1]);
 }
}
