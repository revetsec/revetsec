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
/** Java21 switch consumer dispatch, with one typed overload per family. */
final class PublicSwitchRouter {
 private PublicSwitchRouter(){}
 static @NonNull String route(@NonNull Object value){
  if(value instanceof RecoveryCodeRotationResult result)return PublicResultSwitches.route(result);
  if(value instanceof RecoveryCodeUseResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpEnrollmentCancellationResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpEnrollmentRequestResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpEnrollmentResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpFactorRemovalResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpNamespaceInitializationResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpStoreResealResult result)return PublicResultSwitches.route(result);
  if(value instanceof TotpVerificationResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnAccountDisableResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnAuthenticationRequestResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnAuthenticationResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnCredentialRemovalResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnRegistrationRequestResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnRegistrationResult result)return PublicResultSwitches.route(result);
  if(value instanceof WebAuthnReauthenticationResult result)return PublicResultSwitches.route(result);
  throw new AssertionError("Unreviewed public family");
 }
}
