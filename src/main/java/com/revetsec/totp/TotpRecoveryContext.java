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

package com.revetsec.totp;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * The exact immutable scope and sealing configuration requesting recovery admission.
 * Core constructs this context from its actual operation configuration.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public final class TotpRecoveryContext {
 private final @NonNull String credentialNamespace;
 private final @NonNull String recoveryEpoch;
 private final @NonNull String activeSealingKeyId;
 private final @NonNull Set<@NonNull String> openingSealingKeyIds;
 private final TotpRecoveryContext.@NonNull Purpose purpose;
 private TotpRecoveryContext(@NonNull String namespace, @NonNull String epoch,
   @NonNull String activeKeyId, @NonNull Set<@NonNull String> openingKeyIds,
   TotpRecoveryContext.@NonNull Purpose purpose) {
  TotpStoreKey.validateScope(namespace); TotpStoreKey.validateScope(epoch);
  this.credentialNamespace = namespace; this.recoveryEpoch = epoch;
  this.activeSealingKeyId = Objects.requireNonNull(activeKeyId);
  this.openingSealingKeyIds = Set.copyOf(openingKeyIds);
  if (activeKeyId.isEmpty() || !this.openingSealingKeyIds.contains(activeKeyId)
    || this.openingSealingKeyIds.size() > 17)
   throw new IllegalArgumentException("Invalid TOTP sealing configuration");
  this.purpose = Objects.requireNonNull(purpose);
 }
 static @NonNull TotpRecoveryContext fromConfiguration(@NonNull String credentialNamespace,
   @NonNull String recoveryEpoch, @NonNull String activeSealingKeyId,
   @NonNull Set<@NonNull String> openingSealingKeyIds, TotpRecoveryContext.@NonNull Purpose purpose) {
  return new TotpRecoveryContext(credentialNamespace, recoveryEpoch, activeSealingKeyId,
    openingSealingKeyIds, purpose);
 }
 /**
  * Returns the configured credential namespace.
  * @return the namespace
  * @since 1.0.0
  */
 public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }
 /**
  * Returns the externally controlled recovery epoch.
  * @return the epoch
  * @since 1.0.0
  */
 public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }
 /**
  * Returns the key ID actually used for new records.
  * @return the active sealing key ID
  * @since 1.0.0
  */
 public @NonNull String getActiveSealingKeyId() { return this.activeSealingKeyId; }
 /**
  * Returns the immutable active and retained opening key IDs.
  * @return every configured opening key ID, including the active key
  * @since 1.0.0
  */
 public @NonNull Set<@NonNull String> getOpeningSealingKeyIds() { return this.openingSealingKeyIds; }
 /**
  * Returns the requested admission purpose.
  * @return initialization or ordinary operation
  * @since 1.0.0
  */
 public TotpRecoveryContext.@NonNull Purpose getPurpose() { return this.purpose; }
 /**
  * Redacts the scope and key configuration.
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "TotpRecoveryContext{configuration=<redacted>}"; }
 /**
  * The explicitly authorized recovery admission purpose.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 public enum Purpose {
  /**
   * Provision only a fresh externally authorized epoch.
   * @since 1.0.0
   */ INITIALIZE_NAMESPACE,
  /**
   * Authenticate or manage an initialized epoch.
   * @since 1.0.0
   */ OPERATION
 }
}
