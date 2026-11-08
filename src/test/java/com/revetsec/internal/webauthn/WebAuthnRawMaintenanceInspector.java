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

package com.revetsec.internal.webauthn;

import com.revetsec.StateSealer;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Instant;

/** Test-only codec oracle, never packaged in the production artifact. */
public final class WebAuthnRawMaintenanceInspector {
 private WebAuthnRawMaintenanceInspector(){}
 public static @NonNull NamespaceFacts namespaceFacts(@NonNull StateSealer sealer,@NonNull WebAuthnStoreKey key,byte @NonNull [] sealed,@NonNull Clock admittedClock)throws Exception{
  try(var decoded=new WebAuthnRecordCodec(sealer).openAdmittedRecord(key,sealed,admittedClock)){return new NamespaceFacts(decoded.authorityId().orElseThrow(),decoded.floor(),decoded.expiresAt());}
 }
 @Immutable public record NamespaceFacts(@NonNull String authorityId,@NonNull Instant minimum,@NonNull Instant expiresAt){@Override public @NonNull String toString(){return "NamespaceFacts{<redacted>}";}}
}
