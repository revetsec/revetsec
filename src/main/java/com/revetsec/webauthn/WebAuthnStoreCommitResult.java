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

package com.revetsec.webauthn;

/** Outcome of one atomic WebAuthn store write. Only COMMITTED permits a protocol proof. @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public enum WebAuthnStoreCommitResult {
 /** All predicates matched and all changes committed to the selected store. Durability across
  * restarts requires a durable implementation. @since 1.0.0 */
 COMMITTED,
 /** A predicate failed; no mutation took effect. @since 1.0.0 */
 CONFLICT,
 /** Capacity was insufficient; no mutation took effect. @since 1.0.0 */
 CAPACITY,
 /** The store failed before attempting a write; no mutation took effect. @since 1.0.0 */
 UNAVAILABLE,
 /** The write may have taken effect; reconciliation is required. @since 1.0.0 */
 UNKNOWN
}
