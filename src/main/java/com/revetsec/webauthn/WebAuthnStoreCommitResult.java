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

/** Outcome of one atomic WebAuthn store write. Values describe facts inside a contextual receipt, not proof release eligibility.
 * @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public enum WebAuthnStoreCommitResult {
 /** All predicates matched and all changes committed to the selected store. Durability across
  * restarts requires a durable implementation. @since 1.0.0 */
 COMMITTED,
 /** A predicate failed; no mutation took effect. @since 1.0.0 */
 CONFLICT,
 /** Capacity was insufficient; no mutation took effect. @since 1.0.0 */
 CAPACITY,
 /** The active authority, recovery or clock generation differs; no mutation took effect. @since 1.0.0 */
 FENCED,
 /** No healthy admitted time was available; no mutation took effect. @since 1.0.0 */
 TIME_UNAVAILABLE,
 /** Fresh validation time precedes the inclusive floor; no mutation took effect. @since 1.0.0 */
 TIME_BEFORE_FLOOR,
 /** Fresh validation time reached the exclusive expiry; no mutation took effect. @since 1.0.0 */
 TIME_EXPIRED,
 /** The store refused with known no effect, including a confirmed abort. @since 1.0.0 */
 UNAVAILABLE,
 /** The write may have taken effect; reconciliation is required. @since 1.0.0 */
 UNKNOWN
}
