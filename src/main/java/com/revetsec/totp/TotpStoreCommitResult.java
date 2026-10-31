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

/**
 * Payload-free acknowledgement of an atomic TOTP write. Only COMMITTED confirms the transition.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public enum TotpStoreCommitResult {
 /**
  * All predicates matched and all mutations committed.
  * @since 1.0.0
  */ COMMITTED,
 /**
  * A version or absence predicate failed; no mutation occurred.
  * @since 1.0.0
  */ CONFLICT,
 /**
  * Capacity was insufficient; no record was evicted and no mutation occurred.
  * @since 1.0.0
  */ CAPACITY_REFUSED,
 /**
  * The active authority, recovery/clock generation or address epoch was fenced; no mutation occurred.
  * @since 1.0.0
  */ FENCED,
 /**
  * Current data admission exists but healthy admitted time was unavailable at validation; no effect.
  * @since 1.0.0
  */ TIME_UNAVAILABLE,
 /**
  * Fresh admitted validation time was below the inclusive condition floor; no effect.
  * @since 1.0.0
  */ TIME_BEFORE_FLOOR,
 /**
  * Fresh admitted validation time reached the original exclusive expiry; no effect.
  * @since 1.0.0
  */ TIME_EXPIRED,
 /**
  * The backend failed before any possible mutation.
  * @since 1.0.0
  */ UNAVAILABLE,
 /**
  * A write may have committed; never retry automatically.
  * @since 1.0.0
  */ UNKNOWN
}
