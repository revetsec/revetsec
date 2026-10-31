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

package com.revetsec.oauth.server;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Outcome of an atomic, durable issuer store commit. An uncertain outcome never implies rollback or safe retry.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 *
 * @since 1.0.0
 */
@Immutable
public enum OAuthStoreCommitStatus {
 /** All predicates and mutations linearized durably together.
  * @since 1.0.0 */
 COMMITTED,
 /** An exact predicate failed with no effect.
  * @since 1.0.0 */
 CONFLICT,
 /** Assigned backend capacity refused the whole mutation with no eviction.
  * @since 1.0.0 */
 CAPACITY,
 /** The active authority/recovery/clock tuple does not match.
  * @since 1.0.0 */
 FENCED,
 /** No healthy admitted time was available at final validation.
  * @since 1.0.0 */
 TIME_UNAVAILABLE,
 /** Fresh validation time precedes the required inclusive floor.
  * @since 1.0.0 */
 TIME_BEFORE_FLOOR,
 /** Fresh validation time reached the original exclusive upper bound.
  * @since 1.0.0 */
 TIME_EXPIRED,
 /** Definitive unavailability with no effect from this callback.
  * @since 1.0.0 */
 UNAVAILABLE,
 /** The outcome is uncertain; reconcile before repeating a non-idempotent operation.
  * @since 1.0.0 */
 UNKNOWN
}
