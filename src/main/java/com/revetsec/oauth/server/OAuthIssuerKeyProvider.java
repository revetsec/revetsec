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
import java.time.Duration;
import javax.annotation.concurrent.ThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * Trusted application-owned durable key lifecycle and distribution callback. Implementations must be thread-safe,
 * return promptly on the calling thread, cooperate with interruption and the remaining original operation budget,
 * and preserve published-key retention through all issued token expiries and configured margins across nodes and
 * restarts. Returning a snapshot declares that its generation was actually published at its publication instant.
 * Construction does not call the provider. Ordinary key rotation does not invalidate grants; compromise or store
 * restoration requires an explicit issuer revocation fence before reopening traffic.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface OAuthIssuerKeyProvider {
 /**
  * Returns the current immutable declaration, preserving in-flight signing and public verification overlap.
  * @param remainingBudget positive time left in the original operation
  * @return one immutable snapshot
  * @since 1.0.0
  */
 @NonNull OAuthIssuerKeySnapshot getSnapshot(@NonNull Duration remainingBudget);
 /**
  * Supplies one fixed immutable declaration without I/O.
  * @param snapshot required snapshot
  * @return a thread-safe fixed provider
  * @throws NullPointerException if snapshot is null
  * @since 1.0.0
  */
 @CheckReturnValue
 static @NonNull OAuthIssuerKeyProvider fromSnapshot(@NonNull OAuthIssuerKeySnapshot snapshot) {
  requireNonNull(snapshot);return budget -> { requireNonNull(budget);return snapshot; };
 }
}
