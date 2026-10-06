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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.net.InetAddress;
import java.time.Duration;
import java.util.List;

/**
 * Trusted bounded address resolution for opt-in client metadata retrieval.
 * Implementations return every numeric answer for the checked original hostname and honor the
 * shrinking remaining budget on the calling thread. They must be safe for concurrent callers.
 * Revetsec checks all answers and pins an approved numeric peer; this callback does not fetch
 * metadata or authorize clients. No implicit system resolver or owned executor is supplied.
 * Construction of a metadata policy never invokes this callback.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface OAuthClientMetadataAddressResolver {
 /**
  * Resolves every address under the supplied remaining budget, without reverse lookup.
  * @param hostname the checked original hostname
  * @param remainingBudget the positive remaining operation budget
  * @return all numeric answers; an empty list cannot establish a destination
  * @since 1.0.0
  */
 @NonNull List<@NonNull InetAddress> resolve(@NonNull String hostname, @NonNull Duration remainingBudget);
}
