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
package com.revetsec.oidc;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.oauth.OAuthObserver;
import com.revetsec.testing.*;
import java.time.*;
import org.jspecify.annotations.NonNull;

final class OidcCacheCancellationTests extends DiscoveryCacheCancellationChecks {
    @Override protected @NonNull Cache create(@NonNull TestHttpsServer server, @NonNull Clock clock) {
        OidcProviderCache<OidcProviderMetadata> cache = new OidcProviderCache<>(server.getBaseUri(),
                HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                OutboundUriPolicy.defaultInstance(), false, Duration.ofSeconds(5), clock, OAuthObserver.disabledInstance(),
                Duration.ofSeconds(1), Duration.ofMinutes(1), Duration.ofMinutes(10), Duration.ofSeconds(30), value -> value, System::nanoTime);
        return cache::get;
    }
    @Override protected @NonNull String metadataPath() { return "/.well-known/openid-configuration"; }
    @Override protected @NonNull String cacheClassName() { return OidcProviderCache.class.getName(); }
}
