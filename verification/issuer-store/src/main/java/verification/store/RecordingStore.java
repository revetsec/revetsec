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

package verification.store;

import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.Optional;
import java.util.List;

/** Generic contract adapter captures genuine engine transactions without manufacturing authority. */
final class RecordingStore implements OAuthAuthorizationServerStore {
    private final @NonNull OAuthAuthorizationServerStore backend;
    @Nullable OAuthStoreTransaction last;
    @NonNull List<@NonNull String> before=java.util.List.of();
    RecordingStore(@NonNull OAuthAuthorizationServerStore backend) {this.backend=backend;}
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {return this.backend.read(key,budget);}
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction txn,@NonNull Duration budget) {this.last=txn;this.before=StoreContract.snapshot(this.backend,txn);return this.backend.commit(txn,budget);}
}
