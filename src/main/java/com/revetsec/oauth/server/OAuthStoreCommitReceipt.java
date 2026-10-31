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
import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Immutable factual issuer commitment, definitive refusal or uncertainty.
 * Acknowledgement lateness or later admission failure cannot erase a known commitment.
 * This carrier grants no credential, current readiness or permission to retry.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthStoreCommitReceipt {
    private final @NonNull OAuthStoreCommitStatus status;
    private final @Nullable StoreAdmission admission;
    private final @Nullable StoreCommitTiming timing;
    private OAuthStoreCommitReceipt(@NonNull OAuthStoreCommitStatus status,
            @Nullable StoreAdmission admission,@Nullable StoreCommitTiming timing) {
        this.status=requireNonNull(status);this.admission=admission;this.timing=timing;
    }
    /** Records a known committed timed mutation or predicate barrier.
     * @param timing required validation and optional completion timing
     * @return the factual committed receipt
     * @since 1.0.0 */
    public static @NonNull OAuthStoreCommitReceipt fromCommittedTiming(@NonNull StoreCommitTiming timing) {
        requireNonNull(timing);
        return new OAuthStoreCommitReceipt(OAuthStoreCommitStatus.COMMITTED,
                timing.getValidatedTime().getAdmission(),timing);
    }
    /** Records a known committed FENCE_ONLY epoch transition without claiming UTC health.
     * @param admission the current current admitted identities
     * @return the factual fence receipt
     * @since 1.0.0 */
    public static @NonNull OAuthStoreCommitReceipt fromFenceAdmission(@NonNull StoreAdmission admission) {
        return new OAuthStoreCommitReceipt(OAuthStoreCommitStatus.COMMITTED,requireNonNull(admission),null);
    }
    /** Records a definitive refusal with no effects from this callback.
     * @param status a refusal other than COMMITTED or UNKNOWN
     * @return the no-effect receipt
     * @throws IllegalArgumentException if status is COMMITTED or UNKNOWN
     * @since 1.0.0 */
    public static @NonNull OAuthStoreCommitReceipt fromRefusal(@NonNull OAuthStoreCommitStatus status) {
        requireNonNull(status);
        if(status==OAuthStoreCommitStatus.COMMITTED || status==OAuthStoreCommitStatus.UNKNOWN) throw OAuthStoreFormat.invalid();
        return new OAuthStoreCommitReceipt(status,null,null);
    }
    /** Records a genuinely uncertain possible commitment with no claimed timing or admission.
     * @return the unknown receipt
     * @since 1.0.0 */
    public static @NonNull OAuthStoreCommitReceipt unknownInstance() {
        return new OAuthStoreCommitReceipt(OAuthStoreCommitStatus.UNKNOWN,null,null);
    }
    /** Returns the factual outcome.
     * @return the status
     * @since 1.0.0 */
    public @NonNull OAuthStoreCommitStatus getStatus(){return this.status;}
    /** Returns current admission only for a committed receipt.
     * @return optional admission
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull StoreAdmission> getAdmission(){return Optional.ofNullable(this.admission);}
    /** Returns timing for a committed TIMED request; FENCE_ONLY has no timing.
     * @return optional timing
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull StoreCommitTiming> getTiming(){return Optional.ofNullable(this.timing);}
    /** Redacts all identities and timestamps.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString(){return "OAuthStoreCommitReceipt{receipt=<redacted>}";}
}
