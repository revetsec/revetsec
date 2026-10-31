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

import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import org.jspecify.annotations.NonNull;
import java.time.Instant;
import java.util.List;

/** Private package bridge for structural backend carriers, never service/authentication evidence. */
public final class QualificationIssuerCarrier {
    private QualificationIssuerCarrier() { }
    public static @NonNull OAuthStoreTransaction insert(OAuthStoreReadResult.@NonNull Available root,
            OAuthStoreReadResult.@NonNull Available target,@NonNull OAuthStoreKey key,
            @NonNull String version,@NonNull Instant time) {
        StoreTimeObservation.Healthy point=(StoreTimeObservation.Healthy)root.getTimeObservation();
        StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation(point,time,time.plusSeconds(60));
        OAuthStoreEntry entry=OAuthStoreEntry.fromStoredForm(key,version,Instant.ofEpochSecond(Instant.MAX.getEpochSecond()),"structural-fixture");
        return OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,point.getAdmission(),condition,
                List.of(OAuthStoreTransaction.Condition.fromVersion(root.getEntry().orElseThrow().getKey(),root.getEntry().orElseThrow().getVersion()),
                        target.getEntry().map(value->OAuthStoreTransaction.Condition.fromVersion(key,value.getVersion())).orElseGet(()->OAuthStoreTransaction.Condition.fromAbsent(key))),
                List.of(OAuthStoreTransaction.Mutation.fromPut(entry)));
    }
}
