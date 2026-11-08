/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package com.revetsec.oauth.server;

import com.revetsec.StoreTemporalCondition;
import org.jspecify.annotations.NonNull;
import java.time.Instant;
import java.util.List;

/** Private structural temporal SPI fixture, never an authenticated engine transaction. */
public final class TemporalIssuerCarrier {
    private TemporalIssuerCarrier() { }
    public static @NonNull OAuthStoreTransaction insert(OAuthStoreReadResult.@NonNull Available read,
            @NonNull OAuthStoreKey key,@NonNull String version,@NonNull String form,
            @NonNull Instant retain,@NonNull StoreTemporalCondition condition){
        OAuthStoreTransaction.Condition expected=read.getEntry().map(value->OAuthStoreTransaction.Condition.fromVersion(key,value.getVersion())).orElseGet(()->OAuthStoreTransaction.Condition.fromAbsent(key));
        return OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,condition.getAdmission(),condition,
                List.of(expected),List.of(OAuthStoreTransaction.Mutation.fromPut(OAuthStoreEntry.fromStoredForm(key,version,retain,form))));
    }
}
