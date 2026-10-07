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
import java.util.*;

/** Reusable checks over public engine-created transactions. No restricted constructor/reflection/package access. */
final class StoreContract {
    private StoreContract() { }
    private static void check(boolean valid,@NonNull String name) {if(!valid)throw new AssertionError(name);System.out.println("PASS "+name);}
    static @NonNull List<@NonNull String> snapshot(@NonNull OAuthAuthorizationServerStore store,@NonNull OAuthStoreTransaction txn) {
        List<String> values=new ArrayList<>();
        for(var condition:txn.getConditions()) {
            var entry=store.read(condition.getKey(),Duration.ofSeconds(5));
            values.add(entry.map(e->e.getVersion()+":"+e.getRetainUntil()+":"+e.toSealedForm()).orElse("ABSENT"));
        }
        return values;
    }
    static void run(@NonNull RecordingStore backend,@NonNull IssuerFixture initial,
                    @NonNull Runnable injectPartialWriteFailure,@NonNull Runnable clearFailure) {
        // Genuine initialization transaction: exact ABSENT comparison, stable retained permanent transport.
        check(initial.server.initializeFreshIssuer()==OAuthStoreCommitStatus.COMMITTED,"fresh-absence-commit");
        OAuthStoreTransaction init=Objects.requireNonNull(backend.last);
        List<String> before=snapshot(backend,init);
        check(backend.commit(init,Duration.ofSeconds(5))==OAuthStoreCommitStatus.CONFLICT,"absence-is-not-any-version");
        check(before.equals(snapshot(backend,init)),"conflict-zero-effects");
        var entry=backend.read(init.getConditions().get(0).getKey(),Duration.ofSeconds(5)).orElseThrow();
        check(entry.getRetainUntil().getEpochSecond()==java.time.Instant.MAX.getEpochSecond(),"permanent-retention-exact");
        initial.server.establishNewSubject("subject");
        String code=initial.code();
        // This fixture-specific probe throws after a real SQL write; the full transaction must rollback.
        injectPartialWriteFailure.run();
        try {initial.redeem(code);throw new AssertionError("Expected backend failure");}catch(OAuthServerStoreException e){check(e.getReason()==OAuthServerException.Reason.STORE_UNAVAILABLE,"partial-sql-failure-unavailable");}
        OAuthStoreTransaction issuance=Objects.requireNonNull(backend.last);clearFailure.run();
        check(issuance.getMutations().size()>=4,"multi-key-issuance");
        check(backend.before.equals(snapshot(backend,issuance)),"partial-writes-fully-rolled-back");
        var result=(OAuthTokenResult.Succeeded)initial.redeem(code);
        String token=IssuerFixture.tokenField(result.getResponse(),"access_token");
        check(initial.active(token),"authoritative-status-active");
        OAuthStoreTransaction barrier=Objects.requireNonNull(backend.last);
        check(barrier.getMutations().isEmpty() && barrier.getConditions().size()>=4,"condition-only-complete-read-set");
        check(backend.commit(barrier,Duration.ofSeconds(5))==OAuthStoreCommitStatus.COMMITTED,"condition-only-commit");
        initial.server.revokeAllGrants();
        var revoked=snapshot(backend,barrier);
        check(backend.commit(barrier,Duration.ofSeconds(5))==OAuthStoreCommitStatus.CONFLICT,"stale-condition-only-conflict");
        check(revoked.equals(snapshot(backend,barrier)),"stale-barrier-zero-effects");
        check(!initial.active(token),"epoch-fence-invalidates-status");
        check(initial.server.initializeFreshIssuer()==OAuthStoreCommitStatus.CONFLICT,"never-reinitialize-established-issuer");
        try{backend.read(entry.getKey(),Duration.ZERO);throw new AssertionError("Expected budget failure");}catch(IllegalStateException e){check(true,"zero-budget-fails");}
        try{Thread.currentThread().interrupt();backend.read(entry.getKey(),Duration.ofSeconds(1));throw new AssertionError("Expected interrupt failure");}catch(IllegalStateException e){check(Thread.currentThread().isInterrupted(),"interrupt-preserved");}finally{Thread.interrupted();}
    }
}
