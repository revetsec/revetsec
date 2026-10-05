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
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

/** Atomic single-process test double. No persistence, failover or durable-backend claim. */
final class OAuthAtomicStoreFixture implements OAuthAuthorizationServerStore {
	final @NonNull Map<@NonNull OAuthStoreKey, @NonNull OAuthStoreEntry> rows = new LinkedHashMap<>();
	final @NonNull List<@NonNull Duration> budgets = new ArrayList<>();
	@Nullable Runnable beforeRead;
	@Nullable Runnable beforeCommit;
	@Nullable Runnable afterCommit;
	@Nullable Throwable fault;
	boolean nullRead;
	boolean nullCommit;
	boolean unknownBefore;
	boolean unknownAfter;
	int conflicts;
	int reads;
	int commits;
	@Nullable OAuthStoreEntry substitute;
	@Nullable OAuthStoreTransaction lastTransaction;
	OAuthAtomicStoreFixture() { }
	@Override @NonNull @SuppressWarnings("NullAway") // Deliberate invalid SPI return exercises caller checks.
	public Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key, @NonNull Duration budget) {
		this.reads++; this.budgets.add(budget);
		Runnable hook = this.beforeRead; this.beforeRead = null; if (hook != null) hook.run();
		if (this.fault != null) raise(this.fault);
		if (this.nullRead) return null;
		synchronized (this.rows) { return Optional.ofNullable(this.substitute == null ? this.rows.get(key) : this.substitute); }
	}
	@Override @NonNull @SuppressWarnings("NullAway") // Deliberate invalid SPI return exercises caller checks.
	public OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
		this.commits++; this.budgets.add(budget); this.lastTransaction = transaction;
		Runnable hook = this.beforeCommit; this.beforeCommit = null; if (hook != null) hook.run();
		if (this.fault != null) raise(this.fault);
		if (this.nullCommit) return null;
		if (this.unknownBefore) return OAuthStoreCommitStatus.UNKNOWN;
		if (this.conflicts > 0) { this.conflicts--; return OAuthStoreCommitStatus.CONFLICT; }
		synchronized (this.rows) {
			for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
				OAuthStoreEntry current = this.rows.get(condition.getKey());
				if (!condition.getExpectedVersion().equals(current == null ? Optional.empty() : Optional.of(current.getVersion())))
					return OAuthStoreCommitStatus.CONFLICT;
			}
			for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
				if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE) this.rows.remove(mutation.getKey());
				else this.rows.put(mutation.getKey(), mutation.getEntry().orElseThrow());
			}
		}
		hook = this.afterCommit; this.afterCommit = null; if (hook != null) hook.run();
		return this.unknownAfter ? OAuthStoreCommitStatus.UNKNOWN : OAuthStoreCommitStatus.COMMITTED;
	}
	@SuppressWarnings("unchecked")
	private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T { throw (T) failure; }
}
