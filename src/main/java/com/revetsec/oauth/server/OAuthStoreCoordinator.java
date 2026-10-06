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

import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/**
 * Authoritative caller-thread coordination. No cache, owned threads or backend callback transaction.
 * The backend owns atomicity/durability; a return enum cannot establish those properties by itself.
 */
final class OAuthStoreCoordinator {
	private final @NonNull OAuthAuthorizationServerStore store;
	private final @NonNull OAuthStoreRecordCodec codec;
	private final @NonNull Clock clock;
	private final int maximumAttempts;
	private final int maximumSubjectLength;
	OAuthStoreCoordinator(@NonNull OAuthAuthorizationServerStore store, @NonNull OAuthStoreRecordCodec codec,
			@NonNull Clock clock, int maximumAttempts, int maximumSubjectLength) {
		this.store = requireNonNull(store); this.codec = requireNonNull(codec); this.clock = requireNonNull(clock);
		if (maximumAttempts < 1 || maximumAttempts > 8 || maximumSubjectLength < 16 || maximumSubjectLength > 1024)
			throw OAuthStoreFormat.invalid();
		this.maximumAttempts = maximumAttempts; this.maximumSubjectLength = maximumSubjectLength;
	}
	/** Operator assertion: this namespace has never been used/restored. Absence alone cannot prove that. */
	@NonNull OAuthStoreCommitStatus initializeFreshIssuer(@NonNull Deadline deadline) {
		OAuthStoreKey key = this.codec.issuerKey();
		Optional<OAuthStoreEntry> old = read(key, deadline);
		if (old.isPresent()) { decode(old.orElseThrow(), now()); return OAuthStoreCommitStatus.CONFLICT; }
		OAuthStoreReadSet reads = new OAuthStoreReadSet(); reads.observe(key, old);
		OAuthStoreEntry entry = seal(key, initialIssuer(now()));
		return submit(reads.transaction(List.of(OAuthStoreTransaction.Mutation.fromPut(entry))), deadline);
	}
	/** Explicit initialization outcome for management only, never credential admission. */
	@NonNull OAuthStoreCommitStatus initializeFreshIssuerResult(@NonNull Deadline deadline) {
		try {return initializeFreshIssuer(deadline);}
		catch(OAuthStoreFailure failure) {if(failure.reason()==COMMIT_OUTCOME_UNKNOWN) return OAuthStoreCommitStatus.UNKNOWN;throw failure;}
	}
	/** Established operation: a missing permanent issuer fence is a configuration fault, never initialization. */
	@NonNull Session begin(@NonNull Deadline deadline) { return new Session(deadline); }
	/** Explicit first registration only; established status/revocation must use Session.subject instead. */
	@NonNull OAuthStoreFence establishNewSubject(@NonNull String subject, @NonNull Deadline deadline) {
		OAuthStoreKey key = subjectKey(subject);
		for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
			Session session = begin(deadline); Optional<OAuthStoreEntry> old = session.read(key);
			OAuthStoreFence fence = old.isPresent() ? decode(old.orElseThrow(), session.observedNow)
				: initialSubject();
			List<OAuthStoreTransaction.Mutation> mutations = old.isPresent() ? List.of()
				: List.of(OAuthStoreTransaction.Mutation.fromPut(seal(key, fence)));
			OAuthStoreCommitStatus status = old.isPresent() ? session.barrier() : session.commit(mutations);
			if (status == OAuthStoreCommitStatus.COMMITTED) return fence;
		}
		throw failure(UNAVAILABLE);
	}
	@NonNull OAuthStoreFence revokeSubject(@NonNull String subject, @NonNull Deadline deadline) {
		OAuthStoreKey key = subjectKey(subject);
		for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
			Session session = begin(deadline); OAuthStoreFence current = session.subject(subject);
			OAuthStoreFence next = advance(current, session.observedNow);
			if (session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(seal(key, next))))
				== OAuthStoreCommitStatus.COMMITTED) return next;
		}
		throw failure(UNAVAILABLE);
	}
	@NonNull OAuthStoreFence revokeAll(@NonNull Deadline deadline) {
		for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
			Session session = begin(deadline); OAuthStoreFence next = advance(session.issuer, session.observedNow);
			if (session.commit(List.of(), next) == OAuthStoreCommitStatus.COMMITTED) return next;
		}
		throw failure(UNAVAILABLE);
	}
	/** One CAS maintenance attempt; caller reconciles UNKNOWN rather than retrying it automatically. */
	@NonNull OAuthStoreCommitStatus reseal(@NonNull OAuthStoreKey key, @NonNull Deadline deadline) {
		requireNonNull(key);
		if (!OAuthStoreFormat.namespace(key).equals(OAuthStoreFormat.namespace(this.codec.issuerKey()))) throw OAuthStoreFormat.invalid();
		Instant time = now(); OAuthStoreReadSet reads = new OAuthStoreReadSet();
		Optional<OAuthStoreEntry> issuerEntry = read(this.codec.issuerKey(), deadline);
		OAuthStoreFence issuer = decode(issuerEntry.orElseThrow(() -> failure(CORRUPT_STATE)), time);
		if (time.isBefore(issuer.highWater())) throw failure(UNAVAILABLE);
		reads.observe(this.codec.issuerKey(), issuerEntry);
		Optional<OAuthStoreEntry> entry = key.equals(this.codec.issuerKey()) ? issuerEntry : read(key, deadline);
		if (entry.isEmpty() || !time.isBefore(entry.orElseThrow().getRetainUntil())) return OAuthStoreCommitStatus.CONFLICT;
		reads.observe(key, entry); OAuthStoreEntry old = entry.orElseThrow();
		com.revetsec.json.JsonObject payload = crypto(() -> this.codec.open(old, Clock.fixed(time, java.time.ZoneOffset.UTC)));
		if (key.getKind() == OAuthStoreKey.Kind.ISSUER_STATE || key.getKind() == OAuthStoreKey.Kind.SUBJECT_STATE)
			crypto(() -> OAuthStoreFence.decode(payload, key.getKind()));
  else {
   OAuthServerIngressLimits limits=new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128);
   String name=key.getStorageKey();String id=name.substring(name.lastIndexOf(':')+1);
   OAuthAuthorizationRecord record=crypto(() -> OAuthAuthorizationRecord.decode(key.getKind(),id,payload,limits,this.maximumSubjectLength));
   if(!record.retention().equals(old.getRetainUntil())) throw failure(CORRUPT_STATE);
  }
		OAuthStoreEntry replacement = crypto(() -> this.codec.seal(key, old.getRetainUntil(), payload.toJson()));
		return submit(reads.transaction(List.of(OAuthStoreTransaction.Mutation.fromPut(replacement))), deadline, true);
	}
	private @NonNull OAuthStoreKey subjectKey(@NonNull String subject) {
		OAuthServerConfiguration.text(subject, this.maximumSubjectLength);
		return this.codec.subjectKey(subject);
	}
	private @NonNull OAuthStoreFence initialIssuer(@NonNull Instant now) {
		return crypto(() -> OAuthStoreFence.initialIssuer(this.codec.freshVersion(), now));
	}
	private @NonNull OAuthStoreFence initialSubject() {
		return crypto(() -> OAuthStoreFence.initialSubject(this.codec.freshVersion()));
	}
	private @NonNull OAuthStoreFence advance(@NonNull OAuthStoreFence fence, @NonNull Instant time) {
		return crypto(() -> fence.advance(time));
	}
	private @NonNull OAuthStoreEntry seal(@NonNull OAuthStoreKey key, @NonNull OAuthStoreFence fence) {
		return crypto(() -> this.codec.seal(key, OAuthStoreFormat.PERMANENT, fence.toPayload()));
	}
	private @NonNull OAuthStoreFence decode(@NonNull OAuthStoreEntry entry, @NonNull Instant time) {
		return crypto(() -> OAuthStoreFence.decode(this.codec.open(entry, Clock.fixed(time, ZoneOffset.UTC)), entry.getKey().getKind()));
	}
	private static <T> @NonNull T crypto(@NonNull Supplier<@NonNull T> operation) {
		try { return operation.get(); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable exception) { throw failure(CORRUPT_STATE); }
	}
	private @NonNull Instant now() {
		try { Instant time = this.clock.instant();
			if (time == null || !time.isBefore(OAuthStoreFormat.PERMANENT)) throw failure(UNAVAILABLE);
			return time;
		} catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable exception) { throw callbackFailure(exception); }
	}
	private @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key, @NonNull Deadline deadline) {
		Optional<OAuthStoreEntry> entry;
		try { entry = this.store.read(key, remaining(deadline)); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable exception) { throw callbackFailure(exception); }
		remaining(deadline);
		if (entry == null) throw failure(UNAVAILABLE);
		if (entry.isPresent() && !key.equals(entry.orElseThrow().getKey())) throw failure(CORRUPT_STATE);
		return entry;
	}
	private @NonNull OAuthStoreCommitStatus submit(@NonNull OAuthStoreTransaction transaction, @NonNull Deadline deadline) {
  return submit(transaction, deadline, false);
 }
 private @NonNull OAuthStoreCommitStatus submit(@NonNull OAuthStoreTransaction transaction, @NonNull Deadline deadline, boolean allowUnknown) {
		OAuthStoreCommitStatus status;
		try { status = this.store.commit(transaction, remaining(deadline)); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable exception) { throw callbackFailure(exception); }
		// Uncertainty remains uncertainty even if the callback also exhausted its cooperative budget.
		if (status == OAuthStoreCommitStatus.UNKNOWN) { if (allowUnknown) return status; throw failure(COMMIT_OUTCOME_UNKNOWN); }
		remaining(deadline);
		if (status == null) throw failure(UNAVAILABLE);
		return status;
	}
	private static @NonNull Duration remaining(@NonNull Deadline deadline) {
		requireNonNull(deadline);
		if (Thread.currentThread().isInterrupted()) throw failure(UNAVAILABLE);
		Duration budget = deadline.remaining();
		if (budget.isZero() || budget.isNegative()) throw failure(UNAVAILABLE);
		return budget;
	}
	private static @NonNull OAuthStoreFailure callbackFailure(@NonNull Throwable exception) {
		if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
		return failure(UNAVAILABLE);
	}
	private static @NonNull OAuthStoreFailure failure(OAuthStoreFailure.@NonNull Reason reason) {
		return new OAuthStoreFailure(reason);
	}

	/** One operation attempt, thread-confined; every observation is included and no uncertain attempt is reusable. */
	final class Session {
		private final @NonNull Deadline deadline;
		private final @NonNull OAuthStoreReadSet reads = new OAuthStoreReadSet();
		private final @NonNull Map<@NonNull OAuthStoreKey, @NonNull Optional<@NonNull OAuthStoreEntry>> loaded = new LinkedHashMap<>();
		private final @NonNull OAuthStoreFence issuer;
		private final @NonNull Instant observedNow;
		private boolean finished;
		private @Nullable Instant validBefore;
		private Session(@NonNull Deadline deadline) {
			this.deadline = requireNonNull(deadline); remaining(deadline);
			OAuthStoreEntry entry = read(codec.issuerKey()).orElseThrow(() -> failure(CORRUPT_STATE));
			this.observedNow = now(); this.issuer = decode(entry, this.observedNow);
			if (this.observedNow.isBefore(this.issuer.highWater())) throw failure(UNAVAILABLE);
		}
		/** Cooperative operation validity boundary, checked immediately before/after the backend returns. */
		void requireBefore(@NonNull Instant expires) {
			checkOpen(); requireNonNull(expires);
			Instant previous = this.validBefore;
			if (previous == null || expires.isBefore(previous)) this.validBefore = expires;
			checkedNow();
		}
		@NonNull OAuthStoreFence issuer() { checkOpen(); return this.issuer; }
		@NonNull Instant effectiveNow() { checkOpen(); return this.observedNow; }
		@NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key) {
			checkOpen(); requireNonNull(key); remaining(this.deadline);
			// Reject a foreign namespace before contacting the trusted backend.
			if (!OAuthStoreFormat.namespace(key).equals(OAuthStoreFormat.namespace(codec.issuerKey()))) throw OAuthStoreFormat.invalid();
			Optional<OAuthStoreEntry> previous = this.loaded.get(key);
			if (previous != null) return previous;
			if (this.loaded.size() == 16) throw OAuthStoreFormat.invalid();
			Optional<OAuthStoreEntry> entry = OAuthStoreCoordinator.this.read(key, this.deadline);
			this.reads.observe(key, entry); this.loaded.put(key, entry); return entry;
		}
		@NonNull OAuthStoreFence subject(@NonNull String subject) {
			OAuthStoreEntry entry = read(subjectKey(subject)).orElseThrow(() -> failure(CORRUPT_STATE));
			return decode(entry, this.observedNow);
		}
		/** COMMITTED is the admission point; the caller must bind every relevant ledger row before this call. */
		@NonNull OAuthStoreCommitStatus barrier() { return finish(List.of()); }
		@NonNull OAuthStoreCommitStatus commit(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
			return commit(mutations, this.issuer);
		}
		private @NonNull OAuthStoreCommitStatus commit(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations,
				@NonNull OAuthStoreFence issuerState) {
			checkOpen(); requireNonNull(mutations); requireNonNull(issuerState);
			// One of eight mutation slots belongs to the durable clock/epoch fence.
			if (mutations.size() > 7) throw OAuthStoreFormat.invalid();
			for (OAuthStoreTransaction.Mutation mutation : mutations)
				if (requireNonNull(mutation).getKey().equals(codec.issuerKey())) throw OAuthStoreFormat.invalid();
			Instant time = checkedNow(); List<OAuthStoreTransaction.Mutation> prepared = new ArrayList<>(mutations);
			prepared.add(OAuthStoreTransaction.Mutation.fromPut(seal(codec.issuerKey(), issuerState.atTime(time))));
			return finish(prepared);
		}
		private @NonNull Instant checkedNow() {
			Instant time = now();
			Instant boundary = this.validBefore;
			if (time.isBefore(this.observedNow) || time.isBefore(this.issuer.highWater())
				|| boundary != null && !time.isBefore(boundary)) throw failure(UNAVAILABLE);
			return time;
		}
		private @NonNull OAuthStoreCommitStatus finish(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
			checkOpen(); this.finished = true; checkedNow();
			OAuthStoreTransaction transaction = this.reads.transaction(mutations);
			OAuthStoreCommitStatus status = submit(transaction, this.deadline); checkedNow(); return status;
		}
		private void checkOpen() {
			if (this.finished) throw new IllegalStateException("OAuth store attempt is closed.");
		}
	}
}
