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
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;
import com.revetsec.internal.ObserverDispatch;
import java.time.Duration;

/** One caller-thread operation event pair. Never use while holding a lock or store transaction. */
final class OAuthServerObservation {
	private final @NonNull OAuthServerObserver observer;
	private final OAuthServerObserver.@NonNull Endpoint endpoint;
	private final long started;
	private boolean finished;
	OAuthServerObservation(@NonNull OAuthServerObserver observer, OAuthServerObserver.@NonNull Endpoint endpoint) {
		this.observer=requireNonNull(observer); this.endpoint=requireNonNull(endpoint); this.started=System.nanoTime();
		ObserverDispatch.dispatch(observer,o->o.willHandleEndpoint(endpoint));
	}
	void succeeded(@Nullable Integer status) {
		finish(status); Duration elapsed=elapsed(); ObserverDispatch.dispatch(this.observer,o->o.didHandleEndpoint(this.endpoint,status,elapsed));
	}
	void rejected(OAuthServerException.@NonNull Reason reason, @Nullable Integer status) {
		requireNonNull(reason).requireKind(OAuthServerException.Kind.VALIDATION); finish(status); Duration elapsed=elapsed();
		ObserverDispatch.dispatch(this.observer,o->o.didRejectEndpoint(this.endpoint,reason,status,elapsed));
	}
	void failed(@NonNull OAuthServerException failure) {
		requireNonNull(failure); finishOnce(); Duration elapsed=elapsed();
		ObserverDispatch.dispatch(this.observer,o->o.didFailToHandleEndpoint(this.endpoint,failure,elapsed));
	}
	private void finish(@Nullable Integer status) {
		boolean http=switch(this.endpoint) {
			case ACCESS_TOKEN_VALIDATION,GRANT_REVOCATION,SUBJECT_REVOCATION,ISSUER_REVOCATION,STORE_RESEAL -> false;
			default -> true;
		};
		if (http ? status==null || status<100 || status>599 : status!=null) throw OAuthStoreFormat.invalid();
		finishOnce();
	}
	private void finishOnce() { if(this.finished) throw new IllegalStateException("The issuer observation has already completed."); this.finished=true; }
	private @NonNull Duration elapsed() { return Duration.ofNanos(Math.max(0,System.nanoTime()-this.started)); }
}
