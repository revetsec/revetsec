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

package com.revetsec.internal.jose;

import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwsAlgorithm;
import java.util.Set;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.jose.JwtValidator;
import java.util.function.LongSupplier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.locks.ReentrantLock;
import static java.util.Objects.requireNonNull;

/** Set-once access to the existing JWT validator with a protocol transaction's shared HTTP deadline. */
@ThreadSafe
public final class JwtValidationAccess {
	private static final ReentrantLock SET_LOCK = new ReentrantLock();
	private static volatile @Nullable Operations operations;
	private JwtValidationAccess() { }
	@ThreadSafe
	public interface Operations {
		@NonNull Jwt validate(@NonNull JwtValidator validator, @NonNull String compact, @NonNull LongSupplier remainingNanos);
		@NonNull Jwt validatePrepared(@NonNull JwtValidator validator, @NonNull PreparedJws prepared, @NonNull LongSupplier remainingNanos);
		@NonNull Jwt validateIssuerRevocation(@NonNull JwtValidator validator, @NonNull String compact, @NonNull LongSupplier remainingNanos);
		@NonNull Jwt validateUserInfo(@NonNull JwtValidator validator, @NonNull String compact, @NonNull LongSupplier remainingNanos);
		@NonNull Jwt validateOidc(@NonNull JwtValidator validator, @NonNull String compact, @NonNull Set<@NonNull JwsAlgorithm> algorithms,
				byte @NonNull [] secret, @NonNull LongSupplier remainingNanos, @NonNull Runnable hmacUsed);
		@NonNull Jwt validateMicrosoftEntra(@NonNull JwtValidator validator, @NonNull String compact, @NonNull LongSupplier remainingNanos);
		@NonNull Jwt validateMicrosoftEntraUserInfo(@NonNull JwtValidator validator, @NonNull String compact,
				@NonNull String verifiedTenantIssuer, @NonNull LongSupplier remainingNanos);
		void warmUp(@NonNull RemoteJsonWebKeySource source, @NonNull LongSupplier remainingNanos);
	}
	public static void set(@NonNull Operations value) {
		requireNonNull(value);
		if (value.getClass().getNestHost() != JwtValidator.class)
			throw new IllegalArgumentException("Only JwtValidator installs the deadline operations.");
		SET_LOCK.lock();
		try {
			if (operations != null) throw new IllegalStateException("The JWT deadline operations are installed.");
			operations = value;
		} finally { SET_LOCK.unlock(); }
	}
	public static @NonNull Operations get() {
		try { MethodHandles.lookup().ensureInitialized(JwtValidator.class); }
		catch (IllegalAccessException impossible) { throw new IllegalStateException("JwtValidator cannot be initialized."); }
		Operations installed = operations;
		if (installed == null) throw new IllegalStateException("The JWT deadline operations are not installed.");
		return installed;
	}
}
