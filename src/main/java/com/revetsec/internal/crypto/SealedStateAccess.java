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

package com.revetsec.internal.crypto;

import com.revetsec.StateSealer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.lang.invoke.MethodHandles;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * The protocol packages' way to seal and open state under the internal type labels, which the public
 * {@link StateSealer} API does not offer (M1 plan G6-10; the JDK's {@code SharedSecrets} pattern).
 * <p>
 * {@code StateSealer}'s static initializer installs its {@link Operations} here with {@link #set(Operations)},
 * once; a second call throws {@link IllegalStateException}, and operations that {@code StateSealer} did not define
 * (whose class is not one of its nestmates) are refused with {@link IllegalArgumentException}. {@link #get()} first
 * forces {@code StateSealer}'s class initialization with {@link MethodHandles.Lookup#ensureInitialized(Class)}, so a
 * caller that arrives before any {@code StateSealer} has been built still finds the operations installed.
 * <p>
 * The one mutable static field is {@code volatile} and written at most once, under a lock. It is the reviewed
 * exception to the {@code mutable-static} source rule (R4, G6-10).
 * <p>
 * This keeps the labels out of the public, japicmp-frozen API. An application can still reach this internal class,
 * which is acceptable: it already holds the sealing keys.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class SealedStateAccess {
	/**
	 * Guards the one write to {@link #operations}, so two concurrent calls to {@link #set(Operations)} cannot both
	 * succeed.
	 */
	@NonNull
	private static final ReentrantLock SET_LOCK = new ReentrantLock();

	/**
	 * The installed operations: {@code null} until {@code StateSealer}'s static initializer calls
	 * {@link #set(Operations)}, and never changed after that.
	 */
	@Nullable
	private static volatile Operations operations;

	/**
	 * Sealing and opening under any {@link SealedStateType}, with the caller's notion of time.
	 * <p>
	 * Arguments are checked first, as in the public {@code StateSealer} API: a {@code null} throws
	 * {@link NullPointerException}, and an invalid argument throws {@link IllegalArgumentException}, never
	 * {@link UnsealException}.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@ThreadSafe
	public interface Operations {
		/**
		 * Seals {@code plaintext} under {@code type} with the sealer's active key.
		 * <p>
		 * The value stops opening at {@code expiresAt} rounded up to a whole second: its notAfter is the first epoch
		 * second at or after {@code expiresAt}. The caller bounds the lifetime; this method does not compare
		 * {@code expiresAt} with any clock.
		 *
		 * @param sealer    the sealer whose active key seals
		 * @param type      the type label to bind
		 * @param plaintext the plaintext, well-formed UTF-16
		 * @param context   the context to bind, 1 to 256 characters of well-formed UTF-16
		 * @param expiresAt when the sealed record expires
		 * @return the sealed value
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if the plaintext or context is not valid, or the sealed value would be longer
		 *                                  than the sealer's maximum sealed length
		 * @throws IllegalStateException    if the JCA provider refuses to seal or cannot supply random bytes
		 */
		@NonNull
		String seal(@NonNull StateSealer sealer,
								@NonNull SealedStateType type,
								@NonNull String plaintext,
								@NonNull String context,
								@NonNull Instant expiresAt);

		/**
		 * Opens {@code sealed}, which must have been sealed under {@code type} for {@code context} with one of the
		 * sealer's keys, and must not have expired by {@code clock}'s current time.
		 *
		 * @param sealer  the sealer whose keys may open it
		 * @param type    the type label the value must have been sealed under
		 * @param sealed  the sealed value, untrusted
		 * @param context the context, 1 to 256 characters of well-formed UTF-16
		 * @param clock   the caller's clock, which supplies the current time
		 * @return the plaintext
		 * @throws NullPointerException     if an argument is {@code null}
		 * @throws IllegalArgumentException if the context is not valid
		 * @throws UnsealException          with {@link UnsealException.Kind#EXPIRED} if the value is authentic but has
		 *                                  expired, and with {@link UnsealException.Kind#INVALID} for every other
		 *                                  failure
		 */
		@NonNull
		String unseal(@NonNull StateSealer sealer,
									@NonNull SealedStateType type,
									@NonNull String sealed,
									@NonNull String context,
									@NonNull Clock clock) throws UnsealException;
	}

	private SealedStateAccess() {
		// Static accessor only.
	}

	/**
	 * Installs the operations. Only {@code StateSealer}'s static initializer calls this.
	 *
	 * @param operations the operations to install, defined by {@code StateSealer}
	 * @throws NullPointerException     if {@code operations} is {@code null}
	 * @throws IllegalArgumentException if {@code operations}' class is not a nestmate of {@code StateSealer}
	 * @throws IllegalStateException    if operations are already installed
	 */
	public static void set(@NonNull Operations operations) {
		requireNonNull(operations);

		if (operations.getClass().getNestHost() != StateSealer.class)
			throw new IllegalArgumentException("Only StateSealer installs the sealed-state operations.");

		SET_LOCK.lock();

		try {
			if (SealedStateAccess.operations != null)
				throw new IllegalStateException("The sealed-state operations are already installed.");

			SealedStateAccess.operations = operations;
		} finally {
			SET_LOCK.unlock();
		}
	}

	/**
	 * Returns the installed operations, initializing {@code StateSealer} first if nothing has yet.
	 *
	 * @return the installed operations
	 * @throws IllegalStateException if no operations are installed even after {@code StateSealer}'s initialization,
	 *                               which happens only while that initialization is still running on this thread
	 */
	@NonNull
	public static Operations get() {
		try {
			MethodHandles.lookup().ensureInitialized(StateSealer.class);
		} catch (IllegalAccessException e) {
			// Unreachable: StateSealer is a public class in an exported package.
			throw new IllegalStateException("StateSealer cannot be initialized.", e);
		}

		Operations installed = operations;

		if (installed == null)
			throw new IllegalStateException("The sealed-state operations are not installed.");

		return installed;
	}

	/**
	 * Returns whether operations are installed, without initializing anything, so a test in a fresh JVM can show
	 * that {@link #get()} is what installs them.
	 */
	static boolean isInstalled() {
		return operations != null;
	}
}
