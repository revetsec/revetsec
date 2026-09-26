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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * The minimum Java runtime for builders that perform network I/O (plan section 9.6, D2).
 * <p>
 * JDK 17.0.0 to 17.0.2, and 18 before 18.0.1, verify ECDSA signatures with the r = s = 0 flaw (CVE-2022-21449).
 * Revetsec checks ECDSA values itself for its own JWS and XML signature verification, but it cannot protect the JDK's
 * TLS and certificate-path checks, so on those runtimes a network attacker could impersonate a provider and serve a
 * forged key set. So {@code build()} of every networked type calls {@link #require(Boolean)}, which throws
 * {@link IllegalStateException} below the floor unless the application acknowledged the risk.
 * <p>
 * The floor is 17.0.3 on feature release 17 and 18.0.1 on 18, compared with
 * {@link Runtime.Version#compareToIgnoreOptional(Runtime.Version)}; 19 and later pass. That comparison fails closed on
 * unusual version strings: a pre-release such as {@code 17-ea} or {@code 17.0.3-ea} sorts below its release, and
 * {@code 17.0.2.0.1} below {@code 17.0.3}. A build number or optional text ({@code 17.0.3+7-LTS}) does not matter. A
 * feature release below 17, which cannot run Revetsec's class files, is below the floor too.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RuntimeFloor {
	/**
	 * The floor on feature release 17: the April 2022 update, which fixed CVE-2022-21449 and CVE-2022-21476.
	 */
	public static final Runtime.Version JAVA_17_FLOOR = Runtime.Version.parse("17.0.3");

	/**
	 * The floor on feature release 18.
	 */
	public static final Runtime.Version JAVA_18_FLOOR = Runtime.Version.parse("18.0.1");

	private RuntimeFloor() {
		// Static helpers only.
	}

	/**
	 * Checks the running JVM ({@link Runtime#version()}); builders call this form.
	 *
	 * @param acknowledged whether the application set {@code acknowledgeUnpatchedRuntime(true)}
	 * @throws NullPointerException  if {@code acknowledged} is {@code null}
	 * @throws IllegalStateException if the runtime is below the floor and {@code acknowledged} is {@code false}
	 */
	public static void require(@NonNull Boolean acknowledged) {
		require(Runtime.version(), acknowledged);
	}

	/**
	 * Checks {@code version}; tests pass explicit versions.
	 *
	 * @param version      the runtime version to check
	 * @param acknowledged whether the application set {@code acknowledgeUnpatchedRuntime(true)}
	 * @throws NullPointerException  if an argument is {@code null}
	 * @throws IllegalStateException if {@code version} is below the floor and {@code acknowledged} is {@code false}
	 */
	public static void require(Runtime.@NonNull Version version,
														 @NonNull Boolean acknowledged) {
		requireNonNull(version);
		requireNonNull(acknowledged);

		if (isBelowFloor(version) && !acknowledged)
			throw new IllegalStateException("This Java runtime (" + version + ") is below Revetsec's minimum for network "
					+ "I/O, 17.0.3 (18.0.1 on Java 18), whose TLS and certificate checks are exposed to CVE-2022-21449. "
					+ "Update the JDK, or set acknowledgeUnpatchedRuntime(true) to accept the risk.");
	}

	/**
	 * Whether {@code version} is below the floor.
	 *
	 * @param version the runtime version to check
	 * @return {@code true} if a networked builder must refuse to build without an acknowledgment
	 * @throws NullPointerException if {@code version} is {@code null}
	 */
	public static boolean isBelowFloor(Runtime.@NonNull Version version) {
		requireNonNull(version);

		int feature = version.feature();

		if (feature < 17)
			return true;

		if (feature == 17)
			return version.compareToIgnoreOptional(JAVA_17_FLOOR) < 0;

		if (feature == 18)
			return version.compareToIgnoreOptional(JAVA_18_FLOOR) < 0;

		return false;
	}
}
