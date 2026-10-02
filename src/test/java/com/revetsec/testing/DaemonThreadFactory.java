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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;

/**
 * Names the test servers' threads and makes them daemons, so a server a test forgets to close never keeps the
 * Surefire fork alive.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class DaemonThreadFactory implements ThreadFactory {
	private final String namePrefix;
	private final AtomicInteger nextNumber = new AtomicInteger(1);

	DaemonThreadFactory(@NonNull String namePrefix) {
		this.namePrefix = requireNonNull(namePrefix);
	}

	@Override
	public @NonNull Thread newThread(@NonNull Runnable runnable) {
		Thread thread = new Thread(runnable, this.namePrefix + "-" + this.nextNumber.getAndIncrement());
		thread.setDaemon(true);
		return thread;
	}
}
