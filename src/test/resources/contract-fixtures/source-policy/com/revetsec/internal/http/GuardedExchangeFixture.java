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

import javax.annotation.concurrent.GuardedBy;

/**
 * Control: provided-annotation-with-element covers the exported packages themselves, not their subpackages, so
 * GuardedBy in internal.http (as on HttpExchange's lock-guarded state) is not reported.
 */
final class GuardedExchangeFixture {
	private final java.util.concurrent.locks.ReentrantLock lock = new java.util.concurrent.locks.ReentrantLock();
	@GuardedBy("lock")
	private boolean done;

	boolean isDone() {
		this.lock.lock();
		try {
			return this.done;
		} finally {
			this.lock.unlock();
		}
	}
}
