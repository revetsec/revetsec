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

package com.revetsec.jose;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

/**
 * The {@link JoseObserver} whose hooks all do nothing, returned by {@link JoseObserver#disabledInstance()}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class DisabledJoseObserver implements JoseObserver {
	/**
	 * The one instance.
	 */
	@NonNull
	static final DisabledJoseObserver INSTANCE = new DisabledJoseObserver();

	private DisabledJoseObserver() {
		// The shared instance only.
	}

	/**
	 * Names this observer.
	 *
	 * @return {@code JoseObserver.disabledInstance()}
	 */
	@Override
	@NonNull
	public String toString() {
		return "JoseObserver.disabledInstance()";
	}
}
