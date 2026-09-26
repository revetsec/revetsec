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

package com.revetsec.oauth;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;

/**
 * Control: an observer that extends another, as OAuthObserver extends JoseObserver. It inherits the parent's hooks,
 * which are checked on the parent, and declares its own disabledInstance(), since static interface methods are not
 * inherited.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface ExtendedObserver extends CompliantObserver {
	/**
	 * The observer whose hooks do nothing.
	 *
	 * @return the disabled observer
	 * @since 1.0.0
	 */
	static @NonNull ExtendedObserver disabledInstance() {
		return DisabledExtendedObserver.INSTANCE;
	}

	/**
	 * Called after a refresh.
	 *
	 * @param uri the URI
	 * @since 1.0.0
	 */
	default void didRefresh(@Nullable URI uri) {
	}
}

/**
 * The package-private disabled observer.
 */
final class DisabledExtendedObserver implements ExtendedObserver {
	static final DisabledExtendedObserver INSTANCE = new DisabledExtendedObserver();

	private DisabledExtendedObserver() {
	}
}
