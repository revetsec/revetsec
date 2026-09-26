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

package com.revetsec.internal;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Control: the one class allowed to log (G6-4), through java.util.logging or System.Logger; its static final logger
 * is not mutable static state either. Seeded violation: even here, nothing is written to the console.
 */
final class ObserverDispatch {
	private static final Logger LOGGER = Logger.getLogger("com.revetsec");

	void contained(Throwable failure) {
		if (LOGGER.isLoggable(Level.FINE))
			LOGGER.log(Level.FINE, "An observer hook failed", failure);
		System.getLogger("com.revetsec").log(System.Logger.Level.DEBUG, "An observer hook failed");
		System.err.println("An observer hook failed");
	}
}
