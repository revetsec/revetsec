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

package com.revetsec;

import static java.lang.System.*;

/**
 * Seeded violations: logging outside internal.ObserverDispatch (G6-4). java.util.logging and System.Logger are
 * reported where they are named, and javac-resolved calls catch System.getLogger and LoggerFinder reached through the
 * static import above, a method reference, and calls on loggers whose type the line does not name.
 */
final class LoggingFixture {
	void seeded(java.util.logging.Logger logger, System.Logger systemLogger) {
		java.util.logging.Level level = java.util.logging.Level.FINE;
		logger.fine("A seeded message");
		System.getLogger("com.revetsec");
		getLogger("com.revetsec");
		java.util.function.Function<String, ?> loggers = System::getLogger;
		System.Logger.Level systemLevel = System.Logger.Level.DEBUG;
		systemLogger.isLoggable(systemLevel);
		LoggerFinder.getLoggerFinder();
	}
}
