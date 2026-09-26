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

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Seeded violation: an exported exception that inherits a public static method from a package-private base class.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public final class LeafFixtureException extends BaseFixtureException {
	private static final long serialVersionUID = 1L;

	private LeafFixtureException() {
		super("Leaf.");
	}
}
