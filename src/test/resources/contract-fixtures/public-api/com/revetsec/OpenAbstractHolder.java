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

import javax.annotation.concurrent.ThreadSafe;

/**
 * Holds an exported nested abstract class that ContractMetaTests lists in OPEN_ABSTRACT_TYPES only by its canonical
 * name (Outer.Nested), which exempts nothing.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class OpenAbstractHolder {
	private OpenAbstractHolder() {
	}

	/**
	 * Seeded violation: neither sealed nor listed by its binary name.
	 *
	 * @since 1.0.0
	 */
	@ThreadSafe
	public abstract static class NestedOpenFixture {
		/**
		 * For subclasses.
		 *
		 * @since 1.0.0
		 */
		protected NestedOpenFixture() {
		}
	}
}
