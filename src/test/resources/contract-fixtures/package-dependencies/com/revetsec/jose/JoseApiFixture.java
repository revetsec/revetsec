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

import com.revetsec.internal.jose.InternalDocumentedFixture;
import com.revetsec.internal.jose.InternalRuntimeFixture;
import com.revetsec.internal.jose.InternalSourceFixture;

/**
 * Seeded violations: an internal supertype reached through a package-private class, an inherited member that
 * returns an internal type, and published internal annotations on the type, a method and a parameter. The
 * source-retained annotation is a control.
 */
@InternalDocumentedFixture
public final class JoseApiFixture extends JoseBaseFixture {
	private JoseApiFixture() {
	}

	@InternalRuntimeFixture
	public void marked(@InternalDocumentedFixture String value) {
	}

	@InternalSourceFixture
	public void control() {
	}
}
