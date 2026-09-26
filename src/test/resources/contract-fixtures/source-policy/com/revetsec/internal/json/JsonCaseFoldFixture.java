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

package com.revetsec.internal.json;

import static java.lang.String.CASE_INSENSITIVE_ORDER;

/**
 * Seeded violations in internal.json (G7-7): the comparator constant through a static import (the import line and
 * the use), and equalsIgnoreCase.
 */
final class JsonCaseFoldFixture {
	java.util.Comparator<String> seeded(String name, String other) {
		boolean duplicate = name.equalsIgnoreCase(other);
		return duplicate ? CASE_INSENSITIVE_ORDER : java.util.Comparator.naturalOrder();
	}
}
