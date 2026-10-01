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

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
final class BearerErrorTests {
	@Test void wireErrorsAndRecommendedStatusCodesRemainDistinct() {
		assertEquals(400, BearerError.INVALID_REQUEST.getStatusCode());
		assertEquals("invalid_request", BearerError.INVALID_REQUEST.getWireValue());
		assertEquals(401, BearerError.INVALID_TOKEN.getStatusCode());
		assertEquals("invalid_token", BearerError.INVALID_TOKEN.getWireValue());
		assertEquals(403, BearerError.INSUFFICIENT_SCOPE.getStatusCode());
		assertEquals("insufficient_scope", BearerError.INSUFFICIENT_SCOPE.getWireValue());
	}
}
