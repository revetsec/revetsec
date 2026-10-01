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

import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.Immutable;

/**
 * Explicit access-token interoperability modes. Future constants require a switch default.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum AccessTokenCompatibilityMode {

	/**
	 * Admits absent or JWT type with explicit extra required claims and no identity-token claims.
	 */
	UNTYPED_ACCESS_TOKENS
}
