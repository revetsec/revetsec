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

/**
 * Time-based one-time passwords and single-use recovery codes with application-owned
 * authoritative storage and recovery admission. Successful verification and recovery-code
 * consumption are distinct method proofs; the application owns account authorization,
 * login completion, session policy and a recovery epoch outside restored storage.
 * Provisioning URIs, manual-entry keys and newly issued recovery codes contain secrets.
 *
 * @since 1.0.0
 */
@NullMarked
package com.revetsec.totp;

import org.jspecify.annotations.NullMarked;
