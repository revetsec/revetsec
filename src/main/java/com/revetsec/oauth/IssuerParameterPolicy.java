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

import javax.annotation.concurrent.Immutable;

/**
 * Whether the RFC 9207 callback issuer is required. A present issuer always has to match exactly. Multi-AS
 * deployments with an optional issuer must use distinct trusted callback routes for each AS.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum IssuerParameterPolicy {
	/** Require issuer only when the authenticated begin-time metadata advertised it. */
	METADATA_DRIVEN,
	/** Require issuer on every callback, including manually configured servers. */
	REQUIRED
}
