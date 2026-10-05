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

package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;

/** Pure internal settings, pending their approved server-builder registry rows. No public limit is claimed yet. */
final class OAuthServerIngressLimits {
	final int bodyBytes, queryLength, headerBytes, stateLength, clientIdLength;
	final int resources, redirects, scopes, scopeLength;
	OAuthServerIngressLimits(int bodyBytes, int queryLength, int headerBytes, int stateLength, int clientIdLength,
			int resources, int redirects, int scopes, int scopeLength) {
		this.bodyBytes = checked(bodyBytes, 1024, 65536);
		this.queryLength = checked(queryLength, 1024, 65536);
		this.headerBytes = checked(headerBytes, 1024, 65536);
		this.stateLength = checked(stateLength, 128, 4096);
		this.clientIdLength = checked(clientIdLength, 256, 4096);
		this.resources = checked(resources, 1, 1024);
		this.redirects = checked(redirects, 1, 64);
		this.scopes = checked(scopes, 1, 128);
		this.scopeLength = checked(scopeLength, 1, 128);
	}
	static @NonNull OAuthServerIngressLimits fromDefaults() {
		return new OAuthServerIngressLimits(16384, 16384, 16384, 1024, 2048, 64, 32, 32, 128);
	}
	private static int checked(int value, int minimum, int maximum) {
		if (value < minimum || value > maximum) throw new IllegalArgumentException("Invalid issuer ingress limit.");
		return value;
	}
}
