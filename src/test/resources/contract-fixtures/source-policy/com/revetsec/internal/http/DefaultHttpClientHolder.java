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

package com.revetsec.internal.http;

import java.net.http.HttpClient;

/**
 * Control: the one class allowed to create the default HttpClient (D36). Seeded violation: even here, no executor
 * may be created for it.
 */
final class DefaultHttpClientHolder {
	static final HttpClient DEFAULT_HTTP_CLIENT = HttpClient.newBuilder()
			.followRedirects(HttpClient.Redirect.NEVER)
			.executor(java.util.concurrent.Executors.newFixedThreadPool(4))
			.build();

	private DefaultHttpClientHolder() {
	}
}
