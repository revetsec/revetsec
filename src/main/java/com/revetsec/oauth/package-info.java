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
 * OAuth 2.0 client flows and pure bearer presentation, challenge and protected-resource metadata helpers
 * (RFC 6749, RFC 7636, RFC 6750, RFC 9728). Resource-server validators are still being built.
 * <p>
 * It depends only on {@code com.revetsec.jose}, {@code com.revetsec.json} and the root package.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.oauth;

import org.jspecify.annotations.NullMarked;
