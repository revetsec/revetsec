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
 * Bounded SCIM 2.0 server primitives: registered schemas, immutable resources, schema-bound
 * filters and explicit policies, result-based request parsing, query/page descriptions and prepared responses.
 * <p>
 * Syntax success does not authorize a query. Applications authenticate and authorize callers,
 * execute approved queries and persist candidates atomically. Ordered atomic PATCH and conservative
 * membership reduction are supported; the optional collection evaluator follows separately.
 * <p>
 * It depends only on {@code com.revetsec.json} and the root package.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.scim;

import org.jspecify.annotations.NullMarked;
