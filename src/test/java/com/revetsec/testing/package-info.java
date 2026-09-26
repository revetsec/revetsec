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
 * Shared test infrastructure (M1 plan, "Test helpers"; plan 14.1 as amended by A-2).
 * <p>
 * <strong>Test code only.</strong> Nothing here is compiled into the Revetsec JAR. The helpers are public so tests in
 * every Revetsec package can use them, and their names carry no {@code Tests} suffix, so Surefire never runs them as
 * test classes:
 * <ul>
 *   <li>{@link com.revetsec.testing.TestTls}: SSL contexts and an {@code HttpClient} built from the TEST ONLY PKI in
 *   {@code src/test/resources/tls/};</li>
 *   <li>{@link com.revetsec.testing.TestHttpsServer}: a JDK {@code HttpsServer} with per-path scripts, hit counters
 *   and a request recorder;</li>
 *   <li>{@link com.revetsec.testing.RawTlsServer}: a TLS server that writes exact bytes and reports whether the
 *   client closed each connection;</li>
 *   <li>{@link com.revetsec.testing.TestClock}: a settable, thread-safe {@link java.time.Clock};</li>
 *   <li>{@link com.revetsec.testing.ChildJvm}: runs a main class in a child JVM and captures its output;</li>
 *   <li>{@link com.revetsec.testing.Sentinels}: sentinel secrets and a walker that looks for them in renderings;</li>
 *   <li>{@link com.revetsec.testing.RecordingObserver}: a proxy that records every observer hook call.</li>
 * </ul>
 * Test assertions never sleep. Servers release every wait when they close, and the only timed pacing is
 * {@code RawTlsServer}'s server-side trickle, which runs on the server's own scheduled executor.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.testing;

import org.jspecify.annotations.NullMarked;
