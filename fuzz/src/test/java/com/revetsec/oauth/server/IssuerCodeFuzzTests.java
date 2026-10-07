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

import com.code_intelligence.jazzer.junit.FuzzTest;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** Public issuer state transitions; no construction of restricted proofs. */
@ThreadSafe
public final class IssuerCodeFuzzTests {
	@FuzzTest(maxDuration = "5m")
	public void codeTransitionsRespectBindingsAndSingleUse(byte @NonNull [] input) throws Exception {
		IssuerCodeFuzzModel.run(input);
	}
	@Test public void s256Calibration() throws Exception { IssuerCodeFuzzModel.run(new byte[]{0, 0, 0, 1}); }
	@Test public void resourceCalibration() throws Exception { IssuerCodeFuzzModel.run(new byte[]{0, 0, 0, 2}); }
	@Test public void consumedCodeCalibration() throws Exception { IssuerCodeFuzzModel.run(new byte[]{0, 0, 0, 0}); }
	@Test public void consumedCodeRecordCannotBeConsumedAgain() throws Exception { IssuerCodeFuzzModel.consumedCodeRecordCannotBeConsumedAgain(); }
}
