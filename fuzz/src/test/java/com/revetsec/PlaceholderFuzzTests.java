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

package com.revetsec;

import com.code_intelligence.jazzer.junit.FuzzTest;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;

/**
 * M0 placeholder fuzz target. <strong>Delete at M1</strong>, when the first real targets (the JSON
 * codec) land.
 * <p>
 * It exists only because ClusterFuzzLite's build check fails when a build produces no fuzz targets
 * (plan §12.3 M0). It exercises nothing security-relevant and no RevetSec code: it checks a JDK
 * property, that decoding arbitrary bytes as UTF-8 (with replacement) and re-encoding the result is
 * a fixed point after one round.
 * <p>
 * Its passing says nothing about RevetSec. It proves only that the fuzz module, its seed corpus and
 * the ClusterFuzzLite wiring run end to end.
 */
@ThreadSafe
public class PlaceholderFuzzTests {
	private static volatile int sink;

	@FuzzTest(maxDuration = "30s")
	public void utf8ReplacementDecodingIsAFixedPointAfterOneRound(byte[] input) {
		String decoded = new String(input, StandardCharsets.UTF_8);
		byte[] reencoded = decoded.getBytes(StandardCharsets.UTF_8);
		String redecoded = new String(reencoded, StandardCharsets.UTF_8);

		if (!decoded.equals(redecoded))
			throw new IllegalStateException("UTF-8 replacement decoding was not a fixed point after one round");

		sink += redecoded.length();
	}
}
