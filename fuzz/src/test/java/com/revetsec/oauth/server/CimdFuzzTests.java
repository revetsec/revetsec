/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.code_intelligence.jazzer.junit.FuzzTest;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** CIMD document/cache admission plus numeric-peer and HTTP framing semantics. */
@ThreadSafe
public final class CimdFuzzTests {
	@FuzzTest(maxDuration = "5m")
	public void metadataCachePeerAndFramingRemainBound(byte @NonNull [] input) throws Exception {
		CimdFuzzModel.run(input);
	}
	@Test public void validControl() throws Exception { CimdFuzzModel.run(new byte[]{0, 0, 0, 0}); }
	@Test public void privatePeerControl() throws Exception { CimdFuzzModel.run(new byte[]{0, 0, 1, 0}); }
}
