/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.code_intelligence.jazzer.junit.FuzzTest;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** Refresh-family rotation and uncached issuer, subject, and grant status transitions. */
@ThreadSafe
public final class IssuerRefreshFuzzTests {
	@FuzzTest(maxDuration = "5m")
	public void refreshFamilyAndStatusTransitionsRemainAtomic(byte @NonNull [] input) throws Exception {
		IssuerRefreshFuzzModel.run(input);
	}
	@Test public void usedRefreshReplayCalibration() throws Exception { IssuerRefreshFuzzModel.usedRefreshReplayCalibration(); }
	@Test public void subjectStatusCalibration() throws Exception { IssuerRefreshFuzzModel.subjectStatusCalibration(); }
	@Test public void grantStatusCalibration() throws Exception { IssuerRefreshFuzzModel.grantStatusCalibration(); }
}
