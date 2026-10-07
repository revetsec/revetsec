/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.code_intelligence.jazzer.junit.FuzzTest;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** Fixed issuer access-token claims, profile, active-key selection and independent signature checks. */
@ThreadSafe
public final class IssuerSigningFuzzTests {
	@FuzzTest(maxDuration = "5m")
	public void accessTokensMatchFixedProfileAndIndependentSignature(byte @NonNull [] input) throws Exception {
		IssuerSigningFuzzModel.run(input);
	}
	@Test public void fixedProfileCalibration() throws Exception { IssuerSigningFuzzModel.run(new byte[]{0, 1, 1, 3, 4, 1, 2}); }
}
