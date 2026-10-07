/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.code_intelligence.jazzer.junit.FuzzTest;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** Issuer store address, namespace, envelope, version and retention semantics. */
@ThreadSafe
public final class IssuerStoreFuzzTests {
	@FuzzTest(maxDuration = "5m")
	public void recordsAuthenticateNamespaceVersionRetentionAndPayload(byte @NonNull [] input) throws Exception {
		IssuerStoreFuzzModel.run(input);
	}
	@Test public void validControl() throws Exception { IssuerStoreFuzzModel.run(new byte[]{0, 0, 0, 0}); }
	@Test public void namespaceControl() throws Exception { IssuerStoreFuzzModel.run(new byte[]{3, 5, 0, 0}); }
}
