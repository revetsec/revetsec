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
package com.revetsec.oauth;

import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static java.util.Objects.requireNonNull;

/** Actual independently registered private_key_jwt provider across three algorithms and both audience modes. */
final class NodeClientAssertionIT {
	private static @Nullable ClientAssertionProviderChecksIT fixture;
	@BeforeAll static void start() throws Exception { fixture = new ClientAssertionProviderChecksIT(true); }
	@AfterAll static void stop() throws Exception { if (fixture != null) fixture.close(); }
	private static @NonNull ClientAssertionProviderChecksIT provider() { return requireNonNull(fixture); }
	@Test void rs256IssuerAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.RS256, ClientAssertionAudience.ISSUER); }
	@Test void rs256EndpointAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.RS256, ClientAssertionAudience.TOKEN_ENDPOINT); }
	@Test void rs384IssuerAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.RS384, ClientAssertionAudience.ISSUER); }
	@Test void rs384EndpointAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.RS384, ClientAssertionAudience.TOKEN_ENDPOINT); }
	@Test void ps256IssuerAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.PS256, ClientAssertionAudience.ISSUER); }
	@Test void ps256EndpointAudienceAllRolesAndRegistrationNegatives() throws Exception { provider().check(JwsAlgorithm.PS256, ClientAssertionAudience.TOKEN_ENDPOINT); }
}
