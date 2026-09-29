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

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CapturedAuthorizationServerMetadataTests {
	private static final String ENTRA_TENANT =
			"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0";

	@Test
	void googleCaptureAdvertisesIssuerParameterAndS256() throws Exception {
		AuthorizationServerMetadata google = AuthorizationServerMetadata.fromJson("https://accounts.google.com",
				fixture("google/2026-09-28/openid-configuration.json"));
		assertTrue(google.isAuthorizationResponseIssuerSupported());
		assertTrue(google.getCodeChallengeMethodsSupported().orElseThrow().contains("S256"));
	}

	@Test
	void appleCaptureLoadsWithoutPkceAdvertisement() throws Exception {
		AuthorizationServerMetadata apple = AuthorizationServerMetadata.fromJson("https://appleid.apple.com",
				fixture("apple/2026-09-28/openid-configuration.json"));
		assertFalse(apple.isAuthorizationResponseIssuerSupported());
		assertTrue(apple.getCodeChallengeMethodsSupported().isEmpty());
	}

	@Test
	void tenantSpecificEntraLoadsButCommonTemplateCannotPassExactIssuerCheck() throws Exception {
		AuthorizationServerMetadata tenant = AuthorizationServerMetadata.fromJson(ENTRA_TENANT,
				fixture("entra/2026-09-27/tenant-v2-openid.json"));
		assertEquals(ENTRA_TENANT, tenant.getIssuer());
		assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> AuthorizationServerMetadata.fromJson(
						"https://login.microsoftonline.com/common/v2.0",
						fixture("entra/2026-09-27/common-v2-openid.json"))).getReason());
	}

	private static String fixture(String name) throws Exception {
		try (InputStream input = CapturedAuthorizationServerMetadataTests.class.getResourceAsStream(
				"/fixtures/" + name)) {
			if (input == null) throw new IllegalStateException("A captured metadata fixture is missing.");
			return new String(input.readAllBytes(), StandardCharsets.UTF_8);
		}
	}
}
