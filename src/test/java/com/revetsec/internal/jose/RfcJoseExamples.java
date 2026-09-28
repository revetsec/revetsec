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

package com.revetsec.internal.jose;

/**
 * Examples transcribed from the IETF JOSE RFCs, shared by the JWS-layer and validator-level vector tests. Only public
 * key material and signed examples are transcribed, and each pair is self-checking: every token verifies under its key
 * (or, for HMAC, under its secret), so a transcription error fails the tests that use it instead of passing silently.
 * Every transcription here was also compared with its RFC's text, read from rfc-editor.org on 2026-09-28.
 * <p>
 * RFC 7520's examples come from the vendored Wycheproof {@code json_web_signature_test.json}, which carries them as
 * tcIds 345 to 348; the tests read them from there.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
public final class RfcJoseExamples {
	/**
	 * The JWT claims set of RFC 7515 appendices A.1 to A.3, base64url-encoded: {@code {"iss":"joe",\r\n
	 * "exp":1300819380,\r\n "http://example.com/is_root":true}}.
	 */
	public static final String RFC_7515_JWT_PAYLOAD = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9l"
			+ "eGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

	/**
	 * The {@code exp} of that claims set.
	 */
	public static final long RFC_7515_JWT_EXPIRES_AT = 1_300_819_380L;

	/**
	 * RFC 7515 appendix A.1: the HMAC key (section A.1.1, the JWK {@code k}).
	 */
	public static final String RFC_7515_A1_KEY = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgU"
			+ "uTwjAzZr1Z9CAow";

	/**
	 * RFC 7515 appendix A.1: the HS256 JWS, whose header is {@code {"typ":"JWT",\r\n "alg":"HS256"}}.
	 */
	public static final String RFC_7515_A1_JWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + RFC_7515_JWT_PAYLOAD
			+ ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	/**
	 * RFC 7515 appendix A.2: the RSA public key's modulus (section A.2.1); its exponent is {@code AQAB}.
	 */
	public static final String RFC_7515_A2_MODULUS = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Va"
			+ "w-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXn"
			+ "dS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmo"
			+ "udF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

	/**
	 * RFC 7515 appendix A.2: the RS256 JWS, whose header is {@code {"alg":"RS256"}}.
	 */
	public static final String RFC_7515_A2_JWS = "eyJhbGciOiJSUzI1NiJ9." + RFC_7515_JWT_PAYLOAD + ".cC4hiUPoj9Eetdgtv3h"
			+ "F80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
			+ "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWE"
			+ "sqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

	/**
	 * RFC 7515 appendix A.3: the P-256 public key's {@code x} (section A.3.1).
	 */
	public static final String RFC_7515_A3_X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";

	/**
	 * RFC 7515 appendix A.3: the P-256 public key's {@code y}.
	 */
	public static final String RFC_7515_A3_Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

	/**
	 * RFC 7515 appendix A.3: the ES256 JWS, whose header is {@code {"alg":"ES256"}}.
	 */
	public static final String RFC_7515_A3_JWS = "eyJhbGciOiJFUzI1NiJ9." + RFC_7515_JWT_PAYLOAD + ".DtEhU3ljbEg8L38VWAfUA"
			+ "qOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

	/**
	 * RFC 7515 appendix A.4: the P-521 public key's {@code x} (section A.4.1).
	 */
	public static final String RFC_7515_A4_X = "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSf"
			+ "S9tsz4qUxcWceqwQGk";

	/**
	 * RFC 7515 appendix A.4: the P-521 public key's {@code y}.
	 */
	public static final String RFC_7515_A4_Y = "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZ"
			+ "MaZmh9ubmf63e3kyMj2";

	/**
	 * RFC 7515 appendix A.4: the ES512 JWS over the payload {@code Payload}, whose header is {@code {"alg":"ES512"}}.
	 */
	public static final String RFC_7515_A4_JWS = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxM"
			+ "i70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vc"
			+ "nwNrmxYbSW9ERBXukOXolLzeO_Jn";

	/**
	 * RFC 7515 appendix A.5: the unsecured JWS, {@code {"alg":"none"}} with an empty signature.
	 */
	public static final String RFC_7515_A5_JWS = "eyJhbGciOiJub25lIn0." + RFC_7515_JWT_PAYLOAD + ".";

	/**
	 * RFC 7517 appendix A.1's first key, a P-256 key for encryption ({@code use} {@code enc}, {@code kid} {@code 1}).
	 */
	public static final String RFC_7517_A1_EC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iD"
			+ "Z8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";

	/**
	 * RFC 7517 appendix A.2's first key: the same P-256 key with its private {@code d}.
	 */
	public static final String RFC_7517_A2_EC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iD"
			+ "Z8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJ"
			+ "pr5eUZNP4Bk43bVdj3eAE\",\"use\":\"enc\",\"kid\":\"1\"}";

	/**
	 * RFC 7517 appendix A.3's second key: the symmetric key RFC 7515 appendix A.1 MACs with.
	 */
	public static final String RFC_7517_A3_HMAC_KEY = "{\"kty\":\"oct\",\"k\":\"" + RFC_7515_A1_KEY + "\",\"kid\":\"HMAC "
			+ "key used in JWS spec Appendix A.1 example\"}";

	/**
	 * RFC 8037 appendix A.2: the Ed25519 public key's {@code x}.
	 */
	public static final String RFC_8037_A2_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

	/**
	 * RFC 8037 appendix A.4: the EdDSA JWS over {@code Example of Ed25519 signing}.
	 */
	public static final String RFC_8037_A4_JWS = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0"
			+ "JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

	/**
	 * The RFC 8037 appendix A.4 payload re-signed with the appendix A.1 key under {@code {"alg":"Ed25519"}}, the fully
	 * specified name (RFC 9864). Ed25519 signatures are deterministic, so it is the same on every JDK.
	 */
	public static final String ED25519_FIXTURE_JWS = "eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.UxhIYL"
			+ "HGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ";

	/**
	 * The payload of RFC 8037 appendix A.4 and of the Ed25519 fixture.
	 */
	public static final String ED25519_PAYLOAD = "Example of Ed25519 signing";

	private RfcJoseExamples() {
		// Constants only.
	}

	/**
	 * The RFC 7515 appendix A.2 RSA public key as a JWK, with no {@code kid} or {@code alg}.
	 *
	 * @return the JWK's JSON text
	 */
	public static String rfc7515A2Key() {
		return "{\"kty\":\"RSA\",\"n\":\"" + RFC_7515_A2_MODULUS + "\",\"e\":\"AQAB\"}";
	}

	/**
	 * The RFC 7515 appendix A.3 P-256 public key as a JWK, with no {@code kid} or {@code alg}.
	 *
	 * @return the JWK's JSON text
	 */
	public static String rfc7515A3Key() {
		return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + RFC_7515_A3_X + "\",\"y\":\"" + RFC_7515_A3_Y + "\"}";
	}

	/**
	 * The RFC 7515 appendix A.4 P-521 public key as a JWK, with no {@code kid} or {@code alg}.
	 *
	 * @return the JWK's JSON text
	 */
	public static String rfc7515A4Key() {
		return "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"" + RFC_7515_A4_X + "\",\"y\":\"" + RFC_7515_A4_Y + "\"}";
	}

	/**
	 * The RFC 8037 appendix A.2 Ed25519 public key as a JWK.
	 *
	 * @return the JWK's JSON text
	 */
	public static String rfc8037A2Key() {
		return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + RFC_8037_A2_X + "\"}";
	}
}
