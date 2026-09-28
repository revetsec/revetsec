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

package com.revetsec.internal.crypto;

/**
 * Seeded violations: SunEC's P1363 signature names in main code (p1363-signature-name, G8-3): a literal, in lower
 * case, with a dotless i spelled as a Unicode escape (the JCA folds names to upper case, and JDK 17 and 27 resolve
 * that one to SunEC's P1363 signature), in a constant, a constant variable joined to a literal, two concatenations
 * split across lines (two literals, and a constant variable joined to a literal that holds the whole suffix; each is
 * reported once, where it starts), parenthesized parts with a char and an int literal, none of which names it alone,
 * the suffix split over two literals after a variable, the same after a call and regrouped by parentheses (each
 * reported where its run of constants starts), and a text block (reported where it starts). jca-provider-argument
 * applies in internal.crypto too. In controls(), the DER name, a reference to the constant (reported once, where it
 * is declared), a message naming the standard, a name only completed at run time, and a comment are not reported.
 */
final class SignatureNameFixture {
	private static final String PREFIX = "SHA384withECDSAin";
	private static final String DIGEST = "SHA512";
	private static final String NAME = "SHA512withECDSAinP1363Format";

	void seeded(String digest) throws java.security.GeneralSecurityException {
		java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
		java.security.Signature.getInstance("sha256withecdsainp1363format");
		java.security.Signature.getInstance("SHA256withECDSA\u0131nP1363Format");
		java.security.Signature.getInstance(PREFIX + "P1363Format");
		java.security.Signature.getInstance("SHA384withECDSAin"
				+ "P1363Format");
		java.security.Signature.getInstance(DIGEST
				+ "withECDSAinP1363Format");
		java.security.Signature.getInstance(("SHA256withECDSAi" + 'n') + ("P" + 1363 + "Format"));
		java.security.Signature.getInstance(digest + "withECDSAin" + "P1363Format");
		java.security.Signature.getInstance((digest.strip() + "withECDSAi") + ('n' + ("P1363" + "Format")));
		String block = """
				SHA256withECDSAinP1363Format""";
		javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
	}

	void controls(String suffix) throws java.security.GeneralSecurityException {
		java.security.Signature.getInstance("SHA256withECDSA");
		java.security.Signature.getInstance(NAME);
		String message = "IEEE P1363 encodes r and s at a fixed length";
		java.security.Signature.getInstance("SHA256withECDSAin" + suffix);
		// SHA256withECDSAinP1363Format in a comment is not code
	}

	// Seeded: an identifier that is the name, which name() would hand to the JCA (reported by the expression alone).
	enum JcaName {
		SHA256withECDSA,
		SHA256withECDSAinP1363Format
	}
}
