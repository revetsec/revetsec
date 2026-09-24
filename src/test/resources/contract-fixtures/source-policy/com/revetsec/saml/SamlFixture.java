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

package com.revetsec.saml;

/**
 * Seeded violations: an XML factory outside internal.xml, and non-namespace DOM lookups (a call and a method
 * reference) in saml. The namespace-aware lookup is a control.
 */
final class SamlFixture {
	void seeded(org.w3c.dom.Document document) {
		javax.xml.parsers.DocumentBuilderFactory.newInstance();
		document.getElementsByTagName("Assertion");
		java.util.function.Function<String, org.w3c.dom.NodeList> lookup = document::getElementsByTagName;
		document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
	}
}
