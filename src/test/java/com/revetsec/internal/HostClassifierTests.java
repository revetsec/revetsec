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

package com.revetsec.internal;

import com.revetsec.internal.HostClassifier.HostClass;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * The literal parser and host classifier behind {@code OutboundUriPolicy} (M1 plan A-1; gate 8, G8-5 to G8-7;
 * RFC 4291 section 2.2, RFC 1123 section 2.1, RFC 6761 section 6.3). The address-class table that is compared with
 * the JDK and both presets lives in {@code OutboundUriPolicyTests}; these are the parser's edge cases, the G8-5
 * precedence rules, the transcribed registries and the metadata list, none of which reaches a resolver (the
 * comparisons with {@code InetAddress} pass it only literals, which it parses without one).
 * <p>
 * The owner's decisions of 2026-09-27 add Google Compute Engine's IPv6 metadata address and every name under
 * {@code arpa} (RFC 3172), which covers the special-use names and reverse-mapping zones there, and keep the
 * unconfirmed metadata leads as local names.
 * <p>
 * <strong>Sources</strong>, each read once on 2026-09-27 (M2 plan A-1):
 * <ul>
 *   <li>the IANA IPv4 Special-Purpose Address Registry,
 *   {@code https://www.iana.org/assignments/iana-ipv4-special-registry/};</li>
 *   <li>the IANA IPv6 Special-Purpose Address Registry,
 *   {@code https://www.iana.org/assignments/iana-ipv6-special-registry/};</li>
 *   <li>the IANA Special-Use Domain Names registry, {@code https://www.iana.org/assignments/special-use-domain-names/};</li>
 *   <li>ICANN Board resolution 2024.07.29.06, which reserves {@code .INTERNAL} for private use ("Approved Resolutions,
 *   Special Meeting of the ICANN Board, 29 July 2024"),
 *   {@code https://www.icann.org/en/board-activities-and-meetings/materials/approved-resolutions-special-meeting-of-the-icann-board-29-07-2024-en};</li>
 *   <li>the cloud providers' metadata documentation listed at {@link #cloudMetadataEndpointsAreTheConfirmedOnes()}.</li>
 * </ul>
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HostClassifierTests {
	@TestFactory
	Stream<DynamicTest> ipv4FormsParseToTheJdkValue() {
		// The JDK's numeric forms: 1 to 4 decimal parts, the last filling the remaining bytes.
		Map<String, String> forms = Map.ofEntries(
				Map.entry("0", "0.0.0.0"),
				Map.entry("1", "0.0.0.1"),
				Map.entry("4294967295", "255.255.255.255"),
				Map.entry("2852039166", "169.254.169.254"),
				Map.entry("127.1", "127.0.0.1"),
				Map.entry("1.16777215", "1.255.255.255"),
				Map.entry("1.2.65535", "1.2.255.255"),
				Map.entry("169.254.43518", "169.254.169.254"),
				Map.entry("255.255.255.255", "255.255.255.255"),
				Map.entry("10.0.0.0", "10.0.0.0"),
				Map.entry("100.100.100.100", "100.100.100.100"));

		return inKeyOrder(forms).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), dotted(HostClassifier.parseLiteral(entry.getKey())))));
	}

	@TestFactory
	Stream<DynamicTest> malformedIpv4FormsAreNotLiterals() {
		// Out of range, too many parts, empty parts, leading zeros (ambiguous with BSD octal), signs and other digits.
		List<String> forms = List.of("", ".", "..", "1.", ".1", "1..1", "1.2.3.4.", "1.2.3.4.5", "256.0.0.0",
				"0.256.0.0", "1.2.3.256", "1.2.65536", "1.16777216", "4294967296", "99999999999", "18446744073709551616",
				"00", "01", "010.0.0.1", "1.02.3.4", "1.2.3.04", "0x1", "0x7f.0.0.1", "1.2.3.0x4", "+1", "-1", "1.-2.3.4",
				"1 .2.3.4", " 1.2.3.4", "1.2.3.4 ", "١.2.3.4", "１.2.3.4", "1².2.3.4", "0000000000000001");

		return forms.stream().map(form -> DynamicTest.dynamicTest("\"" + form + "\"", () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(form));
			Assertions.assertEquals(HostClass.INVALID, HostClassifier.classify(form));
		}));
	}

	@TestFactory
	Stream<DynamicTest> ipv6FormsParse() {
		// RFC 4291 section 2.2: the three text forms, including "::" standing for a single group.
		Map<String, String> forms = Map.ofEntries(
				Map.entry("[::]", "0:0:0:0:0:0:0:0"),
				Map.entry("[::1]", "0:0:0:0:0:0:0:1"),
				Map.entry("[1::]", "1:0:0:0:0:0:0:0"),
				Map.entry("[1::8]", "1:0:0:0:0:0:0:8"),
				Map.entry("[1:2:3:4:5:6:7:8]", "1:2:3:4:5:6:7:8"),
				Map.entry("[1:2:3:4:5:6:7::]", "1:2:3:4:5:6:7:0"),
				Map.entry("[::2:3:4:5:6:7:8]", "0:2:3:4:5:6:7:8"),
				Map.entry("[1:2:3::6:7:8]", "1:2:3:0:0:6:7:8"),
				Map.entry("[FFFF:abcd:0:00:000:0000:1:ABCD]", "ffff:abcd:0:0:0:0:1:abcd"),
				Map.entry("[::ffff:1.2.3.4]", "0:0:0:0:0:ffff:102:304"),
				Map.entry("[::ffff:0:1.2.3.4]", "0:0:0:0:ffff:0:102:304"),
				Map.entry("[::1.2.3.4]", "0:0:0:0:0:0:102:304"),
				Map.entry("[1:2:3:4:5:6:255.255.255.255]", "1:2:3:4:5:6:ffff:ffff"),
				Map.entry("[1::0.0.0.0]", "1:0:0:0:0:0:0:0"),
				Map.entry("[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));

		return inKeyOrder(forms).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), groups(HostClassifier.parseLiteral(entry.getKey())))));
	}

	@TestFactory
	Stream<DynamicTest> malformedIpv6FormsAreInvalid() {
		// Every one of these is rejected: bad compression, too many or too few groups, groups over four digits, a
		// bad IPv4 tail, zone IDs, missing brackets and non-ASCII digits.
		List<String> forms = List.of("[]", "[", "]", "[:]", "[:::]", "[::::]", "[1:::2]", "[1::2::3]", "[:1::]",
				"[::1:]", "[1:]", "[:1]", "[1:2:3:4:5:6:7]", "[1:2:3:4:5:6:7:8:9]", "[1:2:3:4:5:6:7:8::]",
				"[::1:2:3:4:5:6:7:8]", "[12345::]", "[00000::1]", "[g::1]", "[::ffff:1.2.3]", "[::ffff:1.2.3.4.5]",
				"[::ffff:256.1.1.1]", "[::ffff:01.2.3.4]", "[::ffff:1.2.3.4:5]", "[1.2.3.4::]", "[1.2.3.4]",
				"[1:2:3:4:5:6:7:1.2.3.4]", "[::ffff:0x1.2.3.4]", "[::.1.2.3]", "[fe80::1%en0]", "[fe80::1%1]",
				"[fe80::1%]", "[fe80::1%25en0]", "[::1]x", "x[::1]", "[[::1]]", "[::1", "::1]", "::1", "::", "fe80::1",
				"[ ::1]", "[::١]", "[::１]", "[1:2:3:4:5:6:7:8:1.2.3.4]", "[1:2:3:4:5:6:7:8:9:0]",
				"[" + "1:".repeat(22) + "1]", "[" + "1:".repeat(23) + "1]",
				"[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.2555]");

		return forms.stream().map(form -> DynamicTest.dynamicTest("\"" + form + "\"", () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(form));
			Assertions.assertEquals(HostClass.INVALID, HostClassifier.classify(form));
		}));
	}

	@TestFactory
	Stream<DynamicTest> hostnamesFollowRfc1123Syntax() {
		String label63 = "a".repeat(63);
		// 4 labels of 63 plus 3 dots is 255 characters; trimming to 253 keeps it valid.
		String name253 = String.join(".", label63, label63, label63, "a".repeat(61));
		// A valid name is a HOSTNAME unless a name rule claims it: a single label is a LOCAL_NAME (G8-5).
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("a", HostClass.LOCAL_NAME),
				Map.entry("a-b.example.com", HostClass.HOSTNAME),
				// The ends of each character range: z and Z, and 0 and 9, and the characters just past them.
				Map.entry("zz.example.com", HostClass.HOSTNAME),
				Map.entry("ZZ.EXAMPLE.COM", HostClass.HOSTNAME),
				Map.entry("a-z9.example.com", HostClass.HOSTNAME),
				Map.entry("Az.example.com", HostClass.HOSTNAME),
				Map.entry("a{b.example.com", HostClass.INVALID),
				Map.entry("a[b.example.com", HostClass.INVALID),
				Map.entry("a`b.example.com", HostClass.INVALID),
				Map.entry("a@b.example.com", HostClass.INVALID),
				Map.entry("a/b.example.com", HostClass.INVALID),
				Map.entry("a:b.example.com", HostClass.INVALID),
				Map.entry("xn--bcher-kva.example.com", HostClass.HOSTNAME),
				Map.entry("1a.example.com", HostClass.HOSTNAME),
				Map.entry("example.1a", HostClass.HOSTNAME),
				Map.entry("0x7g", HostClass.LOCAL_NAME),
				Map.entry("0a", HostClass.LOCAL_NAME),
				Map.entry("example.0a", HostClass.HOSTNAME),
				Map.entry("example.0x", HostClass.INVALID),
				Map.entry("1e2", HostClass.LOCAL_NAME),
				Map.entry(label63 + ".example.com", HostClass.HOSTNAME),
				Map.entry(name253, HostClass.HOSTNAME),
				Map.entry(name253 + ".", HostClass.HOSTNAME),
				Map.entry("a".repeat(64) + ".example.com", HostClass.INVALID),
				Map.entry(name253 + "a", HostClass.INVALID),
				Map.entry("-a.example.com", HostClass.INVALID),
				Map.entry("a-.example.com", HostClass.INVALID),
				Map.entry("a..example.com", HostClass.INVALID),
				Map.entry(".example.com", HostClass.INVALID),
				Map.entry("example.com..", HostClass.INVALID),
				Map.entry("under_score.example.com", HostClass.INVALID),
				Map.entry("space .example.com", HostClass.INVALID),
				Map.entry("exämple.com", HostClass.INVALID),
				Map.entry("xn--nxasmq6b.сом", HostClass.INVALID),
				Map.entry("localhoſt", HostClass.INVALID),
				Map.entry("metadata.google.İnternal", HostClass.INVALID),
				Map.entry("idp.Kocal", HostClass.INVALID),
				Map.entry("user@example.com", HostClass.INVALID),
				Map.entry("example.com:443", HostClass.INVALID),
				Map.entry("%31.example.com", HostClass.INVALID));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> localhostNamesAreRecognizedInAsciiCaseOnly() {
		// RFC 6761 section 6.3. The comparison folds ASCII only: the Kelvin sign or a dotless i never matches.
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("localhost", HostClass.LOCALHOST_NAME),
				Map.entry("LocalHost", HostClass.LOCALHOST_NAME),
				Map.entry("localhost.", HostClass.LOCALHOST_NAME),
				Map.entry("a.b.localhost", HostClass.LOCALHOST_NAME),
				Map.entry("a.LOCALHOST.", HostClass.LOCALHOST_NAME),
				Map.entry("xlocalhost", HostClass.LOCAL_NAME),
				Map.entry("a.xlocalhost", HostClass.HOSTNAME),
				Map.entry("localhost.example.com", HostClass.HOSTNAME),
				Map.entry("localhos", HostClass.LOCAL_NAME),
				Map.entry("Kocalhost", HostClass.INVALID),
				Map.entry("localhostı", HostClass.INVALID));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> specialUseAndPrivateUseNamesAreLocalNames() {
		// G8-5. Every suffix in the plan's list, each confirmed on 2026-09-27: "local.", "home.arpa.", "test.",
		// "invalid.", "example.", "onion." and "alt." are in the IANA Special-Use Domain Names registry (RFC 6762,
		// 8375, 6761, 7686 and 9476), and ICANN Board resolution 2024.07.29.06 reserves ".INTERNAL" for private use.
		// The owner's decision of 2026-09-27 replaces "home.arpa" and the per-zone arpa list (service.arpa,
		// ipv4only.arpa, resolver.arpa, in-addr.arpa and ip6.arpa) with "arpa" itself, the domain RFC 3172 reserves for
		// Internet infrastructure, which holds every registry entry under it; everyNameUnderArpaIsALocalName covers it.
		// Each suffix matches itself and every name under it, in any ASCII case and with one trailing dot, and only on
		// a label boundary.
		List<String> suffixes = List.of("local", "internal", "test", "invalid", "example", "onion", "alt", "arpa");
		List<DynamicTest> tests = new ArrayList<>();

		for (String suffix : suffixes) {
			String upperCase = suffix.toUpperCase(Locale.ROOT);
			Map<String, HostClass> hosts = Map.of(
					suffix, HostClass.LOCAL_NAME,
					suffix + ".", HostClass.LOCAL_NAME,
					"idp." + suffix, HostClass.LOCAL_NAME,
					"a.b.idp." + suffix + ".", HostClass.LOCAL_NAME,
					"IDP." + upperCase, HostClass.LOCAL_NAME,
					"Idp." + upperCase + ".", HostClass.LOCAL_NAME,
					"idp.x" + suffix, HostClass.HOSTNAME,
					"idp." + suffix + "x.com", HostClass.HOSTNAME,
					"idp." + suffix + ".example.com", HostClass.HOSTNAME);

			new TreeMap<>(hosts).forEach((host, hostClass) -> tests.add(DynamicTest.dynamicTest(host, () ->
					Assertions.assertEquals(hostClass, HostClassifier.classify(host)))));
		}

		// Registry entries outside the list (example.com and example.org, RFC 6761), and names that only contain a
		// suffix as a label or share its text without a label boundary, stay ordinary names.
		for (String host : List.of("example.com", "example.org.", "arpa.example.com", "ipv4only.arpa.example.com",
				"in-addr.arpa.example.com", "home.arpa.example.com", "idp.xarpa", "idp.arpanet", "arpa.idp.com",
				"local.example.com", "internal.example.com", "idp.evilinternal"))
			tests.add(DynamicTest.dynamicTest(host, () ->
					Assertions.assertEquals(HostClass.HOSTNAME, HostClassifier.classify(host))));

		return tests.stream();
	}

	@TestFactory
	Stream<DynamicTest> reverseZoneAndLocallyServedArpaNamesAreLocalNames() {
		// The owner's decisions of 2026-09-27, in the forms a caller would meet: reverse-mapping names for private,
		// loopback, link-local and NAT64-discovery addresses (the registry's own reverse-zone entries among them), a
		// full IPv6 nibble name, the DNS-SD and designated-resolver names, and the NAT64 discovery name itself, in any
		// ASCII case and with one trailing dot. "arpa" alone is local as a single label and as the arpa zone itself. A
		// label with an underscore, such as "_dns.resolver.arpa", is not a hostname at all.
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("1.0.0.127.in-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("10.in-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("16.172.in-addr.arpa.", HostClass.LOCAL_NAME),
				Map.entry("168.192.in-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("254.169.in-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("170.0.0.192.IN-ADDR.ARPA", HostClass.LOCAL_NAME),
				Map.entry("8.8.8.8.in-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("b.e.f.ip6.arpa", HostClass.LOCAL_NAME),
				Map.entry("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", HostClass.LOCAL_NAME),
				Map.entry("D.F.IP6.ARPA", HostClass.LOCAL_NAME),
				Map.entry("default.service.arpa", HostClass.LOCAL_NAME),
				Map.entry("printer.default.service.arpa.", HostClass.LOCAL_NAME),
				Map.entry("dns.resolver.arpa", HostClass.LOCAL_NAME),
				Map.entry("IPv4only.Arpa.", HostClass.LOCAL_NAME),
				Map.entry("arpa", HostClass.LOCAL_NAME),
				Map.entry("_dns.resolver.arpa", HostClass.INVALID),
				Map.entry("in-addr.arpa..", HostClass.INVALID));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> everyNameUnderArpaIsALocalName() {
		// The owner's decision of 2026-09-27: arpa is reserved for Internet infrastructure (RFC 3172), so every name
		// under it is local, whether or not the IANA Special-Use Domain Names registry lists it. That includes G8-5's
		// home.arpa, the registry entries the earlier per-zone list left out (eap.arpa, the deprecated eap-noob.arpa
		// and 6tisch.arpa, as read on 2026-09-27), the infrastructure zones (e164.arpa, uri.arpa, urn.arpa, as112.arpa,
		// the reverse-zone servers) and names that only resemble a listed zone (xin-addr.arpa, notipv4only.arpa), in
		// any ASCII case and with one trailing dot. Only a label boundary counts, so arpa as an inner label, or inside
		// a longer label, does not.
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("ARPA", HostClass.LOCAL_NAME),
				Map.entry("IDP.Arpa.", HostClass.LOCAL_NAME),
				Map.entry("home.arpa", HostClass.LOCAL_NAME),
				Map.entry("Router.Home.Arpa.", HostClass.LOCAL_NAME),
				Map.entry("eap.arpa", HostClass.LOCAL_NAME),
				Map.entry("Anon.Eap-Noob.Arpa.", HostClass.LOCAL_NAME),
				Map.entry("6tisch.arpa", HostClass.LOCAL_NAME),
				Map.entry("e164.arpa", HostClass.LOCAL_NAME),
				Map.entry("4.3.2.1.e164.arpa.", HostClass.LOCAL_NAME),
				Map.entry("uri.arpa", HostClass.LOCAL_NAME),
				Map.entry("urn.arpa", HostClass.LOCAL_NAME),
				Map.entry("as112.arpa", HostClass.LOCAL_NAME),
				Map.entry("in-addr-servers.arpa", HostClass.LOCAL_NAME),
				Map.entry("a.ip6-servers.arpa", HostClass.LOCAL_NAME),
				Map.entry("xhome.arpa", HostClass.LOCAL_NAME),
				Map.entry("xin-addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("idp.xip6.arpa", HostClass.LOCAL_NAME),
				Map.entry("addr.arpa", HostClass.LOCAL_NAME),
				Map.entry("notipv4only.arpa", HostClass.LOCAL_NAME),
				Map.entry("login.example.com.arpa", HostClass.LOCAL_NAME),
				Map.entry("login.example.com.arpa.", HostClass.LOCAL_NAME),
				Map.entry("arpa.example.com", HostClass.HOSTNAME),
				Map.entry("idp.arpa.example.com.", HostClass.HOSTNAME),
				Map.entry("idp.xarpa", HostClass.HOSTNAME),
				Map.entry("idp.arpax", HostClass.HOSTNAME),
				Map.entry("idp.arp", HostClass.HOSTNAME),
				Map.entry("idp.arpa-servers.com", HostClass.HOSTNAME));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> singleLabelNamesAreLocalNames() {
		// G8-5: a resolver may complete a single label with its search domains onto an internal host, so every
		// single-label name is local, with or without its trailing dot. "evilinternal" is local for that reason alone:
		// it is not under ".internal", which "idp.evilinternal" shows.
		Map<String, HostClass> hosts = Map.of(
				"intranet", HostClass.LOCAL_NAME,
				"INTRANET.", HostClass.LOCAL_NAME,
				"evilinternal", HostClass.LOCAL_NAME,
				"idp.evilinternal", HostClass.HOSTNAME,
				"x", HostClass.LOCAL_NAME,
				"a-b", HostClass.LOCAL_NAME,
				"com", HostClass.LOCAL_NAME,
				"idp.com", HostClass.HOSTNAME);

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> metadataNamesAndNamesUnderThemWinOverLocalNames() {
		// G8-5 precedence: METADATA_NAME wins over LOCAL_NAME, in any ASCII case and with one trailing dot. Like every
		// name class, it uses M1's localhost matching: the name itself and every name under it, on a label boundary
		// only, so a look-alike or a name that merely starts with a metadata name keeps its own class.
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("metadata.google.internal", HostClass.METADATA_NAME),
				Map.entry("METADATA.GOOGLE.INTERNAL.", HostClass.METADATA_NAME),
				Map.entry("Metadata.Google.Internal", HostClass.METADATA_NAME),
				Map.entry("metadata.goog", HostClass.METADATA_NAME),
				Map.entry("METADATA.GOOG.", HostClass.METADATA_NAME),
				Map.entry("x.metadata.google.internal", HostClass.METADATA_NAME),
				Map.entry("a.b.METADATA.Google.Internal.", HostClass.METADATA_NAME),
				Map.entry("x.metadata.goog", HostClass.METADATA_NAME),
				Map.entry("X.Metadata.GOOG.", HostClass.METADATA_NAME),
				Map.entry("xmetadata.google.internal", HostClass.LOCAL_NAME),
				Map.entry("x-metadata.google.internal", HostClass.LOCAL_NAME),
				Map.entry("google.internal", HostClass.LOCAL_NAME),
				Map.entry("metadata.google.internal.example.com", HostClass.HOSTNAME),
				Map.entry("xmetadata.goog", HostClass.HOSTNAME),
				Map.entry("x-metadata.goog", HostClass.HOSTNAME),
				Map.entry("metadata.goog.example.com", HostClass.HOSTNAME),
				Map.entry("goog", HostClass.LOCAL_NAME),
				Map.entry("metadata.google.internal..", HostClass.INVALID));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	/**
	 * G8-6: the known cloud metadata endpoints, each kept only because its provider's documentation named it when
	 * read on 2026-09-27:
	 * <ul>
	 *   <li>{@code 100.100.100.200}: Alibaba Cloud, "Get instance properties from within an ECS instance by using the
	 *   metadata service", {@code https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata};</li>
	 *   <li>{@code 168.63.129.16}: Microsoft, "Azure IP Address 168.63.129.16 Overview" (the WireServer; page dated
	 *   2025-07-25), {@code https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16};</li>
	 *   <li>{@code metadata.google.internal} and {@code metadata.goog}: Google Cloud, "View and query VM metadata"
	 *   (last updated 2026-09-24), {@code https://docs.cloud.google.com/compute/docs/metadata/querying-metadata};</li>
	 *   <li>{@code fd00:ec2::254} (M1's entry, re-read): Amazon, "Access instance metadata for an EC2 instance",
	 *   {@code https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html};</li>
	 *   <li>{@code fd00:ec2::23} (a review lead): Amazon, "Set up the Amazon EKS Pod Identity Agent",
	 *   {@code https://docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html};</li>
	 *   <li>{@code fd20:ce::254}: Google Cloud's querying page above and "About VM metadata"
	 *   ({@code https://docs.cloud.google.com/compute/docs/metadata/overview}) document it as the metadata server's IPv6
	 *   address, over {@code http} and, on Shielded VMs, over {@code https}. It is outside G8-6's approved list and was
	 *   added by the owner's decision of 2026-09-27.</li>
	 * </ul>
	 * Two review leads were dropped, because the same reads did not confirm them:
	 * <ul>
	 *   <li>Google's short name {@code metadata}: the querying page, "About VM metadata"
	 *   ({@code https://docs.cloud.google.com/compute/docs/metadata/overview}) and "Troubleshooting metadata server
	 *   access issues" ({@code https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshoot-metadata-server})
	 *   name only {@code metadata.google.internal}, {@code metadata.goog} and the addresses, although the last shows
	 *   {@code google.internal.} among a VM's search domains;</li>
	 *   <li>{@code instance-data} and {@code instance-data.ec2.internal}: none of the three Amazon EC2 instance
	 *   metadata pages ("Access instance metadata for an EC2 instance", "Use instance metadata to manage your EC2
	 *   instance", {@code https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html}, and "Use the
	 *   Instance Metadata Service to access instance metadata",
	 *   {@code https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html}) names
	 *   either.</li>
	 * </ul>
	 * The owner's decision of 2026-09-27 keeps the dropped names as local names, which
	 * {@code defaultInstance()} permits and {@code publicAddressesOnlyInstance()} rejects
	 * ({@code OutboundUriPolicyTests} pins both presets for each).
	 */
	@TestFactory
	Stream<DynamicTest> cloudMetadataEndpointsAreTheConfirmedOnes() {
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("100.100.100.200", HostClass.CLOUD_METADATA),
				Map.entry("168.63.129.16", HostClass.CLOUD_METADATA),
				Map.entry("[fd00:ec2::254]", HostClass.CLOUD_METADATA),
				Map.entry("[fd00:ec2::23]", HostClass.CLOUD_METADATA),
				Map.entry("[fd20:ce::254]", HostClass.CLOUD_METADATA),
				Map.entry("[FD20:00CE:0000:0000:0000:0000:0000:0254]", HostClass.CLOUD_METADATA),
				Map.entry("metadata.google.internal", HostClass.METADATA_NAME),
				Map.entry("metadata.goog", HostClass.METADATA_NAME),
				// The common link-local address stays LINK_LOCAL, which both presets reject too.
				Map.entry("169.254.169.254", HostClass.LINK_LOCAL),
				// Dropped leads, kept as local names by the owner's decision of 2026-09-27.
				Map.entry("metadata", HostClass.LOCAL_NAME),
				Map.entry("METADATA.", HostClass.LOCAL_NAME),
				Map.entry("instance-data", HostClass.LOCAL_NAME),
				Map.entry("Instance-Data.", HostClass.LOCAL_NAME),
				Map.entry("instance-data.ec2.internal", HostClass.LOCAL_NAME),
				Map.entry("INSTANCE-DATA.EC2.INTERNAL.", HostClass.LOCAL_NAME));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@TestFactory
	Stream<DynamicTest> eachIpv6MetadataAddressMatchesOnlyItsOwnPrefixAndLastGroup() {
		// Each IPv6 metadata address is one exact address: its own first two groups, then zeros, then its own last
		// group. Every row here differs from one of them in one group or digit, or pairs one provider's first groups
		// with the other's, and stays in its block's class (fc00::/7 is unique local).
		List<String> neighbors = List.of("[fd20:ce::253]", "[fd20:ce::255]", "[fd20:ce::354]", "[fd20:ce::264]",
				"[fd20:ce::1:254]", "[fd20:ce:1::254]", "[fd20:ce:0:0:1::254]", "[fd20:ce:0:1::254]",
				"[fd20:ce:0:0:0:1:0:254]", "[fd20:cf::254]", "[fd20:1ce::254]", "[fd20:ec2::254]", "[fd21:ce::254]",
				"[fc20:ce::254]", "[fd00:ce::254]", "[fd20:ce::23]", "[fd20:ce::]", "[fd20:ce::254:0]",
				"[fd00:ec2::1:23]", "[fd00:ec2::22]", "[fd00:ec2:0:1::23]");

		return neighbors.stream().map(host -> DynamicTest.dynamicTest(host, () ->
				Assertions.assertEquals(HostClass.UNIQUE_LOCAL, HostClassifier.classify(host))));
	}

	@TestFactory
	Stream<DynamicTest> embeddedIpv4FollowsTheG85Precedence() {
		// G8-5: an IPv4-mapped literal is judged as the IPv4 address inside it, which the JDK turns into an
		// Inet4Address. NAT64 Well-Known Prefix literals also take the IPv4 address's class, global included. The
		// IPv4-compatible and IPv4-translated forms, which the JDK keeps as IPv6, take the IPv4 address's class unless
		// it is OTHER_ADDRESS, and are NON_GLOBAL then. The samples cover every IPv4 class.
		Map<String, HostClass> samples = Map.ofEntries(
				Map.entry("0.1.2.3", HostClass.ANY_LOCAL),
				Map.entry("127.0.0.1", HostClass.LOOPBACK),
				Map.entry("169.254.169.254", HostClass.LINK_LOCAL),
				Map.entry("100.100.100.200", HostClass.CLOUD_METADATA),
				Map.entry("168.63.129.16", HostClass.CLOUD_METADATA),
				Map.entry("10.0.0.1", HostClass.PRIVATE_USE),
				Map.entry("100.64.0.1", HostClass.SHARED_ADDRESS_SPACE),
				Map.entry("192.0.2.1", HostClass.NON_GLOBAL),
				Map.entry("198.18.0.1", HostClass.NON_GLOBAL),
				Map.entry("224.0.0.1", HostClass.MULTICAST_OR_RESERVED),
				Map.entry("255.255.255.255", HostClass.MULTICAST_OR_RESERVED),
				Map.entry("8.8.8.8", HostClass.OTHER_ADDRESS),
				Map.entry("192.0.0.9", HostClass.OTHER_ADDRESS));

		Set<HostClass> covered = EnumSet.noneOf(HostClass.class);
		samples.values().forEach(covered::add);
		Assertions.assertEquals(EnumSet.of(HostClass.ANY_LOCAL, HostClass.LOOPBACK, HostClass.LINK_LOCAL,
				HostClass.CLOUD_METADATA, HostClass.PRIVATE_USE, HostClass.SHARED_ADDRESS_SPACE, HostClass.NON_GLOBAL,
				HostClass.MULTICAST_OR_RESERVED, HostClass.OTHER_ADDRESS), covered, "every IPv4 class is sampled");

		return inKeyOrder(samples).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			String ipv4 = entry.getKey();
			HostClass ipv4Class = entry.getValue();
			HostClass tunneledClass = ipv4Class == HostClass.OTHER_ADDRESS ? HostClass.NON_GLOBAL : ipv4Class;

			Assertions.assertEquals(ipv4Class, HostClassifier.classify(ipv4));

			String mapped = "[::ffff:" + ipv4 + "]";
			Assertions.assertEquals(ipv4Class, HostClassifier.classify(mapped));
			Assertions.assertInstanceOf(Inet4Address.class, InetAddress.getByName(mapped), "the JDK unwraps it");

			String wellKnownPrefix = "[64:ff9b::" + ipv4 + "]";
			Assertions.assertEquals(ipv4Class, HostClassifier.classify(wellKnownPrefix));
			Assertions.assertInstanceOf(Inet6Address.class, InetAddress.getByName(wellKnownPrefix));

			for (String tunneled : List.of("[::" + ipv4 + "]", "[::ffff:0:" + ipv4 + "]")) {
				Assertions.assertEquals(tunneledClass, HostClassifier.classify(tunneled), tunneled);
				Assertions.assertInstanceOf(Inet6Address.class, InetAddress.getByName(tunneled), "the JDK keeps it");
			}

			// The RFC 8215 local-use prefix is rejected as a whole, whatever sits where an IPv4 address might.
			for (String localUse : List.of("[64:ff9b:1::" + ipv4 + "]", "[64:ff9b:1:" + hextets(ipv4) + "::]"))
				Assertions.assertEquals(HostClass.NAT64_LOCAL_USE, HostClassifier.classify(localUse), localUse);
		}));
	}

	@TestFactory
	Stream<DynamicTest> ipv4SpecialPurposeBlocksFollowTheIanaRegistry() {
		// The IANA IPv4 Special-Purpose Address Registry, every entry, as retrieved on 2026-09-27: the block, its
		// "Globally Reachable" value, and the class of its first and last address. A block marked not globally
		// reachable never classifies as OTHER_ADDRESS, and one marked globally reachable always does. The deprecated
		// 6to4 relay anycast block (terminated 2015-03, no value) is non-global as a whole (G8-5).
		List<RegistryRow> rows = List.of(
				ipv4Row("0.0.0.0/8", false, HostClass.ANY_LOCAL, HostClass.ANY_LOCAL),
				ipv4Row("0.0.0.0/32", false, HostClass.ANY_LOCAL, HostClass.ANY_LOCAL),
				ipv4Row("10.0.0.0/8", false, HostClass.PRIVATE_USE, HostClass.PRIVATE_USE),
				ipv4Row("100.64.0.0/10", false, HostClass.SHARED_ADDRESS_SPACE, HostClass.SHARED_ADDRESS_SPACE),
				ipv4Row("127.0.0.0/8", false, HostClass.LOOPBACK, HostClass.LOOPBACK),
				ipv4Row("169.254.0.0/16", false, HostClass.LINK_LOCAL, HostClass.LINK_LOCAL),
				ipv4Row("172.16.0.0/12", false, HostClass.PRIVATE_USE, HostClass.PRIVATE_USE),
				ipv4Row("192.0.0.0/24", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.0.0.0/29", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.0.0.8/32", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.0.0.9/32", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv4Row("192.0.0.10/32", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv4Row("192.0.0.170/32", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.0.0.171/32", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.0.2.0/24", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.31.196.0/24", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv4Row("192.52.193.0/24", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv4Row("192.88.99.0/24", null, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.88.99.2/32", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("192.168.0.0/16", false, HostClass.PRIVATE_USE, HostClass.PRIVATE_USE),
				ipv4Row("192.175.48.0/24", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv4Row("198.18.0.0/15", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("198.51.100.0/24", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("203.0.113.0/24", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv4Row("240.0.0.0/4", false, HostClass.MULTICAST_OR_RESERVED, HostClass.MULTICAST_OR_RESERVED),
				ipv4Row("255.255.255.255/32", false, HostClass.MULTICAST_OR_RESERVED, HostClass.MULTICAST_OR_RESERVED));

		return rows.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			row.assertClasses();
			@Nullable Boolean globallyReachable = row.globallyReachable;
			boolean expectedGlobal = globallyReachable != null && globallyReachable;
			Assertions.assertEquals(expectedGlobal, row.firstClass == HostClass.OTHER_ADDRESS);
			Assertions.assertEquals(expectedGlobal, row.lastClass == HostClass.OTHER_ADDRESS);
		}));
	}

	@TestFactory
	Stream<DynamicTest> ipv6SpecialPurposeBlocksFollowTheIanaRegistryAndTheAllowlist() {
		// The IANA IPv6 Special-Purpose Address Registry, every entry, as retrieved on 2026-09-27: the block, its
		// "Globally Reachable" value, and the class of its first and last address. Where G8-5 departs from the
		// registry, the row says so.
		List<RegistryRow> rows = List.of(
				ipv6Row("::1/128", false, HostClass.LOOPBACK, HostClass.LOOPBACK),
				ipv6Row("::/128", false, HostClass.ANY_LOCAL, HostClass.ANY_LOCAL),
				// IPv4-mapped: judged as the IPv4 address inside, so ::ffff:8.8.8.8 is global like 8.8.8.8.
				ipv6Row("::ffff:0:0/96", false, HostClass.ANY_LOCAL, HostClass.MULTICAST_OR_RESERVED),
				// NAT64 Well-Known Prefix: the IPv4 address's class.
				ipv6Row("64:ff9b::/96", true, HostClass.ANY_LOCAL, HostClass.MULTICAST_OR_RESERVED),
				ipv6Row("64:ff9b:1::/48", false, HostClass.NAT64_LOCAL_USE, HostClass.NAT64_LOCAL_USE),
				ipv6Row("100::/64", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("100:0:0:1::/64", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				// 2001::/23 is non-global as a whole, including the globally reachable assignments inside it; its first
				// address is Teredo's.
				ipv6Row("2001::/23", false, HostClass.TEREDO, HostClass.NON_GLOBAL),
				ipv6Row("2001::/32", null, HostClass.TEREDO, HostClass.TEREDO),
				ipv6Row("2001:1::1/128", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:1::2/128", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:1::3/128", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:2::/48", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:3::/32", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:4:112::/48", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:10::/28", null, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:20::/28", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:30::/28", true, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2001:db8::/32", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("2002::/16", null, HostClass.SIX_TO_FOUR, HostClass.SIX_TO_FOUR),
				ipv6Row("2620:4f:8000::/48", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv6Row("3fff::/20", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("5f00::/16", false, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				// fd00:ec2::23, fd00:ec2::254 and fd20:ce::254 lie between these ends and are CLOUD_METADATA.
				ipv6Row("fc00::/7", false, HostClass.UNIQUE_LOCAL, HostClass.UNIQUE_LOCAL),
				ipv6Row("fe80::/10", false, HostClass.LINK_LOCAL, HostClass.LINK_LOCAL),
				// Not special-purpose entries: the allowlist's own edges and IPv6 multicast.
				ipv6Row("2000::/3", true, HostClass.OTHER_ADDRESS, HostClass.OTHER_ADDRESS),
				ipv6Row("::/3", null, HostClass.ANY_LOCAL, HostClass.NON_GLOBAL),
				ipv6Row("4000::/3", null, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("fe00::/9", null, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("fec0::/10", null, HostClass.NON_GLOBAL, HostClass.NON_GLOBAL),
				ipv6Row("ff00::/8", null, HostClass.MULTICAST_OR_RESERVED, HostClass.MULTICAST_OR_RESERVED));

		return rows.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			row.assertClasses();
			// Fail closed: a block the registry marks not globally reachable never reaches OTHER_ADDRESS at its ends.
			if (Boolean.FALSE.equals(row.globallyReachable)) {
				Assertions.assertNotEquals(HostClass.OTHER_ADDRESS, row.firstClass);
				Assertions.assertNotEquals(HostClass.OTHER_ADDRESS, row.lastClass);
			}
		}));
	}

	@Test
	void everyDigitsAndDotsHostIsALiteralOrInvalid() {
		// M1 plan A-1: a host made only of digits and dots is never treated as a DNS name. The JDK would resolve the
		// ones it cannot parse, so none may pass as a name of any class. Every join of one to four of these parts,
		// with and without a trailing dot, is checked, covering each range boundary and the leading-zero forms.
		List<String> parts = List.of("", "0", "00", "01", "1", "25", "255", "256", "0255", "65535", "65536",
				"16777215", "16777216", "4294967295", "4294967296");
		List<String> hosts = new ArrayList<>(parts);
		Set<HostClass> nameClasses = EnumSet.of(HostClass.HOSTNAME, HostClass.LOCALHOST_NAME, HostClass.LOCAL_NAME,
				HostClass.METADATA_NAME);

		for (int count = 2; count <= 4; ++count) {
			List<String> longer = new ArrayList<>();
			for (String host : hosts)
				if (host.chars().filter(c -> c == '.').count() == count - 2)
					for (String part : parts)
						longer.add(host + "." + part);
			hosts.addAll(longer);
		}

		int literals = 0;

		for (String base : hosts) {
			for (String host : List.of(base, base + ".")) {
				HostClass hostClass = HostClassifier.classify(host);
				Assertions.assertFalse(nameClasses.contains(hostClass), host);
				boolean literal = HostClassifier.parseLiteral(host) != null;
				Assertions.assertEquals(!literal, hostClass == HostClass.INVALID, host);
				if (literal)
					++literals;
			}
		}

		// Sanity: the enumeration reaches both outcomes. The literals are 4^4 dotted quads over {0, 1, 25, 255}, 16 * 6
		// three-part and 4 * 8 two-part forms, and 10 all-digit forms; no trailing-dot form is a literal.
		Assertions.assertEquals(54_240, hosts.size());
		Assertions.assertEquals(256 + 96 + 32 + 10, literals);
	}

	// Loopback http is allowed only to a literal the JDK connects to as loopback. The IPv4-compatible, IPv4-translated
	// and NAT64 forms of 127.0.0.1 classify as LOOPBACK, for rejection, but the JDK connects to them as ordinary IPv6
	// addresses, off the host, so they are not loopback literals. Every literal row is compared with InetAddress, which
	// parses a literal without a resolver.
	@TestFactory
	Stream<DynamicTest> loopbackLiteralsAreExactlyTheOnesTheJdkConnectsToAsLoopback() {
		Map<String, Boolean> hosts = Map.ofEntries(
				Map.entry("127.0.0.1", true),
				Map.entry("127.1", true),
				Map.entry("2130706433", true),
				Map.entry("127.255.255.255", true),
				Map.entry("[::1]", true),
				Map.entry("[0:0:0:0:0:0:0:1]", true),
				Map.entry("[::ffff:127.0.0.1]", true),
				Map.entry("[::FFFF:7f00:1]", true),
				Map.entry("[::ffff:127.1.2.3]", true),
				Map.entry("126.255.255.255", false),
				Map.entry("128.0.0.1", false),
				Map.entry("0.0.0.0", false),
				Map.entry("[::]", false),
				Map.entry("[::2]", false),
				Map.entry("[::127.0.0.1]", false),
				Map.entry("[::7f00:1]", false),
				Map.entry("[::ffff:0:127.0.0.1]", false),
				Map.entry("[64:ff9b::127.0.0.1]", false),
				Map.entry("[64:ff9b::7f00:1]", false),
				Map.entry("[64:ff9b:1::127.0.0.1]", false),
				Map.entry("[::ffff:128.0.0.1]", false),
				Map.entry("[::ffff:10.0.0.1]", false),
				Map.entry("[::feff:127.0.0.1]", false),
				Map.entry("[::fffe:127.0.0.1]", false),
				Map.entry("[1::ffff:127.0.0.1]", false),
				Map.entry("[fe80::1]", false),
				Map.entry("localhost", false),
				Map.entry("example.com", false),
				Map.entry("127.0.0.1.", false),
				Map.entry("[::1%lo0]", false),
				Map.entry("", false));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest("\"" + entry.getKey() + "\"", () -> {
			String host = entry.getKey();

			Assertions.assertEquals(entry.getValue(), HostClassifier.isLoopbackLiteral(host));

			if (HostClassifier.parseLiteral(host) != null)
				Assertions.assertEquals(InetAddress.getByName(host).isLoopbackAddress(),
						HostClassifier.isLoopbackLiteral(host), "the JDK's own loopback test");
		}));
	}

	@TestFactory
	Stream<DynamicTest> plainHttpLoopbackHostsAreLoopbackLiteralsAndExactlyLocalhost() {
		// G8-7: under allowInsecureLoopback(true), plain http goes only to a loopback literal the JDK connects to as
		// loopback, or to exactly "localhost" in any ASCII case with no trailing dot. The JDK sends names under
		// .localhost, and "localhost.", to the platform resolver like any other name. The comparison folds ASCII
		// letters only: the long s (U+017F) upper-cases to S, so a Unicode-aware comparison such as
		// String.equalsIgnoreCase would accept "localhoſt".
		Map<String, Boolean> hosts = Map.ofEntries(
				Map.entry("127.0.0.1", true),
				Map.entry("127.255.255.254", true),
				Map.entry("2130706433", true),
				Map.entry("[::1]", true),
				Map.entry("[::ffff:127.0.0.1]", true),
				Map.entry("[::ffff:127.9.9.9]", true),
				Map.entry("localhost", true),
				Map.entry("LOCALHOST", true),
				Map.entry("LocalHost", true),
				Map.entry("localhost.", false),
				Map.entry("LOCALHOST.", false),
				Map.entry("api.localhost", false),
				Map.entry("localhost.localdomain", false),
				Map.entry("xlocalhost", false),
				Map.entry("localhos", false),
				Map.entry("localhostx", false),
				Map.entry("Kocalhost", false),
				Map.entry("localhostı", false),
				Map.entry("localhoſt", false),
				Map.entry("LOCALHOſT", false),
				Map.entry("[::127.0.0.1]", false),
				Map.entry("[::ffff:0:127.0.0.1]", false),
				Map.entry("[64:ff9b::127.0.0.1]", false),
				Map.entry("0.0.0.0", false),
				Map.entry("[::]", false),
				Map.entry("10.0.0.1", false),
				Map.entry("example.com", false),
				Map.entry("localhost:8080", false),
				Map.entry("", false));

		return inKeyOrder(hosts).map(entry -> DynamicTest.dynamicTest("\"" + entry.getKey() + "\"", () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.isPlainHttpLoopbackHost(entry.getKey()))));
	}

	@Test
	void parseLiteralReturnsAFreshArray() {
		byte @Nullable [] first = HostClassifier.parseLiteral("[::1]");
		byte @Nullable [] second = HostClassifier.parseLiteral("[::1]");

		Assertions.assertNotNull(first);
		Assertions.assertNotNull(second);
		Assertions.assertNotSame(first, second);
	}

	@Test
	void nullHostsThrowNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> HostClassifier.classify(nullString()));
		Assertions.assertThrows(NullPointerException.class, () -> HostClassifier.parseLiteral(nullString()));
		Assertions.assertThrows(NullPointerException.class, () -> HostClassifier.isLoopbackLiteral(nullString()));
		Assertions.assertThrows(NullPointerException.class, () -> HostClassifier.isPlainHttpLoopbackHost(nullString()));
	}

	/**
	 * One transcribed registry entry: a block, its "Globally Reachable" value ({@code null} where the registry gives
	 * none), and the expected classes of its first and last address.
	 */
	private static final class RegistryRow {
		private final String block;
		private final @Nullable Boolean globallyReachable;
		private final String firstHost;
		private final String lastHost;
		private final HostClass firstClass;
		private final HostClass lastClass;

		private RegistryRow(String block, @Nullable Boolean globallyReachable, String firstHost, String lastHost,
				HostClass firstClass, HostClass lastClass) {
			this.block = block;
			this.globallyReachable = globallyReachable;
			this.firstHost = firstHost;
			this.lastHost = lastHost;
			this.firstClass = firstClass;
			this.lastClass = lastClass;
		}

		private void assertClasses() throws Exception {
			for (String host : List.of(this.firstHost, this.lastHost))
				Assertions.assertArrayEquals(toSixteenBytes(InetAddress.getByName(host).getAddress()),
						toSixteenBytes(HostClassifier.parseLiteral(host)), () -> host + " parses as the JDK parses it");

			Assertions.assertEquals(this.firstClass, HostClassifier.classify(this.firstHost), this.firstHost);
			Assertions.assertEquals(this.lastClass, HostClassifier.classify(this.lastHost), this.lastHost);
		}

		@Override
		public String toString() {
			return this.block + " (" + this.firstHost + " .. " + this.lastHost + ")";
		}
	}

	/**
	 * A dotted-quad block {@code a.b.c.d/n}: its first and last addresses as dotted quads.
	 */
	private static RegistryRow ipv4Row(String block, @Nullable Boolean globallyReachable, HostClass firstClass,
			HostClass lastClass) {
		String[] parts = block.split("/", -1);
		byte @Nullable [] base = HostClassifier.parseLiteral(parts[0]);
		Assertions.assertNotNull(base, block);
		long value = new BigInteger(1, base).longValueExact();
		int hostBits = 32 - Integer.parseInt(parts[1]);
		long first = value >>> hostBits << hostBits;
		Assertions.assertEquals(value, first, () -> block + " is not a block base");
		long last = first | ((1L << hostBits) - 1);
		return new RegistryRow(block, globallyReachable, dottedQuad(first), dottedQuad(last), firstClass, lastClass);
	}

	/**
	 * An IPv6 block {@code address/n}: its first and last addresses in full bracketed form.
	 */
	private static RegistryRow ipv6Row(String block, @Nullable Boolean globallyReachable, HostClass firstClass,
			HostClass lastClass) {
		String[] parts = block.split("/", -1);
		byte @Nullable [] base = HostClassifier.parseLiteral("[" + parts[0] + "]");
		Assertions.assertNotNull(base, block);
		BigInteger value = new BigInteger(1, base);
		int hostBits = 128 - Integer.parseInt(parts[1]);
		BigInteger first = value.shiftRight(hostBits).shiftLeft(hostBits);
		Assertions.assertEquals(value, first, () -> block + " is not a block base");
		BigInteger last = first.or(BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE));
		return new RegistryRow(block, globallyReachable, fullIpv6(first), fullIpv6(last), firstClass, lastClass);
	}

	private static String dottedQuad(long value) {
		return ((value >>> 24) & 0xFF) + "." + ((value >>> 16) & 0xFF) + "." + ((value >>> 8) & 0xFF) + "."
				+ (value & 0xFF);
	}

	private static String fullIpv6(BigInteger value) {
		StringBuilder text = new StringBuilder("[");
		for (int i = 7; i >= 0; --i) {
			text.append(Integer.toHexString(value.shiftRight(16 * i).intValue() & 0xFFFF));
			text.append(i == 0 ? ']' : ':');
		}
		return text.toString();
	}

	/**
	 * The two 16-bit groups of a dotted quad, in hexadecimal: {@code 169.254.169.254} is {@code a9fe:a9fe}.
	 */
	private static String hextets(String dottedQuad) {
		byte @Nullable [] address = HostClassifier.parseLiteral(dottedQuad);
		Assertions.assertNotNull(address);
		return Integer.toHexString(((address[0] & 0xFF) << 8) | (address[1] & 0xFF)) + ":"
				+ Integer.toHexString(((address[2] & 0xFF) << 8) | (address[3] & 0xFF));
	}

	/**
	 * Returns 16 bytes: an IPv6 address as is, an IPv4 address in IPv4-mapped form ({@code ::ffff:a.b.c.d}).
	 */
	private static byte[] toSixteenBytes(byte @Nullable [] address) {
		Assertions.assertNotNull(address);
		if (address.length == 16)
			return address.clone();

		Assertions.assertEquals(4, address.length);
		byte[] mapped = new byte[16];
		mapped[10] = (byte) 0xFF;
		mapped[11] = (byte) 0xFF;
		System.arraycopy(address, 0, mapped, 12, 4);
		return mapped;
	}

	private static String dotted(byte @Nullable [] address) {
		Assertions.assertNotNull(address);
		Assertions.assertEquals(4, address.length);
		return (address[0] & 0xFF) + "." + (address[1] & 0xFF) + "." + (address[2] & 0xFF) + "." + (address[3] & 0xFF);
	}

	private static String groups(byte @Nullable [] address) {
		Assertions.assertNotNull(address);
		Assertions.assertEquals(16, address.length);
		StringBuilder text = new StringBuilder();
		for (int i = 0; i < 16; i += 2) {
			if (i > 0)
				text.append(':');
			text.append(Integer.toHexString(((address[i] & 0xFF) << 8) | (address[i + 1] & 0xFF)));
		}
		return text.toString();
	}

	@SuppressWarnings("NullAway")
	private static String nullString() {
		return null;
	}

	/**
	 * The table's rows in key order, so that its dynamic tests have the same order and numbering in every JVM (PIT
	 * reselects a dynamic test by its position, and {@code Map.of} iterates in a per-JVM order).
	 */
	private static <V> Stream<Map.Entry<String, V>> inKeyOrder(Map<String, V> table) {
		return table.entrySet().stream().sorted(Map.Entry.comparingByKey());
	}
}
