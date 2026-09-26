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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The literal parser and host classifier behind {@code OutboundUriPolicy} (M1 plan A-1; RFC 4291 section 2.2,
 * RFC 1123 section 2.1, RFC 6761 section 6.3). The address-class table that is compared with the JDK lives in
 * {@code OutboundUriPolicyTests}; these are the parser's edge cases, none of which reaches a resolver (the loopback
 * test compares with {@code InetAddress} only for literals, which it parses without one).
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

		return forms.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), dotted(HostClassifier.parseLiteral(entry.getKey())))));
	}

	@TestFactory
	Stream<DynamicTest> malformedIpv4FormsAreNotLiterals() {
		// Out of range, too many parts, empty parts, leading zeros (ambiguous with BSD octal), signs and other digits.
		List<String> forms = List.of("", ".", "..", "1.", ".1", "1..1", "1.2.3.4.", "1.2.3.4.5", "256.0.0.0",
				"0.256.0.0", "1.2.3.256", "1.2.65536", "1.16777216", "4294967296", "99999999999", "18446744073709551616",
				"00", "01", "010.0.0.1", "1.02.3.4", "1.2.3.04", "0x1", "0x7f.0.0.1", "1.2.3.0x4", "+1", "-1", "1.-2.3.4",
				"1 .2.3.4", " 1.2.3.4", "1.2.3.4 ", "\u0661.2.3.4", "\uFF11.2.3.4", "1\u00B2.2.3.4", "0000000000000001");

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
				Map.entry("[::1.2.3.4]", "0:0:0:0:0:0:102:304"),
				Map.entry("[1:2:3:4:5:6:255.255.255.255]", "1:2:3:4:5:6:ffff:ffff"),
				Map.entry("[1::0.0.0.0]", "1:0:0:0:0:0:0:0"),
				Map.entry("[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));

		return forms.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
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
				"[ ::1]", "[::\u0661]", "[::\uFF11]", "[1:2:3:4:5:6:7:8:1.2.3.4]", "[1:2:3:4:5:6:7:8:9:0]",
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
		Map<String, HostClass> hosts = Map.ofEntries(
				Map.entry("a", HostClass.HOSTNAME),
				Map.entry("a-b.example", HostClass.HOSTNAME),
				Map.entry("xn--bcher-kva.example", HostClass.HOSTNAME),
				Map.entry("1a.example", HostClass.HOSTNAME),
				Map.entry("example.1a", HostClass.HOSTNAME),
				Map.entry("0x7g", HostClass.HOSTNAME),
				Map.entry("0a", HostClass.HOSTNAME),
				Map.entry("example.0a", HostClass.HOSTNAME),
				Map.entry("example.0x", HostClass.INVALID),
				Map.entry("1e2", HostClass.HOSTNAME),
				Map.entry(label63 + ".example", HostClass.HOSTNAME),
				Map.entry(name253, HostClass.HOSTNAME),
				Map.entry(name253 + ".", HostClass.HOSTNAME),
				Map.entry("a".repeat(64) + ".example", HostClass.INVALID),
				Map.entry(name253 + "a", HostClass.INVALID),
				Map.entry("-a.example", HostClass.INVALID),
				Map.entry("a-.example", HostClass.INVALID),
				Map.entry("a..example", HostClass.INVALID),
				Map.entry(".example", HostClass.INVALID),
				Map.entry("example..", HostClass.INVALID),
				Map.entry("under_score.example", HostClass.INVALID),
				Map.entry("space .example", HostClass.INVALID),
				Map.entry("ex\u00E4mple.com", HostClass.INVALID),
				Map.entry("xn--nxasmq6b.\u0441\u043E\u043C", HostClass.INVALID),
				Map.entry("localho\u017Ft", HostClass.INVALID),
				Map.entry("user@example.com", HostClass.INVALID),
				Map.entry("example.com:443", HostClass.INVALID),
				Map.entry("%31.example", HostClass.INVALID));

		return hosts.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
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
				Map.entry("xlocalhost", HostClass.HOSTNAME),
				Map.entry("localhost.example", HostClass.HOSTNAME),
				Map.entry("localhos", HostClass.HOSTNAME),
				Map.entry("\u212Aocalhost", HostClass.INVALID),
				Map.entry("localhost\u0131", HostClass.INVALID));

		return hosts.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				Assertions.assertEquals(entry.getValue(), HostClassifier.classify(entry.getKey()))));
	}

	@Test
	void everyDigitsAndDotsHostIsALiteralOrInvalid() {
		// M1 plan A-1: a host made only of digits and dots is never treated as a DNS name. The JDK would resolve the
		// ones it cannot parse, so none may pass as a hostname. Every join of one to four of these parts, with and
		// without a trailing dot, is checked, covering each range boundary and the leading-zero forms.
		List<String> parts = List.of("", "0", "00", "01", "1", "25", "255", "256", "0255", "65535", "65536",
				"16777215", "16777216", "4294967295", "4294967296");
		List<String> hosts = new ArrayList<>(parts);

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
				Assertions.assertNotEquals(HostClass.HOSTNAME, hostClass, host);
				Assertions.assertNotEquals(HostClass.LOCALHOST_NAME, hostClass, host);
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

	// Loopback http is allowed only to a literal the JDK connects to as loopback. The IPv4-compatible and NAT64 forms of
	// 127.0.0.1 classify as LOOPBACK, for rejection, but the JDK connects to them as ordinary IPv6 addresses, off the
	// host, so they are not loopback literals. Every literal row is compared with InetAddress, which parses a literal
	// without a resolver.
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
				Map.entry("[64:ff9b::127.0.0.1]", false),
				Map.entry("[64:ff9b::7f00:1]", false),
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

		return hosts.entrySet().stream().map(entry -> DynamicTest.dynamicTest("\"" + entry.getKey() + "\"", () -> {
			String host = entry.getKey();

			Assertions.assertEquals(entry.getValue(), HostClassifier.isLoopbackLiteral(host));

			if (HostClassifier.parseLiteral(host) != null)
				Assertions.assertEquals(InetAddress.getByName(host).isLoopbackAddress(),
						HostClassifier.isLoopbackLiteral(host), "the JDK's own loopback test");
		}));
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
}
