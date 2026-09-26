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

package com.revetsec;

import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.HostClassifier.HostClass;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

/**
 * The provisional outbound URI policy and its address-class table (M1 plan A-1 and "OutboundUriPolicy", exit
 * criterion 15; plan R12, D35).
 * <p>
 * Every literal row is also parsed by {@link InetAddress#getByName(String)}, which must agree with Revetsec's own
 * parser. Only strings that Revetsec parses as literals are passed to it, and the JDK parses each of those
 * numerically too, so these tests never perform a DNS lookup.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class OutboundUriPolicyTests {
	/**
	 * One row of the address-class table: a URI host (IPv6 in brackets), its class, and whether
	 * {@code defaultInstance()} permits {@code https://<host>/}. {@code uriHasHost} is false where
	 * {@link URI#getHost()} itself cannot parse the host, which the policy then rejects whatever the class.
	 */
	private static final class Row {
		private final String host;
		private final HostClass hostClass;
		private final boolean permittedByDefault;
		private final boolean uriHasHost;

		private Row(String host, HostClass hostClass, boolean permittedByDefault, boolean uriHasHost) {
			this.host = host;
			this.hostClass = hostClass;
			this.permittedByDefault = permittedByDefault;
			this.uriHasHost = uriHasHost;
		}

		@Override
		public String toString() {
			return this.host + " -> " + this.hostClass;
		}
	}

	private static Row permitted(String host, HostClass hostClass) {
		return new Row(host, hostClass, true, true);
	}

	private static Row rejected(String host, HostClass hostClass) {
		return new Row(host, hostClass, false, true);
	}

	/**
	 * A row whose host {@link URI} cannot parse, so {@code https://<host>/} is rejected even when the class alone
	 * would be permitted.
	 */
	private static Row withoutUriHost(String host, HostClass hostClass) {
		return new Row(host, hostClass, false, false);
	}

	/**
	 * Literal rows: Revetsec parses each one, and so does {@link InetAddress#getByName(String)}.
	 */
	private static final List<Row> LITERAL_ROWS = List.of(
			// Dotted quad.
			permitted("8.8.8.8", HostClass.OTHER_ADDRESS),
			permitted("1.0.0.0", HostClass.OTHER_ADDRESS),
			rejected("0.0.0.0", HostClass.ANY_LOCAL),
			rejected("0.255.255.255", HostClass.ANY_LOCAL),
			permitted("127.0.0.1", HostClass.LOOPBACK),
			permitted("127.255.255.255", HostClass.LOOPBACK),
			permitted("126.255.255.255", HostClass.OTHER_ADDRESS),
			permitted("128.0.0.0", HostClass.OTHER_ADDRESS),
			rejected("169.254.169.254", HostClass.LINK_LOCAL),
			rejected("169.254.0.0", HostClass.LINK_LOCAL),
			rejected("169.254.255.255", HostClass.LINK_LOCAL),
			permitted("169.253.255.255", HostClass.OTHER_ADDRESS),
			permitted("169.255.0.0", HostClass.OTHER_ADDRESS),
			permitted("10.0.0.1", HostClass.PRIVATE_USE),
			permitted("9.255.255.255", HostClass.OTHER_ADDRESS),
			permitted("11.0.0.0", HostClass.OTHER_ADDRESS),
			permitted("172.16.0.0", HostClass.PRIVATE_USE),
			permitted("172.31.255.255", HostClass.PRIVATE_USE),
			permitted("172.15.255.255", HostClass.OTHER_ADDRESS),
			permitted("172.32.0.0", HostClass.OTHER_ADDRESS),
			permitted("192.168.0.1", HostClass.PRIVATE_USE),
			permitted("192.167.255.255", HostClass.OTHER_ADDRESS),
			permitted("192.169.0.0", HostClass.OTHER_ADDRESS),
			permitted("100.64.0.0", HostClass.SHARED_ADDRESS_SPACE),
			permitted("100.127.255.255", HostClass.SHARED_ADDRESS_SPACE),
			permitted("100.63.255.255", HostClass.OTHER_ADDRESS),
			permitted("100.128.0.0", HostClass.OTHER_ADDRESS),
			permitted("255.255.255.255", HostClass.OTHER_ADDRESS),
			// All-digit: the whole address as one number (2852039166 is 169.254.169.254).
			rejected("2852039166", HostClass.LINK_LOCAL),
			rejected("0", HostClass.ANY_LOCAL),
			rejected("123", HostClass.ANY_LOCAL),
			permitted("2130706433", HostClass.LOOPBACK),
			permitted("167772161", HostClass.PRIVATE_USE),
			permitted("4294967295", HostClass.OTHER_ADDRESS),
			// Short-dotted: the last part fills the remaining bytes. URI cannot parse these hosts at all.
			withoutUriHost("127.1", HostClass.LOOPBACK),
			withoutUriHost("127.0.1", HostClass.LOOPBACK),
			withoutUriHost("169.254.43518", HostClass.LINK_LOCAL),
			withoutUriHost("169.16689662", HostClass.LINK_LOCAL),
			withoutUriHost("10.1", HostClass.PRIVATE_USE),
			withoutUriHost("192.168.257", HostClass.PRIVATE_USE),
			withoutUriHost("100.64.1", HostClass.SHARED_ADDRESS_SPACE),
			withoutUriHost("0.1", HostClass.ANY_LOCAL),
			// IPv6.
			rejected("[::]", HostClass.ANY_LOCAL),
			rejected("[0:0:0:0:0:0:0:0]", HostClass.ANY_LOCAL),
			permitted("[::1]", HostClass.LOOPBACK),
			permitted("[0:0:0:0:0:0:0:1]", HostClass.LOOPBACK),
			rejected("[fe80::1]", HostClass.LINK_LOCAL),
			rejected("[FE80::1]", HostClass.LINK_LOCAL),
			rejected("[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.LINK_LOCAL),
			permitted("[fe7f::1]", HostClass.OTHER_ADDRESS),
			permitted("[fec0::1]", HostClass.OTHER_ADDRESS),
			rejected("[fd00:ec2::254]", HostClass.CLOUD_METADATA),
			rejected("[fd00:0ec2:0000:0000:0000:0000:0000:0254]", HostClass.CLOUD_METADATA),
			permitted("[fd00:ec2::253]", HostClass.UNIQUE_LOCAL),
			permitted("[fd00:ec2::1:254]", HostClass.UNIQUE_LOCAL),
			permitted("[fc00::1]", HostClass.UNIQUE_LOCAL),
			permitted("[fdff:ffff::1]", HostClass.UNIQUE_LOCAL),
			permitted("[fbff::1]", HostClass.OTHER_ADDRESS),
			permitted("[fe00::1]", HostClass.OTHER_ADDRESS),
			permitted("[2002:a9fe:a9fe::1]", HostClass.SIX_TO_FOUR),
			permitted("[2001:0:4136:e378:8000:63bf:3fff:fdd2]", HostClass.TEREDO),
			permitted("[2001:1::1]", HostClass.OTHER_ADDRESS),
			permitted("[2001:db8::1]", HostClass.OTHER_ADDRESS),
			permitted("[2606:4700:4700::1111]", HostClass.OTHER_ADDRESS),
			permitted("[1:2:3:4:5:6:7:8]", HostClass.OTHER_ADDRESS),
			permitted("[1:2:3:4:5:6:7::]", HostClass.OTHER_ADDRESS),
			permitted("[::2:3:4:5:6:7:8]", HostClass.OTHER_ADDRESS),
			permitted("[1:2:3:4:5:6:1.2.3.4]", HostClass.OTHER_ADDRESS),
			// IPv4-mapped (::ffff:0:0/96): classified as the IPv4 address inside, which the JDK connects to.
			rejected("[::ffff:169.254.169.254]", HostClass.LINK_LOCAL),
			rejected("[::ffff:a9fe:a9fe]", HostClass.LINK_LOCAL),
			rejected("[::FFFF:A9FE:A9FE]", HostClass.LINK_LOCAL),
			rejected("[0:0:0:0:0:ffff:169.254.169.254]", HostClass.LINK_LOCAL),
			rejected("[::ffff:0.0.0.0]", HostClass.ANY_LOCAL),
			permitted("[::ffff:127.0.0.1]", HostClass.LOOPBACK),
			permitted("[::ffff:7f00:1]", HostClass.LOOPBACK),
			permitted("[::ffff:10.0.0.1]", HostClass.PRIVATE_USE),
			permitted("[::ffff:100.64.0.1]", HostClass.SHARED_ADDRESS_SPACE),
			permitted("[::ffff:8.8.8.8]", HostClass.OTHER_ADDRESS),
			// IPv4-compatible (::/96, except :: and ::1).
			rejected("[::169.254.169.254]", HostClass.LINK_LOCAL),
			rejected("[::a9fe:a9fe]", HostClass.LINK_LOCAL),
			rejected("[::0.0.0.2]", HostClass.ANY_LOCAL),
			rejected("[::2]", HostClass.ANY_LOCAL),
			rejected("[::ffff]", HostClass.ANY_LOCAL),
			permitted("[::127.0.0.1]", HostClass.LOOPBACK),
			permitted("[::10.0.0.1]", HostClass.PRIVATE_USE),
			permitted("[::8.8.8.8]", HostClass.OTHER_ADDRESS),
			// NAT64 (64:ff9b::/96, RFC 6052).
			rejected("[64:ff9b::169.254.169.254]", HostClass.LINK_LOCAL),
			rejected("[64:ff9b::a9fe:a9fe]", HostClass.LINK_LOCAL),
			rejected("[64:ff9b::0.0.0.0]", HostClass.ANY_LOCAL),
			permitted("[64:ff9b::127.0.0.1]", HostClass.LOOPBACK),
			permitted("[64:ff9b::8.8.8.8]", HostClass.OTHER_ADDRESS),
			// Outside the three unwrapped prefixes: the NAT64 local-use prefix (RFC 8215) and SIIT (RFC 2765). Gate 8.
			permitted("[64:ff9b:1::a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[::ffff:0:a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[64:ff9b::1:a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			// Near misses, one byte off each prefix, so every byte of every prefix comparison is pinned.
			permitted("[::fffe:a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[::ff:a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[::1:ffff:a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[64:ff9a::a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[64:fe9b::a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[65:ff9b::a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[164:ff9b::a9fe:a9fe]", HostClass.OTHER_ADDRESS),
			permitted("[fd01:ec2::254]", HostClass.UNIQUE_LOCAL),
			permitted("[fc00:ec2::254]", HostClass.UNIQUE_LOCAL),
			permitted("[fd00:fc2::254]", HostClass.UNIQUE_LOCAL),
			permitted("[fd00:ec3::254]", HostClass.UNIQUE_LOCAL),
			permitted("[fd00:ec2::354]", HostClass.UNIQUE_LOCAL),
			permitted("[fd00:ec2:0:0:1::254]", HostClass.UNIQUE_LOCAL),
			permitted("[2000::1]", HostClass.OTHER_ADDRESS),
			permitted("[2003::1]", HostClass.OTHER_ADDRESS),
			permitted("[2001:100::1]", HostClass.OTHER_ADDRESS),
			permitted("[2102::1]", HostClass.OTHER_ADDRESS));

	static {
		// Keeps the no-DNS promise: every literal row is a digits-and-dots IPv4 form or a bracketed IPv6 form, the only
		// shapes the JDK parses numerically, and it is checked before any row reaches InetAddress.getByName.
		for (Row row : LITERAL_ROWS)
			if (!row.host.startsWith("[") && !row.host.chars().allMatch(c -> c == '.' || (c >= '0' && c <= '9')))
				throw new IllegalStateException("Not a numeric literal row: " + row.host);
	}

	/**
	 * Rows that are not strict literals and are rejected. None is passed to {@link InetAddress#getByName(String)},
	 * because the JDK would send several of them to DNS.
	 */
	private static final List<Row> INVALID_ROWS = List.of(
			// Digits and dots that do not parse (the JDK would look these up in DNS).
			rejected("4294967296", HostClass.INVALID),
			withoutUriHost("1.2.3.4.5", HostClass.INVALID),
			withoutUriHost("256.1.1.1", HostClass.INVALID),
			withoutUriHost("1.2.3.256", HostClass.INVALID),
			withoutUriHost("1.2.65536", HostClass.INVALID),
			withoutUriHost("1.16777216", HostClass.INVALID),
			withoutUriHost("127.0.0.1.", HostClass.INVALID),
			withoutUriHost("1..2", HostClass.INVALID),
			// Leading zeros: the JDK reads 010.1.1.1 as decimal and BSD inet_aton as octal. 0251.254.169.254 is too long
			// for the JDK's literal parser, so the JDK asks the platform resolver, and inet_aton reads it as
			// 169.254.169.254.
			rejected("0251.254.169.254", HostClass.INVALID),
			rejected("010.1.1.1", HostClass.INVALID),
			rejected("0177.0.0.1", HostClass.INVALID),
			rejected("127.0.0.01", HostClass.INVALID),
			rejected("00", HostClass.INVALID),
			rejected("0127", HostClass.INVALID),
			// Hexadecimal and other numeric-looking hosts. The JDK's literal parser rejects them and asks the platform
			// resolver, and the macOS resolver reads 0xa9fea9fe as 169.254.169.254. A single label with a trailing
			// dot is still a URI host, so it reaches the classifier.
			rejected("0x7f000001", HostClass.INVALID),
			rejected("0x7f000001.", HostClass.INVALID),
			rejected("0xA9FEA9FE", HostClass.INVALID),
			rejected("2852039166.", HostClass.INVALID),
			rejected("0.", HostClass.INVALID),
			rejected("0000000001.0.0.1", HostClass.INVALID),
			rejected("0X7F000001", HostClass.INVALID),
			rejected("0xa9fea9fe", HostClass.INVALID),
			rejected("0x", HostClass.INVALID),
			withoutUriHost("0x7f.1", HostClass.INVALID),
			withoutUriHost("1.2.3.0x4", HostClass.INVALID),
			withoutUriHost("example.123", HostClass.INVALID),
			withoutUriHost("example.0x1", HostClass.INVALID),
			// Malformed or zone-scoped IPv6.
			rejected("[fe80::1%25en0]", HostClass.INVALID),
			rejected("[fe80::1%251]", HostClass.INVALID),
			rejected("[2001:db8::1%25eth0]", HostClass.INVALID));

	/**
	 * DNS names: never resolved, so each passes whatever its DNS answer would be.
	 */
	private static final List<Row> HOSTNAME_ROWS = List.of(
			permitted("example.com", HostClass.HOSTNAME),
			permitted("EXAMPLE.com", HostClass.HOSTNAME),
			permitted("example.com.", HostClass.HOSTNAME),
			permitted("metadata.google.internal", HostClass.HOSTNAME),
			permitted("revetsec-never-resolved.invalid", HostClass.HOSTNAME),
			permitted("xn--bcher-kva.example", HostClass.HOSTNAME),
			permitted("4.3.2.1.example", HostClass.HOSTNAME),
			permitted("1e2", HostClass.HOSTNAME),
			permitted("deadbeef", HostClass.HOSTNAME),
			permitted("localhost", HostClass.LOCALHOST_NAME),
			permitted("LOCALHOST", HostClass.LOCALHOST_NAME),
			permitted("localhost.", HostClass.LOCALHOST_NAME),
			permitted("api.localhost", HostClass.LOCALHOST_NAME),
			permitted("notlocalhost", HostClass.HOSTNAME),
			permitted("localhost.example", HostClass.HOSTNAME));

	@TestFactory
	Stream<DynamicTest> literalRowsAreClassifiedAndAgreeWithTheJdkParser() {
		// Exit criterion 15: every literal row agrees with InetAddress.getByName.
		return LITERAL_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			byte @Nullable [] parsed = HostClassifier.parseLiteral(row.host);
			Assertions.assertNotNull(parsed, "Revetsec did not parse the literal");

			InetAddress jdkAddress = InetAddress.getByName(row.host);
			// A literal's InetAddress has no hostname of its own; a resolved name would keep it.
			Assertions.assertEquals("/" + jdkAddress.getHostAddress(), jdkAddress.toString(),
					"the JDK did not parse the host numerically");
			Assertions.assertArrayEquals(toSixteenBytes(jdkAddress.getAddress()), toSixteenBytes(parsed));

			Assertions.assertEquals(row.hostClass, HostClassifier.classify(row.host));
			assertAgreesWithJdkPredicates(row.hostClass, jdkAddress);
			assertDefaultPolicy(row);
		}));
	}

	@TestFactory
	Stream<DynamicTest> hostsThatLookNumericButAreNotStrictLiteralsAreRejected() {
		// M1 plan A-1: a host made only of digits and dots that does not parse is rejected. Ambiguous forms that the
		// JDK and BSD inet_aton read differently are rejected too, without asking DNS.
		return INVALID_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(row.host));
			Assertions.assertEquals(HostClass.INVALID, HostClassifier.classify(row.host));
			assertDefaultPolicy(row);
		}));
	}

	@TestFactory
	Stream<DynamicTest> hostnamesPassUnresolved() {
		// M1 plan A-1: hostnames are never resolved, so a name that points at a metadata address still passes. The
		// protection there is https plus an egress proxy on an injected client.
		return HOSTNAME_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(row.host));
			Assertions.assertEquals(row.hostClass, HostClassifier.classify(row.host));
			assertDefaultPolicy(row);
		}));
	}

	@Test
	void thePlanExamplesAreRejected() {
		// M1 plan A-1: https://0/ resolves to 0.0.0.0, and [::] is any-local.
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();

		for (String uri : List.of("https://0/", "https://[::]/", "https://2852039166/latest/meta-data/",
				"https://169.254.169.254/latest/meta-data/", "https://[fd00:ec2::254]/latest/meta-data/",
				"https://[::ffff:169.254.169.254]/", "https://[64:ff9b::169.254.169.254]/", "https://127.1/",
				"https://169.254.43518/"))
			Assertions.assertFalse(policy.permits(URI.create(uri)), uri);
	}

	@Test
	void onlyAbsoluteHttpAndHttpsUrisWithAHostArePermitted() {
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();

		for (String uri : List.of("https://example.com/", "HTTPS://example.com/", "http://127.0.0.1:8080/callback",
				"Http://[::1]:8443/", "https://user@example.com:8443/path?query#fragment"))
			Assertions.assertTrue(policy.permits(URI.create(uri)), uri);

		for (String uri : List.of("ftp://example.com/", "file:///etc/passwd", "jar:file:/x.jar!/", "ldap://example.com/",
				"mailto:someone@example.com", "https:example.com", "//example.com/", "/relative", "https:///path",
				"https://under_score.example/", "https://-leading-hyphen.example/", "httpsx://example.com/",
				"htt1://example.com/", "http5://example.com/", "HTTPZ://example.com/"))
			Assertions.assertFalse(policy.permits(URI.create(uri)), uri);
	}

	@Test
	void theDefaultInstanceIsShared() {
		Assertions.assertSame(OutboundUriPolicy.defaultInstance(), OutboundUriPolicy.defaultInstance());
		Assertions.assertEquals("OutboundUriPolicy{name=default}", OutboundUriPolicy.defaultInstance().toString());
	}

	@Test
	void aNullUriThrowsNullPointerException() {
		// Plan R15: misuse throws NPE.
		Assertions.assertThrows(NullPointerException.class, () -> OutboundUriPolicy.defaultInstance().permits(
				nullUri()));
	}

	@Test
	void thePolicyNeverReferencesTheJdkResolver() throws IOException {
		// M1 plan A-1: hostnames are never resolved. No class on the policy's path may even link InetAddress.
		for (Class<?> type : List.of(OutboundUriPolicy.class, HostClassifier.class, HostClass.class)) {
			String constantPool;

			String classFile = type.getName().substring(type.getPackageName().length() + 1) + ".class";

			try (InputStream input = type.getResourceAsStream(classFile)) {
				Assertions.assertNotNull(input, type::getName);
				constantPool = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);
			}

			for (String resolver : List.of("java/net/InetAddress", "java/net/Inet4Address", "java/net/Inet6Address",
					"java/net/InetSocketAddress", "getByName", "getAllByName"))
				Assertions.assertFalse(constantPool.contains(resolver), () -> type.getName() + " references " + resolver);
		}
	}

	private static void assertDefaultPolicy(Row row) {
		URI uri = URI.create("https://" + row.host + "/");
		Assertions.assertEquals(row.uriHasHost, uri.getHost() != null, "URI.getHost() presence");
		Assertions.assertEquals(row.permittedByDefault, OutboundUriPolicy.defaultInstance().permits(uri),
				"defaultInstance().permits(" + uri + ")");
	}

	/**
	 * Checks the class against the JDK's own predicates where they apply to the address the JDK returned. The JDK
	 * returns IPv4-mapped addresses as {@link Inet4Address}, but keeps IPv4-compatible and NAT64 addresses as IPv6
	 * and has no predicate for most of Revetsec's classes, so only the overlapping cases are compared.
	 */
	private static void assertAgreesWithJdkPredicates(HostClass hostClass, InetAddress jdkAddress) {
		if (jdkAddress.isLoopbackAddress())
			Assertions.assertEquals(HostClass.LOOPBACK, hostClass);
		if (jdkAddress.isLinkLocalAddress())
			Assertions.assertEquals(HostClass.LINK_LOCAL, hostClass);
		if (jdkAddress.isAnyLocalAddress())
			Assertions.assertEquals(HostClass.ANY_LOCAL, hostClass);
		if (jdkAddress instanceof Inet4Address && jdkAddress.isSiteLocalAddress())
			Assertions.assertEquals(HostClass.PRIVATE_USE, hostClass);
	}

	/**
	 * Returns 16 bytes: an IPv6 address as is, an IPv4 address in IPv4-mapped form ({@code ::ffff:a.b.c.d}).
	 */
	private static byte[] toSixteenBytes(byte[] address) {
		if (address.length == 16)
			return address.clone();

		Assertions.assertEquals(4, address.length);
		byte[] mapped = new byte[16];
		mapped[10] = (byte) 0xFF;
		mapped[11] = (byte) 0xFF;
		System.arraycopy(address, 0, mapped, 12, 4);
		return mapped;
	}

	@SuppressWarnings("NullAway")
	private static URI nullUri() {
		return null;
	}
}
