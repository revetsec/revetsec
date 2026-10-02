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

import org.jspecify.annotations.NonNull;

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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The outbound URI policy's two presets and their address-class table (plan R12, D35; gate 8, G8-5 to G8-7; M1 exit
 * criterion 15 and M2 exit criterion 18; the owner's decisions of 2026-09-27 on Google Compute Engine's IPv6 metadata
 * address, the unconfirmed metadata leads, and every name under arpa).
 * <p>
 * Every literal row is also parsed by {@link InetAddress#getByName(String)}, which must agree with Revetsec's own
 * parser. Only strings that Revetsec parses as literals are passed to it, and the JDK parses each of those
 * numerically too, so these tests never perform a DNS lookup.
 * <p>
 * Each row names a host and its class. Whether each preset permits {@code https://<host>/} follows from
 * {@link #PRESET_TABLE}, a transcription of the gate 8 table ("OutboundUriPolicy (final)"), never from the policy's
 * own sets.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class OutboundUriPolicyTests {
	/**
	 * One row of the address-class table: a URI host (IPv6 in brackets) and its class. {@code uriHasHost} is false
	 * where {@link URI#getHost()} itself cannot parse the host, which both presets then reject whatever the class.
	 */
	private static final class Row {
		private final String host;
		private final HostClass hostClass;
		private final boolean uriHasHost;

		private Row(@NonNull String host, @NonNull HostClass hostClass, boolean uriHasHost) {
			this.host = host;
			this.hostClass = hostClass;
			this.uriHasHost = uriHasHost;
		}

		@Override
		public @NonNull String toString() {
			return this.host + " -> " + this.hostClass;
		}
	}

	/**
	 * What the two presets do with one class: {@code defaultInstance()} and {@code publicAddressesOnlyInstance()}.
	 */
	private static final class Decision {
		private final boolean permittedByDefault;
		private final boolean permittedByPublicAddressesOnly;

		private Decision(boolean permittedByDefault, boolean permittedByPublicAddressesOnly) {
			this.permittedByDefault = permittedByDefault;
			this.permittedByPublicAddressesOnly = permittedByPublicAddressesOnly;
		}
	}

	private static final Decision REJECTED_BY_BOTH = new Decision(false, false);
	private static final Decision REJECTED_BY_PUBLIC_ADDRESSES_ONLY = new Decision(true, false);
	private static final Decision PERMITTED_BY_BOTH = new Decision(true, true);

	/**
	 * The gate 8 table ("OutboundUriPolicy (final)"), row by row.
	 */
	private static final Map<HostClass, Decision> PRESET_TABLE = presetTable();

	private static @NonNull Map<@NonNull HostClass, @NonNull Decision> presetTable() {
		Map<HostClass, Decision> table = new EnumMap<>(HostClass.class);
		// M1's rejections, and the two classes G8-6 adds to the default.
		for (HostClass hostClass : List.of(HostClass.INVALID, HostClass.ANY_LOCAL, HostClass.LINK_LOCAL,
				HostClass.CLOUD_METADATA, HostClass.METADATA_NAME, HostClass.NAT64_LOCAL_USE))
			table.put(hostClass, REJECTED_BY_BOTH);
		// Local, private, tunnel and non-global space: permitted by the default only (G8-5).
		for (HostClass hostClass : List.of(HostClass.LOOPBACK, HostClass.PRIVATE_USE, HostClass.SHARED_ADDRESS_SPACE,
				HostClass.UNIQUE_LOCAL, HostClass.LOCALHOST_NAME, HostClass.LOCAL_NAME, HostClass.SIX_TO_FOUR,
				HostClass.TEREDO, HostClass.NON_GLOBAL, HostClass.MULTICAST_OR_RESERVED))
			table.put(hostClass, REJECTED_BY_PUBLIC_ADDRESSES_ONLY);
		// Names and global unicast literals.
		for (HostClass hostClass : List.of(HostClass.HOSTNAME, HostClass.OTHER_ADDRESS))
			table.put(hostClass, PERMITTED_BY_BOTH);
		return Collections.unmodifiableMap(table);
	}

	private static @NonNull Row row(@NonNull String host, @NonNull HostClass hostClass) {
		return new Row(host, hostClass, true);
	}

	/**
	 * A row whose host {@link URI} cannot parse, so {@code https://<host>/} is rejected even when the class alone
	 * would be permitted.
	 */
	private static @NonNull Row withoutUriHost(@NonNull String host, @NonNull HostClass hostClass) {
		return new Row(host, hostClass, false);
	}

	/**
	 * Literal rows: Revetsec parses each one, and so does {@link InetAddress#getByName(String)}. The special-purpose
	 * blocks are the IANA registries' as retrieved on 2026-09-27; {@code HostClassifierTests} transcribes them.
	 */
	private static final List<Row> LITERAL_ROWS = List.of(
			// Dotted quad.
			row("8.8.8.8", HostClass.OTHER_ADDRESS),
			row("1.0.0.0", HostClass.OTHER_ADDRESS),
			row("0.0.0.0", HostClass.ANY_LOCAL),
			row("0.255.255.255", HostClass.ANY_LOCAL),
			row("127.0.0.1", HostClass.LOOPBACK),
			row("127.255.255.255", HostClass.LOOPBACK),
			row("126.255.255.255", HostClass.OTHER_ADDRESS),
			row("128.0.0.0", HostClass.OTHER_ADDRESS),
			row("169.254.169.254", HostClass.LINK_LOCAL),
			row("169.254.0.0", HostClass.LINK_LOCAL),
			row("169.254.255.255", HostClass.LINK_LOCAL),
			row("169.253.255.255", HostClass.OTHER_ADDRESS),
			row("169.255.0.0", HostClass.OTHER_ADDRESS),
			row("10.0.0.1", HostClass.PRIVATE_USE),
			row("9.255.255.255", HostClass.OTHER_ADDRESS),
			row("11.0.0.0", HostClass.OTHER_ADDRESS),
			row("172.16.0.0", HostClass.PRIVATE_USE),
			row("172.31.255.255", HostClass.PRIVATE_USE),
			row("172.15.255.255", HostClass.OTHER_ADDRESS),
			row("172.32.0.0", HostClass.OTHER_ADDRESS),
			row("192.168.0.1", HostClass.PRIVATE_USE),
			row("192.167.255.255", HostClass.OTHER_ADDRESS),
			row("192.169.0.0", HostClass.OTHER_ADDRESS),
			row("100.64.0.0", HostClass.SHARED_ADDRESS_SPACE),
			row("100.127.255.255", HostClass.SHARED_ADDRESS_SPACE),
			row("100.63.255.255", HostClass.OTHER_ADDRESS),
			row("100.128.0.0", HostClass.OTHER_ADDRESS),
			// Known cloud metadata addresses (G8-6): Alibaba Cloud inside the shared address space, Azure WireServer in
			// public space. Their neighbors keep their blocks' classes.
			row("100.100.100.200", HostClass.CLOUD_METADATA),
			row("100.100.100.199", HostClass.SHARED_ADDRESS_SPACE),
			row("100.100.100.201", HostClass.SHARED_ADDRESS_SPACE),
			row("168.63.129.16", HostClass.CLOUD_METADATA),
			row("168.63.129.15", HostClass.OTHER_ADDRESS),
			row("168.63.129.17", HostClass.OTHER_ADDRESS),
			// IANA special-purpose blocks marked not globally reachable (G8-5), with the registry's globally reachable
			// exceptions inside 192.0.0.0/24 and the neighbors of each block.
			row("191.255.255.255", HostClass.OTHER_ADDRESS),
			row("192.0.0.0", HostClass.NON_GLOBAL),
			row("192.0.0.8", HostClass.NON_GLOBAL),
			row("192.0.0.9", HostClass.OTHER_ADDRESS),
			row("192.0.0.10", HostClass.OTHER_ADDRESS),
			row("192.0.0.11", HostClass.NON_GLOBAL),
			row("192.0.0.170", HostClass.NON_GLOBAL),
			row("192.0.0.255", HostClass.NON_GLOBAL),
			row("192.0.1.0", HostClass.OTHER_ADDRESS),
			row("192.0.2.0", HostClass.NON_GLOBAL),
			row("192.0.2.255", HostClass.NON_GLOBAL),
			row("192.0.3.0", HostClass.OTHER_ADDRESS),
			row("192.31.196.1", HostClass.OTHER_ADDRESS),
			row("192.52.193.1", HostClass.OTHER_ADDRESS),
			row("192.88.98.255", HostClass.OTHER_ADDRESS),
			row("192.88.99.0", HostClass.NON_GLOBAL),
			row("192.88.99.2", HostClass.NON_GLOBAL),
			row("192.88.99.255", HostClass.NON_GLOBAL),
			row("192.88.100.0", HostClass.OTHER_ADDRESS),
			row("192.175.48.1", HostClass.OTHER_ADDRESS),
			row("198.17.255.255", HostClass.OTHER_ADDRESS),
			row("198.18.0.0", HostClass.NON_GLOBAL),
			row("198.19.255.255", HostClass.NON_GLOBAL),
			row("198.20.0.0", HostClass.OTHER_ADDRESS),
			row("198.51.99.255", HostClass.OTHER_ADDRESS),
			row("198.51.100.0", HostClass.NON_GLOBAL),
			row("198.51.100.255", HostClass.NON_GLOBAL),
			row("198.51.101.0", HostClass.OTHER_ADDRESS),
			row("203.0.112.255", HostClass.OTHER_ADDRESS),
			row("203.0.113.0", HostClass.NON_GLOBAL),
			row("203.0.113.255", HostClass.NON_GLOBAL),
			row("203.0.114.0", HostClass.OTHER_ADDRESS),
			// Multicast and reserved space.
			row("223.255.255.255", HostClass.OTHER_ADDRESS),
			row("224.0.0.0", HostClass.MULTICAST_OR_RESERVED),
			row("224.0.0.1", HostClass.MULTICAST_OR_RESERVED),
			row("239.255.255.255", HostClass.MULTICAST_OR_RESERVED),
			row("240.0.0.0", HostClass.MULTICAST_OR_RESERVED),
			row("255.255.255.254", HostClass.MULTICAST_OR_RESERVED),
			row("255.255.255.255", HostClass.MULTICAST_OR_RESERVED),
			// All-digit: the whole address as one number (2852039166 is 169.254.169.254).
			row("2852039166", HostClass.LINK_LOCAL),
			row("0", HostClass.ANY_LOCAL),
			row("123", HostClass.ANY_LOCAL),
			row("2130706433", HostClass.LOOPBACK),
			row("167772161", HostClass.PRIVATE_USE),
			row("1684300999", HostClass.SHARED_ADDRESS_SPACE),
			row("1684301000", HostClass.CLOUD_METADATA),
			row("2822734096", HostClass.CLOUD_METADATA),
			row("3758096384", HostClass.MULTICAST_OR_RESERVED),
			row("4294967295", HostClass.MULTICAST_OR_RESERVED),
			row("134744072", HostClass.OTHER_ADDRESS),
			// Short-dotted: the last part fills the remaining bytes. URI cannot parse these hosts at all.
			withoutUriHost("127.1", HostClass.LOOPBACK),
			withoutUriHost("127.0.1", HostClass.LOOPBACK),
			withoutUriHost("169.254.43518", HostClass.LINK_LOCAL),
			withoutUriHost("169.16689662", HostClass.LINK_LOCAL),
			withoutUriHost("10.1", HostClass.PRIVATE_USE),
			withoutUriHost("192.168.257", HostClass.PRIVATE_USE),
			withoutUriHost("100.64.1", HostClass.SHARED_ADDRESS_SPACE),
			withoutUriHost("100.100.25800", HostClass.CLOUD_METADATA),
			withoutUriHost("0.1", HostClass.ANY_LOCAL),
			withoutUriHost("8.526344", HostClass.OTHER_ADDRESS),
			// IPv6.
			row("[::]", HostClass.ANY_LOCAL),
			row("[0:0:0:0:0:0:0:0]", HostClass.ANY_LOCAL),
			row("[::1]", HostClass.LOOPBACK),
			row("[0:0:0:0:0:0:0:1]", HostClass.LOOPBACK),
			row("[fe80::1]", HostClass.LINK_LOCAL),
			row("[FE80::1]", HostClass.LINK_LOCAL),
			row("[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.LINK_LOCAL),
			row("[fe7f::1]", HostClass.NON_GLOBAL),
			row("[fec0::1]", HostClass.NON_GLOBAL),
			row("[fd00:ec2::254]", HostClass.CLOUD_METADATA),
			row("[fd00:0ec2:0000:0000:0000:0000:0000:0254]", HostClass.CLOUD_METADATA),
			row("[fd00:ec2::23]", HostClass.CLOUD_METADATA),
			row("[fd00:ec2::253]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::1:254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::22]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::24]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::1:23]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::123]", HostClass.UNIQUE_LOCAL),
			// Google Compute Engine's IPv6 metadata address, added beyond G8-6's list by the owner's decision of
			// 2026-09-27, and its neighbors, which stay unique local.
			row("[fd20:ce::254]", HostClass.CLOUD_METADATA),
			row("[fd20:00ce:0000:0000:0000:0000:0000:0254]", HostClass.CLOUD_METADATA),
			row("[fd20:ce::253]", HostClass.UNIQUE_LOCAL),
			row("[fd20:ce::23]", HostClass.UNIQUE_LOCAL),
			row("[fd20:ce::1:254]", HostClass.UNIQUE_LOCAL),
			row("[fd20:cf::254]", HostClass.UNIQUE_LOCAL),
			row("[fd21:ce::254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ce::254]", HostClass.UNIQUE_LOCAL),
			row("[fc00::1]", HostClass.UNIQUE_LOCAL),
			row("[fdff:ffff::1]", HostClass.UNIQUE_LOCAL),
			row("[fbff::1]", HostClass.NON_GLOBAL),
			row("[fe00::1]", HostClass.NON_GLOBAL),
			row("[ff00::]", HostClass.MULTICAST_OR_RESERVED),
			row("[ff02::1]", HostClass.MULTICAST_OR_RESERVED),
			row("[FFFF:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.MULTICAST_OR_RESERVED),
			row("[feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.NON_GLOBAL),
			row("[2002:a9fe:a9fe::1]", HostClass.SIX_TO_FOUR),
			row("[2002::]", HostClass.SIX_TO_FOUR),
			row("[2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.SIX_TO_FOUR),
			row("[2001:0:4136:e378:8000:63bf:3fff:fdd2]", HostClass.TEREDO),
			row("[2001::]", HostClass.TEREDO),
			row("[2001:0:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.TEREDO),
			// The IPv6 allowlist (G8-5): 2000::/3, without 2001::/23 as a whole (even its globally reachable
			// assignments), 2001:db8::/32 and 3fff::/20.
			row("[2001:1::]", HostClass.NON_GLOBAL),
			row("[2001:1::1]", HostClass.NON_GLOBAL),
			row("[2001:3::1]", HostClass.NON_GLOBAL),
			row("[2001:4:112::1]", HostClass.NON_GLOBAL),
			row("[2001:20::1]", HostClass.NON_GLOBAL),
			row("[2001:100::1]", HostClass.NON_GLOBAL),
			row("[2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.NON_GLOBAL),
			row("[2001:200::]", HostClass.OTHER_ADDRESS),
			row("[2001:db7:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.OTHER_ADDRESS),
			row("[2001:db8::]", HostClass.NON_GLOBAL),
			row("[2001:db8::1]", HostClass.NON_GLOBAL),
			row("[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.NON_GLOBAL),
			row("[2001:db9::]", HostClass.OTHER_ADDRESS),
			row("[3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.OTHER_ADDRESS),
			row("[3fff::]", HostClass.NON_GLOBAL),
			row("[3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.NON_GLOBAL),
			row("[3fff:1000::]", HostClass.OTHER_ADDRESS),
			row("[3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.OTHER_ADDRESS),
			row("[2620:4f:8000::1]", HostClass.OTHER_ADDRESS),
			row("[2606:4700:4700::1111]", HostClass.OTHER_ADDRESS),
			row("[2000::]", HostClass.OTHER_ADDRESS),
			row("[1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", HostClass.NON_GLOBAL),
			row("[4000::]", HostClass.NON_GLOBAL),
			row("[5f00::1]", HostClass.NON_GLOBAL),
			row("[100::1]", HostClass.NON_GLOBAL),
			row("[100:0:0:1::1]", HostClass.NON_GLOBAL),
			row("[1:2:3:4:5:6:7:8]", HostClass.NON_GLOBAL),
			row("[1:2:3:4:5:6:7::]", HostClass.NON_GLOBAL),
			row("[::2:3:4:5:6:7:8]", HostClass.NON_GLOBAL),
			row("[1:2:3:4:5:6:1.2.3.4]", HostClass.NON_GLOBAL),
			row("[2606:4700::1.2.3.4]", HostClass.OTHER_ADDRESS),
			// IPv4-mapped (::ffff:0:0/96): classified as the IPv4 address inside, which the JDK connects to.
			row("[::ffff:169.254.169.254]", HostClass.LINK_LOCAL),
			row("[::ffff:a9fe:a9fe]", HostClass.LINK_LOCAL),
			row("[::FFFF:A9FE:A9FE]", HostClass.LINK_LOCAL),
			row("[0:0:0:0:0:ffff:169.254.169.254]", HostClass.LINK_LOCAL),
			row("[::ffff:0.0.0.0]", HostClass.ANY_LOCAL),
			row("[::ffff:127.0.0.1]", HostClass.LOOPBACK),
			row("[::ffff:7f00:1]", HostClass.LOOPBACK),
			row("[::ffff:10.0.0.1]", HostClass.PRIVATE_USE),
			row("[::ffff:100.64.0.1]", HostClass.SHARED_ADDRESS_SPACE),
			row("[::ffff:100.100.100.200]", HostClass.CLOUD_METADATA),
			row("[::ffff:168.63.129.16]", HostClass.CLOUD_METADATA),
			row("[::ffff:192.0.2.1]", HostClass.NON_GLOBAL),
			row("[::ffff:224.0.0.1]", HostClass.MULTICAST_OR_RESERVED),
			row("[::ffff:255.255.255.255]", HostClass.MULTICAST_OR_RESERVED),
			row("[::ffff:8.8.8.8]", HostClass.OTHER_ADDRESS),
			// IPv4-compatible (::/96, except :: and ::1): the IPv4 address's class, or NON_GLOBAL for a global one.
			row("[::169.254.169.254]", HostClass.LINK_LOCAL),
			row("[::a9fe:a9fe]", HostClass.LINK_LOCAL),
			row("[::0.0.0.2]", HostClass.ANY_LOCAL),
			row("[::2]", HostClass.ANY_LOCAL),
			row("[::ffff]", HostClass.ANY_LOCAL),
			row("[::127.0.0.1]", HostClass.LOOPBACK),
			row("[::10.0.0.1]", HostClass.PRIVATE_USE),
			row("[::100.100.100.200]", HostClass.CLOUD_METADATA),
			row("[::192.0.2.1]", HostClass.NON_GLOBAL),
			row("[::224.0.0.1]", HostClass.MULTICAST_OR_RESERVED),
			row("[::8.8.8.8]", HostClass.NON_GLOBAL),
			// IPv4-translated (::ffff:0:0:0/96, RFC 2765): the same rule (G8-5, G8-6).
			row("[::ffff:0:a9fe:a9fe]", HostClass.LINK_LOCAL),
			row("[::ffff:0:169.254.169.254]", HostClass.LINK_LOCAL),
			row("[0:0:0:0:ffff:0:169.254.169.254]", HostClass.LINK_LOCAL),
			row("[::ffff:0:0.0.0.0]", HostClass.ANY_LOCAL),
			row("[::ffff:0:0:0]", HostClass.ANY_LOCAL),
			row("[::ffff:0:127.0.0.1]", HostClass.LOOPBACK),
			row("[::ffff:0:10.0.0.1]", HostClass.PRIVATE_USE),
			row("[::ffff:0:100.100.100.200]", HostClass.CLOUD_METADATA),
			row("[::ffff:0:168.63.129.16]", HostClass.CLOUD_METADATA),
			row("[::ffff:0:192.0.2.1]", HostClass.NON_GLOBAL),
			row("[::ffff:0:224.0.0.1]", HostClass.MULTICAST_OR_RESERVED),
			row("[::ffff:0:8.8.8.8]", HostClass.NON_GLOBAL),
			// NAT64 Well-Known Prefix (64:ff9b::/96, RFC 6052): the IPv4 address's class, global included.
			row("[64:ff9b::169.254.169.254]", HostClass.LINK_LOCAL),
			row("[64:ff9b::a9fe:a9fe]", HostClass.LINK_LOCAL),
			row("[64:ff9b::0.0.0.0]", HostClass.ANY_LOCAL),
			row("[64:ff9b::127.0.0.1]", HostClass.LOOPBACK),
			row("[64:ff9b::10.0.0.1]", HostClass.PRIVATE_USE),
			row("[64:ff9b::100.100.100.200]", HostClass.CLOUD_METADATA),
			row("[64:ff9b::192.0.2.1]", HostClass.NON_GLOBAL),
			row("[64:ff9b::224.0.0.1]", HostClass.MULTICAST_OR_RESERVED),
			row("[64:ff9b::8.8.8.8]", HostClass.OTHER_ADDRESS),
			// NAT64 local-use prefix (64:ff9b:1::/48, RFC 8215), as a whole under both presets (G8-6).
			row("[64:ff9b:1::]", HostClass.NAT64_LOCAL_USE),
			row("[64:ff9b:1::a9fe:a9fe]", HostClass.NAT64_LOCAL_USE),
			row("[64:ff9b:1::8.8.8.8]", HostClass.NAT64_LOCAL_USE),
			row("[64:ff9b:1:a9fe:a900::fe]", HostClass.NAT64_LOCAL_USE),
			row("[64:ff9b:1:ffff:ffff:ffff:ffff:ffff]", HostClass.NAT64_LOCAL_USE),
			row("[64:ff9b:2::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[64:ff9b:0:1::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[64:ff9b::1:a9fe:a9fe]", HostClass.NON_GLOBAL),
			// Near misses, one byte off each prefix, so every byte of every prefix comparison is pinned. Outside
			// 2000::/3, each is non-global.
			row("[::fffe:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[::ff:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[::1:ffff:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[::fffe:0:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[::ffff:1:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[0:0:0:1:ffff:0:a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[64:ff9a::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[64:fe9b::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[65:ff9b::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[164:ff9b::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[64:ff9a:1::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[fd01:ec2::254]", HostClass.UNIQUE_LOCAL),
			row("[fc00:ec2::254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:fc2::254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec3::254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2::354]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2:0:0:1::254]", HostClass.UNIQUE_LOCAL),
			row("[fd00:ec2:0:0:1::23]", HostClass.UNIQUE_LOCAL),
			row("[2000::1]", HostClass.OTHER_ADDRESS),
			row("[2003::1]", HostClass.OTHER_ADDRESS),
			row("[2102::1]", HostClass.OTHER_ADDRESS),
			row("[2001:1::a9fe:a9fe]", HostClass.NON_GLOBAL),
			row("[2011::1]", HostClass.OTHER_ADDRESS));

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
			row("4294967296", HostClass.INVALID),
			withoutUriHost("1.2.3.4.5", HostClass.INVALID),
			withoutUriHost("256.1.1.1", HostClass.INVALID),
			withoutUriHost("1.2.3.256", HostClass.INVALID),
			withoutUriHost("1.2.65536", HostClass.INVALID),
			withoutUriHost("1.16777216", HostClass.INVALID),
			withoutUriHost("127.0.0.1.", HostClass.INVALID),
			withoutUriHost("1..2", HostClass.INVALID),
			// Leading zeros: the JDK reads 010.1.1.1 as decimal and BSD inet_aton as octal. 0251.254.169.254 is too long
			// for the JDK's literal parser and inet_aton reads it as 169.254.169.254, so the JDK refuses it as ambiguous
			// by default and asks the platform resolver only when jdk.net.allowAmbiguousIPAddressLiterals is true.
			row("0251.254.169.254", HostClass.INVALID),
			row("010.1.1.1", HostClass.INVALID),
			row("0177.0.0.1", HostClass.INVALID),
			row("127.0.0.01", HostClass.INVALID),
			row("00", HostClass.INVALID),
			row("0127", HostClass.INVALID),
			// Hexadecimal and other numeric-looking hosts. The JDK's literal parser rejects them. It refuses the forms
			// inet_aton reads as addresses, such as 0xa9fea9fe, as ambiguous by default, and asks the platform resolver
			// only when jdk.net.allowAmbiguousIPAddressLiterals is true (the macOS resolver then reads 0xa9fea9fe as
			// 169.254.169.254); it asks the resolver for the others. A single label with a trailing dot is still a URI
			// host, so it reaches the classifier.
			row("0x7f000001", HostClass.INVALID),
			row("0x7f000001.", HostClass.INVALID),
			row("0xA9FEA9FE", HostClass.INVALID),
			row("2852039166.", HostClass.INVALID),
			row("0.", HostClass.INVALID),
			row("0000000001.0.0.1", HostClass.INVALID),
			row("0X7F000001", HostClass.INVALID),
			row("0xa9fea9fe", HostClass.INVALID),
			row("0x", HostClass.INVALID),
			withoutUriHost("0x7f.1", HostClass.INVALID),
			withoutUriHost("1.2.3.0x4", HostClass.INVALID),
			withoutUriHost("example.123", HostClass.INVALID),
			withoutUriHost("example.0x1", HostClass.INVALID),
			// Malformed or zone-scoped IPv6.
			row("[fe80::1%25en0]", HostClass.INVALID),
			row("[fe80::1%251]", HostClass.INVALID),
			row("[2001:db8::1%25eth0]", HostClass.INVALID));

	/**
	 * DNS names: never resolved, and classified by their text alone (G8-5): ASCII case folding only, one optional
	 * trailing dot, suffixes on a label boundary, and metadata names before local names.
	 */
	private static final List<Row> NAME_ROWS = List.of(
			row("example.com", HostClass.HOSTNAME),
			row("EXAMPLE.com", HostClass.HOSTNAME),
			row("example.com.", HostClass.HOSTNAME),
			row("idp.example.com", HostClass.HOSTNAME),
			row("xn--bcher-kva.example.com", HostClass.HOSTNAME),
			row("4.3.2.1.example.com", HostClass.HOSTNAME),
			row("login.microsoftonline.com", HostClass.HOSTNAME),
			// A public name with a z or Z, the ends of the letter ranges, is permitted by both presets.
			row("cognito-idp.us-east-1.amazonaws.com", HostClass.HOSTNAME),
			row("IDP.ZZ.EXAMPLE.COM", HostClass.HOSTNAME),
			// Known cloud metadata names (G8-6) and the names under them, which win over the .internal suffix, in any
			// ASCII case.
			row("metadata.google.internal", HostClass.METADATA_NAME),
			row("METADATA.GOOGLE.INTERNAL.", HostClass.METADATA_NAME),
			row("metadata.goog", HostClass.METADATA_NAME),
			row("Metadata.Goog.", HostClass.METADATA_NAME),
			row("x.metadata.google.internal", HostClass.METADATA_NAME),
			row("x.metadata.goog", HostClass.METADATA_NAME),
			row("xmetadata.goog", HostClass.HOSTNAME),
			row("metadata.goog.example.com", HostClass.HOSTNAME),
			// Review leads that their providers' documentation did not confirm on 2026-09-27 (see HostClassifierTests):
			// they fall under the single-label and .internal rules instead, as the owner decided that day.
			row("instance-data", HostClass.LOCAL_NAME),
			row("instance-data.ec2.internal", HostClass.LOCAL_NAME),
			row("metadata", HostClass.LOCAL_NAME),
			// Localhost names (RFC 6761 section 6.3).
			row("localhost", HostClass.LOCALHOST_NAME),
			row("LOCALHOST", HostClass.LOCALHOST_NAME),
			row("localhost.", HostClass.LOCALHOST_NAME),
			row("api.localhost", HostClass.LOCALHOST_NAME),
			row("localhost.example.com", HostClass.HOSTNAME),
			// Single-label names, which a resolver may complete with its search domains.
			row("notlocalhost", HostClass.LOCAL_NAME),
			row("intranet", HostClass.LOCAL_NAME),
			row("intranet.", HostClass.LOCAL_NAME),
			row("1e2", HostClass.LOCAL_NAME),
			row("deadbeef", HostClass.LOCAL_NAME),
			row("evilinternal", HostClass.LOCAL_NAME),
			// Special-use and private-use names, and names under them.
			row("idp.internal", HostClass.LOCAL_NAME),
			row("IDP.Internal.", HostClass.LOCAL_NAME),
			row("printer.local", HostClass.LOCAL_NAME),
			row("router.home.arpa", HostClass.LOCAL_NAME),
			row("home.arpa", HostClass.LOCAL_NAME),
			row("idp.test", HostClass.LOCAL_NAME),
			row("revetsec-never-resolved.invalid", HostClass.LOCAL_NAME),
			row("idp.example", HostClass.LOCAL_NAME),
			row("localhost.example", HostClass.LOCAL_NAME),
			row("revetsec-test.onion", HostClass.LOCAL_NAME),
			row("idp.alt", HostClass.LOCAL_NAME),
			// Every name under arpa (RFC 3172), by the owner's decision of 2026-09-27: its special-use names, the
			// reverse-mapping zones, and every other name there, special-use or not.
			row("ipv4only.arpa", HostClass.LOCAL_NAME),
			row("IPV4ONLY.ARPA.", HostClass.LOCAL_NAME),
			row("resolver.arpa", HostClass.LOCAL_NAME),
			row("dns.resolver.arpa", HostClass.LOCAL_NAME),
			row("service.arpa", HostClass.LOCAL_NAME),
			row("default.service.arpa.", HostClass.LOCAL_NAME),
			row("in-addr.arpa", HostClass.LOCAL_NAME),
			row("1.0.0.127.in-addr.arpa", HostClass.LOCAL_NAME),
			row("254.169.254.169.In-Addr.Arpa", HostClass.LOCAL_NAME),
			row("ip6.arpa", HostClass.LOCAL_NAME),
			row("b.e.f.ip6.arpa.", HostClass.LOCAL_NAME),
			row("eap.arpa", HostClass.LOCAL_NAME),
			row("e164.arpa", HostClass.LOCAL_NAME),
			row("xhome.arpa", HostClass.LOCAL_NAME),
			row("xin-addr.arpa", HostClass.LOCAL_NAME),
			row("in-addr-servers.arpa", HostClass.LOCAL_NAME),
			row("myip6.arpa", HostClass.LOCAL_NAME),
			row("ARPA.", HostClass.LOCAL_NAME),
			// Look-alikes: a suffix matches only on a label boundary.
			row("idp.evilinternal", HostClass.HOSTNAME),
			row("idp.xlocal", HostClass.HOSTNAME),
			row("idp.internal.example.com", HostClass.HOSTNAME),
			row("idp.local.example.com", HostClass.HOSTNAME),
			row("idp.nottest", HostClass.HOSTNAME),
			row("idp.onion.example.com", HostClass.HOSTNAME),
			row("ipv4only.arpa.example.com", HostClass.HOSTNAME),
			row("arpa.example.com", HostClass.HOSTNAME),
			row("idp.xarpa", HostClass.HOSTNAME));

	// G8-5 to G8-7: the preset table covers every class, and so do the rows.
	@Test
	void thePresetTableAndTheRowsCoverEveryHostClass() {
		Assertions.assertEquals(EnumSet.allOf(HostClass.class), PRESET_TABLE.keySet());

		Set<HostClass> covered = Stream.of(LITERAL_ROWS, INVALID_ROWS, NAME_ROWS)
				.flatMap(List::stream)
				.map(row -> row.hostClass)
				.collect(Collectors.toCollection(() -> EnumSet.noneOf(HostClass.class)));
		Assertions.assertEquals(EnumSet.allOf(HostClass.class), covered);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> literalRowsAreClassifiedAndAgreeWithTheJdkParser() {
		// M1 exit criterion 15 and M2 exit criterion 18: every literal row agrees with InetAddress.getByName.
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
			assertPresets(row);
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> hostsThatLookNumericButAreNotStrictLiteralsAreRejected() {
		// M1 plan A-1: a host made only of digits and dots that does not parse is rejected. Ambiguous forms that the
		// JDK and BSD inet_aton read differently are rejected too, without asking DNS.
		return INVALID_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(row.host));
			Assertions.assertEquals(HostClass.INVALID, HostClassifier.classify(row.host));
			assertPresets(row);
		}));
	}

	@Test
	void theJdkItselfGivesNoAddressForTheAmbiguousFormsAtDefaultSettings() {
		// JDK behavior that Revetsec does not rely on, pinned so that the reasons given for the rows above stay true:
		// with jdk.net.allowAmbiguousIPAddressLiterals unset, InetAddress.getByName refuses a host its own literal
		// parser rejects but BSD inet_aton reads as an address, before any resolver sees it, and gives no address. A
		// proxy or other software that uses inet_aton reads each of these as 169.254.169.254, so Revetsec rejects them
		// whatever the JVM allows.
		Assertions.assertNull(System.getProperty("jdk.net.allowAmbiguousIPAddressLiterals"));
		for (String host : List.of("0xa9fea9fe", "0251.254.169.254")) {
			Assertions.assertEquals(HostClass.INVALID, HostClassifier.classify(host));
			@Nullable InetAddress address;
			try {
				address = InetAddress.getByName(host);
			} catch (UnknownHostException e) {
				address = null;
			}
			Assertions.assertNull(address, host);
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> namesAreClassifiedByTheirTextAndNeverResolved() {
		// G8-5 and G8-7: hostnames are never resolved, so a public name that points at a metadata address still
		// passes; the protection there is https plus an egress proxy on an injected client. Special-use, private-use
		// and metadata names are recognized by their text.
		return NAME_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.toString(), () -> {
			Assertions.assertNull(HostClassifier.parseLiteral(row.host));
			Assertions.assertEquals(row.hostClass, HostClassifier.classify(row.host));
			assertPresets(row);
		}));
	}

	@Test
	void theG85PrecedenceRowsHoldUnderBothPresets() {
		// G8-5 and M2 exit criterion 18. An IPv4-mapped literal is judged as the IPv4 address the JDK connects to; an
		// IPv4-compatible one around a global address is non-global; metadata names win over .internal in any case
		// and with a trailing dot; instance-data (not confirmed as a metadata name) and evilinternal are single-label
		// local names, and a look-alike with a second label is an ordinary hostname.
		assertPermits("https://[::ffff:8.8.8.8]/", true, true);
		assertPermits("https://8.8.8.8/", true, true);
		assertPermits("https://[::8.8.8.8]/", true, false);
		assertPermits("https://[::ffff:0:8.8.8.8]/", true, false);
		assertPermits("https://METADATA.GOOGLE.INTERNAL./", false, false);
		assertPermits("https://instance-data/", true, false);
		assertPermits("https://evilinternal/", true, false);
		assertPermits("https://idp.evilinternal/", true, true);
	}

	@Test
	void thePlanExamplesAreRejectedByBothPresets() {
		// M1 plan A-1: https://0/ resolves to 0.0.0.0, and [::] is any-local. G8-6 adds the NAT64 local-use prefix,
		// IPv4-translated literals around a rejected address, and the known metadata endpoints as of 2026-09-27; the
		// owner's decision of that date adds Google Compute Engine's IPv6 metadata address.
		for (String uri : List.of("https://0/", "https://[::]/", "https://2852039166/latest/meta-data/",
				"https://169.254.169.254/latest/meta-data/", "https://[fd00:ec2::254]/latest/meta-data/",
				"https://[::ffff:169.254.169.254]/", "https://[64:ff9b::169.254.169.254]/", "https://127.1/",
				"https://169.254.43518/", "https://100.100.100.200/latest/meta-data/",
				"http://168.63.129.16/?comp=versions", "http://metadata.google.internal/computeMetadata/v1/",
				"http://metadata.goog/computeMetadata/v1/", "https://x.metadata.goog/", "https://x.metadata.google.internal/",
				"http://[fd00:ec2::23]/v1/credentials", "http://[fd20:ce::254]/computeMetadata/v1/",
				"https://[FD20:CE::254]:443/computeMetadata/v1/instance/",
				"https://[64:ff9b:1::a9fe:a9fe]/", "https://[64:ff9b:1::808:808]/", "https://[::ffff:0:a9fe:a9fe]/",
				"https://[::ffff:0:100.100.100.200]/", "https://[64:ff9b::168.63.129.16]/")) {
			Assertions.assertFalse(OutboundUriPolicy.defaultInstance().permits(URI.create(uri)), uri);
			Assertions.assertFalse(OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)), uri);
		}
	}

	@Test
	void thePublicAddressesOnlyPresetPermitsOnlyGloballyReachableDestinations() {
		// G8-5: global unicast literals and ordinary names pass; everything local, private, special-use or tunneled
		// that the default permits is rejected. Special-use names outside the list, such as example.com, are ordinary
		// names, as the publicAddressesOnlyInstance() Javadoc says; every name under arpa is not.
		for (String uri : List.of("https://idp.example.com/", "https://login.microsoftonline.com/common/discovery/keys",
				"https://8.8.8.8/", "https://[2606:4700:4700::1111]/", "https://[::ffff:8.8.8.8]/",
				"https://[64:ff9b::8.8.8.8]/", "https://192.0.0.9/", "https://[2620:4f:8000::1]/", "https://example.com/",
				"https://arpa.example.com/")) {
			Assertions.assertTrue(OutboundUriPolicy.defaultInstance().permits(URI.create(uri)), uri);
			Assertions.assertTrue(OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)), uri);
		}

		for (String uri : List.of("https://localhost/", "https://LOCALHOST./", "https://api.localhost/",
				"http://127.0.0.1:8080/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://[::127.0.0.1]/",
				"https://10.0.0.1/", "https://172.16.0.1/", "https://192.168.1.1/", "https://100.64.0.1/",
				"https://[fd00::1]/", "https://[fc00::1]/", "https://[2002:808:808::1]/",
				"https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "https://[::8.8.8.8]/", "https://[::ffff:0:8.8.8.8]/",
				"https://192.0.2.1/", "https://198.18.0.1/", "https://192.88.99.1/", "https://224.0.0.1/",
				"https://240.0.0.1/", "https://255.255.255.255/", "https://[ff02::1]/", "https://[2001:db8::1]/",
				"https://[3fff::1]/", "https://[2001:1::1]/", "https://[5f00::1]/", "https://[fec0::1]/",
				"https://intranet/", "https://intranet./", "https://idp.internal/", "https://printer.local/",
				"https://router.home.arpa/", "https://idp.test/", "https://idp.example/", "https://idp.invalid/",
				"https://idp.alt/", "https://ipv4only.arpa/", "https://resolver.arpa/", "https://default.service.arpa/",
				"https://1.0.0.127.in-addr.arpa/", "https://b.e.f.ip6.arpa/", "https://eap.arpa/",
				"https://in-addr-servers.arpa/", "https://[fd20:ce::253]/")) {
			Assertions.assertTrue(OutboundUriPolicy.defaultInstance().permits(URI.create(uri)), uri);
			Assertions.assertFalse(OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)), uri);
		}
	}

	@Test
	void unconfirmedMetadataLeadsArePermittedByTheDefaultAndRejectedByThePublicAddressesPreset() {
		// G8-6 and the owner's decision of 2026-09-27: instance-data, Google's short name metadata and
		// instance-data.ec2.internal were not confirmed by their providers' documentation, so they are not metadata
		// names. They stay local names (single-label, or under .internal): defaultInstance() permits them and
		// publicAddressesOnlyInstance() rejects them, in any ASCII case, with one trailing dot, over http or https.
		for (String host : List.of("instance-data", "metadata", "instance-data.ec2.internal")) {
			for (String form : List.of(host, host + ".", host.toUpperCase(Locale.ROOT))) {
				Assertions.assertEquals(HostClass.LOCAL_NAME, HostClassifier.classify(form), form);
				for (String scheme : List.of("http", "https")) {
					String uri = scheme + "://" + form + "/latest/meta-data/";
					assertPermits(uri, true, false);
				}
			}
		}
	}

	@Test
	void specialUseArpaNamesAndReverseZonesAreRejectedByThePublicAddressesPresetOnly() {
		// The owner's decisions of 2026-09-27: service.arpa, ipv4only.arpa, resolver.arpa, in-addr.arpa and ip6.arpa,
		// and every name under them, in any ASCII case and with one trailing dot, are rejected by
		// publicAddressesOnlyInstance() and still permitted by defaultInstance(), now as names under arpa. A name that
		// only carries one of them as inner labels is outside arpa and passes both.
		for (String host : List.of("service.arpa", "default.service.arpa", "Printer.Default.Service.Arpa.",
				"ipv4only.arpa", "IPV4ONLY.ARPA.", "resolver.arpa", "dns.resolver.arpa.", "in-addr.arpa",
				"10.in-addr.arpa", "1.1.168.192.in-addr.arpa", "170.0.0.192.IN-ADDR.ARPA.", "ip6.arpa",
				"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "B.E.F.IP6.ARPA."))
			assertPermits("https://" + host + "/", true, false);

		for (String host : List.of("service.arpa.example.com", "ip6.arpa.example.com", "in-addr.arpa.example.com."))
			assertPermits("https://" + host + "/", true, true);
	}

	@Test
	void everyNameUnderArpaIsRejectedByThePublicAddressesPresetOnly() {
		// The owner's decision of 2026-09-27: arpa is reserved for Internet infrastructure (RFC 3172), so
		// publicAddressesOnlyInstance() rejects it and every name under it, whether or not the IANA Special-Use Domain
		// Names registry lists the name, in any ASCII case and with one trailing dot, over http or https, while
		// defaultInstance() still permits them. Only a label boundary counts: arpa as an inner label, or inside a
		// longer label, passes both.
		for (String host : List.of("arpa", "ARPA.", "idp.arpa", "home.arpa", "eap.arpa", "6tisch.arpa", "e164.arpa",
				"uri.arpa", "as112.arpa", "in-addr-servers.arpa", "ip6-servers.arpa", "xservice.arpa",
				"notipv4only.arpa", "myresolver.arpa", "xin-addr.arpa", "myip6.arpa", "Login.Example.Com.Arpa.")) {
			Assertions.assertEquals(HostClass.LOCAL_NAME, HostClassifier.classify(host), host);
			for (String scheme : List.of("http", "https"))
				assertPermits(scheme + "://" + host + "/.well-known/jwks.json", true, false);
		}

		for (String host : List.of("arpa.example.com", "login.arpa.example.com.", "idp.xarpa", "idp.arpax",
				"arpa-idp.example.com"))
			assertPermits("https://" + host + "/", true, true);
	}

	@Test
	void onlyAbsoluteHttpAndHttpsUrisWithAHostArePermitted() {
		for (String uri : List.of("https://example.com/", "HTTPS://example.com/", "http://127.0.0.1:8080/callback",
				"Http://[::1]:8443/", "https://user@example.com:8443/path?query#fragment"))
			Assertions.assertTrue(OutboundUriPolicy.defaultInstance().permits(URI.create(uri)), uri);

		for (String uri : List.of("https://example.com/", "HTTP://8.8.8.8:8080/",
				"https://user@example.com:8443/path?query#fragment"))
			Assertions.assertTrue(OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)), uri);

		for (String uri : List.of("ftp://example.com/", "file:///etc/passwd", "jar:file:/x.jar!/", "ldap://example.com/",
				"mailto:someone@example.com", "https:example.com", "//example.com/", "/relative", "https:///path",
				"https://under_score.example.com/", "https://-leading-hyphen.example.com/", "httpsx://example.com/",
				"htt1://example.com/", "http5://example.com/", "HTTPZ://example.com/", "ftp://8.8.8.8/")) {
			Assertions.assertFalse(OutboundUriPolicy.defaultInstance().permits(URI.create(uri)), uri);
			Assertions.assertFalse(OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)), uri);
		}
	}

	@Test
	void eachPresetIsShared() {
		Assertions.assertSame(OutboundUriPolicy.defaultInstance(), OutboundUriPolicy.defaultInstance());
		Assertions.assertSame(OutboundUriPolicy.publicAddressesOnlyInstance(),
				OutboundUriPolicy.publicAddressesOnlyInstance());
		Assertions.assertNotSame(OutboundUriPolicy.defaultInstance(), OutboundUriPolicy.publicAddressesOnlyInstance());
		Assertions.assertEquals("OutboundUriPolicy{name=default}", OutboundUriPolicy.defaultInstance().toString());
		Assertions.assertEquals("OutboundUriPolicy{name=publicAddressesOnly}",
				OutboundUriPolicy.publicAddressesOnlyInstance().toString());
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void aNullUriThrowsNullPointerException() {
		// Plan R15: misuse throws NPE.
		Assertions.assertThrows(NullPointerException.class, () -> OutboundUriPolicy.defaultInstance().permits(
				nullUri()));
		Assertions.assertThrows(NullPointerException.class, () -> OutboundUriPolicy.publicAddressesOnlyInstance()
				.permits(nullUri()));
	}

	@Test
	void thePolicyNeverReferencesTheJdkResolver() throws IOException {
		// M1 plan A-1 and G8-7: hostnames are never resolved. No class on the policy's path may even link InetAddress.
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

	private static void assertPresets(@NonNull Row row) {
		URI uri = URI.create("https://" + row.host + "/");
		Decision decision = PRESET_TABLE.get(row.hostClass);

		Assertions.assertNotNull(decision, row::toString);
		Assertions.assertEquals(row.uriHasHost, uri.getHost() != null, "URI.getHost() presence");
		Assertions.assertEquals(row.uriHasHost && decision.permittedByDefault,
				OutboundUriPolicy.defaultInstance().permits(uri), "defaultInstance().permits(" + uri + ")");
		Assertions.assertEquals(row.uriHasHost && decision.permittedByPublicAddressesOnly,
				OutboundUriPolicy.publicAddressesOnlyInstance().permits(uri),
				"publicAddressesOnlyInstance().permits(" + uri + ")");
	}

	private static void assertPermits(@NonNull String uri, boolean permittedByDefault, boolean permittedByPublicAddressesOnly) {
		Assertions.assertEquals(permittedByDefault, OutboundUriPolicy.defaultInstance().permits(URI.create(uri)),
				"defaultInstance().permits(" + uri + ")");
		Assertions.assertEquals(permittedByPublicAddressesOnly,
				OutboundUriPolicy.publicAddressesOnlyInstance().permits(URI.create(uri)),
				"publicAddressesOnlyInstance().permits(" + uri + ")");
	}

	/**
	 * Checks the class against the JDK's own predicates where they apply to the address the JDK returned. The JDK
	 * returns IPv4-mapped addresses as {@link Inet4Address}, but keeps the other embedded forms as IPv6 and has no
	 * predicate for most of Revetsec's classes, so only the overlapping cases are compared.
	 */
	private static void assertAgreesWithJdkPredicates(@NonNull HostClass hostClass, @NonNull InetAddress jdkAddress) {
		if (jdkAddress.isLoopbackAddress())
			Assertions.assertEquals(HostClass.LOOPBACK, hostClass);
		if (jdkAddress.isLinkLocalAddress())
			Assertions.assertEquals(HostClass.LINK_LOCAL, hostClass);
		if (jdkAddress.isAnyLocalAddress())
			Assertions.assertEquals(HostClass.ANY_LOCAL, hostClass);
		if (jdkAddress.isMulticastAddress())
			Assertions.assertEquals(HostClass.MULTICAST_OR_RESERVED, hostClass);
		if (jdkAddress instanceof Inet4Address && jdkAddress.isSiteLocalAddress())
			Assertions.assertEquals(HostClass.PRIVATE_USE, hostClass);
		// The deprecated IPv6 site-local block, fec0::/10, is outside 2000::/3.
		if (jdkAddress instanceof Inet6Address && jdkAddress.isSiteLocalAddress())
			Assertions.assertEquals(HostClass.NON_GLOBAL, hostClass);
	}

	/**
	 * Returns 16 bytes: an IPv6 address as is, an IPv4 address in IPv4-mapped form ({@code ::ffff:a.b.c.d}).
	 */
	private static byte @NonNull [] toSixteenBytes(byte @NonNull [] address) {
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
	private static @Nullable URI nullUri() {
		return null;
	}
}
