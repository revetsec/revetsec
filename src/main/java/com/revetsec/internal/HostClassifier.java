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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Classifies the host of an outbound URI without ever resolving it (plan R12, D35; M1 plan A-1).
 * <p>
 * A host is one of three things:
 * <ul>
 *   <li>an <em>IP literal</em>: an IPv4 form that {@code InetAddress.getByName} would also parse numerically, or a
 *   bracketed IPv6 address. It is classified by address;</li>
 *   <li>a <em>hostname</em>: a syntactically valid DNS name. It is never resolved, so its class says nothing about
 *   the addresses it points at;</li>
 *   <li>{@link HostClass#INVALID}: anything else, including every host that looks numeric but is not a strict
 *   literal.</li>
 * </ul>
 * <strong>IPv4 forms</strong> follow the JDK's own numeric parser: one to four decimal parts, where the last part
 * fills the remaining bytes, so {@code 2852039166}, {@code 169.254.43518} and {@code 127.1} are all literals. The
 * JDK 17 API has no {@code Inet4Address.ofLiteral} (it arrived in 22), so Revetsec parses literals itself, and
 * {@code OutboundUriPolicyTests} compares every literal row with {@code InetAddress.getByName}. Two kinds of host are
 * {@link HostClass#INVALID} rather than guessed at, because the JDK and other software read them differently:
 * <ul>
 *   <li>a part with a leading zero. The JDK reads {@code 010.1.1.1} as decimal (10.1.1.1), while BSD
 *   {@code inet_aton}, which some proxies and resolvers use, reads it as octal (8.1.1.1). {@code 0251.254.169.254} is longer than
 *   the JDK's literal parser accepts, so the JDK passes it to the platform resolver, and {@code inet_aton} reads it
 *   as 169.254.169.254;</li>
 *   <li>any host whose last label is all digits or a {@code 0x} hexadecimal number but that is not a strict literal,
 *   such as {@code 1.2.3.4.5}, {@code 256.1.1.1}, {@code 127.0.0.1.} or {@code 0xa9fea9fe}. The JDK's literal parser
 *   rejects these and passes them to the platform resolver, which may still read them as addresses: the macOS
 *   resolver reads {@code 0xa9fea9fe} as 169.254.169.254.</li>
 * </ul>
 * <strong>IPv6 forms</strong> are RFC 4291 section 2.2 text in brackets: groups of one to four hexadecimal digits,
 * at most one {@code ::}, and an optional dotted-quad IPv4 tail with no leading zeros. A zone ID ({@code %en0}) makes
 * the host {@link HostClass#INVALID}.
 * <p>
 * <strong>Embedded IPv4.</strong> {@code ::} and {@code ::1} are classified as themselves. An IPv4-mapped address
 * ({@code ::ffff:0:0/96}) is classified as the IPv4 address inside it, because {@code InetAddress} turns it into that
 * {@code Inet4Address} and the JDK connects to it. IPv4-compatible ({@code ::/96}) and NAT64 Well-Known Prefix
 * ({@code 64:ff9b::/96}) addresses are also classified as the IPv4 address inside them, but only conservatively, so
 * that they can be rejected: the JDK keeps them as IPv6 and connects to the IPv6 address, which a tunnel or
 * translator may deliver to that IPv4 address. For these two forms the class does not mean that the JDK connects to
 * the IPv4 address, so a caller that grants anything for a class must not rely on it; {@link #isLoopbackLiteral}
 * is the test for plain {@code http} to loopback. Other NAT64 prefixes (the RFC 8215 local-use prefix
 * {@code 64:ff9b:1::/48} and network-specific prefixes), SIIT, 6to4 and Teredo addresses are classified as
 * themselves; whether to look inside them is left to gate 8.
 * <p>
 * This class is the only literal parser in Revetsec. It never calls {@code InetAddress} or any other resolver.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class HostClassifier {
	/**
	 * The longest IPv6 text form, {@code ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255}.
	 */
	private static final int MAXIMUM_IPV6_LENGTH = 45;

	/**
	 * The longest IPv4 form, {@code 255.255.255.255}.
	 */
	private static final int MAXIMUM_IPV4_LENGTH = 15;

	/**
	 * The longest DNS name without its trailing dot (RFC 1035 section 2.3.4, as presentation text).
	 */
	private static final int MAXIMUM_HOSTNAME_LENGTH = 253;

	/**
	 * The longest DNS label (RFC 1035 section 2.3.4).
	 */
	private static final int MAXIMUM_LABEL_LENGTH = 63;

	/**
	 * The RFC 6761 section 6.3 special-use name, in lower case.
	 */
	private static final String LOCALHOST = "localhost";

	/**
	 * What a host is, for outbound-URI policy decisions. Literal addresses are classified after unwrapping any
	 * embedded IPv4 address (see {@link HostClassifier}).
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum HostClass {
		/**
		 * Not a usable host: empty, bad characters, a malformed DNS name, a malformed or zone-scoped IPv6 literal, or
		 * a host that looks numeric but is not a strict literal.
		 */
		INVALID,
		/**
		 * A syntactically valid DNS name other than a localhost name. It is never resolved.
		 */
		HOSTNAME,
		/**
		 * {@code localhost} or a name under {@code .localhost} (RFC 6761 section 6.3), in any ASCII case, with or
		 * without a trailing dot. It is never resolved.
		 */
		LOCALHOST_NAME,
		/**
		 * The IPv4 "this network" block {@code 0.0.0.0/8} (RFC 791, RFC 6890) and the IPv6 unspecified address
		 * {@code ::}. A connection to {@code 0.0.0.0} or {@code ::} can reach the local host.
		 */
		ANY_LOCAL,
		/**
		 * {@code 127.0.0.0/8} (RFC 1122) and {@code ::1} (RFC 4291), including the IPv4-compatible and NAT64 forms of
		 * a {@code 127.0.0.0/8} address, which the JDK does not connect to as loopback (see {@link HostClassifier}).
		 * Use {@link #isLoopbackLiteral(String)} to decide whether a connection stays on the host.
		 */
		LOOPBACK,
		/**
		 * {@code 169.254.0.0/16} (RFC 3927) and {@code fe80::/10} (RFC 4291). This includes the common cloud
		 * metadata address {@code 169.254.169.254}.
		 */
		LINK_LOCAL,
		/**
		 * A cloud metadata address outside the link-local ranges: {@code fd00:ec2::254} (the IPv6 address of the
		 * Amazon EC2 instance metadata service).
		 */
		CLOUD_METADATA,
		/**
		 * The RFC 1918 private-use blocks {@code 10.0.0.0/8}, {@code 172.16.0.0/12} and {@code 192.168.0.0/16}.
		 */
		PRIVATE_USE,
		/**
		 * The RFC 6598 shared address space {@code 100.64.0.0/10}, used for carrier-grade NAT.
		 */
		SHARED_ADDRESS_SPACE,
		/**
		 * The RFC 4193 unique local addresses {@code fc00::/7}, except {@link #CLOUD_METADATA}.
		 */
		UNIQUE_LOCAL,
		/**
		 * The RFC 3056 6to4 prefix {@code 2002::/16}.
		 */
		SIX_TO_FOUR,
		/**
		 * The RFC 4380 Teredo prefix {@code 2001::/32}.
		 */
		TEREDO,
		/**
		 * Any other literal address, including public, multicast, reserved and documentation addresses.
		 */
		OTHER_ADDRESS
	}

	private HostClassifier() {
		// Static helpers only.
	}

	/**
	 * Classifies a URI host as {@link java.net.URI#getHost()} returns it: IPv6 literals keep their brackets.
	 *
	 * @param host the host
	 * @return the host's class; never {@code null}
	 */
	@NonNull
	public static HostClass classify(@NonNull String host) {
		requireNonNull(host);

		if (host.isEmpty())
			return HostClass.INVALID;

		if (host.charAt(0) == '[') {
			byte @Nullable [] address = parseBracketedIpv6(host);
			return address == null ? HostClass.INVALID : classifyIpv6(address);
		}

		for (int i = 0; i < host.length(); ++i)
			if (!isHostnameCharacter(host.charAt(i)))
				return HostClass.INVALID;

		if (endsInNumber(host)) {
			byte @Nullable [] address = parseIpv4(host);
			return address == null ? HostClass.INVALID : classifyIpv4(address, 0);
		}

		if (!isValidHostname(host))
			return HostClass.INVALID;

		return isLocalhostName(host) ? HostClass.LOCALHOST_NAME : HostClass.HOSTNAME;
	}

	/**
	 * Returns whether {@code host} is a literal address that the JDK connects to as loopback: an IPv4 literal in
	 * {@code 127.0.0.0/8} (in any strict IPv4 form), {@code [::1]}, or an IPv4-mapped literal in
	 * {@code ::ffff:127.0.0.0/104}, which {@code InetAddress} turns into that IPv4 address. The IPv4-compatible and
	 * NAT64 forms of a loopback address are not loopback here, although {@link #classify(String)} gives them
	 * {@link HostClass#LOOPBACK}: the JDK connects to them as ordinary IPv6 addresses, which leave the host.
	 *
	 * @param host the host, with brackets around an IPv6 address
	 * @return {@code true} if a connection to the literal stays on the local host
	 */
	public static boolean isLoopbackLiteral(@NonNull String host) {
		byte @Nullable [] address = parseLiteral(host);

		if (address == null)
			return false;
		if (address.length == 4)
			return (address[0] & 0xFF) == 127;
		if (allZero(address, 0, 15))
			return address[15] == 1;

		return allZero(address, 0, 10) && (address[10] & 0xFF) == 0xFF && (address[11] & 0xFF) == 0xFF
				&& (address[12] & 0xFF) == 127;
	}

	/**
	 * Parses a host that is a strict IP literal (see {@link HostClassifier}).
	 *
	 * @param host the host, with brackets around an IPv6 address
	 * @return a new 4-byte array for an IPv4 form, a new 16-byte array for a bracketed IPv6 form, or {@code null} if
	 * the host is not a strict literal
	 */
	public static byte @Nullable [] parseLiteral(@NonNull String host) {
		requireNonNull(host);

		if (!host.isEmpty() && host.charAt(0) == '[')
			return parseBracketedIpv6(host);

		return parseIpv4(host);
	}

	/**
	 * Parses a strict IPv4 form: one to four decimal parts without leading zeros, each leading part at most 255 and
	 * the last part filling the remaining bytes.
	 */
	private static byte @Nullable [] parseIpv4(@NonNull String text) {
		int length = text.length();

		if (length == 0 || length > MAXIMUM_IPV4_LENGTH)
			return null;

		byte[] address = new byte[4];
		int partCount = 0;
		long value = 0;
		int digits = 0;

		for (int i = 0; i < length; ++i) {
			char c = text.charAt(i);

			if (c == '.') {
				if (digits == 0 || partCount == 3 || value > 0xFF)
					return null;
				address[partCount++] = (byte) value;
				value = 0;
				digits = 0;
			} else if (c >= '0' && c <= '9') {
				// A leading zero is ambiguous: the JDK reads 010 as ten, BSD inet_aton as eight.
				if (digits == 1 && value == 0)
					return null;
				value = value * 10 + (c - '0');
				++digits;
			} else {
				return null;
			}
		}

		if (digits == 0 || value >= (1L << ((4 - partCount) * 8)))
			return null;

		for (int i = 3; i >= partCount; --i) {
			address[i] = (byte) value;
			value >>>= 8;
		}

		return address;
	}

	/**
	 * Parses {@code [IPv6]}, the form {@link java.net.URI#getHost()} returns.
	 */
	private static byte @Nullable [] parseBracketedIpv6(@NonNull String host) {
		int length = host.length();

		if (length < 2 || host.charAt(0) != '[' || host.charAt(length - 1) != ']')
			return null;

		return parseIpv6(host.substring(1, length - 1));
	}

	/**
	 * Parses RFC 4291 section 2.2 text, following the structure of BIND's {@code inet_pton6}, with strict
	 * dotted-quad tails and no zone ID.
	 */
	private static byte @Nullable [] parseIpv6(@NonNull String text) {
		int length = text.length();

		if (length < 2 || length > MAXIMUM_IPV6_LENGTH)
			return null;

		byte[] address = new byte[16];
		int index = 0;
		int next = 0;
		int compressionAt = -1;
		int groupStart;
		int value = 0;
		int hexDigits = 0;

		// A leading "::" is the only place a colon may start the text.
		if (text.charAt(0) == ':') {
			if (text.charAt(1) != ':')
				return null;
			index = 1;
		}

		groupStart = index;

		while (index < length) {
			char c = text.charAt(index++);
			int hexValue = hexValue(c);

			if (hexValue >= 0) {
				if (++hexDigits > 4)
					return null;
				value = (value << 4) | hexValue;
				continue;
			}

			if (c == ':') {
				groupStart = index;

				if (hexDigits == 0) {
					if (compressionAt >= 0)
						return null;
					compressionAt = next;
					continue;
				}

				// A single colon may not end the text.
				if (index == length || next + 2 > address.length)
					return null;

				address[next++] = (byte) (value >>> 8);
				address[next++] = (byte) value;
				value = 0;
				hexDigits = 0;
				continue;
			}

			if (c == '.' && next + 4 <= address.length) {
				byte @Nullable [] ipv4 = parseDottedQuad(text.substring(groupStart));

				if (ipv4 == null)
					return null;

				for (byte octet : ipv4)
					address[next++] = octet;

				// The dotted quad ran to the end of the text.
				hexDigits = 0;
				break;
			}

			return null;
		}

		if (hexDigits > 0) {
			if (next + 2 > address.length)
				return null;
			address[next++] = (byte) (value >>> 8);
			address[next++] = (byte) value;
		}

		if (compressionAt >= 0) {
			// "::" stands for at least one group of zeros.
			if (next == address.length)
				return null;

			int moved = next - compressionAt;

			for (int i = 1; i <= moved; ++i) {
				address[address.length - i] = address[compressionAt + moved - i];
				address[compressionAt + moved - i] = 0;
			}

			next = address.length;
		}

		return next == address.length ? address : null;
	}

	/**
	 * Parses exactly four decimal parts, each 0 to 255 with no leading zeros (the IPv4 tail of an IPv6 address).
	 */
	private static byte @Nullable [] parseDottedQuad(@NonNull String text) {
		int dots = 0;

		for (int i = 0; i < text.length(); ++i)
			if (text.charAt(i) == '.')
				++dots;

		return dots == 3 ? parseIpv4(text) : null;
	}

	private static int hexValue(char c) {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		return -1;
	}

	/**
	 * Classifies the IPv4 address at {@code address[offset..offset + 3]}.
	 */
	@NonNull
	private static HostClass classifyIpv4(byte @NonNull [] address, int offset) {
		int first = address[offset] & 0xFF;
		int second = address[offset + 1] & 0xFF;

		if (first == 0)
			return HostClass.ANY_LOCAL;
		if (first == 127)
			return HostClass.LOOPBACK;
		if (first == 169 && second == 254)
			return HostClass.LINK_LOCAL;
		if (first == 10 || (first == 172 && (second & 0xF0) == 16) || (first == 192 && second == 168))
			return HostClass.PRIVATE_USE;
		if (first == 100 && (second & 0xC0) == 64)
			return HostClass.SHARED_ADDRESS_SPACE;

		return HostClass.OTHER_ADDRESS;
	}

	@NonNull
	private static HostClass classifyIpv6(byte @NonNull [] address) {
		boolean firstNinetySixBitsZero = allZero(address, 0, 12);

		if (firstNinetySixBitsZero) {
			// :: and ::1 are themselves; the rest of ::/96 is IPv4-compatible.
			if (allZero(address, 12, 15)) {
				if (address[15] == 0)
					return HostClass.ANY_LOCAL;
				if (address[15] == 1)
					return HostClass.LOOPBACK;
			}
			return classifyIpv4(address, 12);
		}

		// IPv4-mapped, ::ffff:0:0/96.
		if (allZero(address, 0, 10) && (address[10] & 0xFF) == 0xFF && (address[11] & 0xFF) == 0xFF)
			return classifyIpv4(address, 12);

		int first = address[0] & 0xFF;
		int second = address[1] & 0xFF;

		// NAT64 well-known prefix, 64:ff9b::/96 (RFC 6052).
		if (first == 0x00 && second == 0x64 && (address[2] & 0xFF) == 0xFF && (address[3] & 0xFF) == 0x9B
				&& allZero(address, 4, 12))
			return classifyIpv4(address, 12);

		if (first == 0xFE && (second & 0xC0) == 0x80)
			return HostClass.LINK_LOCAL;

		// fd00:ec2::254
		if (first == 0xFD && second == 0x00 && address[2] == 0x0E && (address[3] & 0xFF) == 0xC2
				&& allZero(address, 4, 14) && address[14] == 0x02 && address[15] == 0x54)
			return HostClass.CLOUD_METADATA;

		if ((first & 0xFE) == 0xFC)
			return HostClass.UNIQUE_LOCAL;

		if (first == 0x20 && second == 0x02)
			return HostClass.SIX_TO_FOUR;

		if (first == 0x20 && second == 0x01 && address[2] == 0 && address[3] == 0)
			return HostClass.TEREDO;

		return HostClass.OTHER_ADDRESS;
	}

	/**
	 * Returns whether {@code address[from..to - 1]} are all zero.
	 */
	private static boolean allZero(byte @NonNull [] address, int from, int to) {
		for (int i = from; i < to; ++i)
			if (address[i] != 0)
				return false;
		return true;
	}

	private static boolean isHostnameCharacter(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
	}

	/**
	 * The WHATWG URL Standard's "ends in a number" check: after one trailing dot is removed, the last label is all
	 * ASCII digits or a {@code 0x} hexadecimal number. Such a host must be a strict literal or it is invalid.
	 */
	private static boolean endsInNumber(@NonNull String host) {
		int end = host.endsWith(".") ? host.length() - 1 : host.length();
		int start = host.lastIndexOf('.', end - 1) + 1;

		if (start >= end)
			return false;

		boolean allDigits = true;

		for (int i = start; i < end; ++i) {
			char c = host.charAt(i);
			if (c < '0' || c > '9') {
				allDigits = false;
				break;
			}
		}

		if (allDigits)
			return true;

		if (end - start < 2 || host.charAt(start) != '0' || (host.charAt(start + 1) != 'x'
				&& host.charAt(start + 1) != 'X'))
			return false;

		for (int i = start + 2; i < end; ++i)
			if (hexValue(host.charAt(i)) < 0)
				return false;

		return true;
	}

	/**
	 * RFC 1123 section 2.1 host syntax: dot-separated labels of letters, digits and hyphens, 1 to 63 characters,
	 * neither starting nor ending with a hyphen, at most 253 characters in all, with one optional trailing dot.
	 */
	private static boolean isValidHostname(@NonNull String host) {
		int end = host.endsWith(".") ? host.length() - 1 : host.length();

		if (end == 0 || end > MAXIMUM_HOSTNAME_LENGTH)
			return false;

		int labelStart = 0;

		for (int i = 0; i <= end; ++i) {
			if (i == end || host.charAt(i) == '.') {
				int labelLength = i - labelStart;

				if (labelLength == 0 || labelLength > MAXIMUM_LABEL_LENGTH || host.charAt(labelStart) == '-'
						|| host.charAt(i - 1) == '-')
					return false;

				labelStart = i + 1;
			}
		}

		return true;
	}

	/**
	 * Returns whether an ASCII host is {@code localhost} or ends in {@code .localhost}, ignoring ASCII case and one
	 * trailing dot. The comparison folds ASCII letters only, so no Unicode case mapping can make a name match.
	 */
	private static boolean isLocalhostName(@NonNull String host) {
		int end = host.endsWith(".") ? host.length() - 1 : host.length();
		int start = end - LOCALHOST.length();

		if (start < 0)
			return false;

		for (int i = 0; i < LOCALHOST.length(); ++i) {
			char c = host.charAt(start + i);
			char lowerCase = c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
			if (lowerCase != LOCALHOST.charAt(i))
				return false;
		}

		return start == 0 || host.charAt(start - 1) == '.';
	}
}
