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
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Classifies the host of an outbound URI without ever resolving it (plan R12, D35; M1 plan A-1; gate 8, G8-5 to
 * G8-7).
 * <p>
 * A host is one of three things:
 * <ul>
 *   <li>an <em>IP literal</em>: an IPv4 form that {@code InetAddress.getByName} would also parse numerically, or a
 *   bracketed IPv6 address. It is classified by address;</li>
 *   <li>a <em>DNS name</em>: a syntactically valid name. It is never resolved, so its class comes from its text alone
 *   and says nothing about the addresses it points at;</li>
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
 *   {@code inet_aton}, which some proxies and resolvers use, reads it as octal (8.1.1.1). {@code 0251.254.169.254}
 *   is longer than the JDK's literal parser accepts, and {@code inet_aton} reads it as 169.254.169.254. By default
 *   the JDK refuses such a host as an ambiguous literal, without asking the resolver; only with the system property
 *   {@code jdk.net.allowAmbiguousIPAddressLiterals} set to {@code true} does it pass it to the platform resolver,
 *   and the macOS resolver then reads it as 251.254.169.254;</li>
 *   <li>any host whose last label is all digits or a {@code 0x} hexadecimal number but that is not a strict literal,
 *   such as {@code 1.2.3.4.5}, {@code 256.1.1.1}, {@code 127.0.0.1.} or {@code 0xa9fea9fe}. The JDK's literal parser
 *   rejects all of these. It passes {@code 1.2.3.4.5}, {@code 256.1.1.1} and {@code 127.0.0.1.} to the platform
 *   resolver, which may still read them as addresses. {@code 0xa9fea9fe}, which {@code inet_aton} reads as
 *   169.254.169.254, it refuses by default as an ambiguous literal, and passes to the platform resolver only with
 *   that system property set; the macOS resolver then reads it as 169.254.169.254.</li>
 * </ul>
 * A proxy, or other software that parses the host with {@code inet_aton}, reads both {@code 0xa9fea9fe} and
 * {@code 0251.254.169.254} as 169.254.169.254, so these hosts are refused here rather than left to a JVM setting, a
 * resolver or a proxy.
 * <strong>IPv6 forms</strong> are RFC 4291 section 2.2 text in brackets: groups of one to four hexadecimal digits,
 * at most one {@code ::}, and an optional dotted-quad IPv4 tail with no leading zeros. A zone ID ({@code %en0}) makes
 * the host {@link HostClass#INVALID}.
 * <p>
 * <strong>IPv4 is a denylist, IPv6 an allowlist.</strong> An IPv4 address is {@link HostClass#OTHER_ADDRESS} unless a
 * listed block names it, so a block IANA adds later is permitted until it is listed here. An IPv6 address is
 * {@link HostClass#OTHER_ADDRESS} only inside {@code 2000::/3} and outside its non-global blocks ({@code 2001::/23},
 * {@code 2001:db8::/32}, {@code 2002::/16} and {@code 3fff::/20}); everything else has a rejectable class, so a future
 * special allocation outside {@code 2000::/3} fails closed.
 * <p>
 * <strong>Embedded IPv4</strong> (one class per host; G8-5):
 * <ul>
 *   <li>{@code ::} and {@code ::1} are classified as themselves;</li>
 *   <li>an IPv4-mapped address ({@code ::ffff:0:0/96}) is classified as the IPv4 address inside it, because
 *   {@code InetAddress} turns it into that {@code Inet4Address} and the JDK connects to it. So
 *   {@code [::ffff:8.8.8.8]} is {@link HostClass#OTHER_ADDRESS}, like {@code 8.8.8.8};</li>
 *   <li>a NAT64 Well-Known Prefix address ({@code 64:ff9b::/96}, RFC 6052) is classified as the IPv4 address inside
 *   it: a translator delivers it to that address;</li>
 *   <li>IPv4-compatible ({@code ::/96}) and RFC 2765 IPv4-translated ({@code ::ffff:0:0:0/96}) addresses take the
 *   class of the IPv4 address inside them, so that they can be rejected, except that a global IPv4 address inside
 *   makes them {@link HostClass#NON_GLOBAL}: the JDK keeps them as IPv6 and connects to the IPv6 address, which a
 *   tunnel or translator may deliver to the IPv4 address;</li>
 *   <li>the RFC 8215 local-use NAT64 prefix {@code 64:ff9b:1::/48} is {@link HostClass#NAT64_LOCAL_USE} as a whole,
 *   because where the IPv4 address sits depends on the operator's prefix length;</li>
 *   <li>6to4 and Teredo addresses are not unwrapped: the IPv4 address inside is a tunnel endpoint, not the
 *   destination.</li>
 * </ul>
 * Network-specific NAT64 prefixes (RFC 6052 section 2.3) and RFC 7757 explicit address mappings look like ordinary
 * IPv6 addresses and cannot be recognized from the text.
 * <p>
 * For the embedded forms other than IPv4-mapped, a class does not mean that the JDK connects to the IPv4 address, so a
 * caller that grants anything for a class must not rely on it: {@link #isPlainHttpLoopbackHost(String)} is the test
 * for plain {@code http} to loopback.
 * <p>
 * <strong>DNS names</strong> are compared as text, folding ASCII letters only, ignoring one trailing dot, and matching
 * a suffix only on a label boundary. Each name rule covers a name and every name under it, so
 * {@code METADATA.GOOGLE.INTERNAL.} and {@code x.metadata.goog} are metadata names and {@code idp.evilinternal} is
 * not under {@code .internal}. The first matching class wins:
 * {@link HostClass#METADATA_NAME}, then {@link HostClass#LOCALHOST_NAME}, then {@link HostClass#LOCAL_NAME}, then
 * {@link HostClass#HOSTNAME}.
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

	// Known cloud metadata endpoints as of 2026-09-27 (G8-6, and the owner's decision of that date for fd20:ce::254).
	// Each entry was confirmed in its provider's documentation on that date; the sources are listed in
	// HostClassifierTests, and beside isCloudMetadataIpv6 for fd20:ce::254. The list is not exhaustive.

	/**
	 * Alibaba Cloud ECS instance metadata, {@code 100.100.100.200}, inside the shared address space.
	 */
	private static final int ALIBABA_CLOUD_METADATA = ipv4(100, 100, 100, 200);

	/**
	 * Azure WireServer, {@code 168.63.129.16}, a virtual public address that no identity provider can use.
	 */
	private static final int AZURE_WIRESERVER = ipv4(168, 63, 129, 16);

	/**
	 * The metadata names, in lower case (Google Compute Engine's {@code metadata.google.internal} and
	 * {@code metadata.goog}). Each name and every name under it is a {@link HostClass#METADATA_NAME}, like every other
	 * name rule here (G8-5).
	 */
	private static final List<@NonNull String> METADATA_NAMES = List.of("metadata.google.internal", "metadata.goog");

	/**
	 * The special-use, private-use and infrastructure names, in lower case: each name and every name under it is a
	 * {@link HostClass#LOCAL_NAME}.
	 * <ul>
	 *   <li>{@code local} (RFC 6762), {@code internal} (ICANN Board resolution 2024.07.29.06), {@code test},
	 *   {@code invalid} and {@code example} (RFC 6761), {@code onion} (RFC 7686) and {@code alt} (RFC 9476)
	 *   (G8-5), each listed in the IANA Special-Use Domain Names registry or reserved for private use as of
	 *   2026-09-27;</li>
	 *   <li>{@code arpa}, the domain reserved for Internet infrastructure (RFC 3172), as a whole (the owner's decision
	 *   of 2026-09-27). It holds G8-5's {@code home.arpa} (RFC 8375), the registry's other entries there on that date
	 *   ({@code service.arpa}, {@code ipv4only.arpa}, {@code resolver.arpa}, {@code eap.arpa}, the deprecated
	 *   {@code eap-noob.arpa}, {@code 6tisch.arpa} and the reverse zones it lists) and the reverse-mapping zones
	 *   {@code in-addr.arpa} (RFC 1035 section 3.5) and {@code ip6.arpa} (RFC 3596 section 2.5). Its names serve
	 *   Internet infrastructure, not services such as an identity provider, so every one of them is local here,
	 *   whether or not the registry lists it.</li>
	 * </ul>
	 * Other registry entries, such as {@code example.com}, are not listed, so the list is not exhaustive.
	 */
	private static final List<@NonNull String> LOCAL_NAME_SUFFIXES = List.of("local", "internal", "test", "invalid",
			"example", "onion", "alt", "arpa");

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
		 * A syntactically valid DNS name of two or more labels that no other name class covers. It is never resolved.
		 */
		HOSTNAME,
		/**
		 * {@code localhost} or a name under {@code .localhost} (RFC 6761 section 6.3), in any ASCII case, with or
		 * without a trailing dot. It is never resolved.
		 */
		LOCALHOST_NAME,
		/**
		 * A name that is local by construction or reserved for a use no identity provider has: a single-label name,
		 * which a resolver may expand with its search domains onto an internal host; {@code local}, {@code internal},
		 * {@code test}, {@code invalid}, {@code example}, {@code onion} or {@code alt}; {@code arpa}, the Internet
		 * infrastructure domain, which holds {@code home.arpa}, the other special-use names there and the
		 * reverse-mapping zones {@code in-addr.arpa} and {@code ip6.arpa}; or a name under one of them. It is never
		 * resolved.
		 */
		LOCAL_NAME,
		/**
		 * A known cloud metadata name as of 2026-09-27, {@code metadata.google.internal} or {@code metadata.goog}, or
		 * a name under one of them. This class wins over {@link #LOCAL_NAME}.
		 */
		METADATA_NAME,
		/**
		 * The IPv4 "this network" block {@code 0.0.0.0/8} (RFC 791, RFC 6890) and the IPv6 unspecified address
		 * {@code ::}. A connection to {@code 0.0.0.0} or {@code ::} can reach the local host.
		 */
		ANY_LOCAL,
		/**
		 * {@code 127.0.0.0/8} (RFC 1122) and {@code ::1} (RFC 4291), including the IPv4-mapped, IPv4-compatible,
		 * IPv4-translated and NAT64 Well-Known Prefix forms of a {@code 127.0.0.0/8} address, all but the first of
		 * which the JDK does not connect to as loopback (see {@link HostClassifier}). Use
		 * {@link HostClassifier#isPlainHttpLoopbackHost(String)} to decide whether plain {@code http} may be used.
		 */
		LOOPBACK,
		/**
		 * {@code 169.254.0.0/16} (RFC 3927) and {@code fe80::/10} (RFC 4291). This includes the common cloud
		 * metadata address {@code 169.254.169.254}.
		 */
		LINK_LOCAL,
		/**
		 * A known cloud metadata address outside the link-local ranges, as of 2026-09-27: {@code 100.100.100.200}
		 * (Alibaba Cloud ECS), {@code 168.63.129.16} (Azure WireServer), {@code fd00:ec2::254} (the Amazon EC2
		 * instance metadata service), {@code fd00:ec2::23} (the Amazon EKS Pod Identity Agent) and
		 * {@code fd20:ce::254} (the Google Compute Engine metadata server over IPv6). This class wins over
		 * {@link #SHARED_ADDRESS_SPACE} and {@link #UNIQUE_LOCAL}.
		 */
		CLOUD_METADATA,
		/**
		 * The RFC 1918 private-use blocks {@code 10.0.0.0/8}, {@code 172.16.0.0/12} and {@code 192.168.0.0/16}.
		 */
		PRIVATE_USE,
		/**
		 * The RFC 6598 shared address space {@code 100.64.0.0/10}, used for carrier-grade NAT, except
		 * {@link #CLOUD_METADATA}.
		 */
		SHARED_ADDRESS_SPACE,
		/**
		 * The RFC 4193 unique local addresses {@code fc00::/7}, except {@link #CLOUD_METADATA}.
		 */
		UNIQUE_LOCAL,
		/**
		 * The RFC 3056 6to4 prefix {@code 2002::/16}. It is not unwrapped.
		 */
		SIX_TO_FOUR,
		/**
		 * The RFC 4380 Teredo prefix {@code 2001::/32}. It is not unwrapped.
		 */
		TEREDO,
		/**
		 * The RFC 8215 local-use NAT64 prefix {@code 64:ff9b:1::/48}, as a whole.
		 */
		NAT64_LOCAL_USE,
		/**
		 * A literal outside globally reachable unicast space that no other class names:
		 * <ul>
		 *   <li>the IPv4 blocks of the IANA IPv4 Special-Purpose Address Registry marked not globally reachable:
		 *   {@code 192.0.0.0/24} except {@code 192.0.0.9} and {@code 192.0.0.10}, {@code 192.0.2.0/24},
		 *   {@code 198.18.0.0/15}, {@code 198.51.100.0/24} and {@code 203.0.113.0/24}, and the deprecated 6to4 relay
		 *   anycast block {@code 192.88.99.0/24} as a whole;</li>
		 *   <li>IPv6 outside {@code 2000::/3} that no other class names (reserved space, {@code 100::/64},
		 *   {@code 5f00::/16}, the deprecated site-local {@code fec0::/10}, ...), and inside it {@code 2001::/23} other
		 *   than Teredo, as a whole, {@code 2001:db8::/32} and {@code 3fff::/20};</li>
		 *   <li>an IPv4-compatible or IPv4-translated address whose IPv4 address is global.</li>
		 * </ul>
		 */
		NON_GLOBAL,
		/**
		 * IPv4 multicast {@code 224.0.0.0/4}, the reserved block {@code 240.0.0.0/4}, which includes the limited
		 * broadcast address {@code 255.255.255.255}, and IPv6 multicast {@code ff00::/8}.
		 */
		MULTICAST_OR_RESERVED,
		/**
		 * A literal in globally reachable unicast space: an IPv4 address that no other class names, an IPv6 address in
		 * {@code 2000::/3} outside its non-global blocks, or an IPv4-mapped or NAT64 Well-Known Prefix address around
		 * such an IPv4 address.
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

		return classifyName(host);
	}

	/**
	 * Returns whether {@code host} is a literal address that the JDK connects to as loopback: an IPv4 literal in
	 * {@code 127.0.0.0/8} (in any strict IPv4 form), {@code [::1]}, or an IPv4-mapped literal in
	 * {@code ::ffff:127.0.0.0/104}, which {@code InetAddress} turns into that IPv4 address. The IPv4-compatible,
	 * IPv4-translated and NAT64 forms of a loopback address are not loopback here, although {@link #classify(String)}
	 * gives them {@link HostClass#LOOPBACK}: the JDK connects to them as ordinary IPv6 addresses, which leave the host.
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
	 * Returns whether plain {@code http} to {@code host} may be allowed when a builder explicitly allows insecure
	 * loopback for tests (G8-7): a literal the JDK connects to as loopback ({@link #isLoopbackLiteral(String)}), or
	 * exactly {@code localhost}, in any ASCII case and with no trailing dot.
	 * <p>
	 * Names under {@code .localhost} and {@code localhost.} are not accepted: the JDK sends them to the platform
	 * resolver like any other name. Even {@code localhost} reaches loopback only through the platform's name service
	 * (normally the hosts file), with the JDK's own loopback answer only as a fallback when that lookup fails, so
	 * plain {@code http} to {@code localhost} depends on the hosts file.
	 *
	 * @param host the host as {@link java.net.URI#getHost()} returns it, with brackets around an IPv6 address
	 * @return {@code true} if plain {@code http} to the host may be allowed for tests
	 */
	public static boolean isPlainHttpLoopbackHost(@NonNull String host) {
		requireNonNull(host);
		return isLoopbackLiteral(host) || (host.length() == LOCALHOST.length() && regionEqualsIgnoringAsciiCase(host,
				0, LOCALHOST));
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
	 * Classifies the IPv4 address at {@code address[offset..offset + 3]}: a denylist, checked in this order.
	 * <p>
	 * The non-global blocks follow the IANA IPv4 Special-Purpose Address Registry as of 2026-09-27: every block marked
	 * not globally reachable, at the registry's most specific entry, and the deprecated 6to4 relay anycast block
	 * {@code 192.88.99.0/24}, whose allocation has ended, as a whole. The registry's globally reachable entries
	 * ({@code 192.0.0.9}, {@code 192.0.0.10}, {@code 192.31.196.0/24}, {@code 192.52.193.0/24} and
	 * {@code 192.175.48.0/24}) stay {@link HostClass#OTHER_ADDRESS}.
	 */
	@NonNull
	private static HostClass classifyIpv4(byte @NonNull [] address, int offset) {
		int value = ((address[offset] & 0xFF) << 24) | ((address[offset + 1] & 0xFF) << 16)
				| ((address[offset + 2] & 0xFF) << 8) | (address[offset + 3] & 0xFF);

		if (isInIpv4Block(value, ipv4(0, 0, 0, 0), 8))
			return HostClass.ANY_LOCAL;
		if (isInIpv4Block(value, ipv4(127, 0, 0, 0), 8))
			return HostClass.LOOPBACK;
		if (isInIpv4Block(value, ipv4(169, 254, 0, 0), 16))
			return HostClass.LINK_LOCAL;
		if (value == ALIBABA_CLOUD_METADATA || value == AZURE_WIRESERVER)
			return HostClass.CLOUD_METADATA;
		if (isInIpv4Block(value, ipv4(10, 0, 0, 0), 8) || isInIpv4Block(value, ipv4(172, 16, 0, 0), 12)
				|| isInIpv4Block(value, ipv4(192, 168, 0, 0), 16))
			return HostClass.PRIVATE_USE;
		if (isInIpv4Block(value, ipv4(100, 64, 0, 0), 10))
			return HostClass.SHARED_ADDRESS_SPACE;
		// 224.0.0.0/4 and 240.0.0.0/4 together: the top two bits set.
		if (isInIpv4Block(value, ipv4(224, 0, 0, 0), 3))
			return HostClass.MULTICAST_OR_RESERVED;
		if ((isInIpv4Block(value, ipv4(192, 0, 0, 0), 24) && value != ipv4(192, 0, 0, 9)
				&& value != ipv4(192, 0, 0, 10))
				|| isInIpv4Block(value, ipv4(192, 0, 2, 0), 24)
				|| isInIpv4Block(value, ipv4(192, 88, 99, 0), 24)
				|| isInIpv4Block(value, ipv4(198, 18, 0, 0), 15)
				|| isInIpv4Block(value, ipv4(198, 51, 100, 0), 24)
				|| isInIpv4Block(value, ipv4(203, 0, 113, 0), 24))
			return HostClass.NON_GLOBAL;

		return HostClass.OTHER_ADDRESS;
	}

	/**
	 * Classifies an IPv6 address: embedded IPv4 first (see {@link HostClassifier}), then an allowlist for
	 * {@code 2000::/3}. The special blocks follow the IANA IPv6 Special-Purpose Address Registry as of 2026-09-27.
	 */
	@NonNull
	private static HostClass classifyIpv6(byte @NonNull [] address) {
		int first = group(address, 0);
		int second = group(address, 1);

		if (allZero(address, 0, 12)) {
			// :: and ::1 are themselves; the rest of ::/96 is IPv4-compatible.
			if (allZero(address, 12, 15)) {
				if (address[15] == 0)
					return HostClass.ANY_LOCAL;
				if (address[15] == 1)
					return HostClass.LOOPBACK;
			}
			return classifyTunneledIpv4(address);
		}

		// IPv4-mapped, ::ffff:0:0/96: the JDK connects to the IPv4 address itself.
		if (allZero(address, 0, 10) && group(address, 5) == 0xFFFF)
			return classifyIpv4(address, 12);

		// IPv4-translated, ::ffff:0:0:0/96 (RFC 2765).
		if (allZero(address, 0, 8) && group(address, 4) == 0xFFFF && group(address, 5) == 0)
			return classifyTunneledIpv4(address);

		if (first == 0x0064 && second == 0xFF9B) {
			// NAT64 Well-Known Prefix, 64:ff9b::/96 (RFC 6052).
			if (allZero(address, 4, 12))
				return classifyIpv4(address, 12);
			// NAT64 local-use prefix, 64:ff9b:1::/48 (RFC 8215).
			if (group(address, 2) == 0x0001)
				return HostClass.NAT64_LOCAL_USE;
		}

		if ((first & 0xFFC0) == 0xFE80)
			return HostClass.LINK_LOCAL;

		if (isCloudMetadataIpv6(address))
			return HostClass.CLOUD_METADATA;

		if ((first & 0xFE00) == 0xFC00)
			return HostClass.UNIQUE_LOCAL;

		if ((first & 0xFF00) == 0xFF00)
			return HostClass.MULTICAST_OR_RESERVED;

		if (first == 0x2002)
			return HostClass.SIX_TO_FOUR;

		if (first == 0x2001 && second == 0x0000)
			return HostClass.TEREDO;

		// The allowlist: global unicast is 2000::/3 without 2001::/23 (as a whole), 2001:db8::/32 and 3fff::/20.
		if ((first & 0xE000) != 0x2000
				|| (first == 0x2001 && second < 0x0200)
				|| (first == 0x2001 && second == 0x0DB8)
				|| (first == 0x3FFF && (second & 0xF000) == 0))
			return HostClass.NON_GLOBAL;

		return HostClass.OTHER_ADDRESS;
	}

	/**
	 * The class of an IPv4-compatible or IPv4-translated address, which the JDK keeps as IPv6: the class of the IPv4
	 * address inside, or {@link HostClass#NON_GLOBAL} when that address is global (G8-5).
	 */
	@NonNull
	private static HostClass classifyTunneledIpv4(byte @NonNull [] address) {
		HostClass embedded = classifyIpv4(address, 12);
		return embedded == HostClass.OTHER_ADDRESS ? HostClass.NON_GLOBAL : embedded;
	}

	/**
	 * {@code fd00:ec2::254} (Amazon EC2 instance metadata), {@code fd00:ec2::23} (Amazon EKS Pod Identity Agent) and
	 * {@code fd20:ce::254} (the Google Compute Engine metadata server over IPv6). Each prefix is paired with its own
	 * last group only, so {@code fd20:ce::23} stays {@link HostClass#UNIQUE_LOCAL}.
	 */
	private static boolean isCloudMetadataIpv6(byte @NonNull [] address) {
		if (!allZero(address, 4, 14))
			return false;

		int first = group(address, 0);
		int second = group(address, 1);
		int last = group(address, 7);

		if (first == 0xFD00 && second == 0x0EC2)
			return last == 0x0254 || last == 0x0023;

		// Google Cloud documents fd20:ce::254 as the metadata server's IPv6 address, over http and, on Shielded VMs,
		// over https: "View and query VM metadata" (last updated 2026-09-24),
		// https://docs.cloud.google.com/compute/docs/metadata/querying-metadata, and "About VM metadata",
		// https://docs.cloud.google.com/compute/docs/metadata/overview, both retrieved 2026-09-27. Added by the owner's
		// decision of 2026-09-27, beyond G8-6's list.
		return first == 0xFD20 && second == 0x00CE && last == 0x0254;
	}

	/**
	 * Returns the 16-bit group {@code index} (0 to 7) of an IPv6 address.
	 */
	private static int group(byte @NonNull [] address, int index) {
		return ((address[2 * index] & 0xFF) << 8) | (address[2 * index + 1] & 0xFF);
	}

	/**
	 * Returns an IPv4 address as a 32-bit value.
	 */
	private static int ipv4(int a, int b, int c, int d) {
		return (a << 24) | (b << 16) | (c << 8) | d;
	}

	/**
	 * Returns whether {@code value} lies in the IPv4 block {@code base/prefixLength} (1 to 32).
	 */
	private static boolean isInIpv4Block(int value, int base, int prefixLength) {
		int mask = -1 << (32 - prefixLength);
		return (value & mask) == base;
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
	 * Classifies a valid DNS name (see {@link HostClassifier}): metadata names, then localhost names, then local
	 * names.
	 */
	@NonNull
	private static HostClass classifyName(@NonNull String host) {
		for (String metadataName : METADATA_NAMES)
			if (matchesName(host, metadataName))
				return HostClass.METADATA_NAME;

		if (matchesName(host, LOCALHOST))
			return HostClass.LOCALHOST_NAME;

		int end = host.endsWith(".") ? host.length() - 1 : host.length();

		// A single label, with or without its trailing dot.
		if (host.lastIndexOf('.', end - 1) < 0)
			return HostClass.LOCAL_NAME;

		for (String suffix : LOCAL_NAME_SUFFIXES)
			if (matchesName(host, suffix))
				return HostClass.LOCAL_NAME;

		return HostClass.HOSTNAME;
	}

	/**
	 * Returns whether an ASCII host is {@code lowerCaseName} or ends in {@code "." + lowerCaseName}, ignoring ASCII
	 * case and one trailing dot. The comparison folds ASCII letters only, so no Unicode case mapping can make a name
	 * match, and a suffix matches only on a label boundary.
	 */
	private static boolean matchesName(@NonNull String host,
																		 @NonNull String lowerCaseName) {
		int end = host.endsWith(".") ? host.length() - 1 : host.length();
		int start = end - lowerCaseName.length();

		if (start < 0 || !regionEqualsIgnoringAsciiCase(host, start, lowerCaseName))
			return false;

		return start == 0 || host.charAt(start - 1) == '.';
	}

	/**
	 * Returns whether {@code text[start..start + lowerCaseExpected.length() - 1]} equals {@code lowerCaseExpected},
	 * folding ASCII letters only. The caller guarantees the region lies inside {@code text}.
	 */
	private static boolean regionEqualsIgnoringAsciiCase(@NonNull String text,
																											 int start,
																											 @NonNull String lowerCaseExpected) {
		for (int i = 0; i < lowerCaseExpected.length(); ++i) {
			char c = text.charAt(start + i);
			char lowerCase = c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
			if (lowerCase != lowerCaseExpected.charAt(i))
				return false;
		}

		return true;
	}
}
