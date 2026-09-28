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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Decides which URIs Revetsec may send requests to.
 * <p>
 * Revetsec applies the policy to every URI it is about to fetch, such as an issuer, a JSON Web Key Set and every
 * endpoint named in remote metadata, before any request is sent. There are two presets:
 * {@link #defaultInstance()}, which rejects the addresses and names it knows to reach a machine's own metadata or
 * configuration services, and {@link #publicAddressesOnlyInstance()}, which also rejects the local, private-use and
 * special-use addresses and names it lists. Neither list is exhaustive.
 * <p>
 * <strong>Hostnames are never resolved.</strong> The policy looks only at the text of the URI. It classifies IP
 * address literals, including the all-digit form ({@code https://2852039166/} is 169.254.169.254), and IPv4 addresses
 * embedded in IPv4-mapped, IPv4-compatible, IPv4-translated and NAT64 IPv6 addresses, and it recognizes special-use
 * and private-use names by their text, folding ASCII letters only and ignoring one trailing dot. A URI whose host
 * {@link URI} cannot parse, including the short dotted forms {@code https://127.1/} and
 * {@code https://169.254.43518/} that {@link java.net.InetAddress} would accept, has no host and is rejected.
 * <p>
 * The policy cannot see where a DNS name points, so no policy stops a hostname that resolves to a private or metadata
 * address, or a name whose DNS answer changes between checks (DNS rebinding). A network-specific NAT64 prefix and an
 * explicit address mapping (RFC 7757) look like ordinary IPv6 addresses, so the policy cannot tell where they lead
 * either. When the URIs come from someone you do not control, such as a tenant-supplied issuer, send Revetsec's
 * traffic through an egress proxy that enforces the destinations you allow, by configuring it on the
 * {@link java.net.http.HttpClient} you give Revetsec.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OutboundUriPolicy {
	private static final OutboundUriPolicy DEFAULT_INSTANCE = new OutboundUriPolicy("default",
			EnumSet.of(HostClass.INVALID, HostClass.ANY_LOCAL, HostClass.LINK_LOCAL, HostClass.CLOUD_METADATA,
					HostClass.METADATA_NAME, HostClass.NAT64_LOCAL_USE));

	private static final OutboundUriPolicy PUBLIC_ADDRESSES_ONLY_INSTANCE = new OutboundUriPolicy(
			"publicAddressesOnly", EnumSet.complementOf(EnumSet.of(HostClass.HOSTNAME, HostClass.OTHER_ADDRESS)));

	@NonNull
	private final String name;
	/**
	 * Never modified after construction and never exposed.
	 */
	@NonNull
	private final Set<@NonNull HostClass> rejectedHostClasses;

	/**
	 * Returns the default policy.
	 * <p>
	 * It permits an absolute {@code https} or {@code http} URI whose host is a DNS name or an IP address literal,
	 * except:
	 * <ul>
	 *   <li>a link-local literal: {@code 169.254.0.0/16}, which includes the common cloud metadata address
	 *   {@code 169.254.169.254}, and {@code fe80::/10};</li>
	 *   <li>an any-local literal: {@code 0.0.0.0/8} (so {@code https://0/} is rejected) and {@code ::};</li>
	 *   <li>the known cloud metadata endpoints as of 2026-09-27: the addresses {@code 100.100.100.200} (Alibaba
	 *   Cloud), {@code 168.63.129.16} (Azure WireServer), {@code fd00:ec2::254} (Amazon EC2), {@code fd00:ec2::23}
	 *   (Amazon EKS Pod Identity) and {@code fd20:ce::254} (Google Compute Engine, over IPv6), and Google Compute
	 *   Engine's names {@code metadata.google.internal} and {@code metadata.goog} and every name under them. The list
	 *   is not exhaustive;</li>
	 *   <li>any address in the RFC 8215 local-use NAT64 prefix {@code 64:ff9b:1::/48};</li>
	 *   <li>an IPv4-mapped, IPv4-compatible, IPv4-translated or NAT64 Well-Known Prefix IPv6 literal around one of the
	 *   IPv4 addresses above.</li>
	 * </ul>
	 * It also rejects a URI with no parseable host; a host that looks numeric but is not a well-formed address
	 * literal, such as {@code 0xa9fea9fe} or {@code 0251.254.169.254}, which the JDK refuses by default but passes to
	 * the platform resolver when {@code jdk.net.allowAmbiguousIPAddressLiterals} is {@code true}, and which a proxy or
	 * resolver that uses {@code inet_aton} reads as {@code 169.254.169.254}; and an IPv6 literal with a zone ID.
	 * <p>
	 * Loopback, private, shared (carrier-grade NAT), unique local, 6to4, Teredo, multicast, reserved and other
	 * non-global addresses are permitted, and so are {@code localhost} and other local names. Revetsec's HTTP layer
	 * separately requires {@code https}, except that a builder may explicitly allow plain {@code http} for tests, to a
	 * loopback literal or exactly {@code localhost} only.
	 *
	 * @return the default policy; always the same instance
	 * @since 1.0.0
	 */
	@NonNull
	public static OutboundUriPolicy defaultInstance() {
		return DEFAULT_INSTANCE;
	}

	/**
	 * Returns the policy that permits only globally reachable destinations, as far as the URI's text shows.
	 * <p>
	 * It permits an absolute {@code https} or {@code http} URI whose host is either:
	 * <ul>
	 *   <li>an IPv4 literal outside the blocks listed below, or an IPv4-mapped ({@code ::ffff:0:0/96}) or NAT64
	 *   Well-Known Prefix ({@code 64:ff9b::/96}) IPv6 literal around one. IPv4 is checked against a list, so a block
	 *   that IANA marks as not globally reachable after 2026-09-27 is permitted until Revetsec lists it;</li>
	 *   <li>an IPv6 literal in the global unicast block {@code 2000::/3}, except {@code 2001::/23} as a whole (which
	 *   includes Teredo, {@code 2001::/32}), 6to4 ({@code 2002::/16}) and the documentation blocks
	 *   {@code 2001:db8::/32} and {@code 3fff::/20}. Everything outside {@code 2000::/3} is rejected, so an IPv6
	 *   block allocated for a special purpose in the future is rejected too;</li>
	 *   <li>a DNS name of at least two labels that is none of the names listed below. Other special-use names, such
	 *   as {@code example.com}, are permitted.</li>
	 * </ul>
	 * On top of everything {@link #defaultInstance()} rejects, it therefore rejects:
	 * <ul>
	 *   <li>loopback, in every form ({@code 127.0.0.0/8}, {@code ::1} and the IPv6 forms around a loopback IPv4
	 *   address);</li>
	 *   <li>the private-use blocks {@code 10.0.0.0/8}, {@code 172.16.0.0/12} and {@code 192.168.0.0/16}, the shared
	 *   address space {@code 100.64.0.0/10} and unique local addresses ({@code fc00::/7});</li>
	 *   <li>the IPv4 blocks that IANA's special-purpose registry marked as not globally reachable as of 2026-09-27,
	 *   such as the documentation and benchmarking blocks, and the deprecated 6to4 relay anycast block
	 *   {@code 192.88.99.0/24};</li>
	 *   <li>multicast and reserved space: {@code 224.0.0.0/4}, {@code 240.0.0.0/4}, {@code 255.255.255.255} and
	 *   {@code ff00::/8};</li>
	 *   <li>6to4 and Teredo as a whole: the IPv4 address inside them is a tunnel endpoint, not the destination;</li>
	 *   <li>IPv4-compatible ({@code ::/96}) and IPv4-translated ({@code ::ffff:0:0:0/96}) literals, whatever the IPv4
	 *   address inside;</li>
	 *   <li>the names {@code localhost} and every name under it, every single-label name (which a resolver may
	 *   complete with its search domains), and {@code local}, {@code internal}, {@code test}, {@code invalid},
	 *   {@code example}, {@code onion} and {@code alt} and every name under them;</li>
	 *   <li>{@code arpa}, the domain reserved for Internet infrastructure (RFC 3172), and every name under it, such as
	 *   {@code home.arpa}, the other special-use names there ({@code service.arpa}, {@code ipv4only.arpa},
	 *   {@code resolver.arpa} and others) and the reverse-mapping zones {@code in-addr.arpa} and
	 *   {@code ip6.arpa}.</li>
	 * </ul>
	 * A name is matched in any ASCII case, with or without one trailing dot, and a suffix only on a label boundary:
	 * {@code idp.internal.} is rejected, {@code idp.evilinternal} is not.
	 * <p>
	 * This policy does not resolve names either, so a public name that points at a private address still passes; see
	 * {@link OutboundUriPolicy}. An identity provider reached through a private DNS zone, such as a name under
	 * {@code .internal}, needs {@link #defaultInstance()} and, where the URIs are not your own, an egress proxy.
	 *
	 * @return the public-addresses-only policy; always the same instance
	 * @since 1.0.0
	 */
	@NonNull
	public static OutboundUriPolicy publicAddressesOnlyInstance() {
		return PUBLIC_ADDRESSES_ONLY_INSTANCE;
	}

	private OutboundUriPolicy(@NonNull String name,
														@NonNull Set<@NonNull HostClass> rejectedHostClasses) {
		this.name = requireNonNull(name);
		this.rejectedHostClasses = Collections.unmodifiableSet(EnumSet.copyOf(rejectedHostClasses));
	}

	/**
	 * Returns whether this policy permits a request to {@code uri}.
	 * <p>
	 * The URI must be absolute, with the scheme {@code https} or {@code http} in any case and a host that
	 * {@link URI#getHost()} can parse; a URI without one, such as {@code https://127.1/} (whose host
	 * {@link URI} cannot parse), is rejected. The host is never resolved. The port, path, query and user
	 * information are not examined.
	 *
	 * @param uri the URI Revetsec is about to send a request to
	 * @return {@code true} if the policy permits the request
	 * @throws NullPointerException if {@code uri} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Boolean permits(@NonNull URI uri) {
		requireNonNull(uri);

		@Nullable String scheme = uri.getScheme();

		if (scheme == null || !(isAsciiCaseInsensitiveMatch(scheme, "https") || isAsciiCaseInsensitiveMatch(scheme,
				"http")))
			return false;

		@Nullable String host = uri.getHost();

		if (host == null)
			return false;

		return !this.rejectedHostClasses.contains(HostClassifier.classify(host));
	}

	/**
	 * Returns a description of this policy.
	 *
	 * @return a description of this policy
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{name=" + this.name + "}";
	}

	/**
	 * Compares a URI scheme with a lower-case ASCII expectation, folding ASCII letters only.
	 */
	private static boolean isAsciiCaseInsensitiveMatch(@NonNull String value,
																										 @NonNull String lowerCaseExpected) {
		if (value.length() != lowerCaseExpected.length())
			return false;

		for (int i = 0; i < value.length(); ++i) {
			char c = value.charAt(i);
			char lowerCase = c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
			if (lowerCase != lowerCaseExpected.charAt(i))
				return false;
		}

		return true;
	}
}
