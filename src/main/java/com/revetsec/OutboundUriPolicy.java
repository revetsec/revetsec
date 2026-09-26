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
 * Revetsec applies the policy to every URI it is about to fetch, such as an issuer and every endpoint named in
 * remote metadata, before any request is sent.
 * <p>
 * <strong>Hostnames are never resolved.</strong> The policy looks only at the text of the URI. It classifies IP
 * address literals, including the all-digit form ({@code https://2852039166/} is 169.254.169.254), and IPv4 addresses
 * embedded in IPv4-mapped, IPv4-compatible and NAT64 IPv6 addresses. A URI whose host {@link URI} cannot parse,
 * including the short dotted forms {@code https://127.1/} and {@code https://169.254.43518/} that
 * {@link java.net.InetAddress} would accept, has no host and is rejected. The policy cannot see where a DNS name
 * points, so no policy stops a hostname that resolves to a private or metadata address, or a name whose DNS answer
 * changes between checks (DNS rebinding). When the URIs come from someone you do not control, such as a
 * tenant-supplied issuer, send Revetsec's traffic through an egress proxy that enforces the destinations you allow,
 * by configuring it on the {@link java.net.http.HttpClient} you give Revetsec.
 * <p>
 * <strong>Provisional.</strong> Only {@link #defaultInstance()} exists so far; stricter presets may be added before
 * 1.0.0.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OutboundUriPolicy {
	private static final OutboundUriPolicy DEFAULT_INSTANCE = new OutboundUriPolicy("default",
			EnumSet.of(HostClass.INVALID, HostClass.ANY_LOCAL, HostClass.LINK_LOCAL, HostClass.CLOUD_METADATA));

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
	 * except a literal in one of these ranges:
	 * <ul>
	 *   <li>link-local: {@code 169.254.0.0/16}, which includes the common cloud metadata address
	 *   {@code 169.254.169.254}, and {@code fe80::/10};</li>
	 *   <li>the IPv6 cloud metadata address {@code fd00:ec2::254};</li>
	 *   <li>any-local: {@code 0.0.0.0/8} (so {@code https://0/} is rejected) and {@code ::}.</li>
	 * </ul>
	 * It also rejects a URI with no parseable host; a host that looks numeric but is not a well-formed address
	 * literal, such as {@code 0xa9fea9fe} or {@code 0251.254.169.254}, which the JDK passes to the platform resolver
	 * and which some resolvers read as {@code 169.254.169.254}; and an IPv6 literal with a zone ID.
	 * <p>
	 * Loopback and private addresses are permitted. Revetsec's HTTP layer separately requires {@code https}, except
	 * for loopback {@code http} when a builder explicitly allows it for tests.
	 *
	 * @return the default policy; always the same instance
	 * @since 1.0.0
	 */
	@NonNull
	public static OutboundUriPolicy defaultInstance() {
		return DEFAULT_INSTANCE;
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
