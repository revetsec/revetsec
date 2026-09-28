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

package com.revetsec.internal.http;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.HostClassifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;

import static java.util.Objects.requireNonNull;

/**
 * The one check of an outbound request URI, shared by a builder's {@code build()} and by
 * {@link HttpExchange#execute(HttpExchangeRequest, Deadline)}, so the two cannot drift (M2 plan, G8-7 and G8-9).
 * <p>
 * A URI passes when all of these hold, in this order:
 * <ol>
 *   <li>it is absolute and hierarchical, with a host {@link URI} can parse, and a port from 1 to 65535 if one is
 *   given;</li>
 *   <li>it has no user information;</li>
 *   <li>it has no fragment, not even an empty one;</li>
 *   <li>its scheme is {@code https}, in any ASCII case, or {@code http} when the component allows insecure loopback
 *   for tests and the host is one {@link HostClassifier#isPlainHttpLoopbackHost(String)} accepts: a literal the JDK
 *   connects to as loopback, or exactly {@code localhost}. Names under {@code .localhost} and {@code localhost.} are
 *   refused, because the JDK hands them to the platform resolver, and even {@code localhost} reaches loopback through
 *   the platform's name service, normally the hosts file;</li>
 *   <li>the component's {@link OutboundUriPolicy} permits it.</li>
 * </ol>
 * A query is allowed. Every check reads only the URI's text and the component's fixed settings, so a URI that passes
 * when a component is built passes at every request it makes.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class UriChecks {
	private static final String HTTPS = "https";
	private static final String HTTP = "http";

	private UriChecks() {
		// Static helpers only.
	}

	/**
	 * Returns whether a request to {@code uri} may be sent (see the class description).
	 *
	 * @param uri                     the request URI
	 * @param outboundUriPolicy       the component's outbound URI policy
	 * @param insecureLoopbackAllowed whether the component allows plain {@code http} to loopback, for tests
	 * @return {@code true} if every check passes
	 * @throws NullPointerException if {@code uri} or {@code outboundUriPolicy} is {@code null}
	 */
	public static boolean isPermitted(@NonNull URI uri,
																		@NonNull OutboundUriPolicy outboundUriPolicy,
																		boolean insecureLoopbackAllowed) {
		return rejection(uri, outboundUriPolicy, insecureLoopbackAllowed) == null;
	}

	/**
	 * Requires that a request to {@code uri} may be sent, for a builder's {@code build()}.
	 *
	 * @param uri                     the request URI
	 * @param outboundUriPolicy       the component's outbound URI policy
	 * @param insecureLoopbackAllowed whether the component allows plain {@code http} to loopback, for tests
	 * @return {@code uri}
	 * @throws NullPointerException     if {@code uri} or {@code outboundUriPolicy} is {@code null}
	 * @throws IllegalArgumentException if a check fails; the message names the check, never the URI
	 */
	@NonNull
	public static URI requirePermitted(@NonNull URI uri,
																		 @NonNull OutboundUriPolicy outboundUriPolicy,
																		 boolean insecureLoopbackAllowed) {
		@Nullable String rejection = rejection(uri, outboundUriPolicy, insecureLoopbackAllowed);

		if (rejection != null)
			throw new IllegalArgumentException(rejection);

		return uri;
	}

	/**
	 * The fixed message of the first check that fails, or {@code null} if every check passes.
	 */
	@Nullable
	private static String rejection(@NonNull URI uri,
																	@NonNull OutboundUriPolicy outboundUriPolicy,
																	boolean insecureLoopbackAllowed) {
		requireNonNull(uri);
		requireNonNull(outboundUriPolicy);

		@Nullable String scheme = uri.getScheme();
		@Nullable String host = uri.getHost();
		int port = uri.getPort();

		// A URI is absolute exactly when it has a scheme (URI#isAbsolute), so the null check is the absolute check.
		if (scheme == null || uri.isOpaque() || host == null || (port != -1 && (port < 1 || port > 65_535)))
			return "The URI must be absolute and hierarchical, with a host and, if it has a port, a port from 1 to 65535.";

		if (uri.getRawUserInfo() != null)
			return "The URI must not contain user information.";

		if (uri.getRawFragment() != null)
			return "The URI must not contain a fragment.";

		String lowerCaseScheme = MediaType.asciiLowerCase(scheme);

		if (!HTTPS.equals(lowerCaseScheme) && !(HTTP.equals(lowerCaseScheme) && insecureLoopbackAllowed
				&& HostClassifier.isPlainHttpLoopbackHost(host)))
			return "The URI must use https, or plain http to a loopback address or exactly localhost when insecure "
					+ "loopback is allowed.";

		if (!outboundUriPolicy.permits(uri))
			return "The outbound URI policy does not permit the URI.";

		return null;
	}
}
