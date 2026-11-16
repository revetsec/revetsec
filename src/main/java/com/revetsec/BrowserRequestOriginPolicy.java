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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.HostClassifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Checks browser request metadata against exact configured origins.
 * <p>
 * Configure this immutable policy once, then pass it the HTTP method and every raw field occurrence for
 * {@code Sec-Fetch-Site} and {@code Origin}. Safe methods are admitted. For other methods,
 * {@code Sec-Fetch-Site: same-origin} and {@code Sec-Fetch-Site: none} are sufficient when {@code Origin} is absent,
 * opaque or exactly configured, including when a no-referrer page sends {@code Origin: null}. A contradictory
 * concrete origin rejects. Same-site, cross-site, absent and future syntactically valid fetch-site values require an
 * exact configured origin. Duplicate or malformed fields reject.
 * <p>
 * This is a request-origin admission layer, not a complete CSRF defense. Keep application state or synchronizer
 * tokens where the workflow requires them, validate the request's host at a trusted edge, and do not derive allowed
 * origins from {@code Host} or {@code Forwarded}.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class BrowserRequestOriginPolicy {
    private static final int MAXIMUM_ORIGIN_LENGTH = 2_048;
    private static final int MAXIMUM_FETCH_SITE_LENGTH = 64;

    private final @NonNull Set<@NonNull String> allowedOrigins;
    private final boolean allowMissingMetadata;

    private BrowserRequestOriginPolicy(@NonNull Builder builder) {
        Set<String> origins = new LinkedHashSet<>();
        for (URI origin : builder.allowedOrigins)
            origins.add(requireCanonicalOrigin(origin, builder.allowInsecureLoopback));
        if (origins.isEmpty())
            throw new IllegalArgumentException("At least one allowed browser origin is required");
        this.allowedOrigins = Set.copyOf(origins);
        this.allowMissingMetadata = builder.allowMissingMetadata;
    }

    /**
     * Starts a policy with an exact, complete allowed-origin set.
     * <p>
     * Origins must use their canonical ASCII serialization: lower-case {@code https} scheme and host, no user
     * information, path, query or fragment, and no explicit default port. Plain {@code http} is rejected unless the
     * development option is enabled, and then is limited to a loopback literal or exactly {@code localhost}.
     *
     * @param allowedOrigins exact allowed origins
     * @return a new builder
     * @throws NullPointerException if the set or an entry is {@code null}
     * @since 1.0.0
     */
    public static @NonNull Builder withAllowedOrigins(@NonNull Set<@NonNull URI> allowedOrigins) {
        return new Builder(allowedOrigins);
    }

    /**
     * Checks a request without retaining its metadata.
     * <p>
     * The two lists must preserve separate field occurrences. A list with more than one element rejects even if the
     * values are identical. Safe methods ({@code GET}, {@code HEAD} and {@code OPTIONS}) are admitted before request
     * metadata is inspected. Frameworks are responsible for supplying a valid HTTP method token.
     *
     * @param method HTTP method
     * @param secFetchSiteHeaderValues every raw {@code Sec-Fetch-Site} field occurrence
     * @param originHeaderValues every raw {@code Origin} field occurrence
     * @return closed admission outcome
     * @throws NullPointerException if an input, list entry or method is {@code null}
     * @throws IllegalArgumentException if {@code method} is not a valid HTTP token
     * @since 1.0.0
     */
    public @NonNull BrowserRequestOriginResult checkResult(@NonNull String method,
            @NonNull List<@NonNull String> secFetchSiteHeaderValues,
            @NonNull List<@NonNull String> originHeaderValues) {
        requireHttpToken(requireNonNull(method));
        requireEntries(secFetchSiteHeaderValues);
        requireEntries(originHeaderValues);
        if (method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS"))
            return BrowserRequestOriginResult.allowed(BrowserRequestOriginResult.Basis.SAFE_METHOD);
        if (secFetchSiteHeaderValues.size() > 1 || originHeaderValues.size() > 1)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.MALFORMED);

        @Nullable String fetchSite = secFetchSiteHeaderValues.isEmpty() ? null
                : structuredToken(secFetchSiteHeaderValues.get(0));
        if (!secFetchSiteHeaderValues.isEmpty() && fetchSite == null)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.MALFORMED);

        @Nullable String origin = originHeaderValues.isEmpty() ? null : originHeaderValues.get(0);
        OriginKind originKind = classifyOrigin(origin);
        if (originKind == OriginKind.MALFORMED)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.MALFORMED);

        if ("same-origin".equals(fetchSite) || "none".equals(fetchSite)) {
            if (originKind == OriginKind.UNTRUSTED)
                return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
            return BrowserRequestOriginResult.allowed("same-origin".equals(fetchSite)
                    ? BrowserRequestOriginResult.Basis.SAME_ORIGIN
                    : BrowserRequestOriginResult.Basis.USER_INITIATED);
        }
        if (originKind == OriginKind.CONFIGURED)
            return BrowserRequestOriginResult.allowed(BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);
        if (originKind == OriginKind.NULL)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.NULL_ORIGIN);
        if (originKind == OriginKind.UNTRUSTED)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
        if ("cross-site".equals(fetchSite))
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.CROSS_SITE);
        if ("same-site".equals(fetchSite))
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.SAME_SITE);
        if (fetchSite != null)
            return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.UNRECOGNIZED_FETCH_SITE);
        if (this.allowMissingMetadata)
            return BrowserRequestOriginResult.allowed(
                    BrowserRequestOriginResult.Basis.MISSING_METADATA_COMPATIBILITY);
        return BrowserRequestOriginResult.rejected(BrowserRequestOriginResult.Reason.MISSING_METADATA);
    }

    /**
     * Redacts the configured origins and options.
     *
     * @return a fixed description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "BrowserRequestOriginPolicy{configuration=<redacted>}";
    }

    private @NonNull OriginKind classifyOrigin(@Nullable String origin) {
        if (origin == null)
            return OriginKind.ABSENT;
        if (origin.equals("null"))
            return OriginKind.NULL;
        if (origin.length() > MAXIMUM_ORIGIN_LENGTH)
            return OriginKind.MALFORMED;
        final URI parsed;
        try {
            parsed = URI.create(origin);
        } catch (IllegalArgumentException invalid) {
            return OriginKind.MALFORMED;
        }
        @Nullable String canonical = canonicalOrigin(parsed);
        if (canonical == null || !canonical.equals(origin))
            return OriginKind.MALFORMED;
        return this.allowedOrigins.contains(canonical) ? OriginKind.CONFIGURED : OriginKind.UNTRUSTED;
    }

    private static @Nullable String structuredToken(@NonNull String raw) {
        if (raw.length() > MAXIMUM_FETCH_SITE_LENGTH)
            return null;
        int first = 0;
        int last = raw.length();
        while (first < last && (raw.charAt(first) == ' ' || raw.charAt(first) == '\t')) first++;
        while (last > first && (raw.charAt(last - 1) == ' ' || raw.charAt(last - 1) == '\t')) last--;
        if (first == last || !isTokenFirst(raw.charAt(first)))
            return null;
        for (int index = first + 1; index < last; index++)
            if (!isTokenRest(raw.charAt(index))) return null;
        return raw.substring(first, last);
    }

    private static boolean isTokenFirst(char character) {
        return character == '*' || (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z');
    }

    private static boolean isTokenRest(char character) {
        return isTokenFirst(character) || (character >= '0' && character <= '9')
                || ":/!#$%&'*+-.^_`|~".indexOf(character) >= 0;
    }

    private static void requireEntries(@NonNull List<@NonNull String> values) {
        requireNonNull(values);
        for (String value : values) requireNonNull(value);
    }

    private static void requireHttpToken(@NonNull String method) {
        if (method.isEmpty())
            throw new IllegalArgumentException("HTTP method must be a token");
        for (int index = 0; index < method.length(); index++) {
            char character = method.charAt(index);
            boolean token = (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z') || "!#$%&'*+-.^_`|~".indexOf(character) >= 0;
            if (!token) throw new IllegalArgumentException("HTTP method must be a token");
        }
    }

    private static @NonNull String requireCanonicalOrigin(@NonNull URI origin, boolean allowInsecureLoopback) {
        requireNonNull(origin);
        @Nullable String canonical = canonicalOrigin(origin);
        if (canonical == null || !canonical.equals(origin.toASCIIString()))
            throw new IllegalArgumentException("Allowed browser origins must use canonical origin syntax");
        if (origin.getScheme().equals("http")
                && (!allowInsecureLoopback || !HostClassifier.isPlainHttpLoopbackHost(requireNonNull(origin.getHost()))))
            throw new IllegalArgumentException("Plain HTTP browser origins require the loopback development option");
        return canonical;
    }

    private static @Nullable String canonicalOrigin(@NonNull URI origin) {
        @Nullable String scheme = origin.getScheme();
        @Nullable String host = origin.getHost();
        if (scheme == null || host == null || !(scheme.equals("https") || scheme.equals("http"))
                || origin.getRawUserInfo() != null || origin.getRawQuery() != null || origin.getRawFragment() != null
                || !origin.getRawPath().isEmpty() || origin.getPort() == 0 || origin.getPort() > 65_535)
            return null;
        final String renderedHost;
        if (host.startsWith("[")) {
            // URI.getHost() keeps IPv6 brackets. Browsers send the WHATWG serialization, so render that form.
            byte @Nullable [] address = HostClassifier.parseLiteral(host);
            if (address == null || address.length != 16)
                return null;
            renderedHost = "[" + serializeIpv6(address) + "]";
        } else {
            renderedHost = host.toLowerCase(Locale.ROOT);
        }
        int port = origin.getPort();
        if ((port == 443 && scheme.equals("https")) || (port == 80 && scheme.equals("http")))
            port = -1;
        return scheme + "://" + renderedHost + (port < 0 ? "" : ":" + port);
    }

    /** WHATWG URL IPv6 serializer: lower-case hex, first longest run of two or more zero pieces compressed. */
    private static @NonNull String serializeIpv6(byte @NonNull [] address) {
        int[] pieces = new int[8];
        for (int index = 0; index < 8; index++)
            pieces[index] = ((address[2 * index] & 0xff) << 8) | (address[2 * index + 1] & 0xff);
        int compress = -1;
        int longest = 1;
        int start = 0;
        while (start < 8) {
            if (pieces[start] != 0) { start++; continue; }
            int end = start;
            while (end < 8 && pieces[end] == 0) end++;
            if (end - start > longest) { compress = start; longest = end - start; }
            start = end;
        }
        StringBuilder output = new StringBuilder(39);
        int index = 0;
        while (index < 8) {
            if (index == compress) {
                output.append(index == 0 ? "::" : ":");
                index += longest;
                continue;
            }
            output.append(Integer.toHexString(pieces[index]));
            if (index != 7) output.append(':');
            index++;
        }
        return output.toString();
    }

    private enum OriginKind { ABSENT, NULL, CONFIGURED, UNTRUSTED, MALFORMED }

    /**
     * Mutable, non-thread-safe browser-origin policy configuration.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @NonNull Set<@NonNull URI> allowedOrigins;
        private boolean allowInsecureLoopback;
        private boolean allowMissingMetadata;

        private Builder(@NonNull Set<@NonNull URI> allowedOrigins) {
            requireNonNull(allowedOrigins);
            this.allowedOrigins = Set.copyOf(allowedOrigins);
        }

        /**
         * Allows canonical plain-HTTP loopback origins for local development. It never allows plain HTTP to a
         * non-loopback host. {@code null} restores the secure default.
         *
         * @param value whether to allow plain-HTTP loopback origins
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) {
            this.allowInsecureLoopback = Boolean.TRUE.equals(value);
            return this;
        }

        /**
         * Allows an unsafe-method request with neither metadata header. The resulting admission basis remains
         * observable as {@link BrowserRequestOriginResult.Basis#MISSING_METADATA_COMPATIBILITY}. {@code null}
         * restores the rejecting default.
         *
         * @param value whether to allow missing browser metadata
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowMissingMetadata(@Nullable Boolean value) {
            this.allowMissingMetadata = Boolean.TRUE.equals(value);
            return this;
        }

        /**
         * Builds the immutable policy.
         *
         * @return configured policy
         * @since 1.0.0
         */
        public @NonNull BrowserRequestOriginPolicy build() {
            return new BrowserRequestOriginPolicy(this);
        }
    }
}
