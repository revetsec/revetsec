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

package com.revetsec.oauth;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;

/** M5 synthetic offline resource-server input boundaries and independently evaluated profile rules.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class ResourceServerFuzzTests {
    private static final String ISSUER = "http://localhost:1/issuer";
    private static final String AUDIENCE = "https://resource.example/mcp";
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");
    private static final KeyPair KEY = key();
    private static final StaticJsonWebKeySource KEYS = keys();
    private static final JwtAccessTokenValidator STRICT = validator(false);
    private static final JwtAccessTokenValidator COMPATIBILITY = validator(true);
    private static final Pattern BEARER = Pattern.compile("[Bb][Ee][Aa][Rr][Ee][Rr] {1,58}[A-Za-z0-9._~+/-]+=*");
    private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final byte[] CALLBACK = "code=TEST-ONLY-code&state=TEST-ONLY-state".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INACTIVE = "{\"active\":false}".getBytes(StandardCharsets.UTF_8);

    /** RFC6750 header grammar, duplicate rejection and result/throwing API equivalence. */
    @FuzzTest(maxDuration = "5m")
    public void bearerPresentationMatchesTheHeaderGrammar(byte @NonNull [] input) {
        String field = new String(input, StandardCharsets.ISO_8859_1);
        boolean valid = field.length() <= 8_256 && BEARER.matcher(field).matches();
        // The independent regexp limits the prefix; count the credential separately for the configured 8 KiB cap.
        if (valid) valid = field.substring(6).stripLeading().length() <= 8_192;
        for (List<String> fields : List.of(List.<String>of(), List.of(field), List.of(field, field))) {
            BearerTokenResult result = BearerToken.fromAuthorizationHeaderValuesResult(fields, 8_192);
            if (fields.isEmpty()) {
                Assertions.assertInstanceOf(BearerTokenResult.Absent.class, result);
                Assertions.assertTrue(BearerToken.fromAuthorizationHeaderValues(fields, 8_192).isEmpty());
            } else if (fields.size() == 1 && valid) {
                BearerToken token = Assertions.assertInstanceOf(BearerTokenResult.Present.class, result).getToken();
                Assertions.assertEquals("BearerToken{value=<redacted>}", token.toString());
                Assertions.assertEquals(field.substring(6).stripLeading(), token.value());
                Assertions.assertTrue(BearerToken.fromAuthorizationHeaderValues(fields, 8_192).isPresent());
            } else {
                Assertions.assertInstanceOf(BearerTokenResult.Malformed.class, result);
                AccessTokenValidationException failure = Assertions.assertThrows(AccessTokenValidationException.class,
                        () -> BearerToken.fromAuthorizationHeaderValues(fields, 8_192));
                Assertions.assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST, failure.getReason());
                fixed(failure);
            }
        }
    }

    /** Trusted challenge text is ASCII-only, escaped exactly and bounded after expansion (RFC6750 section3). */
    @FuzzTest(maxDuration = "5m")
    public void challengesEscapeAndBoundTrustedParameters(byte @NonNull [] input) {
        String text = new String(input, StandardCharsets.ISO_8859_1);
        for (boolean description : List.of(false, true)) {
            String quoted = text.replace("\\", "\\\\").replace("\"", "\\\"");
            String expected = description ? "Bearer error=\"invalid_token\", error_description=\"" + quoted + "\""
                    : "Bearer realm=\"" + quoted + "\"";
            boolean valid = text.length() <= 65_536 && text.chars().allMatch(c -> c >= 32 && c <= 126
                    && (!description || (c != '"' && c != '\\'))) && expected.length() <= 1_024;
            try {
                BearerChallenge.Builder builder = BearerChallenge.builder().maximumHeaderLength(1_024);
                BearerChallenge accepted = description
                        ? builder.error(BearerError.INVALID_TOKEN).errorDescription(text).build() : builder.realm(text).build();
                Assertions.assertTrue(valid);
                Assertions.assertEquals(expected, accepted.getHeaderValue());
                Assertions.assertEquals("BearerChallenge{parameters=<redacted>}", accepted.toString());
                Assertions.assertTrue(accepted.getHeaderValue().chars().allMatch(c -> c >= 32 && c <= 126));
            } catch (IllegalArgumentException rejected) {
                Assertions.assertFalse(valid);
                fixed(rejected);
            }
        }
    }

    /** Raw form-post MIME has one field, duplicate-free parameters and only absent/UTF-8 charset. */
    @FuzzTest(maxDuration = "5m")
    public void formPostMimeMatchesIndependentFieldGrammar(byte @NonNull [] input) {
        String field = new String(input, StandardCharsets.ISO_8859_1);
        boolean valid = field.length() <= 8_192 && formMime(field);
        for (List<String> fields : List.of(List.<String>of(), List.of(field), List.of(field, field))) {
            try {
                AuthorizationResponse accepted = AuthorizationResponse.fromFormBody(CALLBACK, fields, null);
                Assertions.assertTrue(valid && fields.size() == 1);
                Assertions.assertEquals(Optional.of("TEST-ONLY-code"), accepted.getCode());
                Assertions.assertEquals(Optional.of("TEST-ONLY-state"), accepted.getState());
                Assertions.assertEquals("AuthorizationResponse{parameters=<redacted>}", accepted.toString());
            } catch (OAuthResponseException rejected) {
                Assertions.assertFalse(valid && fields.size() == 1);
                Assertions.assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, rejected.getReason());
                fixed(rejected);
            }
        }
    }

    /** Role-specific metadata checks exact issuer; configured resource identifiers preserve raw components. */
    @FuzzTest(maxDuration = "5m")
    public void metadataKeepsRolesAndRawResourceIdentifiers(byte @NonNull [] input) {
        JsonObject object = object(input, 262_144, false);
        for (ResourceServerMetadata.Role role : ResourceServerMetadata.Role.values()) {
            boolean valid = metadata(object, role);
            try {
                ResourceServerMetadata parsed = ResourceServerMetadata.parse(ISSUER, input, role);
                Assertions.assertTrue(valid);
                Assertions.assertEquals(ISSUER, parsed.issuer());
                Assertions.assertEquals(text(object.getMembers().get(role == ResourceServerMetadata.Role.JWT
                        ? "jwks_uri" : "introspection_endpoint")), parsed.endpoint().toString());
                Assertions.assertEquals("ResourceServerMetadata{data=<redacted>}", parsed.toString());
            } catch (OAuthException rejected) {
                Assertions.assertFalse(valid);
                fixed(rejected);
            }
        }
        String resource = new String(input, StandardCharsets.ISO_8859_1);
        URI uri;
        try { uri = URI.create(resource); }
        catch (IllegalArgumentException rejected) { return; }
        boolean valid = resourceUri(uri);
        try {
            ProtectedResourceMetadata parsed = ProtectedResourceMetadata.withResource(uri).allowInsecureLoopback(true)
                    .authorizationServers(List.of("https://issuer.example", "https://issuer.example"))
                    .scopesSupported(List.of("read", "write", "read")).build();
            Assertions.assertTrue(valid);
            Assertions.assertEquals(resource, parsed.getResource().toString());
            Assertions.assertEquals(List.of("https://issuer.example"), parsed.getAuthorizationServers());
            Assertions.assertEquals(List.of("read", "write"), parsed.getScopesSupported());
            String path = uri.getRawPath();
            if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
            Assertions.assertEquals(uri.getScheme() + "://" + uri.getRawAuthority()
                    + "/.well-known/oauth-protected-resource" + path
                    + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()), parsed.getWellKnownUri().toString());
            Assertions.assertTrue(parsed.toJson().getBytes(StandardCharsets.UTF_8).length <= 262_144);
            Assertions.assertEquals(resource, object(parsed.toJson().getBytes(StandardCharsets.UTF_8), 262_144, false)
                    .findString("resource").orElseThrow());
        } catch (IllegalArgumentException rejected) {
            // Extremely long syntactically safe URIs can hit the JSON size bound.
            Assertions.assertFalse(valid && resource.length() < 32_768);
            fixed(rejected);
        }
    }

    /** JDK Ed25519 signs arbitrary claims, reaching strict and explicitly configured untyped checks. */
    @FuzzTest(maxDuration = "5m")
    public void signedAccessTokensRespectStrictAndUntypedProfiles(byte @NonNull [] input) {
        JsonObject claims = object(input, 65_536, true);
        for (String type : List.of("at+jwt", "MISSING", "JWT", "logout+jwt")) {
            String token = signed(input, type);
            BearerToken credential = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + token), 1_048_576).orElseThrow();
            for (boolean compatibility : List.of(false, true)) {
                boolean valid = token.length() <= 65_536 && jwt(claims, compatibility,
                        type.equals("MISSING") || type.equals("JWT"))
                        && (type.equals("at+jwt") || compatibility && (type.equals("MISSING") || type.equals("JWT")));
                AccessTokenValidationResult result = (compatibility ? COMPATIBILITY : STRICT).validateResult(credential);
                if (valid) {
                    VerifiedAccessToken accepted = Assertions.assertInstanceOf(AccessTokenValidationResult.Succeeded.class, result).getAccessToken();
                    Assertions.assertEquals(ISSUER, accepted.getIssuer());
                    Assertions.assertTrue(accepted.getAudiences().contains(AUDIENCE));
                    Assertions.assertEquals(text(claims.getMembers().get("sub")), accepted.getSubject().orElseThrow());
                    Assertions.assertEquals("VerifiedAccessToken{data=<redacted>}", accepted.toString());
                    Assertions.assertEquals(scopes(claims.getMembers().get("scope")), accepted.getScopes());
                } else Assertions.assertInstanceOf(AccessTokenValidationResult.Rejected.class, result);
            }
        }
    }

    /** Public introspection performs a fresh authenticated POST for each checked synthetic response. */
    @FuzzTest(maxDuration = "5m")
    public void introspectionResponsesAreTypedAudienceCheckedAndUncached(byte @NonNull [] input) {
        JsonObject claims = object(input, 262_144, false);
        int expected = introspection(claims); // 0 malformed/provider failure, 1 local rejection, 2 checked proof.
        ResourceFuzzHttpClient transport = new ResourceFuzzHttpClient(input, INACTIVE);
        OAuthClient oauth = OAuthClient.withIssuer(ISSUER).clientId("TEST-ONLY-client")
                .clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"))
                .httpClient(transport).allowInsecureLoopback(true).clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
        TokenIntrospectionClient validator = TokenIntrospectionClient.withOAuthClient(oauth)
                .expectedAudiences(Set.of(AUDIENCE)).introspectionEndpoint(URI.create(ISSUER + "/introspection"))
                .clockSkew(Duration.ZERO).build();
        BearerToken token = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer TEST-ONLY-opaque")).orElseThrow();
        try {
            AccessTokenValidationResult result = validator.validateResult(token);
            Assertions.assertTrue(expected != 0);
            if (expected == 2) {
                VerifiedAccessToken accepted = Assertions.assertInstanceOf(AccessTokenValidationResult.Succeeded.class, result).getAccessToken();
                Assertions.assertEquals(ISSUER, accepted.getIssuer());
                Assertions.assertTrue(accepted.getAudiences().contains(AUDIENCE));
                Assertions.assertEquals(scopes(claims.getMembers().get("scope")), accepted.getScopes());
                Assertions.assertEquals("VerifiedAccessToken{data=<redacted>}", accepted.toString());
            } else Assertions.assertInstanceOf(AccessTokenValidationResult.Rejected.class, result);
            AccessTokenValidationResult.Rejected second = Assertions.assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                    validator.validateResult(token));
            Assertions.assertEquals(AccessTokenValidationException.Reason.INACTIVE, second.getReason());
            Assertions.assertEquals(2, transport.getRequests());
        } catch (OAuthException failure) {
            Assertions.assertEquals(0, expected);
            fixed(failure);
            Assertions.assertEquals(1, transport.getRequests());
        }
    }

    private static boolean formMime(@NonNull String field) {
        List<String> segments = new ArrayList<>();
        boolean quoted = false, escape = false;
        int start = 0;
        for (int i = 0; i < field.length(); i++) {
            char c = field.charAt(i);
            if (escape) { escape = false; continue; }
            if (quoted && c == '\\') { escape = true; continue; }
            if (c == '"') quoted = !quoted;
            if (c == ';' && !quoted) { segments.add(field.substring(start, i)); start = i + 1; }
        }
        if (quoted || escape) return false;
        segments.add(field.substring(start));
        if (!ows(segments.get(0)).equalsIgnoreCase("application/x-www-form-urlencoded")) return false;
        Set<String> names = new HashSet<>();
        for (int i = 1; i < segments.size(); i++) {
            String part = ows(segments.get(i));
            if (part.isEmpty()) continue;
            int equal = part.indexOf('=');
            if (equal <= 0 || !TOKEN.matcher(part.substring(0, equal)).matches()) return false;
            String name = part.substring(0, equal).toLowerCase(Locale.ROOT);
            if (!names.add(name)) return false;
            String value = part.substring(equal + 1);
            if (value.startsWith("\"")) {
                if (value.length() < 2 || !value.endsWith("\"")) return false;
                StringBuilder decoded = new StringBuilder();
                for (int n = 1; n < value.length() - 1; n++) {
                    char c = value.charAt(n);
                    if (c == '\\') {
                        if (++n >= value.length() - 1) return false;
                        c = value.charAt(n);
                        if (!(c == '\t' || c >= 32 && c <= 255 && c != 127)) return false;
                    } else if (!(c == '\t' || c == ' ' || c == 33 || c >= 35 && c <= 91 || c >= 93 && c <= 255 && c != 127)) return false;
                    decoded.append(c);
                }
                value = decoded.toString();
            } else if (!TOKEN.matcher(value).matches()) return false;
            if (name.equals("charset") && !value.equalsIgnoreCase("utf-8")) return false;
        }
        return true;
    }

    private static @NonNull String ows(@NonNull String text) {
        int start = 0, end = text.length();
        while (start < end && (text.charAt(start) == ' ' || text.charAt(start) == '\t')) start++;
        while (end > start && (text.charAt(end - 1) == ' ' || text.charAt(end - 1) == '\t')) end--;
        return text.substring(start, end);
    }

    private static boolean metadata(@Nullable JsonObject object, ResourceServerMetadata.@NonNull Role role) {
        if (object == null || !ISSUER.equals(text(object.getMembers().get("issuer")))) return false;
        String endpoint = text(object.getMembers().get(role == ResourceServerMetadata.Role.JWT ? "jwks_uri" : "introspection_endpoint"));
        if (endpoint == null || endpoint.isEmpty()) return false;
        try { URI.create(endpoint); } catch (IllegalArgumentException malformed) { return false; }
        JsonValue methods = object.getMembers().get("introspection_endpoint_auth_methods_supported");
        if (methods == null) return true;
        if (!(methods instanceof JsonArray array)) return false;
        Set<String> names = new HashSet<>();
        for (JsonValue item : array.getElements()) {
            String name = text(item);
            if (name == null || name.isEmpty() || !names.add(name)) return false;
        }
        return true;
    }

    private static boolean resourceUri(@NonNull URI uri) {
        String host = uri.getHost();
        String scheme = uri.getScheme();
        boolean loopback = host != null && com.revetsec.internal.HostClassifier.isPlainHttpLoopbackHost(host);
        return scheme != null && host != null && !uri.isOpaque() && uri.getRawUserInfo() == null
                && uri.getRawFragment() == null && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65_535)
                && (scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http") && loopback);
    }

    private static boolean jwt(@Nullable JsonObject claims, boolean compatibility, boolean untyped) {
        if (claims == null) return false;
        Map<String, JsonValue> c = claims.getMembers();
        if (!ISSUER.equals(text(c.get("iss"))) || !nonempty(c.get("sub")) || !audience(c.get("aud"), false)) return false;
        for (String name : List.of("iss", "sub", "jti")) if (c.containsKey(name) && !(c.get(name) instanceof JsonString)) return false;
        Instant exp = date(c.get("exp"), false), iat = date(c.get("iat"), false);
        if (exp == null || iat == null || !NOW.isBefore(exp) || iat.isAfter(NOW)) return false;
        if (c.containsKey("nbf") && (date(c.get("nbf"), false) == null || date(c.get("nbf"), false).isAfter(NOW))) return false;
        if (c.containsKey("cnf") || !scopeValid(c.get("scope"))) return false;
        if (!compatibility && (!nonempty(c.get("client_id")) || !nonempty(c.get("jti")))) return false;
        if (c.containsKey("client_id") && !nonempty(c.get("client_id"))) return false;
        if (compatibility && (!c.containsKey("app") || c.get("app") instanceof JsonNull)) return false;
        if (untyped && c.keySet().stream().anyMatch(Set.of("nonce", "at_hash", "c_hash", "auth_time")::contains)) return false;
        return true;
    }

    private static int introspection(@Nullable JsonObject claims) {
        if (claims == null || !(claims.getMembers().get("active") instanceof JsonBoolean active)) return 0;
        if (!active.getValue()) return 1;
        Map<String, JsonValue> c = claims.getMembers();
        for (String name : List.of("iss", "sub", "client_id", "token_type")) if (c.containsKey(name) && !nonempty(c.get(name))) return 0;
        JsonValue aud = c.get("aud");
        if (aud != null && !audienceShape(aud, true)) return 0;
        for (String name : List.of("exp", "iat", "nbf")) if (c.containsKey(name) && date(c.get(name), true) == null) return 0;
        if (c.containsKey("scope") && !(c.get("scope") instanceof JsonString)) return 0;
        if (!audience(aud, true) || c.containsKey("iss") && !ISSUER.equals(text(c.get("iss"))) || c.containsKey("cnf")) return 1;
        if (c.containsKey("token_type") && !"Bearer".equalsIgnoreCase(text(c.get("token_type")))) return 1;
        Instant exp = date(c.get("exp"), true), iat = date(c.get("iat"), true), nbf = date(c.get("nbf"), true);
        if (exp != null && !NOW.isBefore(exp) || iat != null && iat.isAfter(NOW) || nbf != null && nbf.isAfter(NOW)) return 1;
        return scopeValid(c.get("scope")) ? 2 : 1;
    }

    private static boolean audience(@Nullable JsonValue value, boolean introspection) {
        if (!audienceShape(value, introspection)) return false;
        return value instanceof JsonString s ? s.getValue().equals(AUDIENCE)
                : ((JsonArray) value).getElements().stream().anyMatch(v -> AUDIENCE.equals(text(v)));
    }
    private static boolean audienceShape(@Nullable JsonValue value, boolean introspection) {
        if (value instanceof JsonString s) return !introspection || !s.getValue().isEmpty();
        if (!(value instanceof JsonArray a) || !introspection && a.getElements().isEmpty()) return false;
        return a.getElements().stream().allMatch(v -> v instanceof JsonString s && (!introspection || !s.getValue().isEmpty()));
    }
    private static boolean nonempty(@Nullable JsonValue value) { return value instanceof JsonString s && !s.getValue().isEmpty(); }
    private static @Nullable String text(@Nullable JsonValue value) { return value instanceof JsonString s ? s.getValue() : null; }
    private static boolean scopeValid(@Nullable JsonValue value) {
        if (value == null) return true;
        if (!(value instanceof JsonString s)) return false;
        String scopes = s.getValue();
        return scopes.isEmpty() || !scopes.startsWith(" ") && !scopes.endsWith(" ") && !scopes.contains("  ")
                && scopes.chars().allMatch(c -> c == 32 || c > 32 && c < 127 && c != '"' && c != '\\');
    }
    private static @NonNull Set<@NonNull String> scopes(@Nullable JsonValue value) {
        String text = text(value);
        return text == null || text.isEmpty() ? Set.of() : Set.copyOf(Arrays.asList(text.split(" ")));
    }
    private static @Nullable Instant date(@Nullable JsonValue value, boolean integer) {
        if (!(value instanceof JsonNumber n)) return null;
        try {
            if (integer) return Instant.ofEpochSecond(n.getValue().longValueExact());
            BigDecimal decimal = n.getValue();
            if (decimal.compareTo(BigDecimal.valueOf(-377_705_116_800L)) < 0
                    || decimal.compareTo(BigDecimal.valueOf(253_402_300_800L)) >= 0) return null;
            BigDecimal nanos = decimal.setScale(9, RoundingMode.FLOOR).movePointRight(9);
            BigDecimal[] parts = nanos.divideAndRemainder(BigDecimal.valueOf(1_000_000_000L));
            return Instant.ofEpochSecond(parts[0].longValueExact(), parts[1].longValueExact());
        } catch (ArithmeticException | DateTimeException malformed) { return null; }
    }
    private static @Nullable JsonObject object(byte @NonNull [] bytes, int maximum, boolean jose) {
        try { return JsonCodec.parse(bytes, jose ? JsonLimits.jose(maximum) : JsonLimits.protocolDocument(maximum)) instanceof JsonObject o ? o : null; }
        catch (JsonParseException malformed) { return null; }
    }
    private static @NonNull KeyPair key() {
        try { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
        catch (GeneralSecurityException failure) { throw new IllegalStateException(failure); }
    }
    private static @NonNull StaticJsonWebKeySource keys() {
        byte[] encoded = KEY.getPublic().getEncoded();
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"Ed25519\",\"kid\":\"TEST-ONLY-fuzz-key\",\"x\":\"" + x + "\"}]}"));
    }
    private static @NonNull JwtAccessTokenValidator validator(boolean compatibility) {
        JwtAccessTokenValidator.Builder builder = JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUDIENCE))
                .jsonWebKeySource(KEYS).allowedAlgorithms(Set.of(JwsAlgorithm.ED25519)).clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .clockSkew(Duration.ZERO);
        return (compatibility ? builder.compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("app")) : builder).build();
    }
    private static @NonNull String signed(byte @NonNull [] input, @NonNull String type) {
        String header = "{\"alg\":\"Ed25519\",\"kid\":\"TEST-ONLY-fuzz-key\"" + (type.equals("MISSING") ? "" : ",\"typ\":\"" + type + "\"") + "}";
        String signing = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8))
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(input);
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(KEY.getPrivate());
            signer.update(signing.getBytes(StandardCharsets.US_ASCII));
            return signing + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        } catch (GeneralSecurityException failure) { throw new IllegalStateException(failure); }
    }
    private static void fixed(@NonNull RuntimeException failure) {
        if (failure instanceof OAuthException oauth)
            Assertions.assertEquals((oauth instanceof OAuthValidationException
                    ? OAuthValidationException.fromReason(oauth.getReason())
                    : oauth instanceof OAuthTransportException
                    ? OAuthTransportException.fromReason(oauth.getReason(), null)
                    : OAuthResponseException.fromReason(oauth.getReason())).getMessage(), failure.getMessage());
        else if (failure instanceof AccessTokenValidationException credential)
            Assertions.assertEquals(AccessTokenValidationException.fromReason(credential.getReason()).getMessage(), failure.getMessage());
        Assertions.assertNull(failure.getCause());
        Assertions.assertEquals(0, failure.getSuppressed().length);
    }
}
