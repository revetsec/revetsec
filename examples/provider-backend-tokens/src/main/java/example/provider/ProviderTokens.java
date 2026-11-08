/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.provider;

import com.revetsec.jose.*;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/** Application recipe policy; only validated claims reach the account lookup. */
final class ProviderTokens {
    static final @NonNull String GOOGLE="https://accounts.google.com",GOOGLE_LEGACY="accounts.google.com",APPLE="https://appleid.apple.com";
    static final @NonNull URI GOOGLE_KEYS=URI.create("https://www.googleapis.com/oauth2/v3/certs"),APPLE_KEYS=URI.create("https://appleid.apple.com/auth/keys");
    private final @NonNull JwtValidator google,googleLegacy,apple;
    private final @NonNull String googleAudience,appleAudience;
    private final @Nullable String hostedDomain;

    ProviderTokens(BackendApplication.@NonNull Configuration config,@NonNull JwksSource googleKeys,
            @NonNull JwksSource legacyKeys,@NonNull JwksSource appleKeys,@NonNull Clock clock){
        this.googleAudience=config.googleClientId();this.appleAudience=config.appleAppId();this.hostedDomain=config.googleHostedDomain();
        this.google=validator(GOOGLE,this.googleAudience,googleKeys,clock);
        this.googleLegacy=validator(GOOGLE_LEGACY,this.googleAudience,legacyKeys,clock);
        this.apple=validator(APPLE,this.appleAudience,appleKeys,clock);
    }
    static @NonNull ProviderTokens production(BackendApplication.@NonNull Configuration config,@NonNull Clock clock){
        // Separate source instances keep each validator's exact issuer binding.
        return new ProviderTokens(config,remote(GOOGLE_KEYS,clock),remote(GOOGLE_KEYS,clock),remote(APPLE_KEYS,clock),clock);
    }
    private static @NonNull RemoteJwksSource remote(@NonNull URI uri,@NonNull Clock clock){
        return RemoteJwksSource.withUri(uri).clock(clock).requestTimeout(Duration.ofSeconds(1))
                .maximumResponseBytes(65_536).maximumKeys(8).maximumStaleness(Duration.ZERO).build();
    }
    private static @NonNull JwtValidator validator(@NonNull String issuer,@NonNull String audience,@NonNull JwksSource keys,@NonNull Clock clock){
        return JwtValidator.withIssuer(issuer).jwksSource(keys).expectedAudiences(Set.of(audience))
                .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).requiredClaims(Set.of("sub","iat","nonce"))
                .maximumTokenLength(8192).clockSkew(Duration.ZERO).clock(clock).build();
    }
    @Nullable Identity validate(BackendApplication.@NonNull Provider provider,@NonNull String compact,
            @NonNull String nonce,BackendApplication.@NonNull Budget budget){
        budget.beforeKeyWork();
        JwtValidationResult result=(provider==BackendApplication.Provider.GOOGLE?this.google:this.apple).validateResult(compact);
        // This is a fixed second issuer policy, never discovery or retry after a key-source failure.
        if(provider==BackendApplication.Provider.GOOGLE&&result instanceof JwtValidationResult.Rejected rejection
                &&rejection.getReason()==JoseException.Reason.ISSUER_MISMATCH){
            budget.beforeKeyWork();result=this.googleLegacy.validateResult(compact);
        }
        budget.check();
        if(!(result instanceof JwtValidationResult.Succeeded success))return null;
        JwtClaims claims=success.getJwt().getClaims();String expected=provider==BackendApplication.Provider.GOOGLE?this.googleAudience:this.appleAudience;
        if(!claims.getAudiences().equals(List.of(expected))||!same(nonce,text(claims,"nonce")))return null;
        String subject=claims.getSubject().orElse("");
        if(subject.isEmpty()||subject.length()>255||!subject.chars().allMatch(c->c>=0x21&&c<=0x7e))return null;
        JsonValue presenter=claims.getClaim("azp").orElse(null);
        if(presenter!=null&&(!(presenter instanceof JsonString value)||!value.getValue().equals(expected)))return null;
        if(provider==BackendApplication.Provider.GOOGLE&&this.hostedDomain!=null&&!this.hostedDomain.equals(text(claims,"hd")))return null;
        JsonValue supported=claims.getClaim("nonce_supported").orElse(null);
        if(provider==BackendApplication.Provider.APPLE&&supported!=null&&(!(supported instanceof JsonBoolean value)||!value.getValue()))return null;
        return new Identity(provider==BackendApplication.Provider.GOOGLE?GOOGLE:APPLE,subject,claims.getIssuedAt().orElseThrow(),claims.getExpiresAt().orElseThrow());
    }
    private static @Nullable String text(@NonNull JwtClaims claims,@NonNull String name){return claims.getClaim(name).filter(v->v instanceof JsonString).map(v->((JsonString)v).getValue()).orElse(null);}
    static boolean same(@NonNull String expected,@Nullable String actual){return actual!=null&&actual.length()<=1024&&MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),actual.getBytes(StandardCharsets.UTF_8));}
    record Identity(@NonNull String issuer,@NonNull String subject,@NonNull Instant issued,@NonNull Instant expires){
        @Override public @NonNull String toString(){return "Identity{<redacted>}";}
    }
    @Override public @NonNull String toString(){return "ProviderTokens{<redacted>}";}
}
