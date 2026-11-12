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

package com.revetsec.oauth.server;

import com.revetsec.ConfigurationDiagnostic;
import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Pure immutable internal snapshot for the approved issuer builder settings. */
final class OAuthServerSettings {
 final @NonNull Duration retentionExtension;
 final @NonNull Duration authorizationInteractionLifetime;
 final @NonNull Duration authorizationCodeLifetime;
 final @NonNull Duration accessTokenLifetime;
 final @NonNull Duration refreshTokenIdleLifetime;
 final @NonNull Duration refreshTokenAbsoluteLifetime;
 final @NonNull Duration clockSkew;
 final @NonNull Duration totalDeadline;
 final @NonNull Duration requestTimeout;
 final @NonNull Duration publicMetadataHttpCacheMaxAge;
 final int maximumRequestBodyBytes;
 final int maximumRawQueryLength;
 final int maximumHeaderBytes;
 final int maximumResponseBodyBytes;
 final int maximumStoreRecordBytes;
 final int maximumStoreCommitAttempts;
 final int maximumResources;
 final int maximumRedirectUris;
 final int maximumScopesPerResource;
 final int maximumScopeLength;
 final int maximumStateLength;
 final int maximumClientIdLength;
 final int maximumSubjectLength;
 private OAuthServerSettings(@NonNull Builder builder, boolean refreshEnabled, int sealerMaximumLength) {
  if (!builder.configurationDiagnostics(refreshEnabled, sealerMaximumLength).isEmpty())
   throw OAuthStoreFormat.invalid();
  this.authorizationInteractionLifetime = Limits.AS_AUTHORIZATION_INTERACTION_LIFETIME.require(builder.authorizationInteractionLifetime == null ? Limits.AS_AUTHORIZATION_INTERACTION_LIFETIME.getDefaultDuration() : builder.authorizationInteractionLifetime);
  this.authorizationCodeLifetime = Limits.AS_AUTHORIZATION_CODE_LIFETIME.require(builder.authorizationCodeLifetime == null ? Limits.AS_AUTHORIZATION_CODE_LIFETIME.getDefaultDuration() : builder.authorizationCodeLifetime);
  this.accessTokenLifetime = Limits.AS_ACCESS_TOKEN_LIFETIME.require(builder.accessTokenLifetime == null ? Limits.AS_ACCESS_TOKEN_LIFETIME.getDefaultDuration() : builder.accessTokenLifetime);
  this.refreshTokenIdleLifetime = Limits.AS_REFRESH_TOKEN_IDLE_LIFETIME.require(builder.refreshTokenIdleLifetime == null ? Limits.AS_REFRESH_TOKEN_IDLE_LIFETIME.getDefaultDuration() : builder.refreshTokenIdleLifetime);
  this.refreshTokenAbsoluteLifetime = Limits.AS_REFRESH_TOKEN_ABSOLUTE_LIFETIME.require(builder.refreshTokenAbsoluteLifetime == null ? Limits.AS_REFRESH_TOKEN_ABSOLUTE_LIFETIME.getDefaultDuration() : builder.refreshTokenAbsoluteLifetime);
  this.clockSkew = Limits.AS_CLOCK_SKEW.require(builder.clockSkew == null ? Limits.AS_CLOCK_SKEW.getDefaultDuration() : builder.clockSkew);
  this.totalDeadline = Limits.AS_TOTAL_DEADLINE.require(builder.totalDeadline == null ? Limits.AS_TOTAL_DEADLINE.getDefaultDuration() : builder.totalDeadline);
  this.requestTimeout = Limits.AS_REQUEST_TIMEOUT.require(builder.requestTimeout == null ? Limits.AS_REQUEST_TIMEOUT.getDefaultDuration() : builder.requestTimeout);
  this.publicMetadataHttpCacheMaxAge = Limits.AS_PUBLIC_METADATA_HTTP_CACHE_MAX_AGE.require(builder.publicMetadataHttpCacheMaxAge == null ? Limits.AS_PUBLIC_METADATA_HTTP_CACHE_MAX_AGE.getDefaultDuration() : builder.publicMetadataHttpCacheMaxAge);
  this.maximumRequestBodyBytes = Limits.AS_MAXIMUM_REQUEST_BODY_BYTES.require(builder.maximumRequestBodyBytes == null ? Limits.AS_MAXIMUM_REQUEST_BODY_BYTES.getDefaultIntValue() : builder.maximumRequestBodyBytes);
  this.maximumRawQueryLength = Limits.AS_MAXIMUM_RAW_QUERY_LENGTH.require(builder.maximumRawQueryLength == null ? Limits.AS_MAXIMUM_RAW_QUERY_LENGTH.getDefaultIntValue() : builder.maximumRawQueryLength);
  this.maximumHeaderBytes = Limits.AS_MAXIMUM_HEADER_BYTES.require(builder.maximumHeaderBytes == null ? Limits.AS_MAXIMUM_HEADER_BYTES.getDefaultIntValue() : builder.maximumHeaderBytes);
  this.maximumResponseBodyBytes = Limits.AS_MAXIMUM_RESPONSE_BODY_BYTES.require(builder.maximumResponseBodyBytes == null ? Limits.AS_MAXIMUM_RESPONSE_BODY_BYTES.getDefaultIntValue() : builder.maximumResponseBodyBytes);
  this.maximumStoreRecordBytes = Limits.AS_MAXIMUM_STORE_RECORD_BYTES.require(builder.maximumStoreRecordBytes == null ? Limits.AS_MAXIMUM_STORE_RECORD_BYTES.getDefaultIntValue() : builder.maximumStoreRecordBytes);
  this.maximumStoreCommitAttempts = Limits.AS_MAXIMUM_STORE_COMMIT_ATTEMPTS.require(builder.maximumStoreCommitAttempts == null ? Limits.AS_MAXIMUM_STORE_COMMIT_ATTEMPTS.getDefaultIntValue() : builder.maximumStoreCommitAttempts);
  this.maximumResources = Limits.AS_MAXIMUM_RESOURCES.require(builder.maximumResources == null ? Limits.AS_MAXIMUM_RESOURCES.getDefaultIntValue() : builder.maximumResources);
  this.maximumRedirectUris = Limits.AS_MAXIMUM_REDIRECT_URIS.require(builder.maximumRedirectUris == null ? Limits.AS_MAXIMUM_REDIRECT_URIS.getDefaultIntValue() : builder.maximumRedirectUris);
  this.maximumScopesPerResource = Limits.AS_MAXIMUM_SCOPES_PER_RESOURCE.require(builder.maximumScopesPerResource == null ? Limits.AS_MAXIMUM_SCOPES_PER_RESOURCE.getDefaultIntValue() : builder.maximumScopesPerResource);
  this.maximumScopeLength = Limits.AS_MAXIMUM_SCOPE_LENGTH.require(builder.maximumScopeLength == null ? Limits.AS_MAXIMUM_SCOPE_LENGTH.getDefaultIntValue() : builder.maximumScopeLength);
  this.maximumStateLength = Limits.AS_MAXIMUM_STATE_LENGTH.require(builder.maximumStateLength == null ? Limits.AS_MAXIMUM_STATE_LENGTH.getDefaultIntValue() : builder.maximumStateLength);
  this.maximumClientIdLength = Limits.AS_MAXIMUM_CLIENT_ID_LENGTH.require(builder.maximumClientIdLength == null ? Limits.AS_MAXIMUM_CLIENT_ID_LENGTH.getDefaultIntValue() : builder.maximumClientIdLength);
  this.maximumSubjectLength = Limits.AS_MAXIMUM_SUBJECT_LENGTH.require(builder.maximumSubjectLength == null ? Limits.AS_MAXIMUM_SUBJECT_LENGTH.getDefaultIntValue() : builder.maximumSubjectLength);
  this.retentionExtension = retentionExtension(this.accessTokenLifetime, this.clockSkew,
   this.totalDeadline, this.publicMetadataHttpCacheMaxAge);
 }
 private static @NonNull Duration retentionExtension(@NonNull Duration access, @NonNull Duration skew,
   @NonNull Duration deadline, @NonNull Duration metadataAge) {
  return Duration.ofNanos(access.plus(skew).plus(deadline).plus(metadataAge).toNanos());
 }
 static @NonNull Builder builder() { return new Builder(); }
 @NonNull OAuthServerIngressLimits ingress() {
  return new OAuthServerIngressLimits(this.maximumRequestBodyBytes, this.maximumRawQueryLength, this.maximumHeaderBytes,
   this.maximumStateLength, this.maximumClientIdLength, this.maximumResources, this.maximumRedirectUris,
   this.maximumScopesPerResource, this.maximumScopeLength);
 }
 @Override public @NonNull String toString() { return "OAuthServerSettings{<redacted>}"; }
 static final class Builder {
  private @Nullable Duration authorizationInteractionLifetime;
  private @Nullable Duration authorizationCodeLifetime;
  private @Nullable Duration accessTokenLifetime;
  private @Nullable Duration refreshTokenIdleLifetime;
  private @Nullable Duration refreshTokenAbsoluteLifetime;
  private @Nullable Duration clockSkew;
  private @Nullable Duration totalDeadline;
  private @Nullable Duration requestTimeout;
  private @Nullable Duration publicMetadataHttpCacheMaxAge;
  private @Nullable Integer maximumRequestBodyBytes;
  private @Nullable Integer maximumRawQueryLength;
  private @Nullable Integer maximumHeaderBytes;
  private @Nullable Integer maximumResponseBodyBytes;
  private @Nullable Integer maximumStoreRecordBytes;
  private @Nullable Integer maximumStoreCommitAttempts;
  private @Nullable Integer maximumResources;
  private @Nullable Integer maximumRedirectUris;
  private @Nullable Integer maximumScopesPerResource;
  private @Nullable Integer maximumScopeLength;
  private @Nullable Integer maximumStateLength;
  private @Nullable Integer maximumClientIdLength;
  private @Nullable Integer maximumSubjectLength;
  private Builder() {}
  @NonNull Builder authorizationInteractionLifetime(@Nullable Duration value) { this.authorizationInteractionLifetime = value; return this; }
  @NonNull Builder authorizationCodeLifetime(@Nullable Duration value) { this.authorizationCodeLifetime = value; return this; }
  @NonNull Builder accessTokenLifetime(@Nullable Duration value) { this.accessTokenLifetime = value; return this; }
  @NonNull Builder refreshTokenIdleLifetime(@Nullable Duration value) { this.refreshTokenIdleLifetime = value; return this; }
  @NonNull Builder refreshTokenAbsoluteLifetime(@Nullable Duration value) { this.refreshTokenAbsoluteLifetime = value; return this; }
  @NonNull Builder clockSkew(@Nullable Duration value) { this.clockSkew = value; return this; }
  @NonNull Builder totalDeadline(@Nullable Duration value) { this.totalDeadline = value; return this; }
  @NonNull Builder requestTimeout(@Nullable Duration value) { this.requestTimeout = value; return this; }
  @NonNull Builder publicMetadataHttpCacheMaxAge(@Nullable Duration value) { this.publicMetadataHttpCacheMaxAge = value; return this; }
  @NonNull Builder maximumRequestBodyBytes(@Nullable Integer value) { this.maximumRequestBodyBytes = value; return this; }
  @NonNull Builder maximumRawQueryLength(@Nullable Integer value) { this.maximumRawQueryLength = value; return this; }
  @NonNull Builder maximumHeaderBytes(@Nullable Integer value) { this.maximumHeaderBytes = value; return this; }
  @NonNull Builder maximumResponseBodyBytes(@Nullable Integer value) { this.maximumResponseBodyBytes = value; return this; }
  @NonNull Builder maximumStoreRecordBytes(@Nullable Integer value) { this.maximumStoreRecordBytes = value; return this; }
  @NonNull Builder maximumStoreCommitAttempts(@Nullable Integer value) { this.maximumStoreCommitAttempts = value; return this; }
  @NonNull Builder maximumResources(@Nullable Integer value) { this.maximumResources = value; return this; }
  @NonNull Builder maximumRedirectUris(@Nullable Integer value) { this.maximumRedirectUris = value; return this; }
  @NonNull Builder maximumScopesPerResource(@Nullable Integer value) { this.maximumScopesPerResource = value; return this; }
  @NonNull Builder maximumScopeLength(@Nullable Integer value) { this.maximumScopeLength = value; return this; }
  @NonNull Builder maximumStateLength(@Nullable Integer value) { this.maximumStateLength = value; return this; }
  @NonNull Builder maximumClientIdLength(@Nullable Integer value) { this.maximumClientIdLength = value; return this; }
  @NonNull Builder maximumSubjectLength(@Nullable Integer value) { this.maximumSubjectLength = value; return this; }
  @NonNull OAuthServerSettings build(boolean refreshEnabled, int sealerMaximumLength) {
   return new OAuthServerSettings(this, refreshEnabled, sealerMaximumLength);
  }
  @NonNull List<@NonNull ConfigurationDiagnostic> configurationDiagnostics(boolean refreshEnabled, @Nullable Integer sealerMaximumLength) {
   List<ConfigurationDiagnostic> issues = new ArrayList<>();
   Duration authorizationInteractionLifetimeValue = checkedDuration(this.authorizationInteractionLifetime, Limits.AS_AUTHORIZATION_INTERACTION_LIFETIME, ConfigurationDiagnostic.OAUTH_AUTHORIZATION_INTERACTION_LIFETIME_INVALID, issues);
   Duration authorizationCodeLifetimeValue = checkedDuration(this.authorizationCodeLifetime, Limits.AS_AUTHORIZATION_CODE_LIFETIME, ConfigurationDiagnostic.OAUTH_AUTHORIZATION_CODE_LIFETIME_INVALID, issues);
   Duration accessTokenLifetimeValue = checkedDuration(this.accessTokenLifetime, Limits.AS_ACCESS_TOKEN_LIFETIME, ConfigurationDiagnostic.OAUTH_ACCESS_TOKEN_LIFETIME_INVALID, issues);
   Duration refreshTokenIdleLifetimeValue = checkedDuration(this.refreshTokenIdleLifetime, Limits.AS_REFRESH_TOKEN_IDLE_LIFETIME, ConfigurationDiagnostic.OAUTH_REFRESH_TOKEN_IDLE_LIFETIME_INVALID, issues);
   Duration refreshTokenAbsoluteLifetimeValue = checkedDuration(this.refreshTokenAbsoluteLifetime, Limits.AS_REFRESH_TOKEN_ABSOLUTE_LIFETIME, ConfigurationDiagnostic.OAUTH_REFRESH_TOKEN_ABSOLUTE_LIFETIME_INVALID, issues);
   Duration clockSkewValue = checkedDuration(this.clockSkew, Limits.AS_CLOCK_SKEW, ConfigurationDiagnostic.OAUTH_CLOCK_SKEW_INVALID, issues);
   Duration totalDeadlineValue = checkedDuration(this.totalDeadline, Limits.AS_TOTAL_DEADLINE, ConfigurationDiagnostic.OAUTH_TOTAL_DEADLINE_INVALID, issues);
   Duration requestTimeoutValue = checkedDuration(this.requestTimeout, Limits.AS_REQUEST_TIMEOUT, ConfigurationDiagnostic.OAUTH_REQUEST_TIMEOUT_INVALID, issues);
   checkedDuration(this.publicMetadataHttpCacheMaxAge, Limits.AS_PUBLIC_METADATA_HTTP_CACHE_MAX_AGE, ConfigurationDiagnostic.OAUTH_PUBLIC_METADATA_HTTP_CACHE_MAX_AGE_INVALID, issues);
   checkedInt(this.maximumRequestBodyBytes, Limits.AS_MAXIMUM_REQUEST_BODY_BYTES, ConfigurationDiagnostic.OAUTH_MAXIMUM_REQUEST_BODY_BYTES_INVALID, issues);
   checkedInt(this.maximumRawQueryLength, Limits.AS_MAXIMUM_RAW_QUERY_LENGTH, ConfigurationDiagnostic.OAUTH_MAXIMUM_RAW_QUERY_LENGTH_INVALID, issues);
   checkedInt(this.maximumHeaderBytes, Limits.AS_MAXIMUM_HEADER_BYTES, ConfigurationDiagnostic.OAUTH_MAXIMUM_HEADER_BYTES_INVALID, issues);
   checkedInt(this.maximumResponseBodyBytes, Limits.AS_MAXIMUM_RESPONSE_BODY_BYTES, ConfigurationDiagnostic.OAUTH_MAXIMUM_RESPONSE_BODY_BYTES_INVALID, issues);
   Integer maximumStoreRecordBytesValue = checkedInt(this.maximumStoreRecordBytes, Limits.AS_MAXIMUM_STORE_RECORD_BYTES, ConfigurationDiagnostic.OAUTH_MAXIMUM_STORE_RECORD_BYTES_INVALID, issues);
   checkedInt(this.maximumStoreCommitAttempts, Limits.AS_MAXIMUM_STORE_COMMIT_ATTEMPTS, ConfigurationDiagnostic.OAUTH_MAXIMUM_STORE_COMMIT_ATTEMPTS_INVALID, issues);
   checkedInt(this.maximumResources, Limits.AS_MAXIMUM_RESOURCES, ConfigurationDiagnostic.OAUTH_MAXIMUM_RESOURCES_INVALID, issues);
   checkedInt(this.maximumRedirectUris, Limits.AS_MAXIMUM_REDIRECT_URIS, ConfigurationDiagnostic.OAUTH_MAXIMUM_REDIRECT_URIS_INVALID, issues);
   checkedInt(this.maximumScopesPerResource, Limits.AS_MAXIMUM_SCOPES_PER_RESOURCE, ConfigurationDiagnostic.OAUTH_MAXIMUM_SCOPES_PER_RESOURCE_INVALID, issues);
   checkedInt(this.maximumScopeLength, Limits.AS_MAXIMUM_SCOPE_LENGTH, ConfigurationDiagnostic.OAUTH_MAXIMUM_SCOPE_LENGTH_INVALID, issues);
   checkedInt(this.maximumStateLength, Limits.AS_MAXIMUM_STATE_LENGTH, ConfigurationDiagnostic.OAUTH_MAXIMUM_STATE_LENGTH_INVALID, issues);
   checkedInt(this.maximumClientIdLength, Limits.AS_MAXIMUM_CLIENT_ID_LENGTH, ConfigurationDiagnostic.OAUTH_MAXIMUM_CLIENT_ID_LENGTH_INVALID, issues);
   checkedInt(this.maximumSubjectLength, Limits.AS_MAXIMUM_SUBJECT_LENGTH, ConfigurationDiagnostic.OAUTH_MAXIMUM_SUBJECT_LENGTH_INVALID, issues);
   if (requestTimeoutValue != null && totalDeadlineValue != null) {
    try { Limits.requireRequestTimeoutWithinTotalDeadline(requestTimeoutValue, totalDeadlineValue); }
    catch (IllegalArgumentException invalid) { issues.add(ConfigurationDiagnostic.OAUTH_REQUEST_TIMEOUT_EXCEEDS_DEADLINE); }
   }
   if (authorizationCodeLifetimeValue != null && authorizationInteractionLifetimeValue != null
     && authorizationCodeLifetimeValue.compareTo(authorizationInteractionLifetimeValue) > 0)
    issues.add(ConfigurationDiagnostic.OAUTH_CODE_LIFETIME_EXCEEDS_INTERACTION);
   // OAuthRefreshRotation always retains both lifetimes, even when refresh issuance is disabled.
   if (accessTokenLifetimeValue != null && refreshTokenIdleLifetimeValue != null
     && accessTokenLifetimeValue.compareTo(refreshTokenIdleLifetimeValue) > 0)
    issues.add(ConfigurationDiagnostic.OAUTH_ACCESS_LIFETIME_EXCEEDS_IDLE);
   if (refreshEnabled && refreshTokenIdleLifetimeValue != null && refreshTokenAbsoluteLifetimeValue != null
     && refreshTokenIdleLifetimeValue.compareTo(refreshTokenAbsoluteLifetimeValue) > 0)
    issues.add(ConfigurationDiagnostic.OAUTH_IDLE_LIFETIME_EXCEEDS_ABSOLUTE);
   if (clockSkewValue != null && accessTokenLifetimeValue != null
     && clockSkewValue.compareTo(accessTokenLifetimeValue.dividedBy(2)) > 0)
    issues.add(ConfigurationDiagnostic.OAUTH_CLOCK_SKEW_EXCEEDS_HALF_ACCESS);
   if (maximumStoreRecordBytesValue != null && sealerMaximumLength != null
     && maximumStoreRecordBytesValue > Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.require(sealerMaximumLength))
    issues.add(ConfigurationDiagnostic.OAUTH_STORE_RECORD_EXCEEDS_SEALER);
   return List.copyOf(issues);
  }
  @Nullable OAuthServerIngressLimits resourceLimitsForDiagnostics() {
   try {
    return new OAuthServerIngressLimits(
     Limits.AS_MAXIMUM_REQUEST_BODY_BYTES.require(this.maximumRequestBodyBytes==null?Limits.AS_MAXIMUM_REQUEST_BODY_BYTES.getDefaultIntValue():this.maximumRequestBodyBytes),
     Limits.AS_MAXIMUM_RAW_QUERY_LENGTH.require(this.maximumRawQueryLength==null?Limits.AS_MAXIMUM_RAW_QUERY_LENGTH.getDefaultIntValue():this.maximumRawQueryLength),
     Limits.AS_MAXIMUM_HEADER_BYTES.require(this.maximumHeaderBytes==null?Limits.AS_MAXIMUM_HEADER_BYTES.getDefaultIntValue():this.maximumHeaderBytes),
     Limits.AS_MAXIMUM_STATE_LENGTH.require(this.maximumStateLength==null?Limits.AS_MAXIMUM_STATE_LENGTH.getDefaultIntValue():this.maximumStateLength),
     Limits.AS_MAXIMUM_CLIENT_ID_LENGTH.require(this.maximumClientIdLength==null?Limits.AS_MAXIMUM_CLIENT_ID_LENGTH.getDefaultIntValue():this.maximumClientIdLength),
     Limits.AS_MAXIMUM_RESOURCES.require(this.maximumResources==null?Limits.AS_MAXIMUM_RESOURCES.getDefaultIntValue():this.maximumResources),
     Limits.AS_MAXIMUM_REDIRECT_URIS.require(this.maximumRedirectUris==null?Limits.AS_MAXIMUM_REDIRECT_URIS.getDefaultIntValue():this.maximumRedirectUris),
     Limits.AS_MAXIMUM_SCOPES_PER_RESOURCE.require(this.maximumScopesPerResource==null?Limits.AS_MAXIMUM_SCOPES_PER_RESOURCE.getDefaultIntValue():this.maximumScopesPerResource),
     Limits.AS_MAXIMUM_SCOPE_LENGTH.require(this.maximumScopeLength==null?Limits.AS_MAXIMUM_SCOPE_LENGTH.getDefaultIntValue():this.maximumScopeLength));
   } catch(IllegalArgumentException invalid) { return null; }
  }
  private static @Nullable Duration checkedDuration(@Nullable Duration value, @NonNull Limit limit,
    @NonNull ConfigurationDiagnostic code, @NonNull List<@NonNull ConfigurationDiagnostic> issues) {
   try { return limit.require(value == null ? limit.getDefaultDuration() : value); }
   catch (IllegalArgumentException invalid) { issues.add(code); return null; }
  }
  private static @Nullable Integer checkedInt(@Nullable Integer value, @NonNull Limit limit,
    @NonNull ConfigurationDiagnostic code, @NonNull List<@NonNull ConfigurationDiagnostic> issues) {
   try { return limit.require(value == null ? limit.getDefaultIntValue() : value); }
   catch (IllegalArgumentException invalid) { issues.add(code); return null; }
  }
  @Override public @NonNull String toString() { return "OAuthServerSettings.Builder{<redacted>}"; }
 }
}
