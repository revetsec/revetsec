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

package com.revetsec.scim;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Immutable framework-neutral SCIM schema, request and response primitives. Applications authenticate,
 * authorize, execute queries and persist candidates atomically; this facade performs no I/O.
 * Each direct-result operation has one bounded work budget and redacted observer lifecycle.
 * Parsed carriers are tied to this registration and compatibility snapshot. Base-URI-only copies
 * share that semantic registration; changed compatibility requires fresh parsing.
 * Resource-type arguments must be the exact immutable objects registered with this provider,
 * rather than separately constructed equal definitions. Passing a foreign trusted type is a
 * programming error; expected untrusted-input failures return checked fixed rejections.
 * Original query/header occurrences must reach these operations before framework normalization.
 * A prepared response proves bounded output only. Applications prepare the final authorized
 * candidate before commit where preparation can fail, then emit it only after confirmed persistence.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimServiceProvider {
    private final @NonNull URI baseUri;
    private final @NonNull List<@NonNull ScimResourceType> resourceTypes;
    private final @NonNull ScimServiceProviderConfig serviceProviderConfig;
    private final @NonNull ScimLimits limits;
    private final @NonNull ScimCompatibility compatibility;

    @SuppressWarnings("Immutable") // Application SPI contract explicitly requires thread safety.
    private final @Nullable ScimStringMatching stringMatching;

    @SuppressWarnings("Immutable") // Application SPI contract explicitly requires thread safety.
    private final @NonNull ScimObserver observer;

    private final @NonNull Map<@NonNull ScimResourceType, @NonNull ScimFilterPolicy> filterPolicies;
    private final @NonNull Map<@NonNull ScimResourceType, @NonNull ScimFilterBinding> bindings;
    private final @NonNull List<@NonNull ScimSchema> schemas;
    private final @NonNull Object semanticContext;

    private ScimServiceProvider(@NonNull Builder builder, @Nullable Object context) {
        baseUri = base(requireNonNull(builder.baseUri, "SCIM base URI is required."));
        resourceTypes = builder.resourceTypes;
        if (resourceTypes.isEmpty())
            throw new IllegalStateException("SCIM requires at least one resource type.");
        serviceProviderConfig =
                builder.serviceProviderConfig == null
                        ? ScimServiceProviderConfig.builder().build()
                        : builder.serviceProviderConfig;
        compatibility =
                builder.compatibility == null
                        ? ScimCompatibility.strictInstance()
                        : builder.compatibility;
        limits = builder.limits == null ? ScimLimits.fromDefaults() : builder.limits;
        observer = builder.observer == null ? ScimObserver.disabledInstance() : builder.observer;
        stringMatching = builder.stringMatching;
        if (serviceProviderConfig.isPatchSupported() && stringMatching == null)
            throw new IllegalStateException(
                    "Advertised SCIM PATCH requires an application matching strategy.");
        if (serviceProviderConfig.getPagination().getMaximumPageSize() > limits.getMaximumPageSize()
                || serviceProviderConfig.getFilterMaximumResults() > limits.getMaximumPageSize())
            throw new IllegalArgumentException(
                    "SCIM advertised maxima exceed configured processing limits.");
        schemas = registrations(resourceTypes);
        Map<ScimResourceType, ScimFilterPolicy> policies = new LinkedHashMap<>();
        for (Map.Entry<ScimResourceType, ScimFilterPolicy> entry :
                builder.filterPolicies.entrySet()) {
            registered(entry.getKey());
            policies.put(entry.getKey(), entry.getValue());
        }
        IdentityHashMap<ScimResourceType, ScimFilterBinding> bound = new IdentityHashMap<>();
        for (ScimResourceType type : resourceTypes) {
            ScimFilterPolicy policy = identityPolicy(policies, type);
            if (policy == null && serviceProviderConfig.isFilterSupported())
                throw new IllegalStateException(
                        "Advertised SCIM filtering requires an explicit policy for every type.");
            bound.put(
                    type,
                    new ScimFilterBinding(
                            type,
                            limits.getFilterLimits(),
                            compatibility,
                            policy == null ? ScimFilterPolicy.rejectAllInstance() : policy,
                            serviceProviderConfig.isFilterSupported()));
        }
        filterPolicies = Collections.unmodifiableMap(policies);
        bindings = Collections.unmodifiableMap(bound);
        semanticContext = context == null ? new Object() : context;
    }

    /** Starts configuration with no resource registrations; PATCH, filter, sort and password-change
     * advertisement are disabled, and ETags are enabled. The application still owns password
     * authorization and handling for a supplied write-only {@code password} value.
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() {
        return new Builder();
    }

    /** Starts a copy retaining the current semantic registration unless compatibility changes.
     * @return a new copier
     * @since 1.0.0
     */
    public @NonNull Copier copy() {
        return new Copier(this);
    }

    /** Returns the trusted canonical trailing-slash base URI.
     * @return the trusted canonical trailing-slash base URI
     * @since 1.0.0
     */
    public @NonNull URI getBaseUri() {
        return baseUri;
    }

    /** Returns the immutable registered resource types.
     * @return the immutable registered resource types
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimResourceType> getResourceTypes() {
        return resourceTypes;
    }

    /** Returns the advertised capabilities.
     * @return the advertised capabilities
     * @since 1.0.0
     */
    public @NonNull ScimServiceProviderConfig getServiceProviderConfig() {
        return serviceProviderConfig;
    }

    /** Returns the processing limits.
     * @return the processing limits
     * @since 1.0.0
     */
    public @NonNull ScimLimits getLimits() {
        return limits;
    }

    /** Returns the explicit compatibility features.
     * @return the explicit compatibility features
     * @since 1.0.0
     */
    public @NonNull ScimCompatibility getCompatibility() {
        return compatibility;
    }

    /** Returns the optional application matching strategy.
     * @return the optional application matching strategy
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimStringMatching> getStringMatching() {
        return Optional.ofNullable(stringMatching);
    }

    /** Returns the immutable configured filter policies.
     * @return the immutable configured filter policies
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull ScimResourceType, @NonNull ScimFilterPolicy> getFilterPolicies() {
        return filterPolicies;
    }

    /** Validates exactly one original physical media-type header occurrence.
     * Accepts application/scim+json or application/json with the selected syntactically valid charset
     * accommodation. Bodies remain strictly UTF-8 regardless of a charset label. Missing, duplicate,
     * malformed or unsupported values reject; do not join physical occurrences before validation.
     * @param rawHeaderValues original physical Content-Type values, including an empty list when absent
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimContentTypeResult validateContentTypeResult(
            @NonNull List<@NonNull String> rawHeaderValues) {
        requireNonNull(rawHeaderValues);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.CONTENT_TYPE,
                used,
                () -> media(rawHeaderValues, work),
                () -> new ScimContentTypeResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses, binds and approves the complete normalized filter under the configured policy.
     * Syntax alone grants no query permission. Applications execute the returned tree and separately
     * authorize the caller and tenant; this operation executes no storage query.
     * @param resourceType the exact registered resource-type object
     * @param expression the complete untrusted filter expression
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimFilterParseResult parseFilterResult(
            @NonNull ScimResourceType resourceType, @NonNull String expression) {
        registered(resourceType);
        requireNonNull(expression);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.FILTER,
                used,
                () -> binding(resourceType).bind(expression, used, work),
                () -> new ScimFilterParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    @NonNull ScimFilterEvaluationResult evaluateFilterResult(
            @NonNull ScimResource resource, @NonNull ScimFilter filter) {
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.FILTER_EVALUATE,
                used,
                () -> {
                    if (!associated(resource))
                        return new ScimFilterEvaluationResult.Rejected(ScimError.invalidValueInstance());
                    String expression = ScimFilterEvaluation.expression(filter, limits.getFilterLimits(), work);
                    if (expression == null)
                        return new ScimFilterEvaluationResult.Rejected(work.wasExceeded()
                                ? ScimError.requestTooLargeInstance() : ScimError.invalidFilterInstance());
                    ScimFilterParseResult rebound = binding(resource.getResourceType()).bind(expression, used, work);
                    if (rebound instanceof ScimFilterParseResult.Rejected rejected)
                        return new ScimFilterEvaluationResult.Rejected(work.wasExceeded()
                                ? ScimError.requestTooLargeInstance() : rejected.getError());
                    return ScimFilterEvaluation.evaluate(resource,
                            ((ScimFilterParseResult.Succeeded) rebound).getFilter(),
                            requireNonNull(stringMatching), work);
                },
                () -> new ScimFilterEvaluationResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a raw GET collection query with strict bounded decoding and complete filter approval.
     * Preserve physical repeated fields; do not first pass through a framework parameter map.
     * Raw plus means space and percent escapes are decoded strictly. Applications own execution,
     * authorization and cursor authenticity/context binding.
     * @param resourceType the exact registered resource-type object
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimQueryParseResult parseQueryResult(
            @NonNull ScimResourceType resourceType, @NonNull String rawQuery) {
        registered(resourceType);
        requireNonNull(rawQuery);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.QUERY,
                used,
                () ->
                        ScimQueries.query(
                                resourceType,
                                rawQuery,
                                serviceProviderConfig,
                                limits,
                                compatibility,
                                semanticContext,
                                binding(resourceType),
                                used,
                                work),
                () -> new ScimQueryParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a bound projection from the original raw query, separately from caller authorization.
     * Preserve physical repeated fields and undecoded text before framework parameter normalization.
     * The returned selection retains this provider's semantic registration.
     * @param resourceType the exact registered resource-type object
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimAttributeSelectionResult parseAttributeSelectionResult(
            @NonNull ScimResourceType resourceType, @NonNull String rawQuery) {
        registered(resourceType);
        requireNonNull(rawQuery);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.ATTRIBUTE_SELECTION,
                used,
                () -> ScimQueries.selection(resourceType, rawQuery, limits, semanticContext, work),
                () -> new ScimAttributeSelectionResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Checks weak opaque-version If-Match against the existing resource, deliberately differing
     * from general HTTP strong comparison. Absence succeeds; an isolated wildcard tests existence.
     * Applications check this exact authoritative resource under the write's lock/version predicate.
     * @param rawHeaderValues original physical If-Match values, or an empty list when absent
     * @param current the authoritative existing resource from that transaction
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimIfMatchResult checkIfMatchResult(
            @NonNull List<@NonNull String> rawHeaderValues, @NonNull ScimResource current) {
        requireNonNull(rawHeaderValues);
        registered(requireNonNull(current).getResourceType());
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.IF_MATCH,
                used,
                () ->
                        !headerWork(rawHeaderValues, limits.getMaximumConditionalTags(), work)
                                ? new ScimIfMatchResult.Rejected(
                                        ScimError.requestTooLargeInstance())
                                : associated(current)
                                        ? ScimHeaders.ifMatch(rawHeaderValues, current, limits)
                                        : new ScimIfMatchResult.Rejected(
                                                ScimError.invalidValueInstance()),
                () -> new ScimIfMatchResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Checks original conditional-read tags against the authoritative existing resource using weak
     * opaque-version comparison. Absence proceeds; an isolated wildcard can report NotModified
     * without a version. Applications own the corresponding GET/HEAD route and read consistency.
     * @param rawHeaderValues original physical If-None-Match values, or an empty list when absent
     * @param current the authoritative existing resource
     * @return the checked direct result
     * @since 1.0.0
     */
    public @NonNull ScimIfNoneMatchResult checkIfNoneMatchResult(
            @NonNull List<@NonNull String> rawHeaderValues, @NonNull ScimResource current) {
        requireNonNull(rawHeaderValues);
        registered(requireNonNull(current).getResourceType());
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.IF_NONE_MATCH,
                used,
                () ->
                        !headerWork(rawHeaderValues, limits.getMaximumConditionalTags(), work)
                                ? new ScimIfNoneMatchResult.Rejected(
                                        ScimError.requestTooLargeInstance())
                                : associated(current)
                                        ? ScimHeaders.ifNoneMatch(rawHeaderValues, current, limits)
                                        : new ScimIfNoneMatchResult.Rejected(
                                                ScimError.invalidValueInstance()),
                () -> new ScimIfNoneMatchResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a search body after validating original media-type fields.
     * @param resourceType the exact registered resource-type object
     * @param contentTypeHeaderValues original physical media-type occurrences
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimQueryParseResult parseSearchRequestResult(
            @NonNull ScimResourceType resourceType,
            @NonNull List<@NonNull String> contentTypeHeaderValues,
            byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        requireNonNull(contentTypeHeaderValues);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.SEARCH,
                used,
                () -> {
                    ScimContentTypeResult media = media(contentTypeHeaderValues, work);
                    if (media instanceof ScimContentTypeResult.Rejected rejected)
                        return new ScimQueryParseResult.Rejected(rejected.getError());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimQueryParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimQueries.search(
                            resourceType,
                            document,
                            serviceProviderConfig,
                            limits,
                            compatibility,
                            semanticContext,
                            binding(resourceType),
                            used,
                            work);
                },
                () -> new ScimQueryParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a search body whose HTTP framing and media type were already validated.
     * @param resourceType the exact registered resource-type object
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimQueryParseResult parseSearchRequestResult(
            @NonNull ScimResourceType resourceType, byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.SEARCH,
                used,
                () -> {
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimQueryParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimQueries.search(
                            resourceType,
                            document,
                            serviceProviderConfig,
                            limits,
                            compatibility,
                            semanticContext,
                            binding(resourceType),
                            used,
                            work);
                },
                () -> new ScimQueryParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a create body after validating original media-type fields.
     * @param resourceType the exact registered resource-type object
     * @param contentTypeHeaderValues original physical media-type occurrences
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResourceParseResult parseResourceResult(
            @NonNull ScimResourceType resourceType,
            @NonNull List<@NonNull String> contentTypeHeaderValues,
            byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        requireNonNull(contentTypeHeaderValues);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.RESOURCE_CREATE,
                used,
                () -> {
                    ScimContentTypeResult media = media(contentTypeHeaderValues, work);
                    if (media instanceof ScimContentTypeResult.Rejected rejected)
                        return new ScimResourceParseResult.Rejected(rejected.getError());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimResourceParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimResources.create(
                            resourceType, document, compatibility, work, semanticContext, used);
                },
                () -> new ScimResourceParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a create body whose HTTP framing and media type were already validated.
     * @param resourceType the exact registered resource-type object
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResourceParseResult parseResourceResult(
            @NonNull ScimResourceType resourceType, byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.RESOURCE_CREATE,
                used,
                () -> {
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimResourceParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimResources.create(
                            resourceType, document, compatibility, work, semanticContext, used);
                },
                () -> new ScimResourceParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a replace body after validating original media-type fields.
     * @param resourceType the exact registered resource-type object
     * @param current the immutable authoritative current resource
     * @param contentTypeHeaderValues original physical media-type occurrences
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResourceParseResult parseReplacementResult(
            @NonNull ScimResourceType resourceType,
            @NonNull ScimResource current,
            @NonNull List<@NonNull String> contentTypeHeaderValues,
            byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        requireNonNull(current);
        if (!same(current.getResourceType(), resourceType))
            throw new IllegalArgumentException("SCIM replacement type mismatch.");
        requireNonNull(contentTypeHeaderValues);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.RESOURCE_REPLACE,
                used,
                () -> {
                    if (!associated(current))
                        return new ScimResourceParseResult.Rejected(
                                ScimError.invalidValueInstance());
                    ScimContentTypeResult media = media(contentTypeHeaderValues, work);
                    if (media instanceof ScimContentTypeResult.Rejected rejected)
                        return new ScimResourceParseResult.Rejected(rejected.getError());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimResourceParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimResources.replace(
                            resourceType,
                            current,
                            document,
                            compatibility,
                            work,
                            semanticContext,
                            used);
                },
                () -> new ScimResourceParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses a replace body whose HTTP framing and media type were already validated.
     * @param resourceType the exact registered resource-type object
     * @param current the immutable authoritative current resource
     * @param body untrusted UTF-8 JSON; empty bytes reject
     * @return a checked candidate or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResourceParseResult parseReplacementResult(
            @NonNull ScimResourceType resourceType,
            @NonNull ScimResource current,
            byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        requireNonNull(current);
        if (!same(current.getResourceType(), resourceType))
            throw new IllegalArgumentException("SCIM replacement type mismatch.");
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.RESOURCE_REPLACE,
                used,
                () -> {
                    if (!associated(current))
                        return new ScimResourceParseResult.Rejected(
                                ScimError.invalidValueInstance());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimResourceParseResult.Rejected(parsed.error);
                    JsonDocument document = requireNonNull(parsed.document);
                    return ScimResources.replace(
                            resourceType,
                            current,
                            document,
                            compatibility,
                            work,
                            semanticContext,
                            used);
                },
                () -> new ScimResourceParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses ordered PATCH operations after validating original media-type fields.
     * @param resourceType the exact registered resource-type object
     * @param contentTypeHeaderValues original physical media-type occurrences
     * @param body untrusted UTF-8 PatchOp JSON; empty bytes reject
     * @return a schema-bound request or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimPatchParseResult parsePatchRequestResult(
            @NonNull ScimResourceType resourceType,
            @NonNull List<@NonNull String> contentTypeHeaderValues,
            byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(contentTypeHeaderValues);
        requireNonNull(body);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.PATCH_PARSE,
                used,
                () -> {
                    if (!serviceProviderConfig.isPatchSupported())
                        return new ScimPatchParseResult.Rejected(ScimError.forbiddenInstance());
                    ScimContentTypeResult media = media(contentTypeHeaderValues, work);
                    if (media instanceof ScimContentTypeResult.Rejected rejected)
                        return new ScimPatchParseResult.Rejected(rejected.getError());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimPatchParseResult.Rejected(parsed.error);
                    return ScimPatchParsing.parse(resourceType, requireNonNull(parsed.document),
                            compatibility, limits, work, semanticContext, used);
                },
                () -> new ScimPatchParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Parses PATCH bytes whose transport framing and media type were already validated.
     * @param resourceType the exact registered resource-type object
     * @param body untrusted UTF-8 PatchOp JSON; empty bytes reject
     * @return a schema-bound request or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimPatchParseResult parsePatchRequestResult(
            @NonNull ScimResourceType resourceType, byte @NonNull [] body) {
        registered(resourceType);
        requireNonNull(body);
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.PATCH_PARSE,
                used,
                () -> {
                    if (!serviceProviderConfig.isPatchSupported())
                        return new ScimPatchParseResult.Rejected(ScimError.forbiddenInstance());
                    Body parsed = parse(body, work);
                    if (parsed.error != null)
                        return new ScimPatchParseResult.Rejected(parsed.error);
                    return ScimPatchParsing.parse(resourceType, requireNonNull(parsed.document),
                            compatibility, limits, work, semanticContext, used);
                },
                () -> new ScimPatchParseResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Applies every ordered operation to an immutable candidate, publishing only after final validation.
     * Applications authorize attempted and effective paths and persist the candidate atomically.
     * @param current authoritative resource from the application's transaction
     * @param patch schema-bound request from this semantic registration
     * @return a complete candidate with change/provenance paths or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimPatchApplicationResult applyPatchResult(
            @NonNull ScimResource current, @NonNull ScimPatchRequest patch) {
        requireNonNull(current);
        requireNonNull(patch);
        registered(current.getResourceType());
        ScimWork work = work();
        Set<ScimCompatibilityFeature> used = EnumSet.noneOf(ScimCompatibilityFeature.class);
        return process(
                ScimObserver.Operation.PATCH_APPLY,
                used,
                () -> {
                    ScimStringMatching matching = stringMatching;
                    if (!serviceProviderConfig.isPatchSupported() || matching == null)
                        return new ScimPatchApplicationResult.Rejected(ScimError.forbiddenInstance());
                    if (!associated(current) || !associated(patch)
                            || !same(current.getResourceType(), patch.getResourceType()))
                        return new ScimPatchApplicationResult.Rejected(ScimError.invalidValueInstance());
                    return ScimPatchEngine.apply(current, patch, compatibility, matching, work,
                            semanticContext, used);
                },
                () -> new ScimPatchApplicationResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Reduces supported standard Group membership operations into ordered ID steps without reading storage.
     * Metadata-dependent operations require full evaluation. The application executes all steps and the
     * remainder under one authorization decision and transaction/version predicate.
     * @param patch schema-bound request from this semantic registration
     * @return ordered steps, full-evaluation requirement or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimMembershipPatchResult reduceMembershipPatchResult(@NonNull ScimPatchRequest patch) {
        requireNonNull(patch);
        ScimWork work = work();
        return process(
                ScimObserver.Operation.MEMBERSHIP_REDUCE,
                Set.of(),
                () -> {
                    if (!serviceProviderConfig.isPatchSupported())
                        return new ScimMembershipPatchResult.Rejected(ScimError.forbiddenInstance());
                    if (!associated(patch))
                        return new ScimMembershipPatchResult.Rejected(ScimError.invalidValueInstance());
                    return ScimMembershipReduction.reduce(patch, work);
                },
                () -> new ScimMembershipPatchResult.Rejected(ScimError.internalErrorInstance()));
    }

    /** Encodes an authoritative ID as one path segment beneath the trusted type endpoint.
     * @param resourceType the exact registered resource-type object
     * @param authoritativeId application-assigned identifier
     * @return an absolute resource location
     * @since 1.0.0
     */
    public @NonNull URI resourceLocationFor(
            @NonNull ScimResourceType resourceType, @NonNull String authoritativeId) {
        registered(resourceType);
        ScimSchemas.requireText(requireNonNull(authoritativeId), false);
        if (!ScimResourceValidation.validResourceId(authoritativeId))
            throw new IllegalArgumentException("Invalid SCIM resource identifier.");
        StringBuilder segment = new StringBuilder();
        for (byte octet : authoritativeId.getBytes(StandardCharsets.UTF_8)) {
            int value = octet & 255;
            if (value >= 'a' && value <= 'z'
                    || value >= 'A' && value <= 'Z'
                    || value >= '0' && value <= '9'
                    || value == '-'
                    || value == '_'
                    || value == '~') segment.append((char) value);
            else {
                segment.append('%');
                segment.append("0123456789ABCDEF".charAt(value >>> 4));
                segment.append("0123456789ABCDEF".charAt(value & 15));
            }
        }
        return URI.create(
                baseUri.toASCIIString() + resourceType.getEndpoint().substring(1) + "/" + segment);
    }

    /** Prepares a GET resource response without write provenance.
     * @param resource resource to render
     * @param selection bound projection
     * @return a bounded prepared response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult resourceResponseResult(
            @NonNull ScimResource resource, @NonNull ScimAttributeSelection selection) {
        return response(resource, Set.of(), selection, false, 200);
    }

    /** Prepares a replacement response from the final authorized candidate with authoritative metadata.
     * Prepare before commit where preparation can fail, and emit only after confirmed persistence.
     * Supplied paths are trusted application provenance from parsing, separately from attempted or
     * modified authorization targets. The bare set has no private parser/configuration proof; its
     * paths are validated against the target schema. Preparation proves neither authorization nor persistence.
     * @param replaced the final application-assigned replacement candidate
     * @param suppliedPaths canonical paths actually supplied, from the resource parse result
     * @param selection the bound projection from this semantic registration
     * @return a bounded prepared response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult replacementResponseResult(
            @NonNull ScimResource replaced,
            @NonNull Set<@NonNull ScimAttributePath> suppliedPaths,
            @NonNull ScimAttributeSelection selection) {
        return response(replaced, suppliedPaths, selection, true, 200);
    }

    /** Prepares creation from the final authorized candidate with authoritative ID and metadata.
     * Location comes from the trusted base/type endpoint, and any existing meta.location must agree.
     * Prepare before commit where preparation can fail, and emit only after confirmed persistence.
     * Supplied paths are trusted application provenance from parsing, not attempted/modified targets.
     * The bare set has no private parser/configuration proof; its paths are checked against the target
     * schema. Preparation proves neither authorization nor persistence.
     * @param created the final application-assigned creation candidate with an assigned ID
     * @param suppliedPaths canonical paths actually supplied, from the resource parse result
     * @param selection the bound projection from this semantic registration
     * @return a bounded prepared response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult createdResponseResult(
            @NonNull ScimResource created,
            @NonNull Set<@NonNull ScimAttributePath> suppliedPaths,
            @NonNull ScimAttributeSelection selection) {
        return response(created, suppliedPaths, selection, true, 201);
    }

    /** Prepares the final authorized PATCH candidate after application-assigned authoritative metadata.
     * Prepare before commit where preparation can fail, and emit only after confirmed persistence.
     * The resource type's default is used unless either projection parameter was supplied, which
     * forces status 200. Bodyless responses retain authoritative ETag and bounded headers.
     * Supplied paths are trusted application provenance from PATCH application, not attempted/modified
     * authorization targets. The bare set has no private parser/configuration proof; its paths are
     * checked against the target schema. Preparation proves neither authorization nor persistence.
     * @param persistedCandidate the final application-assigned candidate; persistence need not precede preparation
     * @param suppliedPaths canonical paths actually supplied, from the PATCH application result
     * @param selection the bound response projection from this semantic registration
     * @return a bounded prepared response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult patchResponseResult(
            @NonNull ScimResource persistedCandidate,
            @NonNull Set<@NonNull ScimAttributePath> suppliedPaths,
            @NonNull ScimAttributeSelection selection) {
        requireNonNull(persistedCandidate);
        requireNonNull(selection);
        int status = persistedCandidate.getResourceType().isPatchResponseNoContent()
                && !selection.isExplicit() ? 204 : 200;
        return response(persistedCandidate, suppliedPaths, selection, true, status);
    }

    private @NonNull ScimResponseResult response(
            @NonNull ScimResource resource,
            @NonNull Set<@NonNull ScimAttributePath> supplied,
            @NonNull ScimAttributeSelection selection,
            boolean write,
            int status) {
        requireNonNull(resource);
        requireNonNull(selection);
        requireNonNull(supplied);
        registered(resource.getResourceType());
        ScimWork work = work();
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                () -> {
                    if (!associated(resource)
                            || resource.getId().isEmpty()
                            || !associated(selection)
                            || !same(resource.getResourceType(), selection.getResourceType())
                            || !supplied(resource.getResourceType(), supplied, work))
                        return responseError(ScimError.invalidValueInstance());
                    if (status == 204)
                        return ScimResponses.prepare(limits, 204, null, etag(resource), work);
                    JsonObject body =
                            ScimResources.project(resource, selection, supplied, write, work);
                    if (body == null) return responseError(ScimError.responseTooLargeInstance());
                    Map<String, List<String>> headers = etag(resource);
                    if (status == 201) {
                        if (resource.getId().isEmpty())
                            return responseError(ScimError.invalidValueInstance());
                        URI location =
                                resourceLocationFor(
                                        resource.getResourceType(), resource.getId().get());
                        if (resource.getLocation().isPresent()
                                && !resource.getLocation().get().equals(location))
                            return responseError(ScimError.invalidValueInstance());
                        LinkedHashMap<String, JsonValue> members =
                                new LinkedHashMap<>(body.getMembers());
                        JsonValue original = members.get("meta");
                        LinkedHashMap<String, JsonValue> meta =
                                new LinkedHashMap<>(
                                        original instanceof JsonObject object
                                                ? object.getMembers()
                                                : Map.of());
                        meta.put("location", JsonString.fromValue(location.toASCIIString()));
                        members.put("meta", JsonObject.fromMembers(meta));
                        body = JsonObject.fromMembers(members);
                        headers = new LinkedHashMap<>(headers);
                        headers.put("Location", List.of(location.toASCIIString()));
                    }
                    return ScimResponses.prepare(limits, status, body, headers, work);
                },
                () -> responseError(ScimError.internalErrorInstance()));
    }

    /** Prepares a truthful index or cursor ListResponse from an application-produced page.
     * @param page checked page and its originating query
     * @return a bounded prepared response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult listResponseResult(@NonNull ScimListPage page) {
        requireNonNull(page);
        ScimWork work = work();
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                () -> {
                    ScimQuery query = page.getQuery();
                    if (!same(query.getSemanticContext(), semanticContext)
                            || !registeredIdentity(query.getResourceType()))
                        return responseError(ScimError.invalidValueInstance());
                    List<JsonValue> values = new ArrayList<>();
                    for (ScimResource resource : page.getResources()) {
                        if (!work.take(1))
                            return responseError(ScimError.responseTooLargeInstance());
                        if (!associated(resource) || resource.getId().isEmpty())
                            return responseError(ScimError.invalidValueInstance());
                        JsonObject body =
                                ScimResources.project(
                                        resource,
                                        query.getAttributeSelection(),
                                        Set.of(),
                                        false,
                                        work);
                        if (body == null)
                            return responseError(ScimError.responseTooLargeInstance());
                        values.add(body);
                    }
                    LinkedHashMap<String, JsonValue> body = list(values);
                    page.getTotalResults()
                            .ifPresent(
                                    value -> body.put("totalResults", JsonNumber.fromValue(value)));
                    query.getStartIndex()
                            .ifPresent(
                                    value -> body.put("startIndex", JsonNumber.fromValue(value)));
                    page.getNextCursor()
                            .ifPresent(
                                    value -> body.put("nextCursor", JsonString.fromValue(value)));
                    page.getPreviousCursor()
                            .ifPresent(
                                    value ->
                                            body.put(
                                                    "previousCursor", JsonString.fromValue(value)));
                    return ScimResponses.prepare(
                            limits, 200, JsonObject.fromMembers(body), Map.of(), work);
                },
                () -> responseError(ScimError.internalErrorInstance()));
    }

    /** Prepares bounded discovery with projection; discovery filters reject.
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return discovery or a fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult serviceProviderConfigResponseResult(
            @NonNull String rawQuery) {
        return discovery("config", null, requireNonNull(rawQuery));
    }

    /** Prepares bounded discovery with projection; discovery filters reject.
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return discovery or a fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult resourceTypesResponseResult(@NonNull String rawQuery) {
        return discovery("types", null, requireNonNull(rawQuery));
    }

    /** Prepares bounded discovery with projection; discovery filters reject.
     * @param resourceTypeName registered case-exact type name
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return discovery or a fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult resourceTypeResponseResult(
            @NonNull String resourceTypeName, @NonNull String rawQuery) {
        requireNonNull(resourceTypeName);
        return discovery("type", resourceTypeName, requireNonNull(rawQuery));
    }

    /** Prepares bounded discovery with projection; discovery filters reject.
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return discovery or a fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult schemasResponseResult(@NonNull String rawQuery) {
        return discovery("schemas", null, requireNonNull(rawQuery));
    }

    /** Prepares bounded discovery with projection; discovery filters reject.
     * @param schemaId registered schema identifier
     * @param rawQuery the original undecoded query without a leading question mark, or empty when absent
     * @return discovery or a fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult schemaResponseResult(
            @NonNull String schemaId, @NonNull String rawQuery) {
        requireNonNull(schemaId);
        return discovery("schema", schemaId, requireNonNull(rawQuery));
    }

    private @NonNull ScimResponseResult discovery(
            @NonNull String kind, @Nullable String selector, @NonNull String raw) {
        ScimWork work = work();
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                () -> {
                    ScimResourceType descriptor =
                            kind.equals("config")
                                    ? DiscoveryTypes.CONFIG
                                    : kind.equals("type") || kind.equals("types")
                                            ? DiscoveryTypes.TYPE
                                            : DiscoveryTypes.SCHEMA;
                    ScimAttributeSelectionResult selected =
                            ScimQueries.discoverySelection(
                                    descriptor, raw, limits, semanticContext, work);
                    if (selected instanceof ScimAttributeSelectionResult.Rejected rejected)
                        return responseError(rejected.getError());
                    ScimAttributeSelection selection =
                            ((ScimAttributeSelectionResult.Succeeded) selected)
                                    .getAttributeSelection();
                    if (selector != null) {
                        long cap =
                                kind.equals("schema")
                                        ? Limits.SCIM_SCHEMA_ID_LENGTH.getCap()
                                        : Limits.SCIM_ATTRIBUTE_NAME_LENGTH.getCap();
                        if (selector.length() > cap)
                            return responseError(ScimError.requestTooLargeInstance());
                        if (!work.spend(selector.length()))
                            return responseError(ScimError.responseTooLargeInstance());
                    }
                    List<JsonObject> candidates = new ArrayList<>();
                    if (kind.equals("config")) {
                        if (!configurationWork(work))
                            return responseError(ScimError.responseTooLargeInstance());
                        candidates.add(ScimDiscovery.configuration(serviceProviderConfig));
                    } else if (kind.equals("type") || kind.equals("types")) {
                        for (ScimResourceType type : resourceTypes)
                            if (selector == null || type.getName().equals(selector)) {
                                if (!typeWork(type, work))
                                    return responseError(ScimError.responseTooLargeInstance());
                                candidates.add(ScimDiscovery.resourceType(type));
                            }
                    } else
                        for (ScimSchema schema : schemas)
                            if (selector == null
                                    || AsciiCase.fold(schema.getId())
                                            .equals(AsciiCase.fold(selector))) {
                                if (!schemaWork(schema, work))
                                    return responseError(ScimError.responseTooLargeInstance());
                                candidates.add(ScimDiscovery.schema(schema));
                            }
                    if (candidates.isEmpty() && selector != null)
                        return responseError(ScimError.notFoundInstance());
                    List<JsonValue> values = new ArrayList<>();
                    for (JsonObject body : candidates) {
                        JsonObject projected =
                                ScimResources.project(
                                        ScimResource.parsed(descriptor, body, semanticContext),
                                        selection,
                                        Set.of(),
                                        false,
                                        work);
                        if (projected == null)
                            return responseError(ScimError.responseTooLargeInstance());
                        values.add(projected);
                    }
                    JsonObject output;
                    if (kind.equals("types") || kind.equals("schemas")) {
                        LinkedHashMap<String, JsonValue> members = list(values);
                        members.put("totalResults", JsonNumber.fromValue((long) values.size()));
                        members.put("startIndex", JsonNumber.fromValue(1L));
                        output = JsonObject.fromMembers(members);
                    } else output = (JsonObject) values.get(0);
                    return ScimResponses.prepare(limits, 200, output, Map.of(), work);
                },
                () -> responseError(ScimError.internalErrorInstance()));
    }

    // Reserve all descriptor visits and text before allocating their JSON representations.
    private static boolean schemaWork(@NonNull ScimSchema schema, @NonNull ScimWork work) {
        if (!work.spend(
                (long) schema.getId().length()
                        + schema.getName().length()
                        + schema.getDescription().orElse("").length())) return false;
        for (ScimAttributeDefinition definition : schema.getAttributes())
            if (!definitionWork(definition, work)) return false;
        return true;
    }

    private static boolean definitionWork(
            @NonNull ScimAttributeDefinition definition, @NonNull ScimWork work) {
        // Covers emitted facet nodes as well as the subsequent immutable-model scans.
        if (!work.spend(
                16L
                        + definition.getName().length()
                        + definition.getDescription().orElse("").length())) return false;
        for (String value : definition.getCanonicalValues())
            if (!work.spend(2L + value.length())) return false;
        for (String value : definition.getReferenceTypes())
            if (!work.spend(2L + value.length())) return false;
        for (ScimAttributeDefinition child : definition.getSubAttributes())
            if (!definitionWork(child, work)) return false;
        return true;
    }

    private static boolean typeWork(@NonNull ScimResourceType type, @NonNull ScimWork work) {
        if (!work.spend(
                16L
                        + type.getName().length()
                        + type.getEndpoint().length()
                        + type.getSchema().getId().length()
                        + type.getId().orElse("").length()
                        + type.getDescription().orElse("").length())) return false;
        for (ScimSchemaExtension extension : type.getSchemaExtensions())
            if (!work.spend(4L + extension.getSchema().getId().length())) return false;
        return true;
    }

    private boolean configurationWork(@NonNull ScimWork work) {
        if (!work.spend(
                32L
                        + serviceProviderConfig
                                .getDocumentationUri()
                                .map(URI::toString)
                                .orElse("")
                                .length())) return false;
        for (ScimAuthenticationScheme scheme : serviceProviderConfig.getAuthenticationSchemes())
            if (!work.spend(
                    8L
                            + scheme.getType().length()
                            + scheme.getName().length()
                            + scheme.getDescription().length()
                            + scheme.getSpecUri().map(URI::toString).orElse("").length()
                            + scheme.getDocumentationUri().map(URI::toString).orElse("").length()))
                return false;
        return true;
    }

    /** Returns the fixed bounded no-content response.
     * @return a bodyless 204 response
     * @since 1.0.0
     */
    public @NonNull ScimResponse noContentResponse() {
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                ScimResponses::noContent,
                () -> ScimResponses.error(ScimError.internalErrorInstance()));
    }

    /** Prepares a bounded bodyless conditional read response with current ETag when enabled.
     * @param current authoritative existing resource
     * @return a bounded 304 response or fixed error
     * @since 1.0.0
     */
    public @NonNull ScimResponseResult notModifiedResponseResult(@NonNull ScimResource current) {
        requireNonNull(current);
        registered(current.getResourceType());
        ScimWork work = work();
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                () ->
                        associated(current)
                                ? ScimResponses.prepare(limits, 304, null, etag(current), work)
                                : responseError(ScimError.invalidValueInstance()),
                () -> responseError(ScimError.internalErrorInstance()));
    }

    /** Returns a fixed bounded error without including request data or causes.
     * @param error fixed core error
     * @return an error response
     * @since 1.0.0
     */
    public @NonNull ScimResponse errorResponse(@NonNull ScimError error) {
        requireNonNull(error);
        return process(
                ScimObserver.Operation.RESPONSE_PREPARE,
                Set.of(),
                () -> ScimResponses.error(error),
                () -> ScimResponses.error(ScimError.internalErrorInstance()));
    }

    /** Returns a fixed redacted description.
     * @return a redacted description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "ScimServiceProvider{<redacted>}";
    }

    private @NonNull Body parse(byte @NonNull [] body, @NonNull ScimWork work) {
        if (!work.spend(body.length)) return new Body(null, ScimError.requestTooLargeInstance());
        JsonParseResult result =
                JsonCodec.parseResult(
                        body,
                        JsonLimits.scim(
                                limits.getMaximumBodyBytes(), limits.getMaximumJsonNodes()));
        return result instanceof JsonParseResult.Succeeded success
                ? new Body(success.getDocument(), null)
                : new Body(null, jsonError((JsonParseResult.Rejected) result));
    }

    private static final class Body {
        final @Nullable JsonDocument document;
        final @Nullable ScimError error;

        Body(@Nullable JsonDocument document, @Nullable ScimError error) {
            this.document = document;
            this.error = error;
        }
    }

    private static @NonNull ScimError jsonError(JsonParseResult.@NonNull Rejected rejected) {
        return rejected.getKind() == JsonParseException.Kind.INPUT_SIZE
                        || rejected.getKind() == JsonParseException.Kind.NODES
                        || rejected.getKind() == JsonParseException.Kind.DEPTH
                        || rejected.getKind() == JsonParseException.Kind.STRING_LENGTH
                        || rejected.getKind() == JsonParseException.Kind.NUMBER_LENGTH
                        || rejected.getKind() == JsonParseException.Kind.EXPONENT
                ? ScimError.requestTooLargeInstance()
                : ScimError.invalidSyntaxInstance();
    }

    @SuppressWarnings(
            "ReferenceEquality") // Identity is the private registration/provenance capability.
    private static boolean same(@NonNull Object first, @NonNull Object second) {
        return first == second;
    }

    private static boolean headerWork(
            @NonNull List<@NonNull String> values, int maximum, @NonNull ScimWork work) {
        if (values.size() > maximum) return false;
        for (String value : values)
            if (!work.spend(1L + 2L * requireNonNull(value).length())) return false;
        return true;
    }

    private static @NonNull ScimContentTypeResult media(
            @NonNull List<@NonNull String> values, @NonNull ScimWork work) {
        if (values.size() != 1) return ScimHeaders.contentType(values);
        return headerWork(values, 1, work)
                ? ScimHeaders.contentType(values)
                : new ScimContentTypeResult.Rejected(ScimError.requestTooLargeInstance());
    }

    private @NonNull ScimWork work() {
        return new ScimWork(limits.getMaximumWorkUnits());
    }

    private @NonNull ScimFilterBinding binding(@NonNull ScimResourceType type) {
        return requireNonNull(bindings.get(type));
    }

    private boolean registeredIdentity(@NonNull ScimResourceType type) {
        for (ScimResourceType registered : resourceTypes) if (same(type, registered)) return true;
        return false;
    }

    private void registered(@NonNull ScimResourceType type) {
        if (!registeredIdentity(requireNonNull(type)))
            throw new IllegalArgumentException(
                    "SCIM resource type is not registered with this provider.");
    }

    private boolean associated(@NonNull ScimResource resource) {
        Object context = resource.getSemanticContext();
        return registeredIdentity(resource.getResourceType())
                && (context == null || same(context, semanticContext));
    }

    private boolean associated(@NonNull ScimAttributeSelection selection) {
        return registeredIdentity(selection.getResourceType())
                && same(selection.getSemanticContext(), semanticContext);
    }

    private boolean associated(@NonNull ScimPatchRequest patch) {
        return registeredIdentity(patch.getResourceType())
                && same(patch.getSemanticContext(), semanticContext);
    }

    private boolean supplied(
            @NonNull ScimResourceType type,
            @NonNull Set<@NonNull ScimAttributePath> paths,
            @NonNull ScimWork work) {
        if (paths.size() > Limits.SCIM_ATTRIBUTE_DEFINITIONS.getCap()) return false;
        for (ScimAttributePath path : paths) {
            if (!work.take(1)) return false;
            ScimAttributePath canonical =
                    ScimSchemas.canonicalPath(type, requireNonNull(path)).orElse(null);
            if (canonical == null || !canonical.equals(path)) return false;
        }
        return true;
    }

    private @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> etag(
            @NonNull ScimResource resource) {
        return serviceProviderConfig.isEtagSupported() && resource.getVersion().isPresent()
                ? Map.of("ETag", List.of(resource.getVersion().get()))
                : Map.of();
    }

    private static @NonNull LinkedHashMap<@NonNull String, @NonNull JsonValue> list(
            @NonNull List<@NonNull JsonValue> resources) {
        LinkedHashMap<String, JsonValue> body = new LinkedHashMap<>();
        body.put(
                "schemas",
                JsonArray.fromElements(
                        List.of(
                                JsonString.fromValue(
                                        "urn:ietf:params:scim:api:messages:2.0:ListResponse"))));
        body.put("Resources", JsonArray.fromElements(resources));
        body.put("itemsPerPage", JsonNumber.fromValue((long) resources.size()));
        return body;
    }

    private static @NonNull ScimResponseResult responseError(@NonNull ScimError error) {
        return new ScimResponseResult.Rejected(error);
    }

    private <R extends @NonNull Object> @NonNull R process(
            ScimObserver.@NonNull Operation operation,
            @NonNull Set<@NonNull ScimCompatibilityFeature> used,
            @NonNull Supplier<@NonNull R> action,
            @NonNull Supplier<@NonNull R> failure) {
        ObserverDispatch.dispatch(observer, value -> value.willProcess(operation));
        R result;
        try {
            result = requireNonNull(action.get());
        } catch (Throwable unexpected) {
            if (unexpected instanceof VirtualMachineError fatal) throw fatal;
            if (unexpected instanceof InterruptedException) Thread.currentThread().interrupt();
            for (ScimCompatibilityFeature feature : used)
                ObserverDispatch.dispatch(
                        observer, value -> value.didUseCompatibilityFeature(feature));
            ObserverDispatch.dispatch(observer, value -> value.didFailToProcess(operation));
            return requireNonNull(failure.get());
        }
        for (ScimCompatibilityFeature feature : used)
            ObserverDispatch.dispatch(observer, value -> value.didUseCompatibilityFeature(feature));
        ScimObserver.Outcome outcome = outcome(result);
        ObserverDispatch.dispatch(observer, value -> value.didProcess(operation, outcome));
        return result;
    }

    private static ScimObserver.@NonNull Outcome outcome(@NonNull Object result) {
        if (result instanceof ScimResponse || result instanceof ScimResponseResult.Prepared)
            return ScimObserver.Outcome.PREPARED;
        if (result instanceof ScimIfMatchResult.Satisfied) return ScimObserver.Outcome.SATISFIED;
        if (result instanceof ScimIfNoneMatchResult.Proceed) return ScimObserver.Outcome.PROCEED;
        if (result instanceof ScimIfNoneMatchResult.NotModified)
            return ScimObserver.Outcome.NOT_MODIFIED;
        if (result instanceof ScimMembershipPatchResult.RequiresFullEvaluation)
            return ScimObserver.Outcome.REQUIRES_FULL_EVALUATION;
        if (result instanceof ScimContentTypeResult.Accepted
                || result instanceof ScimFilterParseResult.Succeeded
                || result instanceof ScimQueryParseResult.Succeeded
                || result instanceof ScimAttributeSelectionResult.Succeeded
                || result instanceof ScimResourceParseResult.Succeeded
                || result instanceof ScimPatchParseResult.Succeeded
                || result instanceof ScimPatchApplicationResult.Succeeded
                || result instanceof ScimFilterEvaluationResult.Succeeded
                || result instanceof ScimMembershipPatchResult.Reduced)
            return ScimObserver.Outcome.SUCCEEDED;
        return ScimObserver.Outcome.REJECTED;
    }

    private static @Nullable ScimFilterPolicy identityPolicy(
            @NonNull Map<@NonNull ScimResourceType, @NonNull ScimFilterPolicy> policies,
            @NonNull ScimResourceType type) {
        for (Map.Entry<ScimResourceType, ScimFilterPolicy> entry : policies.entrySet())
            if (same(entry.getKey(), type)) return entry.getValue();
        return null;
    }

    private static @NonNull URI base(@NonNull URI uri) {
        if (uri.toString().length() > Limits.SCIM_BASE_URI_LENGTH.getCap()
                || uri.toASCIIString().length() > Limits.SCIM_BASE_URI_LENGTH.getCap()
                || uri.getHost() == null
                || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || !uri.isAbsolute()
                || !("http".equals(AsciiCase.fold(uri.getScheme()))
                        || "https".equals(AsciiCase.fold(uri.getScheme()))))
            throw new IllegalArgumentException(
                    "SCIM base URI requires bounded absolute HTTP(S) without credentials, query or fragment.");
        String path = uri.getRawPath();
        if (path == null) throw new IllegalArgumentException("SCIM base URI requires a path.");
        if (!path.isEmpty() && !path.equals("/"))
            ScimSchemas.requireEndpoint(
                    path.endsWith("/") ? path.substring(0, path.length() - 1) : path);
        String text = uri.toASCIIString();
        if (!text.endsWith("/")) text += "/";
        if (text.length() > Limits.SCIM_BASE_URI_LENGTH.getCap())
            throw new IllegalArgumentException("SCIM canonical base URI exceeds its bound.");
        return URI.create(text);
    }

    private static @NonNull List<@NonNull ScimSchema> registrations(
            @NonNull List<@NonNull ScimResourceType> types) {
        Set<String> names = new LinkedHashSet<>(),
                endpoints = new LinkedHashSet<>(),
                ids = new LinkedHashSet<>();
        LinkedHashMap<String, ScimSchema> all = new LinkedHashMap<>();
        List<ScimSchema> reserved =
                List.of(
                        ScimSchema.userInstance(),
                        ScimSchema.groupInstance(),
                        ScimSchema.enterpriseUserInstance(),
                        ScimSchema.serviceProviderConfigInstance(),
                        ScimSchema.resourceTypeInstance(),
                        ScimSchema.schemaInstance());
        for (ScimResourceType type : types) {
            if (type.getName().equals("Schema")
                    || type.getName().equals("ResourceType")
                    || type.getName().equals("ServiceProviderConfig"))
                throw new IllegalArgumentException(
                        "SCIM application type collides with a discovery type.");
            for (String discovery : List.of("/Schemas", "/ResourceTypes", "/ServiceProviderConfig"))
                if (type.getEndpoint().equals(discovery)
                        || type.getEndpoint().startsWith(discovery + "/"))
                    throw new IllegalArgumentException(
                            "SCIM application endpoint collides with discovery.");
            if (!names.add(type.getName())
                    || !endpoints.add(type.getEndpoint())
                    || type.getId().isPresent() && !ids.add(type.getId().get()))
                throw new IllegalArgumentException("Duplicate SCIM resource registration.");
            for (ScimSchema schema : ScimSchemas.allSchemas(type)) {
                for (ScimSchema builtin : reserved)
                    if (AsciiCase.fold(schema.getId()).equals(AsciiCase.fold(builtin.getId()))
                            && !schema.equals(builtin))
                        throw new IllegalArgumentException(
                                "Reserved SCIM schema identifier has contradictory characteristics.");
                String key = AsciiCase.fold(schema.getId());
                ScimSchema previous = all.putIfAbsent(key, schema);
                if (previous != null && !previous.equals(schema))
                    throw new IllegalArgumentException(
                            "SCIM schema identifier has conflicting definitions.");
                if (previous == null) {
                    if (all.size() > Limits.SCIM_SCHEMAS.getCap())
                        throw new IllegalArgumentException(
                                "SCIM registration exceeds its schema bound.");
                }
            }
        }
        return List.copyOf(all.values());
    }

    private static final class DiscoveryTypes {
        static final @NonNull ScimResourceType CONFIG =
                ScimResourceType.discovery(
                        ScimSchema.serviceProviderConfigInstance(),
                        "ServiceProviderConfig",
                        "/ServiceProviderConfig");
        static final @NonNull ScimResourceType TYPE =
                ScimResourceType.discovery(
                        ScimSchema.resourceTypeInstance(), "ResourceType", "/ResourceTypes");
        static final @NonNull ScimResourceType SCHEMA =
                ScimResourceType.discovery(ScimSchema.schemaInstance(), "Schema", "/Schemas");
    }

    /** Mutable complete provider configuration; null restores each documented default.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @Nullable URI baseUri;
        private @NonNull List<@NonNull ScimResourceType> resourceTypes = List.of();
        private @Nullable ScimServiceProviderConfig serviceProviderConfig;
        private @NonNull Map<@NonNull ScimResourceType, @NonNull ScimFilterPolicy> filterPolicies =
                Map.of();
        private @Nullable ScimCompatibility compatibility;
        private @Nullable ScimStringMatching stringMatching;
        private @Nullable ScimLimits limits;
        private @Nullable ScimObserver observer;

        private Builder() {}

        /** Replaces the value; null restores required base URI to unset.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder baseUri(@Nullable URI value) {
            baseUri = value;
            return this;
        }

        /** Replaces the value; null restores complete registrations to empty.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder resourceTypes(@Nullable List<@NonNull ScimResourceType> value) {
            if (value != null && value.size() > Limits.SCIM_RESOURCE_TYPES.getCap())
                throw new IllegalArgumentException("SCIM resource type count exceeds its bound.");
            resourceTypes = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        /** Replaces the value; null restores capabilities to fresh defaults.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder serviceProviderConfig(@Nullable ScimServiceProviderConfig value) {
            serviceProviderConfig = value;
            return this;
        }

        /** Replaces the value; null restores complete policies to empty.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder filterPolicies(
                @Nullable Map<@NonNull ScimResourceType, @NonNull ScimFilterPolicy> value) {
            if (value != null && value.size() > Limits.SCIM_RESOURCE_TYPES.getCap())
                throw new IllegalArgumentException(
                        "SCIM policy registration count exceeds its bound.");
            filterPolicies = value == null ? Map.of() : Map.copyOf(value);
            return this;
        }

        /** Replaces the value; null restores features to strict.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder compatibility(@Nullable ScimCompatibility value) {
            compatibility = value;
            return this;
        }

        /** Replaces the value; null restores strategy to absent.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder stringMatching(@Nullable ScimStringMatching value) {
            stringMatching = value;
            return this;
        }

        /** Replaces the value; null restores processing limits to fresh defaults.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder limits(@Nullable ScimLimits value) {
            limits = value;
            return this;
        }

        /** Replaces the value; null restores observer to disabled.
         * @param value complete replacement, or null for the stated default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder observer(@Nullable ScimObserver value) {
            observer = value;
            return this;
        }

        /** Snapshots and validates registration, capabilities and all bound policies without callbacks.
         * @return an immutable provider
         * @since 1.0.0
         */
        public @NonNull ScimServiceProvider build() {
            return new ScimServiceProvider(this, null);
        }
    }

    /** Mutable provider copy. Null restores the corresponding source value.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Copier {
        private final @NonNull ScimServiceProvider source;
        private @Nullable URI baseUri;
        private @Nullable ScimCompatibility compatibility;

        private Copier(@NonNull ScimServiceProvider source) {
            this.source = source;
        }

        /** Replaces trusted base URI; null restores the source.
         * @param value new trusted base URI, or null
         * @return this copier
         * @since 1.0.0
         */
        public @NonNull Copier baseUri(@Nullable URI value) {
            baseUri = value;
            return this;
        }

        /** Replaces explicit features; null restores the source.
         * @param value new compatibility, or null
         * @return this copier
         * @since 1.0.0
         */
        public @NonNull Copier compatibility(@Nullable ScimCompatibility value) {
            compatibility = value;
            return this;
        }

        /** Validates a new snapshot without callbacks, retaining semantic context only for unchanged features.
         * @return the copied provider
         * @since 1.0.0
         */
        public @NonNull ScimServiceProvider finish() {
            ScimCompatibility selected =
                    compatibility == null ? source.compatibility : compatibility;
            Builder builder =
                    builder()
                            .baseUri(baseUri == null ? source.baseUri : baseUri)
                            .resourceTypes(source.resourceTypes)
                            .serviceProviderConfig(source.serviceProviderConfig)
                            .filterPolicies(source.filterPolicies)
                            .compatibility(selected)
                            .stringMatching(source.stringMatching)
                            .limits(source.limits)
                            .observer(source.observer);
            return new ScimServiceProvider(
                    builder, selected.equals(source.compatibility) ? source.semanticContext : null);
        }
    }
}
