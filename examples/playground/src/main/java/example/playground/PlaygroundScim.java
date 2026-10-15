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
package example.playground;

import com.revetsec.json.*;
import com.revetsec.scim.*;
import com.revetsec.soklet.SokletScim;
import com.revetsec.soklet.SokletRequestResult;
import com.soklet.Request;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Bounded synthetic provisioning application. The lock is the local transaction boundary.
 * Core candidates never imply authorization or successful commit. This store is not durable. */
public final class PlaygroundScim {
    static final int MAXIMUM_RESOURCES = 128;
    final ScimServiceProvider provider;
    private final ScimFilterEvaluator evaluator;
    private final String bearer;
    private final Clock clock;
    private final Authorizer authorizer;
    private final Map<String, ScimResource> users = new LinkedHashMap<>(), groups = new LinkedHashMap<>();
    private final Map<String, Password> credentials = new HashMap<>();
    private long sequence;
    private Fault nextFault = Fault.NONE;
    private CommitOutcome lastOutcome = CommitOutcome.NONE;
    enum Fault { NONE, BEFORE_COMMIT_UNAVAILABLE, BEFORE_COMMIT_CONFLICT, ACKNOWLEDGEMENT_LOST }
    enum CommitOutcome { NONE, CONFIRMED, CONFLICT, UNAVAILABLE, UNKNOWN }
    interface Authorizer {
        boolean allows(@NonNull String operation, @Nullable ScimResource current, @Nullable ScimResource candidate,
                @NonNull Set<@NonNull ScimAttributePath> attempted, @NonNull Set<@NonNull ScimAttributePath> effective);
    }
    @NonNull PlaygroundScim(@NonNull ScimServiceProvider provider, @NonNull String bearer, @NonNull Clock clock, @NonNull Authorizer authorizer) {
        if (bearer.length() < 32 || bearer.length() > 256 || !ascii(bearer, false))
            throw new IllegalArgumentException("SCIM requires a private bounded ASCII bearer credential.");
        this.provider = provider; this.evaluator = ScimFilterEvaluator.fromServiceProvider(provider);
        this.bearer = bearer; this.clock = clock; this.authorizer = authorizer;
    }
    static @NonNull PlaygroundScim create(@NonNull URI baseUri, @NonNull String bearer) {
        return new PlaygroundScim(provider(baseUri, ScimLimits.builder().maximumBodyBytes(16_384).build()),
                bearer, Clock.systemUTC(), (operation, current, candidate, attempted, effective) -> true);
    }
    static @NonNull ScimServiceProvider provider(@NonNull URI baseUri, @NonNull ScimLimits limits) {
        Set<ScimComparisonOperator> strings = Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.NE,
                ScimComparisonOperator.CO, ScimComparisonOperator.SW, ScimComparisonOperator.EW);
        Set<ScimLogicalOperator> logical = Set.of(ScimLogicalOperator.AND, ScimLogicalOperator.OR, ScimLogicalOperator.NOT);
        ScimFilterPolicy email = ScimFilterPolicy.builder().allowedComparisons(Map.of("value", strings, "type", strings))
                .allowedPresence(Set.of("value", "type")).allowedLogicalOperators(logical).build();
        ScimFilterPolicy member = ScimFilterPolicy.builder().allowedComparisons(Map.of("value", Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.NE)))
                .allowedPresence(Set.of("value")).allowedLogicalOperators(logical).build();
        Map<String, Set<ScimComparisonOperator>> userPaths = new LinkedHashMap<>();
        for (String path : List.of("id", "externalId", "userName", "displayName", "name.givenName", "name.familyName", "emails.value", "emails.type")) userPaths.put(path, strings);
        userPaths.put("active", Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.NE));
        ScimFilterPolicy userPolicy = ScimFilterPolicy.builder().allowedComparisons(userPaths)
                .allowedPresence(userPaths.keySet()).allowedLogicalOperators(logical).allowedValuePaths(Map.of("emails", email)).build();
        ScimFilterPolicy groupPolicy = ScimFilterPolicy.builder().allowedComparisons(Map.of("id", strings, "externalId", strings,
                "displayName", strings, "members.value", Set.of(ScimComparisonOperator.EQ, ScimComparisonOperator.NE)))
                .allowedPresence(Set.of("id", "externalId", "displayName", "members.value"))
                .allowedLogicalOperators(logical).allowedValuePaths(Map.of("members", member)).build();
        return ScimServiceProvider.builder().baseUri(baseUri)
                .resourceTypes(List.of(ScimResourceType.userInstance(), ScimResourceType.groupInstance()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).patchSupported(true).etagSupported(true).changePasswordSupported(true).build())
                .filterPolicies(Map.of(ScimResourceType.userInstance(), userPolicy, ScimResourceType.groupInstance(), groupPolicy))
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build())
                .stringMatching(PlaygroundScim::matchAsciiFixture).limits(limits).build();
    }
    /** Fixture only: deliberate ASCII matching, not a Unicode/PRECIS implementation. */
    private static @NonNull ScimStringMatchResult matchAsciiFixture(@NonNull ScimAttributePath path,
            @NonNull ScimAttributeDefinition definition, @NonNull ScimComparisonOperator operator,
            @NonNull String value, @NonNull String literal) {
        if (!ascii(value, true) || !ascii(literal, true)) return ScimStringMatchResult.unsupportedInstance();
        boolean exactIdentity = path.getAttributeName().equals("id")
                || path.getAttributeName().equals("members") && path.getSubAttributeName().orElse("").equals("value");
        String left = definition.isCaseExact() || exactIdentity ? value : fold(value), right = definition.isCaseExact() || exactIdentity ? literal : fold(literal);
        boolean result = switch (operator) {
            case EQ -> left.equals(right); case NE -> !left.equals(right); case CO -> left.contains(right);
            case SW -> left.startsWith(right); case EW -> left.endsWith(right); case GT -> left.compareTo(right) > 0;
            case GE -> left.compareTo(right) >= 0; case LT -> left.compareTo(right) < 0; case LE -> left.compareTo(right) <= 0;
        };
        return ScimStringMatchResult.fromMatched(result);
    }
    boolean authenticated(@NonNull Request request) {
        List<String> headers = new ArrayList<>();
        request.getHeaders().forEach((name, values) -> { if (fold(name).equals("authorization")) headers.addAll(values); });
        if (headers.size() != 1) return false;
        String expected = "Bearer " + bearer, actual = headers.get(0);
        if (actual.length() != expected.length()) return false;
        int difference = 0;
        for (int index = 0; index < expected.length(); ++index) difference |= expected.charAt(index) ^ actual.charAt(index);
        return difference == 0;
    }
    synchronized @NonNull ScimResponse list(@NonNull ScimResourceType type, @NonNull Request request, boolean search) {
        ScimQueryParseResult parsed;
        if (search) {
            var read = SokletScim.searchRequestResultFor(provider, type, request);
            if (!(read instanceof SokletRequestResult.Completed<ScimQueryParseResult> completed))
                return error(ScimError.requestTooLargeInstance());
            parsed = completed.getResult();
        } else parsed = SokletScim.queryResultFor(provider, type, request);
        if (parsed instanceof ScimQueryParseResult.Rejected rejected) return error(rejected.getError());
        ScimQuery query = ((ScimQueryParseResult.Succeeded) parsed).getQuery();
        List<ScimResource> matched = new ArrayList<>();
        for (ScimResource resource : map(type).values()) {
            if (query.getFilter().isPresent()) {
                ScimFilterEvaluationResult result = evaluator.evaluateResult(resource, query.getFilter().orElseThrow());
                if (result instanceof ScimFilterEvaluationResult.Rejected rejected) return error(rejected.getError());
                if (!((ScimFilterEvaluationResult.Succeeded) result).isMatched()) continue;
            }
            matched.add(resource);
        }
        int start = (int) Math.min(matched.size(), query.getStartIndex().orElse(1L) - 1), end = Math.min(matched.size(), start + query.getCount());
        return prepared(provider.listResponseResult(ScimListPage.withQuery(query).totalResults((long) matched.size()).resources(matched.subList(start, end)).build()));
    }
    synchronized @NonNull ScimResponse get(@NonNull ScimResourceType type, @NonNull String id, @NonNull Request request) {
        ScimResource current = map(type).get(id);
        if (current == null) return error(ScimError.notFoundInstance());
        ScimAttributeSelectionResult selected = SokletScim.attributeSelectionResultFor(provider, type, request);
        if (selected instanceof ScimAttributeSelectionResult.Rejected rejected) return error(rejected.getError());
        ScimIfNoneMatchResult conditional = SokletScim.ifNoneMatchResultFor(provider, current, request);
        if (conditional instanceof ScimIfNoneMatchResult.Rejected rejected) return error(rejected.getError());
        if (conditional instanceof ScimIfNoneMatchResult.NotModified) return prepared(provider.notModifiedResponseResult(current));
        return prepared(provider.resourceResponseResult(current, ((ScimAttributeSelectionResult.Succeeded) selected).getAttributeSelection()));
    }
    synchronized @NonNull ScimResponse create(@NonNull ScimResourceType type, @NonNull Request request) {
        lastOutcome = CommitOutcome.NONE;
        var read = SokletScim.resourceResultFor(provider, type, request);
        if (!(read instanceof SokletRequestResult.Completed<ScimResourceParseResult> completed))
            return error(ScimError.requestTooLargeInstance());
        ScimResourceParseResult parsed = completed.getResult();
        if (parsed instanceof ScimResourceParseResult.Rejected rejected) return error(rejected.getError());
        ScimResourceParseResult.Succeeded accepted = (ScimResourceParseResult.Succeeded) parsed;
        ScimResource candidate = accepted.getResource(); Set<ScimAttributePath> attempted = accepted.getSuppliedAttributePaths();
        if (!authorizer.allows("CREATE", null, candidate, attempted, attempted)) return error(ScimError.forbiddenInstance());
        PasswordChange password = password(candidate, null, attempted);
        if (password.invalid) return error(ScimError.invalidValueInstance());
        candidate = withoutPassword(candidate);
        ScimError invalid = integrity(candidate, null); if (invalid != null) return error(invalid);
        if (users.size() + groups.size() >= MAXIMUM_RESOURCES) return error(ScimError.unavailableInstance());
        ScimAttributeSelectionResult selected = SokletScim.attributeSelectionResultFor(provider, type, request);
        if (selected instanceof ScimAttributeSelectionResult.Rejected rejected) return error(rejected.getError());
        String id = (type == ScimResourceType.userInstance() ? "u-" : "g-") + (sequence + 1);
        Instant now = clock.instant(); candidate = metadata(candidate, id, 1, now, now);
        ScimResponseResult response = provider.createdResponseResult(candidate, attempted, ((ScimAttributeSelectionResult.Succeeded) selected).getAttributeSelection());
        if (response instanceof ScimResponseResult.Rejected rejected) return error(rejected.getError());
        Map<String, ScimResource> replacement = new LinkedHashMap<>(map(type)); replacement.put(id, candidate);
        return commit(type, replacement, ((ScimResponseResult.Prepared) response).getResponse(), true, id, password);
    }
    synchronized @NonNull ScimResponse write(@NonNull ScimResourceType type, @NonNull String id, @NonNull Request request, boolean patch) {
        lastOutcome = CommitOutcome.NONE;
        ScimResource current = map(type).get(id); if (current == null) return error(ScimError.notFoundInstance());
        ScimIfMatchResult conditional = SokletScim.ifMatchResultFor(provider, current, request);
        if (conditional instanceof ScimIfMatchResult.Rejected rejected) return error(rejected.getError());
        ScimResource candidate; Set<ScimAttributePath> attempted, effective, supplied; boolean changed;
        if (patch) {
            var read = SokletScim.patchRequestResultFor(provider, type, request);
            if (!(read instanceof SokletRequestResult.Completed<ScimPatchParseResult> completed))
                return error(ScimError.requestTooLargeInstance());
            ScimPatchParseResult parsed = completed.getResult();
            if (parsed instanceof ScimPatchParseResult.Rejected rejected) return error(rejected.getError());
            ScimPatchApplicationResult applied = provider.applyPatchResult(current, ((ScimPatchParseResult.Succeeded) parsed).getPatchRequest());
            if (applied instanceof ScimPatchApplicationResult.Rejected rejected) return error(rejected.getError());
            ScimPatchResult result = ((ScimPatchApplicationResult.Succeeded) applied).getPatchResult();
            candidate = result.getResource(); attempted = result.getRequestedAttributePaths(); effective = result.getModifiedAttributePaths();
            supplied = result.getSuppliedAttributePaths(); changed = result.isModified();
        } else {
            var read = SokletScim.replacementResultFor(provider, type, current, request);
            if (!(read instanceof SokletRequestResult.Completed<ScimResourceParseResult> completed))
                return error(ScimError.requestTooLargeInstance());
            ScimResourceParseResult parsed = completed.getResult();
            if (parsed instanceof ScimResourceParseResult.Rejected rejected) return error(rejected.getError());
            ScimResourceParseResult.Succeeded result = (ScimResourceParseResult.Succeeded) parsed;
            candidate = result.getResource(); supplied = result.getSuppliedAttributePaths();
            // PUT omission clears writable data: authorize the complete before/after set, also for no-ops.
            attempted = allDataPaths(current, candidate); effective = attempted; changed = !current.getDocument().equals(candidate.getDocument());
        }
        PasswordChange password = password(candidate, id, patch ? attempted : supplied);
        if (password.invalid) return error(ScimError.invalidValueInstance());
        Set<ScimAttributePath> actual = new LinkedHashSet<>(effective); actual.remove(path("password"));
        if (password.changed) actual.add(path("password"));
        effective = Set.copyOf(actual);
        if (!authorizer.allows(patch ? "PATCH" : "PUT", current, candidate, attempted, effective)) return error(ScimError.forbiddenInstance());
        candidate = withoutPassword(candidate);
        changed = !candidate.getDocument().equals(current.getDocument()) || password.changed;
        ScimError invalid = integrity(candidate, id); if (invalid != null) return error(invalid);
        ScimAttributeSelectionResult selected = SokletScim.attributeSelectionResultFor(provider, type, request);
        if (selected instanceof ScimAttributeSelectionResult.Rejected rejected) return error(rejected.getError());
        if (changed) candidate = metadata(candidate, id, version(current) + 1, current.getCreated().orElseThrow(), clock.instant());
        ScimAttributeSelection selection = ((ScimAttributeSelectionResult.Succeeded) selected).getAttributeSelection();
        ScimResponseResult response = patch ? provider.patchResponseResult(candidate, supplied, selection) : provider.replacementResponseResult(candidate, supplied, selection);
        if (response instanceof ScimResponseResult.Rejected rejected) return error(rejected.getError());
        if (!changed) { lastOutcome = CommitOutcome.CONFIRMED; return ((ScimResponseResult.Prepared) response).getResponse(); }
        Map<String, ScimResource> replacement = new LinkedHashMap<>(map(type)); replacement.put(id, candidate);
        return commit(type, replacement, ((ScimResponseResult.Prepared) response).getResponse(), false, id, password);
    }
    synchronized @NonNull ScimResponse delete(@NonNull ScimResourceType type, @NonNull String id, @NonNull Request request) {
        lastOutcome = CommitOutcome.NONE;
        ScimResource current = map(type).get(id); if (current == null) return error(ScimError.notFoundInstance());
        ScimIfMatchResult conditional = SokletScim.ifMatchResultFor(provider, current, request);
        if (conditional instanceof ScimIfMatchResult.Rejected rejected) return error(rejected.getError());
        Set<ScimAttributePath> deleted = new LinkedHashSet<>(allDataPaths(current));
        if (credentials.containsKey(id)) deleted.add(path("password"));
        if (!authorizer.allows("DELETE", current, null, Set.copyOf(deleted), Set.copyOf(deleted))) return error(ScimError.forbiddenInstance());
        // Remove incoming membership references before deleting either kind of resource.
        for (ScimResource group : groups.values()) if (memberIds(group).contains(id)) return error(ScimError.invalidValueInstance());
        if (type == ScimResourceType.userInstance()) for (ScimResource user : users.values()) {
            JsonObject extension = user.getExtension("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User").orElse(JsonObject.emptyInstance());
            JsonValue rawManager = extension.getMembers().get("manager");
            if (rawManager instanceof JsonObject manager && (manager.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse("").equals(id)
                    || manager.find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).map(value -> provider.getBaseUri().resolve(URI.create(value)).equals(provider.resourceLocationFor(type, id))).orElse(false)))
                return error(ScimError.invalidValueInstance());
        }
        Map<String, ScimResource> replacement = new LinkedHashMap<>(map(type)); replacement.remove(id);
        return commit(type, replacement, provider.noContentResponse(), false, id, new PasswordChange(credentials.containsKey(id), false, null));
    }
    private @NonNull ScimResponse commit(@NonNull ScimResourceType type, @NonNull Map<@NonNull String, @NonNull ScimResource> replacement, @NonNull ScimResponse response, boolean created, @NonNull String id, @NonNull PasswordChange password) {
        Fault fault = nextFault; nextFault = Fault.NONE;
        if (fault == Fault.BEFORE_COMMIT_UNAVAILABLE) { lastOutcome = CommitOutcome.UNAVAILABLE; return error(ScimError.unavailableInstance()); }
        if (fault == Fault.BEFORE_COMMIT_CONFLICT) { lastOutcome = CommitOutcome.CONFLICT; return error(ScimError.preconditionFailedInstance()); }
        map(type).clear(); map(type).putAll(replacement); if (created) ++sequence;
        if (password.changed) { if (password.value == null) credentials.remove(id); else credentials.put(id, password.value); }
        if (fault == Fault.ACKNOWLEDGEMENT_LOST) { lastOutcome = CommitOutcome.UNKNOWN; return error(ScimError.unavailableInstance()); }
        lastOutcome = CommitOutcome.CONFIRMED; return response;
    }
    private @Nullable ScimError integrity(@NonNull ScimResource candidate, @Nullable String currentId) {
        
        if (candidate.getResourceType() == ScimResourceType.userInstance()) {
            String name = candidate.getDocument().find("userName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow();
            if (name.length() > 128 || !ascii(name, false)) return ScimError.invalidValueInstance();
            JsonObject extension = candidate.getExtension("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User").orElse(JsonObject.emptyInstance());
            JsonValue rawManager = extension.getMembers().get("manager");
            if (rawManager instanceof JsonObject manager) {
                String managerId = manager.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse(null), reference = manager.find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse(null);
                if (managerId != null && !users.containsKey(managerId)) return ScimError.invalidValueInstance();
                if (reference != null) {
                    URI location = provider.getBaseUri().resolve(URI.create(reference));
                    String target = managerId;
                    if (target == null) for (String known : users.keySet())
                        if (provider.resourceLocationFor(ScimResourceType.userInstance(), known).equals(location)) { target = known; break; }
                    if (target == null || !provider.resourceLocationFor(ScimResourceType.userInstance(), target).equals(location)) return ScimError.invalidValueInstance();
                }
            }
            for (ScimResource other : users.values()) if (!other.getId().orElseThrow().equals(currentId) && fold(other.getDocument().find("userName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow()).equals(fold(name))) return ScimError.uniquenessInstance();
        } else {
            Set<String> ids = new HashSet<>(); JsonValue raw = candidate.getDocument().getMembers().get("members");
            if (raw instanceof JsonArray array) for (JsonValue element : array.getElements()) {
                JsonObject member = (JsonObject) element; String id = member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse("");
                ScimResourceType referenced = users.containsKey(id) ? ScimResourceType.userInstance()
                        : groups.containsKey(id) ? ScimResourceType.groupInstance() : null;
                if (id.isEmpty() || !ids.add(id) || referenced == null || !member.find("type").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse(referenced.getName()).equals(referenced.getName())) return ScimError.invalidValueInstance();
                if (member.find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).isPresent() && !provider.getBaseUri().resolve(URI.create(member.find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow()))
                        .equals(provider.resourceLocationFor(referenced, id))) return ScimError.invalidValueInstance();
            }
        }
        return null;
    }
    private @NonNull ScimResource metadata(@NonNull ScimResource candidate, @NonNull String id, long version, @NonNull Instant created, @NonNull Instant modified) {
        JsonObject meta = JsonObject.builder().put("resourceType", candidate.getResourceType().getName()).put("created", created.toString())
                .put("lastModified", modified.toString()).put("version", "W/\"" + version + "\"")
                .put("location", provider.resourceLocationFor(candidate.getResourceType(), id).toString()).build();
        Map<String, JsonValue> members = new LinkedHashMap<>(candidate.getDocument().getMembers()); members.put("id", JsonString.fromValue(id)); members.put("meta", meta);
        return candidate.copy().document(JsonObject.fromMembers(members)).finish();
    }
    private record Password(byte @NonNull [] salt, byte @NonNull [] digest) { }
    private record PasswordChange(boolean changed, boolean invalid, @Nullable Password value) { }
    private @NonNull PasswordChange password(@NonNull ScimResource candidate, @Nullable String id, @NonNull Set<@NonNull ScimAttributePath> supplied) {
        if (candidate.getResourceType() != ScimResourceType.userInstance() || supplied.stream().noneMatch(path -> path.getAttributeName().equals("password")))
            return new PasswordChange(false, false, null);
        String value = candidate.getDocument().find("password").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse(null);
        Password previous = id == null ? null : credentials.get(id);
        if (value == null) return new PasswordChange(previous != null, false, null);
        if (value.length() > 512) return new PasswordChange(false, true, null);
        byte[] salt = previous == null ? LocalSecrets.randomBytes() : previous.salt;
        char[] characters = value.toCharArray();
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(characters, salt, 20_000, 256);
        try {
            byte[] digest = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            if (previous != null && java.security.MessageDigest.isEqual(previous.digest, digest)) return new PasswordChange(false, false, null);
            return new PasswordChange(true, false, new Password(salt, digest));
        } catch (java.security.GeneralSecurityException unavailable) { throw new IllegalStateException("Fixture password preparation unavailable."); }
        finally { spec.clearPassword(); Arrays.fill(characters, '\0'); }
    }
    private static @NonNull ScimResource withoutPassword(@NonNull ScimResource candidate) {
        if (candidate.getDocument().find("password").isEmpty()) return candidate;
        Map<String, JsonValue> document = new LinkedHashMap<>(candidate.getDocument().getMembers()); document.remove("password");
        return candidate.copy().document(JsonObject.fromMembers(document)).finish();
    }
    private static long version(@NonNull ScimResource resource) { String value = resource.getVersion().orElseThrow(); return Long.parseLong(value.substring(3, value.length() - 1)); }
    private @NonNull Map<@NonNull String, @NonNull ScimResource> map(@NonNull ScimResourceType type) { return type == ScimResourceType.userInstance() ? users : groups; }
    private static @NonNull Set<@NonNull String> memberIds(@NonNull ScimResource group) {
        Set<String> ids = new HashSet<>(); JsonValue raw = group.getDocument().getMembers().get("members");
        if (raw instanceof JsonArray array) for (JsonValue value : array.getElements()) ((JsonObject) value).find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).ifPresent(ids::add); return ids;
    }
    private static @NonNull Set<@NonNull ScimAttributePath> allDataPaths(@NonNull ScimResource @NonNull ... resources) {
        Set<ScimAttributePath> paths = new LinkedHashSet<>();
        for (ScimResource resource : resources) for (Map.Entry<String, JsonValue> member : resource.getDocument().getMembers().entrySet()) {
            String name = member.getKey(); if (Set.of("id", "meta", "schemas").contains(name)) continue;
            boolean extension = resource.getResourceType().getSchemaExtensions().stream().anyMatch(value -> value.getSchema().getId().equals(name));
            if (extension && member.getValue() instanceof JsonObject object) {
                paths.add(path("schemas"));
                object.getMembers().forEach((attribute, value) -> dataPaths(paths, name + ":" + attribute, value));
            } else dataPaths(paths, name, member.getValue());
        }
        return Collections.unmodifiableSet(paths);
    }
    private static void dataPaths(@NonNull Set<@NonNull ScimAttributePath> paths, @NonNull String name, @NonNull JsonValue value) {
        paths.add(path(name));
        if (value instanceof JsonObject object) for (String child : object.getMembers().keySet()) paths.add(path(name + "." + child));
        else if (value instanceof JsonArray array) for (JsonValue element : array.getElements()) if (element instanceof JsonObject object)
            for (String child : object.getMembers().keySet()) paths.add(path(name + "." + child));
    }
    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return ((ScimAttributePathParseResult.Succeeded) ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
    @NonNull ScimResponse prepared(@NonNull ScimResponseResult result) { return result instanceof ScimResponseResult.Prepared accepted ? accepted.getResponse() : error(((ScimResponseResult.Rejected) result).getError()); }
    @NonNull ScimResponse error(@NonNull ScimError error) { return provider.errorResponse(error); }
    synchronized void failNext(@NonNull Fault fault) { nextFault = fault; }
    synchronized @NonNull CommitOutcome lastOutcome() { return lastOutcome; }
    synchronized @Nullable ScimResource snapshot(@NonNull ScimResourceType type, @NonNull String id) { return map(type).get(id); }
    private static boolean ascii(@NonNull String value, boolean spaces) { for (int index = 0; index < value.length(); ++index) if (value.charAt(index) < (spaces ? 32 : 33) || value.charAt(index) > 126) return false; return true; }
    private static @NonNull String fold(@NonNull String value) { StringBuilder folded = new StringBuilder(value.length()); for (int index = 0; index < value.length(); ++index) { char ch = value.charAt(index); folded.append(ch >= 'A' && ch <= 'Z' ? (char) (ch + 32) : ch); } return folded.toString(); }
}
