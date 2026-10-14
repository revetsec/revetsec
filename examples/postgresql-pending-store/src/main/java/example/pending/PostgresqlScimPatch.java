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
package example.pending;

import com.pyranid.*;
import com.revetsec.json.*;
import com.revetsec.scim.*;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Compiled application recipe for a deliberately small, durable SCIM storage profile.
 * One tenant lock serializes all resource/member writers on an authoritative PostgreSQL primary.
 * Authentication chooses this tenant before construction; request data never chooses it.
 * User fields: userName/displayName/active. Group fields: displayName/ordered ID-only members.
 * Unsupported fields reject rather than being silently lost. Full schemas need a host-owned codec. */
public final class PostgresqlScimPatch {
    public interface ConnectionSource { @NonNull Connection open(@NonNull Duration remaining) throws SQLException; }
    public interface Authorizer {
        boolean allows(@NonNull ScimResource current, @NonNull ScimResource candidate,
                @NonNull Set<@NonNull ScimAttributePath> attempted, @NonNull Set<@NonNull ScimAttributePath> effective);
    }
    public sealed interface Outcome permits Ready, Rejected, Unavailable, Unknown { }
    public record Ready(@NonNull ScimResponse response) implements Outcome { }
    public record Rejected(@NonNull ScimError error) implements Outcome { }
    public enum Unavailable implements Outcome { INSTANCE }
    public enum Unknown implements Outcome { INSTANCE }
    private final @NonNull String tenant;
    private final @NonNull ConnectionSource source;
    private final @NonNull ScimServiceProvider provider;
    private final @NonNull Clock clock;
    public PostgresqlScimPatch(@NonNull String tenant, @NonNull ConnectionSource source,
            @NonNull ScimServiceProvider provider, @NonNull Clock clock) {
        if (tenant.isEmpty() || tenant.length() > 128) throw new IllegalArgumentException("Invalid application tenant.");
        this.tenant = tenant; this.source = source; this.provider = provider; this.clock = clock;
    }
    /** The host parses raw body/selection before entering here and emits Ready only after this method returns.
     * Expected rejection, definite unavailability and uncertain writes are distinct. Never replay Unknown. */
    public @NonNull Outcome patch(@NonNull ScimResourceType type, @NonNull String id,
            @NonNull ScimPatchRequest patch, @NonNull List<@NonNull String> ifMatch,
            @NonNull ScimAttributeSelection selection, @NonNull Authorizer authorizer, @NonNull Duration remaining) {
        if (type != ScimResourceType.userInstance() && type != ScimResourceType.groupInstance())
            throw new IllegalArgumentException("The durable fixture stores only its built-in profiles.");
        if (remaining.isNegative() || remaining.isZero() || Thread.currentThread().isInterrupted()) return Unavailable.INSTANCE;
        Duration capped = remaining.compareTo(Duration.ofSeconds(30)) > 0 ? Duration.ofSeconds(30) : remaining;
        long deadline = System.nanoTime() + capped.toNanos();
        Completion completion = new Completion();
        try {
            Database database = Database.withDataSource(new PostgresqlPyranidDataSource(source::open, deadline)).databaseType(DatabaseType.POSTGRESQL).build();
            Optional<Outcome> result = database.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
                database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
                bound(database, deadline);
                database.query("SELECT set_config('synchronous_commit','on',true)").fetchObject(String.class).orElseThrow();
                bound(database, deadline);
                if (!database.query("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on'").fetchObject(Boolean.class).orElseThrow())
                    throw new SQLException("An authoritative durable primary is required.");
                bound(database, deadline);
                if (database.query("SELECT 1 FROM scim_fixture_tenant WHERE tenant=:tenant FOR UPDATE").bind("tenant", tenant).fetchObject(Integer.class).isEmpty())
                    throw new SQLException("The tenant must be provisioned before serving requests.");
                bound(database, deadline);
                Optional<Row> row = database.query("SELECT id,kind,user_name,display_name,active,version,created,modified FROM scim_fixture_resource WHERE tenant=:tenant AND id=:id AND kind=:kind FOR UPDATE")
                        .bind("tenant", tenant).bind("id", id).bind("kind", type.getName()).fetchObject(Row.class);
                if (row.isEmpty()) return Optional.of(new Rejected(ScimError.notFoundInstance()));
                ScimResource current = load(database, type, row.orElseThrow(), deadline);
                ScimIfMatchResult precondition = provider.checkIfMatchResult(ifMatch, current);
                if (precondition instanceof ScimIfMatchResult.Rejected rejected) return Optional.of(new Rejected(rejected.getError()));
                ScimPatchApplicationResult applied = provider.applyPatchResult(current, patch);
                if (applied instanceof ScimPatchApplicationResult.Rejected rejected) return Optional.of(new Rejected(rejected.getError()));
                ScimPatchResult changed = ((ScimPatchApplicationResult.Succeeded) applied).getPatchResult();
                ScimResource candidate = changed.getResource();
                if (type == ScimResourceType.groupInstance() && candidate.getDocument().find("members").isEmpty()) {
                    Map<String, JsonValue> canonical = new LinkedHashMap<>(candidate.getDocument().getMembers());
                    canonical.put("members", JsonArray.fromElements(List.of()));
                    candidate = candidate.copy().document(JsonObject.fromMembers(canonical)).finish();
                }
                boolean modified = !candidate.getDocument().equals(current.getDocument());
                if (!authorizer.allows(current, candidate, changed.getRequestedAttributePaths(), changed.getModifiedAttributePaths()))
                    return Optional.of(new Rejected(ScimError.forbiddenInstance()));
                ScimError invalid = profile(candidate);
                if (invalid != null) return Optional.of(new Rejected(invalid));
                List<String> members = memberIds(candidate);
                if (type == ScimResourceType.groupInstance()) for (String member : members) {
                    bound(database, deadline);
                    if (database.query("SELECT 1 FROM scim_fixture_resource WHERE tenant=:tenant AND id=:id AND kind='User'").bind("tenant", tenant).bind("id", member).fetchObject(Integer.class).isEmpty())
                        return Optional.of(new Rejected(ScimError.invalidValueInstance()));
                }
                if (type == ScimResourceType.userInstance()) {
                    bound(database, deadline);
                    if (database.query("SELECT 1 FROM scim_fixture_resource WHERE tenant=:tenant AND kind='User' AND name_key=:name AND id<>:id")
                            .bind("tenant", tenant).bind("name", asciiFold(candidate.getDocument().findString("userName").orElseThrow())).bind("id", id).fetchObject(Integer.class).isPresent())
                        return Optional.of(new Rejected(ScimError.uniquenessInstance()));
                }
                long version = row.orElseThrow().version();
                if (modified) candidate = metadata(candidate, Math.addExact(version, 1), row.orElseThrow().created(), clock.instant().truncatedTo(ChronoUnit.MICROS).toString());
                ScimResponseResult response = provider.patchResponseResult(candidate, changed.getSuppliedAttributePaths(), selection);
                if (response instanceof ScimResponseResult.Rejected rejected) return Optional.of(new Rejected(rejected.getError()));
                if (modified) {
                    bound(database, deadline); completion.attemptedWrite = true;
                    JsonObject document = candidate.getDocument();
                    long count = database.query("UPDATE scim_fixture_resource SET user_name=:name,name_key=:key,display_name=:display,active=:active,version=:next,modified=:modified WHERE tenant=:tenant AND id=:id AND version=:previous")
                            .bind("name", document.findString("userName").orElse(null)).bind("key", document.findString("userName").map(PostgresqlScimPatch::asciiFold).orElse(null))
                            .bind("display", document.findString("displayName").orElse(null)).bind("active", document.findBoolean("active").orElse(null))
                            .bind("next", version + 1).bind("modified", candidate.getLastModified().orElseThrow().toString())
                            .bind("tenant", tenant).bind("id", id).bind("previous", version).execute();
                    if (count != 1) throw new SQLException("The locked version changed unexpectedly.");
                    if (type == ScimResourceType.groupInstance()) {
                        bound(database, deadline);
                        database.query("DELETE FROM scim_fixture_member WHERE tenant=:tenant AND group_id=:group").bind("tenant", tenant).bind("group", id).execute();
                        int position = 0;
                        for (String member : members) {
                            bound(database, deadline);
                            database.query("INSERT INTO scim_fixture_member(tenant,group_id,ordinal,user_id) VALUES(:tenant,:group,:ordinal,:user)")
                                    .bind("tenant", tenant).bind("group", id).bind("ordinal", position++).bind("user", member).execute();
                        }
                    }
                }
                bound(database, deadline);
                return Optional.of(new Ready(((ScimResponseResult.Prepared) response).getResponse()));
            });
            if (completion.result == TransactionResult.COMMITTED && deadline - System.nanoTime() > 0 && !Thread.currentThread().isInterrupted())
                return result.orElseThrow();
        } catch (RuntimeException failure) {
            // Exception text and SQL values never enter protocol diagnostics. Fatal VM errors escape.
        }
        return completion.attemptedWrite && completion.result != TransactionResult.ROLLED_BACK ? Unknown.INSTANCE : Unavailable.INSTANCE;
    }
    private @NonNull ScimResource load(@NonNull Database database, @NonNull ScimResourceType type, @NonNull Row row, long deadline) throws SQLException {
        JsonObject.Builder document = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId())))).put("id", row.id());
        if (row.userName() != null) document.put("userName", row.userName());
        if (row.displayName() != null) document.put("displayName", row.displayName());
        if (row.active() != null) document.put("active", row.active());
        if (type == ScimResourceType.groupInstance()) {
            bound(database, deadline);
            List<Member> members = database.query("SELECT user_id FROM scim_fixture_member WHERE tenant=:tenant AND group_id=:group ORDER BY ordinal LIMIT 129")
                    .bind("tenant", tenant).bind("group", row.id()).fetchList(Member.class);
            if (members.size() > 128) throw new SQLException("The durable membership profile exceeds capacity.");
            List<JsonValue> values = new ArrayList<>(); for (Member member : members) values.add(JsonObject.builder().put("value", member.userId()).build());
            // Storage profile canonicalizes absent membership as an explicit empty sequence.
            document.put("members", JsonArray.fromElements(values));
        }
        ScimResource resource = ScimResource.withResourceType(type).document(document.build()).build();
        return metadata(resource, row.version(), row.created(), row.modified());
    }
    private @NonNull ScimResource metadata(@NonNull ScimResource candidate, long version, @NonNull String created, @NonNull String modified) {
        Map<String, JsonValue> document = new LinkedHashMap<>(candidate.getDocument().getMembers());
        document.put("meta", JsonObject.builder().put("resourceType", candidate.getResourceType().getName()).put("created", created).put("lastModified", modified)
                .put("version", "W/\"" + version + "\"").put("location", provider.resourceLocationFor(candidate.getResourceType(), candidate.getId().orElseThrow()).toString()).build());
        return candidate.copy().document(JsonObject.fromMembers(document)).finish();
    }
    private static @Nullable ScimError profile(@NonNull ScimResource resource) {
        Set<String> allowed = resource.getResourceType() == ScimResourceType.userInstance() ? Set.of("schemas", "id", "meta", "userName", "displayName", "active") : Set.of("schemas", "id", "meta", "displayName", "members");
        if (!allowed.containsAll(resource.getDocument().getMembers().keySet())) return ScimError.invalidValueInstance();
        for (String name : List.of("userName", "displayName")) if (resource.getDocument().findString(name).isPresent()) {
            String value = resource.getDocument().findString(name).orElseThrow();
            if (value.length() > 256 || !printableAscii(value)) return ScimError.invalidValueInstance();
        }
        List<String> ids = memberIds(resource); if (ids.size() > 128 || new HashSet<>(ids).size() != ids.size()) return ScimError.invalidValueInstance();
        JsonValue raw = resource.getDocument().getMembers().get("members");
        if (raw instanceof JsonArray array) for (JsonValue element : array.getElements()) {
            JsonObject member = (JsonObject) element;
            if (!member.getMembers().keySet().equals(Set.of("value")) || member.findString("value").orElse("").isEmpty()) return ScimError.invalidValueInstance();
        }
        return null;
    }
    private static @NonNull List<@NonNull String> memberIds(@NonNull ScimResource resource) {
        List<String> ids = new ArrayList<>(); JsonValue value = resource.getDocument().getMembers().get("members");
        if (value instanceof JsonArray array) for (JsonValue member : array.getElements()) ((JsonObject) member).findString("value").ifPresent(ids::add);
        return List.copyOf(ids);
    }
    private static boolean printableAscii(@NonNull String value) { for (int index = 0; index < value.length(); ++index) if (value.charAt(index) < 32 || value.charAt(index) > 126) return false; return true; }
    private static @NonNull String asciiFold(@NonNull String value) { StringBuilder result = new StringBuilder(value.length()); for (int index = 0; index < value.length(); ++index) { char ch = value.charAt(index); result.append(ch >= 'A' && ch <= 'Z' ? (char) (ch + 32) : ch); } return result.toString(); }
    private static void bound(@NonNull Database database, long deadline) throws SQLException { PostgresqlPyranidDataSource.bound(database, deadline); }
    public record Row(@NonNull String id, @NonNull String kind, @Nullable String userName, @Nullable String displayName, @Nullable Boolean active, long version, @NonNull String created, @NonNull String modified) { }
    public record Member(@NonNull String userId) { }
    private static final class Completion { private @Nullable TransactionResult result; private boolean attemptedWrite; }
    @Override public @NonNull String toString() { return "PostgresqlScimPatch{storage=<redacted>}"; }
}
