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

import com.revetsec.scim.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Test-only exact profile probe against a real PostgreSQL primary. No data or credentials are printed. */
public final class ScimStoreProbe {
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP = ScimResourceType.groupInstance();
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-13T01:00:00Z"), ZoneOffset.UTC);
    private static final PostgresqlScimPatch.@NonNull Authorizer ALLOW = (current, candidate, attempted, effective) -> true;
    private ScimStoreProbe() { }

    private record Snapshot(@Nullable String userName, @Nullable String displayName, @Nullable Boolean active,
            long version, @NonNull String created, @NonNull String modified, @NonNull List<@NonNull String> members) { }

    private static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_USER")));
        properties.setProperty("password", Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_PASSWORD")));
        int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1000));
        properties.setProperty("connectTimeout", Integer.toString(seconds));
        properties.setProperty("socketTimeout", Integer.toString(seconds)); properties.setProperty("gssEncMode", "disable");
        return DriverManager.getConnection(Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_URL")), properties);
    }

    private static @NonNull Connection injected(@NonNull Duration remaining, boolean afterCommit,
            boolean afterMemberInsert) throws SQLException {
        Connection physical = connection(remaining); AtomicInteger inserted = new AtomicInteger();
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                (Object proxy, Method method, Object[] arguments) -> {
                    try {
                        Object result = method.invoke(physical, arguments);
                        if (afterCommit && method.getName().equals("commit"))
                            throw new SQLException("Fixture acknowledgement lost after actual commit");
                        if (afterMemberInsert && method.getName().equals("prepareStatement") && arguments != null
                                && arguments[0] instanceof String sql && sql.contains("INSERT INTO scim_fixture_member")
                                && result instanceof PreparedStatement statement) {
                            return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(), new Class<?>[]{PreparedStatement.class},
                                    (Object statementProxy, Method operation, Object[] parameters) -> {
                                        try {
                                            Object value = operation.invoke(statement, parameters);
                                            if (operation.getName().startsWith("execute")
                                                    && inserted.incrementAndGet() == 1)
                                                throw new SQLException("Fixture statement failure after actual first member insertion");
                                            return value;
                                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                                    });
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static @NonNull ScimServiceProvider provider(boolean smallOutput) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER, GROUP)).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
                .limits(smallOutput ? ScimLimits.builder().maximumResponseBytes(2048).build() : ScimLimits.fromDefaults())
                .stringMatching((path, definition, operator, value, literal) -> switch (operator) {
                    case EQ -> ScimStringMatchResult.fromMatched(asciiFold(value).equals(asciiFold(literal)));
                    case NE -> ScimStringMatchResult.fromMatched(!asciiFold(value).equals(asciiFold(literal)));
                    default -> ScimStringMatchResult.unsupportedInstance();
                }).build();
    }

    private static @NonNull String asciiFold(@NonNull String input) {
        StringBuilder result = new StringBuilder(input.length());
        for (int index = 0; index < input.length(); ++index) {
            char ch = input.charAt(index); result.append(ch >= 'A' && ch <= 'Z' ? (char) (ch + 32) : ch);
        }
        return result.toString();
    }
    private static @NonNull PostgresqlScimPatch host(@NonNull String tenant,
            PostgresqlScimPatch.@NonNull ConnectionSource source, @NonNull ScimServiceProvider provider) {
        return new PostgresqlScimPatch(tenant, source, provider, CLOCK);
    }
    private static PostgresqlScimPatch.@NonNull Outcome patch(@NonNull String tenant, @NonNull String id,
            @NonNull ScimResourceType type, @NonNull String operations, @NonNull ScimServiceProvider provider,
            PostgresqlScimPatch.@NonNull ConnectionSource source, PostgresqlScimPatch.@NonNull Authorizer authorizer,
            @NonNull List<@NonNull String> ifMatch, @NonNull String rawSelection) {
        byte[] bytes = ("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":" + operations + "}").getBytes(StandardCharsets.UTF_8);
        ScimPatchParseResult parsed = provider.parsePatchRequestResult(type, List.of("application/scim+json"), bytes);
        expect(parsed instanceof ScimPatchParseResult.Succeeded, "fixture-patch-parsed");
        ScimAttributeSelectionResult selected = provider.parseAttributeSelectionResult(type, rawSelection);
        expect(selected instanceof ScimAttributeSelectionResult.Succeeded, "fixture-selection-parsed");
        return host(tenant, source, provider).patch(type, id, ((ScimPatchParseResult.Succeeded) parsed).getPatchRequest(), ifMatch,
                ((ScimAttributeSelectionResult.Succeeded) selected).getAttributeSelection(), authorizer, BUDGET);
    }
    private static PostgresqlScimPatch.@NonNull Outcome patch(@NonNull String tenant, @NonNull String id,
            @NonNull ScimResourceType type, @NonNull String operations) {
        return patch(tenant, id, type, operations, provider(false), ScimStoreProbe::connection, ALLOW, List.of(), "");
    }
    private static @NonNull Snapshot snapshot(@NonNull String tenant, @NonNull String id) throws SQLException {
        try (Connection connection = connection(BUDGET);
                PreparedStatement statement = connection.prepareStatement("SELECT user_name,display_name,active,version,created,modified FROM scim_fixture_resource WHERE tenant=? AND id=?")) {
            statement.setString(1, tenant); statement.setString(2, id);
            try (ResultSet row = statement.executeQuery()) {
                expect(row.next(), "snapshot-resource-present");
                List<String> members = new ArrayList<>();
                try (PreparedStatement read = connection.prepareStatement("SELECT user_id FROM scim_fixture_member WHERE tenant=? AND group_id=? ORDER BY ordinal")) {
                    read.setString(1, tenant); read.setString(2, id);
                    try (ResultSet values = read.executeQuery()) { while (values.next()) members.add(values.getString(1)); }
                }
                Boolean active = row.getObject(3, Boolean.class);
                return new Snapshot(row.getString(1), row.getString(2), active, row.getLong(4), row.getString(5), row.getString(6), List.copyOf(members));
            }
        }
    }
    private static void expect(boolean condition, @NonNull String check) { if (!condition) throw new IllegalStateException(check); }
    private static void ready(PostgresqlScimPatch.@NonNull Outcome outcome, int status, long version) {
        expect(outcome instanceof PostgresqlScimPatch.Ready, "confirmed-ready");
        ScimResponse response = ((PostgresqlScimPatch.Ready) outcome).response();
        expect(response.getStatusCode() == status, "prepared-status");
        expect(response.getHeaders().get("ETag").equals(List.of("W/\"" + version + "\"")), "authoritative-version");
    }
    private static void rejected(PostgresqlScimPatch.@NonNull Outcome outcome, @NonNull ScimError error) {
        expect(outcome instanceof PostgresqlScimPatch.Rejected, "expected-rejection");
        expect(((PostgresqlScimPatch.Rejected) outcome).error() == error, "fixed-error-kind");
    }

    private static void basic() throws SQLException {
        String tenant = "basic"; Snapshot original = snapshot(tenant, "u1"); ScimServiceProvider provider = provider(false);
        AtomicInteger decisions = new AtomicInteger();
        PostgresqlScimPatch.Authorizer observeNoop = (current, candidate, attempted, effective) -> {
            decisions.incrementAndGet(); expect(!attempted.isEmpty(), "noop-attempts-authorized");
            expect(effective.isEmpty(), "noop-no-effective-change"); return true;
        };
        ready(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"original\"}]",
                provider, ScimStoreProbe::connection, observeNoop, List.of(), ""), 200, 1);
        expect(decisions.get() == 1 && snapshot(tenant, "u1").equals(original), "noop-keeps-all-stored-metadata");
        rejected(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"original\"}]",
                provider, ScimStoreProbe::connection, (current, candidate, attempted, effective) -> false, List.of(), ""), ScimError.forbiddenInstance());
        expect(snapshot(tenant, "u1").equals(original), "denied-noop-keeps-storage");
        rejected(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"partial\"},{\"op\":\"remove\",\"path\":\"userName\"}]"), ScimError.mutabilityInstance());
        expect(snapshot(tenant, "u1").equals(original), "last-operation-failure-keeps-storage");
        rejected(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"stale\"}]",
                provider, ScimStoreProbe::connection, ALLOW, List.of("W/\"stale\""), ""), ScimError.preconditionFailedInstance());
        expect(snapshot(tenant, "u1").equals(original), "stale-version-keeps-storage");
        rejected(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"userName\",\"value\":\"BOB\"}]"), ScimError.uniquenessInstance());
        expect(snapshot(tenant, "u1").equals(original), "backend-matching-uniqueness-keeps-storage");
        rejected(patch(tenant, "u1", USER, "[{\"op\":\"add\",\"path\":\"externalId\",\"value\":\"unsupported\"}]"), ScimError.invalidValueInstance());
        expect(snapshot(tenant, "u1").equals(original), "unsupported-profile-never-dropped");
        rejected(patch(tenant, "g", GROUP, "[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"absent\"}]}]"), ScimError.invalidValueInstance());
        Snapshot group = snapshot(tenant, "g");
        ready(patch(tenant, "u1", USER, "[{\"op\":\"replace\",\"path\":\"active\",\"value\":false}]"), 200, 2);
        expect(Boolean.FALSE.equals(snapshot(tenant, "u1").active()), "assigned-false-persists");
        ready(patch(tenant, "g", GROUP, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"changed\"},{\"op\":\"remove\",\"path\":\"members[value eq \\\"u1\\\"]\"},{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u3\"}]}]"), 204, 2);
        Snapshot updated = snapshot(tenant, "g");
        expect("changed".equals(updated.displayName()) && updated.members().equals(List.of("u2", "u3")) && updated.version() == 2, "group-row-members-commit-together");
        expect(updated.created().equals(group.created()) && !updated.modified().equals(group.modified()), "actual-change-updates-only-authoritative-modified");
        ready(patch(tenant, "g", GROUP, "[{\"op\":\"remove\",\"path\":\"members\"}]"), 204, 3);
        Snapshot empty = snapshot(tenant, "g");
        ready(patch(tenant, "g", GROUP, "[{\"op\":\"remove\",\"path\":\"members\"}]"), 204, 3);
        expect(snapshot(tenant, "g").equals(empty) && empty.members().isEmpty(), "repeated-clear-canonical-profile-no-version-churn");
        expect(snapshot("isolated", "u1").version() == 1 && "original".equals(snapshot("isolated", "u1").displayName()), "tenant-isolation");
        System.out.println("BASIC_PASS");
    }

    private static void rollback() throws SQLException {
        Snapshot before = snapshot("rollback", "g");
        PostgresqlScimPatch.Outcome outcome = patch("rollback", "g", GROUP,
                "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"partial\"},{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u3\"}]}]",
                provider(false), remaining -> injected(remaining, false, true), ALLOW, List.of(), "");
        expect(outcome == PostgresqlScimPatch.Unavailable.INSTANCE, "definite-rollback-unavailable");
        expect(snapshot("rollback", "g").equals(before), "sql-failure-rolls-back-row-and-members");
        System.out.println("ROLLBACK_PASS");
    }
    private static void unknown() throws SQLException {
        Snapshot before = snapshot("unknown", "g");
        PostgresqlScimPatch.Outcome outcome = patch("unknown", "g", GROUP,
                "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"committed\"},{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u3\"}]}]",
                provider(false), remaining -> injected(remaining, true, false), ALLOW, List.of(), "");
        expect(outcome == PostgresqlScimPatch.Unknown.INSTANCE, "actual-commit-lost-ack-withholds-success");
        Snapshot committed = snapshot("unknown", "g");
        expect("committed".equals(committed.displayName()) && committed.version() == before.version() + 1
                && committed.members().equals(List.of("u1", "u2", "u3")), "unknown-result-actually-committed-no-auto-replay");
        System.out.println("UNKNOWN_PASS");
    }
    private static void cap() throws SQLException {
        Snapshot before = snapshot("cap", "g");
        List<String> members = new ArrayList<>();
        for (int index = 1; index <= 40; ++index) members.add("{\"value\":\"large" + index + "x".repeat(100) + "\"}");
        rejected(patch("cap", "g", GROUP, "[{\"op\":\"replace\",\"path\":\"members\",\"value\":[" + String.join(",", members) + "]}]",
                provider(true), ScimStoreProbe::connection, ALLOW, List.of(), "attributes=members"), ScimError.responseTooLargeInstance());
        expect(snapshot("cap", "g").equals(before), "bounded-output-prepared-before-storage");
        System.out.println("CAP_PASS");
    }
    private static void race(@NonNull String label) throws Exception {
        System.out.println("RACE_READY"); System.out.flush();
        String signal = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine();
        expect("GO".equals(signal), "bounded-race-signal");
        PostgresqlScimPatch.Outcome outcome = patch("race", "u1", USER,
                "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + label + "\"}]",
                provider(false), ScimStoreProbe::connection, ALLOW, List.of("W/\"1\""), "");
        if (outcome instanceof PostgresqlScimPatch.Ready) { ready(outcome, 200, 2); System.out.println("RACE_COMMITTED"); }
        else { rejected(outcome, ScimError.preconditionFailedInstance()); System.out.println("RACE_REJECTED_412"); }
    }
    private static void verifyRace() throws SQLException {
        Snapshot row = snapshot("race", "u1");
        expect(row.version() == 2 && Set.of("left", "right").contains(row.displayName()), "race-one-authoritative-write");
        System.out.println("RACE_PASS");
    }
    private static void persist() {
        ready(patch("persist", "g", GROUP, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"persisted\"},{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"u2\"},{\"value\":\"u3\"}]}]"), 204, 2);
        System.out.println("PERSISTED_PASS");
    }
    private static void recovered() throws SQLException {
        Snapshot row = snapshot("persist", "g");
        expect(row.version() == 2 && "persisted".equals(row.displayName()) && row.members().equals(List.of("u2", "u3")), "new-jvm-after-primary-restart-keeps-rows-members-version");
        System.out.println("RECOVERED_PASS");
    }
    private static void outage() {
        expect(patch("persist", "g", GROUP, "[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"outage\"}]")
                == PostgresqlScimPatch.Unavailable.INSTANCE, "outage-no-ready-or-rejection");
        System.out.println("OUTAGE_PASS");
    }
    public static void main(String @NonNull [] args) throws Exception {
        switch (args[0]) {
            case "basic" -> basic(); case "rollback" -> rollback(); case "unknown" -> unknown();
            case "cap" -> cap(); case "race" -> race(args[1]); case "verify-race" -> verifyRace();
            case "persist" -> persist(); case "recovered" -> recovered(); case "outage" -> outage();
            default -> throw new IllegalArgumentException("Unknown probe mode");
        }
    }
}
