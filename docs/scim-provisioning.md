# Application-owned SCIM provisioning

`ScimServiceProvider` prepares schema-bound work. `SokletScim` and the paired `ServletScim` helpers translate transport. The application authenticates the caller, resolves the tenant, authorizes attempted and effective changes, enforces uniqueness and references, and confirms persistence before emitting a prepared response.

## Runnable Soklet routes

`examples/playground` selects the [restrictive service-client profile](scim-restrictive-service-clients.md) when at least one explicit SCIM credential is registered. It has fixed alpha/beta tenant roles, default-deny field/query policies, bounded Argon2id work and immutable publication predicates. The standalone `example.playground.ScimDirectoryPlayground` uses that same selected policy and resources.

### Administrative interoperability fixture

The separate `example.playground.ScimPlayground` entrypoint retains the earlier single-administrative-principal fixture for dated independent-client qualification. It is not the complete Playground startup profile and does not expose the new tenant aliases:

```sh
export SCIM_BEARER_TOKEN='<private ASCII credential, 32–256 characters>'
export SCIM_BASE_URI='https://localhost:8445/scim/v2/'
export SCIM_HTTP_HOST='127.0.0.1'
export SCIM_HTTP_PORT='8082'
java -cp "examples/playground/target/playground-1.0.0-SNAPSHOT.jar:examples/playground/target/lib/*" \
  example.playground.ScimPlayground
```

Install matching core, adapter and Soklet dependencies using the [Maven setup instructions](../examples/README.md#build-with-maven), then run `mvn -f examples/playground/pom.xml verify` from the core repository root. An HTTPS edge with a scoped CA and hostname verification is required. The interoperability runner provisions that private edge automatically. The internal HTTP host is configurable for an isolated container network; its default is loopback.

The authenticated synthetic principal owns one local provisioning tenant. The credential is application configuration, never a query parameter or browser cookie. Each request must have exactly one Authorization occurrence. Discovery is GET-only. User and Group routes implement create, get, replace, PATCH, delete, list and resource-specific POST `.search`. Aggregate `.search` returns a fixed SCIM 501; unknown resource roots return a fixed SCIM 404; unsupported methods on known discovery roots return SCIM 405. The fixture explicitly selects only `PATCH_EXTENSION_SCHEMA_ROOT` for registered extension-object URI roots. That named interoperability profile is outside the literal PATCH path ABNF; strict/Entra/Okta presets continue to reject it. The operation exposes the distinct target through `ScimPatchOperation.getExtensionSchemaId()`, and authorization receives canonical child paths. This profile choice and additive getter/enum are reviewable M12 API deltas. The fixture advertises filtering, PATCH, ETags and password changes in its synthetic profile; it does not advertise Bulk, sorting or cursor pagination.

The local store has a maximum of 128 combined resources. Soklet bounds the materialized body to 16KiB and the complete request to 32KiB; the core provider uses the same body cap. Default page size and maximums come from the configured provider, and totalResults is accurate even for count=0. Collection execution uses `ScimFilterEvaluator` against the configured default-deny policies. All matching uses the same provider strategy as PATCH. Username input is restricted to printable non-space ASCII of at most 128 characters, and matching is an explicitly synthetic ASCII profile. It is not a Unicode/PRECIS production default. A deployment must choose authoritative preparation/matching/uniqueness together.

The synthetic principal can supply a User password. The example prepares a salted PBKDF2 digest of a bounded 512-character value before commit, stores it separately from the resource under the same lock, and removes transient plaintext from the resource document and responses. Repeating the same password is a no-op; removing it clears the stored credential. This ephemeral fixture is not a production credential service or password-hashing recommendation. No credential survives restart. Hosts must supply their actual password policy, hashing service and authorization. The fixture's true password-change advertisement reports that application behavior; the core flag neither grants the principal permission nor supplies a credential handler. Default-off advertising in other providers does not make schema parsing a password-rejection gate. Rendering omits the standard password field, while the application remains responsible for the transient candidate and credential state.

Group membership references must identify existing local Users or Groups; supplied type must match the actual resource kind. A non-null `$ref`, resolved against the trusted base when relative, must match that resource's location. Remove incoming membership before deleting its referenced resource in this profile. Enterprise manager references also resolve to an existing User in the same application scope; remove incoming manager references before deletion. Opaque resource/member identifiers compare exactly. Other member lifecycle policies belong to the deployment. Resource and represented member sequence change under one lock. This fixture uses full PATCH evaluation; membership reduction remains available to stores that qualify the same identity/order/metadata semantics.

The Playground's shared User registration explicitly includes the optional
Enterprise User extension. Its fixture stores the supported fields and enforces
manager references. The core `ScimResourceType.userInstance()` preset remains
core User only; the [schema registration guide](scim-server-primitives.md) shows
how to opt in to the extension for an application that supports it.

## Write ordering and failure boundaries

The concrete methods in `PlaygroundScim` follow this order:

1. Authenticate and resolve the local tenant before invoking a parser.
2. Under the transaction lock, load the current resource and evaluate If-Match against it.
3. Apply the ordered pure PATCH or replacement.
4. Authorize attempted and effective paths and candidate values, including no-op attempts and omitted PUT fields.
5. Enforce username uniqueness, reference existence and application input profile; prepare password work separately.
6. Assign authoritative version/time metadata only when persisted state actually changes.
7. Prepare the bounded final response before writing state.
8. Atomically install resource, membership and private credential changes. Emit only on confirmed success.

Tests cover final-operation failure, denied no-op, stale-version and uniqueness races, missing references, response overflow, definite outage/conflict and lost commit acknowledgement. `CommitOutcome.UNKNOWN` withholds success even if the test fixture applied the write. It must be reconciled; automatic replay is unsafe. The in-memory example distinguishes outcomes and demonstrates ordering, but does not establish durable persistence.

## Compiled PostgreSQL recipe

`examples/postgresql-pending-store/src/main/java/example/pending/PostgresqlScimPatch.java` and `scim-schema.sql` provide an application-level durable PATCH recipe using Pyranid. They add no core runtime dependency. The profile stores User userName/displayName/active and Group displayName plus ordered ID-only references to Users. Group-to-Group membership requires a different host storage profile. Unsupported attributes or member metadata reject rather than being lost. Full schema storage needs a host-owned bounded codec and its own qualification.

Authentication selects a stable tenant before constructing the recipe. Provision its tenant row through migrations. Every writer must use the same tenant row lock on the authoritative primary. PATCH locks the row, checks its version, performs full evaluation/authorization, enforces references and ASCII username uniqueness, prepares the response, and then writes resource/member rows in one Pyranid transaction. Database uniqueness constraints and foreign keys supplement application checks. Namespace locking bounds cross-resource races; the version predicate remains explicit. The connection source must acquire a clean primary connection within the shrinking budget. SQL and driver network timeouts use that budget; synchronous_commit, fsync and full_page_writes must be enabled.

This storage profile canonicalizes absent Group membership to an explicit empty sequence before comparing persisted state. Repeated removal of empty membership cannot churn its version. Core stable-ID Group PUT/PATCH reconciliation uses an operation-local ordered ID index and
one shared work budget, preserving requested order and retained protected metadata. The
application's keyed reducer execution must continue to honor the same add-existing,
remove/re-add and replacement contracts. Qualify the actual ID lengths, member counts,
metadata and operation mix; byte ceilings alone do not promise semantic acceptance. Original
body admission and complete JSON output now charge started 16-byte blocks on the same work
carrier; validation/matching and header/framing charges remain, and projection shares immutable
scalars without an extra content-length penalty. No allowance resets per page member or phase.
The default 8 MiB prepared-response ceiling is reachable for qualified linear pages, including
header/framing overhead; the recipe's own smaller transport/storage limits still apply. Requalify
its actual profiles after the accounting change. No partial candidate or rejected prepared response
is eligible for persistence.

Standard Group PUT also supports rows without a member ID. It preserves a current anonymous
row's server display only for an exact normalized writable `$ref`/`type` tuple; duplicate tuples
consume current occurrences once in current order. Changed or additional tuples are new rows
without inherited display, and submitted display never selects an occurrence. This rule does
not turn a reference or array position into persistent identity. The keyed-ID storage recipe
must continue to require assigned IDs; an application that supports anonymous members needs
an explicit occurrence/storage policy and must qualify the full PUT candidate before committing.

Versions/timestamps are authoritative application data. SQL parameters are bound; personal data, driver errors and exception text never enter protocol diagnostics.

The recipe returns `Ready`, `Rejected`, `Unavailable` or `Unknown`. Ready is released only after Pyranid confirms COMMITTED in budget. A failed write without definite rollback returns Unknown; a failed acquisition/read or confirmed rollback returns Unavailable. Do not emit prepared bytes or automatically retry before resolving Unknown. The real PostgreSQL fixture exercises rollback, lost acknowledgement, independent JVM races and restart; it is not a claim about cross-host failover, backups or power-loss recovery.

## Paired Servlet flow

Both Servlet adapters expose the same `ServletScim`/`ServletScimBodyResult` API using their respective servlet namespaces. Read original Content-Type occurrences once, then `bodyResultFor(provider, request)` before Servlet parameter decoding. A Read exposes defensive bytes; Rejected supplies a fixed error; Unavailable distinguishes I/O/interruption from malformed or empty input. The body reader consumes at most the provider cap+1 and does not retain overflowing data. It preserves interruption. Pass Read bytes and the original headers to the core's header-aware parser, follow the same application transaction order, and finally use `writeResponse` with the prepared result. Transport output IOException remains a host concern.

The paired adapter `verification/scim-container` sources compile and run in actual pinned Tomcat containers. Their server connector caps are paired with the core byte cap. Neither bridge installs routes or chooses authorization, tenant, persistence or matching policy. A trusted edge must reject physical ambiguities the downstream framework cannot preserve.

## Interoperability and release evidence

`interop/scim` runs a hash-pinned scim2-tester against the actual Soklet routes, and authentik's production outbound User/Group SCIM clients configured with its official AWS mode against the same routes through normal scoped-CA/hostname verification. Authentik's own SCIM server is not used as an oracle. Its AWS mode uses standard PUT for updates. The pinned release's default mode omits the required top-level PatchOp schema on general updates; that separately reproduced upstream defect is recorded as unresolved. The server continues to reject that malformed envelope. No default-mode compatibility claim follows from the selected-mode qualification. The runner records frozen compiled artifact hashes, tool pins, required outcomes and run identity. Failures remain failures. The tester's explicit optional aggregate-search skip is recorded; unexplained errors are never suppressed.

`differential` compares typed syntax trees with pinned UnboundID. Exact grammar/parser differences have individual dispositions; unexplained divergence fails. This lane provides syntax/AST evidence, not evaluator, authorization, PATCH or persistence assurance.

The nightly authentik workflow provides ongoing interoperability coverage with required outcomes and source-bound evidence for every run. There is no minimum-duration or consecutive-run release gate. Failures, missing artifacts and source/pin mismatches remain observable failures; successful reruns must match their actual run identity and attempt. The workflow and example manifest pin the owner-delivered adapter checkpoint containing the qualified SCIM transport repairs. Future source changes require an explicit reviewed pin refresh; an uncommitted candidate uses recorded source snapshots for local qualification. RC3 still requires the planned mutation/calibration/review/pentest, complete exact-source exit matrix and owner API freeze.
