# SCIM server primitives

The schema, resource, query and response APIs are implemented for Java 17. Ordered PATCH and membership reduction are implemented. The optional collection filter evaluator and provisioning examples are implemented, with independent-client and real-container qualification tooling. Scheduled soak and release assurance have separate evidence gates. See [filter evaluation](scim-filter-evaluation.md) and the [provisioning recipe](scim-provisioning.md). These APIs prepare application-owned work; they do not authenticate callers, query a database or commit changes.

Configure `ScimServiceProvider` with a trusted base URI, resource types and truthful capabilities. The shared `ScimResourceType.userInstance()` registration contains only the standard core User schema; `groupInstance()` contains the standard Group schema. Enterprise User support requires an explicit extension registration. Custom schemas have bounded immutable definitions, with 1,024 definitions per effective resource type, 32 types and 64 schemas per provider. Application registrations cannot occupy the reserved discovery type names or endpoint paths. Applications enforce advertised uniqueness and reference existence.

Resource-type construction gives fully equal rebuilt standard User/Group core schemas and Enterprise User extensions the builtin attribute spellings, including subattributes. It preserves the configured schema identifier, name and description, and an extension's required characteristic. Equality checks all definitions and facets; custom identifiers or changed facets do not gain standard-schema behavior. Accepted schema-URI and attribute-name case variants therefore share identifier validation, typed views and primary-value rules. Rebuilt schemas remain distinct from the builtin singletons used by conservative optional PATCH shortcuts.

```java
ScimResourceType users = ScimResourceType.userInstance();
// Share this immutable provider for this service configuration.
ScimServiceProvider provider = ScimServiceProvider.builder()
    .baseUri(URI.create("https://example.com/scim/v2/"))
    .resourceTypes(List.of(users))
    .serviceProviderConfig(ScimServiceProviderConfig.builder()
        .filterSupported(true)
        .build())
    .filterPolicies(Map.of(users, ScimFilterPolicy.builder()
        .allowedComparisons(Map.of("userName", Set.of(ScimComparisonOperator.EQ)))
        .build()))
    .build();
```

To support Enterprise User attributes, register that schema explicitly:

```java
var usersWithEnterprise = ScimResourceType.withName("User")
  .id("User")
  .endpoint("/Users")
  .schema(ScimSchema.userInstance())
  .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(
    ScimSchema.enterpriseUserInstance(), false)))
  .build();
```

Use this same registration in the provider's resource types, filter policies and
operations. The `false` flag means a User may omit the extension; `true` makes it
required. Both are explicit declarations that the application supports its
attributes. Core-only discovery omits the Enterprise schema, and strict parsing
rejects unregistered Enterprise data or paths. The application must round-trip
supported attributes and enforce references; registration does not create
storage or enable PATCH. The Playground explicitly selects an optional Enterprise
registration because its fixture stores these fields and checks manager references.

Every advertised filterable resource type needs an explicit policy. `rejectAllInstance()` disables filtering for one type. Syntax success alone grants no permission. `parseFilterResult` resolves registered schema paths, canonicalizes names and legal implicit `.value` comparisons, checks literal types and applies the entire policy. It returns exactly the approved tree. Parsed/bound roots privately retain their bounded original expression so optional evaluation can recheck receiving input limits and policy without treating longer canonical normalization as new untrusted input. Canonical export can exceed the original input-character cap; it is not an approval or a guaranteed same-limit reparse. Flat comparison permission does not grant ValuePath permission; AND, OR and NOT need explicit permission. Unknown paths and `returned:never` paths cannot be filtered or sorted. Query execution and value-level authorization remain application responsibilities.

Use `parseQueryResult` with the original raw query string. Decoding preserves physical multiplicity, maps plus to space, validates percent escapes and UTF-8, and rejects duplicate recognized parameters, including ASCII case variants. Unknown parameters are ignored only after bounded decoding. `parseSearchRequestResult` accepts the equivalent JSON SearchRequest form, including its required message schema; unknown fields reject. Body parsers have header-aware overloads for HTTP and byte-only overloads for previously validated framing.

Queries expose a bound filter, projection, sort path/direction and pagination request. Sorting is a description for the application: multi-valued sort uses primary then first, absent values go last ascending or first descending, and stable ID tie-breaking is application-owned. Unsupported sort requests reject. String matching must agree with the backend's attribute-specific preparation and collation; the library supplies no general Unicode matching default.

Index pagination defaults to startIndex 1 and count 100, with maximum 1,000. Negative count becomes zero and startIndex below one becomes one. Index counts clamp to the configured maximum. The original requested count remains available. Enabling cursor pagination requires an explicit timeout commitment. Cursor counts exceeding the maximum reject; cursor plus startIndex rejects. Empty or omitted cursor denotes the first cursor page. Cursor strings use unreserved ASCII. The application authenticates and binds cursors to tenant, caller, permissions, resource type, approved query, sort, projection, page size and expiry.

Build `ScimListPage` with its originating query, actual resources and accurate page metadata. Index pages require totalResults. Cursor pages declare more results exactly when nextCursor is present; a short page alone does not prove exhaustion. The first cursor page cannot have previousCursor. A count-zero cursor response is a count-only operation: accurate totalResults, empty Resources and no traversal cursors. This exact-total requirement is the selected Revetsec profile.

`ScimServiceProviderConfig.Builder.changePasswordSupported(...)` sets the password-change
capability advertisement, false by default; null restores false. Discovery reports that value.
This flag does not gate schema-bound User `password` input on create, PUT or an enabled PATCH,
and true does not enable PATCH or authorize a credential change. PATCH has its own support
switch. The standard password attribute remains optional, write-only and `returned:never`.
An accepted parse/PATCH candidate can contain the supplied plaintext for the application to
handle. The host authenticates and authorizes the attempted/effective write, applies its
password policy and credential service, and controls storage and transient secret handling.
Parsing does not change a credential store or supply a password handler. Rendering omits the
password from GET, create, PUT, PATCH and list responses even with explicit `attributes=password`
or supplied-path provenance. That omission does not erase input bytes or candidate values;
avoid persisting or logging transient plaintext. Advertise password-change support only when
the application implements and authorizes it.
For an application policy that forbids password writes, reject supplied password values in the
application's authorization/validation layer; the advertisement setting alone is insufficient.

`parseResourceResult` prepares a create candidate. It ignores submitted readOnly fields before checking required values. `parseReplacementResult` applies PUT semantics to an immutable current resource: preserve readOnly and assigned immutable values, clear omitted readWrite values, reject immutable changes, then check required fields and extensions. Failure preserves the original. A supplied complex object clears omitted writable children while retaining protected children.

Group member replacement reconciles protected metadata by exact member `value`, allowing add, remove and reorder without transferring metadata between IDs. Incoming Group resources with duplicate assigned member IDs are rejected; clean up any previously persisted duplicates before replacing those resources. For custom multi-valued complex attributes containing assigned protected descendants, replacement accepts the unchanged sequence and rejects ambiguous changes; it does not guess element identity from array position. Applications needing different semantics must define an explicit identity contract in a later API extension.

Multi-valued complex attributes with a declared BOOLEAN `primary` subattribute enforce one true primary and use the declared spelling when transferring primary status. This also applies to custom schemas with a case variant such as `PRIMARY`; their normalized documents retain the custom spelling. A STRING `primary` or a differently named BOOLEAN remains an ordinary value.

Wire INTEGER values reject fraction and exponent syntax, including `1.0` and `1e0`, at every bound position. INTEGER values are exact bounded integers, without an invented 64-bit restriction on resource attributes. DATE_TIME follows XML Schema dateTime, including optional timezone, valid calendar dates and legal 24:00 notation; server metadata exposed as `Instant` additionally requires an offset and representable range. Relative references are allowed and never fetched. Binary padding is optional. Canonical values are suggestions, not a mandatory whitelist.

After authorization, uniqueness/reference checks and password handling, assign authoritative metadata and prepare the final candidate with `createdResponseResult` or `replacementResponseResult`, using the parse result's actually supplied canonical paths. Prepare the bounded response before commit when preparation can fail; persist atomically and emit the prepared response only after the application confirms success. A prepared response establishes neither authorization nor persistence. This bare path set is trusted application provenance: the renderer validates its paths against the target schema, but the set does not retain its originating parser or configuration. Assign authoritative IDs, versions and timestamps in trusted resource construction. Pass `provider.getLimits()` to `ScimResource.withResourceType(type).limits(...)` when building trusted GET data, especially when the provider raises its work budget. A resource parsed by the provider carries that budget into `resource.copy().finish()`; a copier can override it with `.limits(...)`. Trusted construction reports `ScimResourceWorkLimitException` separately from a schema violation. GET uses `resourceResponseResult` without write provenance. Projection always removes `returned:never`, retains `returned:always`, and reveals `returned:request` only when explicitly selected or actually supplied for that write. A broad supplied complex parent does not expose unrelated stored request-only children. Response preparation requires an assigned ID, checks resource/type/selection associations, emits defensive bytes and headers, and enforces output, header and aggregate work bounds before buffer growth.

The default aggregate work budget is 4,000,000 units, bounded by the configured
10,000,000-unit ceiling. The earlier 1,000,000-unit default could reject a body
within the default 1 MiB body limit during parsing and normalization. Applications
can set a lower budget for narrower resource profiles or raise it within the cap.

The aggregate work allowance is shared across each original operation: parsing/normalization,
projection and emission do not reset it, and pages/patches do not receive a new allowance per
resource or operation. The default remains 4,000,000 units, with configurable range
10,000–10,000,000. Work units are accounting units, not bytes or elapsed time.

| Processing | Charge model |
| --- | --- |
| Original request-body admission | `ceil(original UTF-8 bytes / 16)`, before JSON decoding; whitespace/escapes count in the original bytes. |
| Schema validation, binding, matching and mutation | Existing per-visit, field, character and comparison charges, including expensive matching reservations. |
| Projection | Schema/path/selected-value visits. Immutable scalar references are shared without charging their content length again. |
| JSON emission | One visit per JSON value plus `ceil(total emitted UTF-8 body bytes / 16)`. The byte total is cumulative across all writes/resources, not rounded separately per character/chunk. |
| Response headers/framing | Existing encoded-header byte charges plus 128 framing units. |

Byte reservations and work reservations precede buffer growth. Response byte limits include the
JSON body, encoded headers and 128 bytes of framing. UTF-8 expansion and JSON escapes count as
emitted bytes; projection does not establish an output-size allowance. Existing codec structural
fences and body/header/response ceilings each remain enforced.

Builders validate each configured range rather than promise affordability for every schema/body.
A request body needs at least `ceil(bodyBytes / 16)` remaining units before decode and additional
semantic work afterward; prior media/header work also consumes the operation allowance. A
response needs projection work, headers/framing, value visits and the cumulative byte charge.
A deliberately low work setting can therefore reject data below its byte ceiling. If acceptance
at the byte ceiling matters, qualify actual schemas, text lengths, nodes, matching and operations;
there is no universal bytes-to-work ratio that guarantees semantic acceptance.

Current focused profiles cover the default 1 MiB input/default work, a 6 MiB ASCII input at the
existing maximum work, a 10 MiB UTF-8 input at that same maximum, and representative pages that
fill the default 8 MiB and configured 32 MiB prepared-response ceilings with default work. These
are constructive profiles, not guarantees for all payloads. In particular, a 10 MiB ASCII body
can exceed semantic character work even when its wire-byte admission fits. Below-cap structurally
or computationally excessive inputs still refuse with 413; response-cap/work refusal remains a
fixed response-preparation error with no partial prepared response.

This accounting change bills cheap byte-linear traversal in blocks and removes a projection
penalty for sharing immutable scalar values. Numeric limits and schema/matching charges stay
unchanged, but acceptance thresholds change; requalify deployment profiles instead of reusing
older per-byte work measurements as current evidence. Application storage, authorization,
concurrency, response preparation before commit and confirmed persistence remain separate.

Create responses use status 201 and a Location derived from the trusted base, type endpoint and one encoded ID segment. Submitted Host/Forwarded/meta values do not choose the location. An existing meta.location must agree; the response carries the authoritative location. Responses include ETag from meta.version when enabled and use private/no-store. `notModifiedResponseResult` prepares bounded bodyless 304; fixed errors and 204 fit minimum output budgets. Adapters preserve the prepared bytes, status and original header occurrences.

`resourceLocationFor` leaves the ASCII unreserved characters `A-Z a-z 0-9 - . _ ~` literal,
following [RFC 3986 section 2.3](https://www.rfc-editor.org/rfc/rfc3986#section-2.3).
Other UTF-8 bytes use uppercase percent escapes; slash, backslash, percent, space, query and
fragment punctuation stay data inside one raw path segment. Standalone `.` and `..` IDs still
reject before encoding. For example, `a.b` ends in `/a.b`, `../x` ends in `/..%2Fx`, and the
literal ID `%2e%2e` ends in `/%252e%252e`. The library does not decode input IDs or resolve them
as relative paths. Route by the original raw segment and decode its ID once; do not normalize a
decoded opaque ID as a filesystem/URI path or decode it repeatedly. Qualify the actual proxy,
container and routing treatment of encoded separators; URI construction alone does not certify it.

This changes the earlier generated dot spelling `%2E` to `.`. Before preparing a create response,
regenerate application-authored `meta.location` from the authoritative ID and current
`resourceLocationFor`, or omit that field from the creation candidate and let preparation set it.
The existing URI equality check remains: an older stored `/a%2Eb` does not agree with the newly
generated `/a.b`, and create preparation rejects it with `invalidValue`. GET rendering does not
rewrite existing metadata. Review application URI comparisons, persisted references and cached
links derived from the old generator, and regenerate them from known authoritative IDs under
the application's authorization/migration policy. Do not apply a blanket percent-decoding pass.
No broad URI decoding/normalization is added to the agreement check;
IDs, ETags, codecs and storage keys are unchanged. Maximum ID length remains 1,024 UTF-16 units,
and valid IDs can still exceed separately configured response/header/work budgets after encoding.

If-Match and If-None-Match accept absent fields, an isolated wildcard, or valid tag lists across physical fields. Malformed or oversized lists reject. Both use weak opaque-version comparison by the approved SCIM profile; If-Match deliberately differs from general HTTP strong comparison. Wildcards test the existing resource even without a version. Tags cannot match a versionless resource. Applications must check write preconditions against the same locked or version-predicated resource they commit.

Discovery emits Schema, ResourceType and ServiceProviderConfig representations, including required capability subfields, disabled Bulk and RFC 9865 pagination metadata. Unknown schema/type returns 404; discovery filters return 403. The host owns GET-only routing and 405 handling. Schema descriptors reflect primary RFC text and selected errata with their actual status; reported or held proposals are not described as verified corrections.

Strict compatibility is the default. Explicit relaxations used by these operations include exact `"true"`/`"false"` boolean strings, narrow post-ValuePath subattribute comparisons rewritten into the same element predicate, inferred missing extension declarations, ignored undeclared schema URIs and ignored unknown attributes. Broader preset features pertaining to PATCH are reserved for its implementation. Scalar complex conversion remains outside the Entra preset. Observer events report fixed operation/outcome/feature names and never request values or exceptions.

Queries, selections and parsed resources, including resource copies, retain private registration and compatibility provenance. A base-URI-only copy can reuse them. A copy with changed compatibility requires fresh parsing; a relaxed result cannot be rendered through a stricter provider. Trusted application-authored resource construction is deliberate data construction, not a request or authorization proof. Builders and copiers perform no I/O or callbacks; null setters restore their documented defaults.

## PATCH and membership

Enable `patchSupported(true)` only for application routes that implement PATCH, and configure an explicit `ScimStringMatching` strategy matching the backend's attribute preparation and collation. The strategy is shared by PATCH selectors and value deduplication; there is no default account-matching approximation. It must be thread-safe, deterministic, bounded and perform no I/O. An unsupported comparison rejects the complete transformation. Unexpected strategy faults yield a fixed internal error; request values and exception text never enter diagnostics.

`parsePatchRequestResult` accepts UTF-8 PatchOp JSON with the PatchOp message schema and a nonempty `Operations` array. The default maximum is 1,000 operations. Each operation has `op`, an optional `path`, and its operation-specific `value`. Missing value and explicit null remain distinct. Only add, remove and replace are supported; array indexing, move, copy and test reject. Field names use ASCII case folding; strict operation names are lowercase. Unknown operation fields and strict remove-with-value reject.

Paths bind to the selected resource schema without using collection query filter policy. Filtered paths address one multi-valued complex attribute, a bound same-element predicate and an optional child suffix. Conditional paths for simple arrays remain deferred. Hidden selector fields reject. A writable `returned:never` attribute such as password can still be supplied as a write, including a filtered child target selected by public fields; rendering always removes it. A hidden field cannot itself be used in the predicate. INTEGER values retain JSON lexical evidence, so fraction or exponent forms reject before a parsed request is published.

`applyPatchResult(current, patch)` transforms an operation-private candidate in request order and publishes a result only after all operations and final required/schema checks succeed. Any rejection leaves `current` untouched. Add sets scalar fields, merges supplied complex children and appends absent multi-values using schema-aware matching. Replace merges supplied complex children while retaining omitted children, and whole-array replacement follows the supplied sequence. Read-only writes reject; assigned immutable values cannot change. Optional-field removal clears the field. Removing a required field or its last assigned value rejects at that operation with mutability; a later operation cannot restore it to rescue the request. A filtered remove with no matches is a successful no-op; filtered add or replace with no matches returns `noTarget` in strict mode. Adding an empty array is a no-op. Explicit primary updates clear other primaries, and introduced extension values update `schemas`.

The application authorizes `getRequestedAttributePaths()` even for no-op attempts, then authorizes `getModifiedAttributePaths()` and the candidate's effective values before persistence. Modified paths conservatively include affected containers and children, induced primary changes and schema declarations. `getSuppliedAttributePaths()` records only actual supplied canonical values for write-response projection. `isModified()` describes the final resource difference: cancelling operations can yield false. The engine does not assign versions or timestamps; a no-op retains current metadata.

The implemented compatibility matrix is narrow and explicitly selected. Entra operation-name casing is normalized; remove-with-value accepts only nonempty ID-only standard Group `members` arrays and never turns an empty selection into remove-all. Dotted or qualified no-path value keys require their named feature; a normal registered extension object is accepted in strict mode. Entra upsert applies only to the shared builtin User schema's add/replace `emails[type eq "literal"].value` with a nonempty string, and creates the email with that type when there is no match. An equal rebuilt User retains the conservative `noTarget` result for this optional shortcut. Okta identical-ID echo applies only to no-path add/replace containing the current exact ID; direct ID writes and changed IDs still reject. Each used relaxation emits its fixed observer feature once per public operation.

`reduceMembershipPatchResult(patch)` prepares ordered ID steps for the standard Group schema without loading membership. It recognizes ID-only member add/replace arrays, exact `members[value eq "id"]` removal and whole-members removal. Only absent or null `$ref` may be discarded. Non-null reference, display/type/other metadata, complex selectors, filtered replacement, child writes and mixed no-path member objects require full evaluation. Duplicate-ID replacement and reconstructed custom Group schemas also use this conservative fallback. Steps retain original zero-based operation indexes and input ID order. Their kinds are `ADD_IDS`, `REMOVE_IDS`, `CLEAR` and `REPLACE_IDS`; nonmember operations remain in an optional bound request with their original indexes.

For the standard Enterprise User extension, changing or clearing `manager.value` clears the old
read-only `manager.displayName`. An inherited `$ref` also clears unless this PATCH request
explicitly addressed the standard manager reference. A reference written by an earlier
operation survives a later value edit, even when that reference write was a no-op. This applies
to child paths, complex manager objects, ordinary no-path extension objects and the selected
whole-extension profile; add/replace and canonical case variants have the same ordering rule.
Explicit reference null/removal still clears it; manager/extension removal cannot resurrect a
reference on recreation. The instruction marker is private to one application call and does not
carry into a subsequent PATCH or PUT. Same-value edits retain existing display data. Applications
must validate the final manager ID/reference pair, reference existence and authorization: the
library does not infer URI/ID agreement. Supply fresh display data from the authoritative store.

Execute steps and remainder operations in original request order under one authorization decision and transaction/version predicate. Add-existing preserves stored member metadata and position; remove-then-add recreates the member; replacement preserves protected metadata for surviving exact IDs and follows the requested sequence. Preserve represented sequence, including the distinction between clear and an explicit empty replacement, or qualify an explicit storage profile. Keyed storage must verify its existing snapshot has unique assigned IDs before executing this fast path; the reducer cannot prove that without a snapshot. The reducer has no membership snapshot and makes no modified/version claim. If full evaluation is required, load the bounded resource and use `applyPatchResult` or reject the unsupported workload according to application policy.

`patchResponseResult` prepares User 200 or Group 204 by default, according to the resource type's setting. Either `attributes` or `excludedAttributes` forces 200 in the selected profile. A 204 carries the authoritative ETag and bounded headers with no body or Content-Type. Use the PATCH result's supplied paths after assigning authoritative metadata. Prepare the bounded response before persistence when preparation can fail, persist resource and membership atomically, and emit only after the application confirms success. Authentication, per-value authorization, uniqueness, reference existence, preconditions and durable transaction outcomes remain application-owned.

The [`SokletScim`](https://javadoc.revetsec.com/com/revetsec/soklet/SokletScim.html)`.patchRequestResultFor` operation returns a [`SokletRequestResult`](https://javadoc.revetsec.com/com/revetsec/soklet/SokletRequestResult.html) of [`ScimPatchParseResult`](https://javadoc.revetsec.com/com/revetsec/scim/ScimPatchParseResult.html): inspect the [`Completed`](https://javadoc.revetsec.com/com/revetsec/soklet/SokletRequestResult.Completed.html)`.getResult()` core outcome, or stop on transport [`TooLarge`](https://javadoc.revetsec.com/com/revetsec/soklet/SokletRequestResult.TooLarge.html) before mutation. It translates the unchanged materialized bytes and original physical Content-Type occurrences through one core parser operation. It makes no tenant, authorization or storage choices. The patch parser, application and membership reducer each have one work budget covering scans, matching calls and snapshots; it never resets per operation. Exhaustion rejects without a partial candidate.

Full PUT and PATCH evaluation use operation-local ordered indexes for standard Group members.
PUT reconciles assigned survivors by exact ID; PATCH add preserves
existing order/metadata, replacement follows incoming order, and the selected remove-with-value
profile uses indexed ID membership. Lookup order never determines output sequence. Indexing
is rebuilt against each operation's current draft, so remove/re-add does not revive old metadata
and later operations see earlier changes. Retained immutable type/reference and read-only data
still go through their existing merge checks, including on add-existing; no positional transfer
of metadata to unrelated IDs is allowed.

Index construction, stable-ID classification, each key lookup/insertion, copying, merging,
validation and diff all consume the operation's same work budget. Key operations reserve work
before accessing the ordered tree, scaled by both key length and a conservative red-black-tree
height bound. The identity join uses logarithmic lookup rather than pairwise scans and is not
sensitive to Java string-hash collisions. Index memory is bounded by admitted input/snapshot
sizes and the work budget; it is private and discarded on refusal. PATCH keeps its generic
equivalence path for Group records without stable IDs; custom-schema array rules are unchanged.

For PUT, optional Group members without `value` no longer prevent unrelated membership changes
or clearing the entire array. After input normalization, such a row matches only the exact tuple
of its writable `$ref` and `type` fields, including absence. Explicit null normalizes to absence;
an empty or malformed `value` still rejects. Identical anonymous tuples consume current
occurrences once, in current order, retaining each occurrence's read-only display. Client-supplied
display cannot choose an occurrence. A changed/omitted tuple field or an additional occurrence
creates a new row without inherited server metadata; changing an anonymous tuple represents
removal plus addition, not an update identified by `$ref` or position. Assigned and anonymous
rows never borrow metadata from each other, even with the same reference. Removing a row and
later recreating it cannot revive its old display. Applications that need persistent member
identity should require assigned IDs. Anonymous tuple construction, ordered lookup and occurrence
consumption use the same work budget; references/types remain exact strings rather than URI
or case equivalence. The anonymous tuple rule applies only to standard Group PUT, not custom
schemas, PATCH equivalence or keyed membership reducers.

The default 4,000,000-unit work limit and every body/node/output cap remain unchanged. Focused
qualification covers representative 3,000-member operations at that default and 4,000-member
operations at the existing configurable 10,000,000-unit maximum, including protected metadata.
These are workload profiles, not a guarantee that every body of that cardinality fits: long IDs,
multiple operations, metadata, normalization and output have additional costs. A body/node cap
is independent of remaining work; the accounting model above and application workload profiles
determine admission. Input/mutation work exhaustion returns fixed `requestTooLarge` without a
partial candidate; response preparation has its fixed response-size/work error. Storage commit,
authorization, versions and timestamps remain application-owned.
