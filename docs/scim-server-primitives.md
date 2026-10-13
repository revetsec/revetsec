# SCIM server primitives

The schema, resource, query and response APIs are implemented for Java 17. PATCH, the optional filter evaluator, provisioning examples and provider interoperability qualification follow in later milestones. These APIs prepare application-owned work; they do not authenticate callers, query a database or commit changes.

Configure `ScimServiceProvider` with a trusted base URI, resource types and truthful capabilities. User and Group registrations include the standard schemas; User also registers the optional Enterprise extension. Custom schemas have bounded immutable definitions, with 1,024 definitions per effective resource type, 32 types and 64 schemas per provider. Application registrations cannot occupy the reserved discovery type names or endpoint paths. Applications enforce advertised uniqueness and reference existence.

```java
ScimResourceType users = ScimResourceType.userInstance();
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

Every advertised filterable resource type needs an explicit policy. `rejectAllInstance()` disables filtering for one type. Syntax success alone grants no permission. `parseFilterResult` resolves registered schema paths, canonicalizes names and legal implicit `.value` comparisons, checks literal types and applies the entire policy. It returns exactly the approved tree. Flat comparison permission does not grant ValuePath permission; AND, OR and NOT need explicit permission. Unknown paths and `returned:never` paths cannot be filtered or sorted. Query execution and value-level authorization remain application responsibilities.

Use `parseQueryResult` with the original raw query string. Decoding preserves physical multiplicity, maps plus to space, validates percent escapes and UTF-8, and rejects duplicate recognized parameters, including ASCII case variants. Unknown parameters are ignored only after bounded decoding. `parseSearchRequestResult` accepts the equivalent JSON SearchRequest form, including its required message schema; unknown fields reject. Body parsers have header-aware overloads for HTTP and byte-only overloads for previously validated framing.

Queries expose a bound filter, projection, sort path/direction and pagination request. Sorting is a description for the application: multi-valued sort uses primary then first, absent values go last ascending or first descending, and stable ID tie-breaking is application-owned. Unsupported sort requests reject. String matching must agree with the backend's attribute-specific preparation and collation; the library supplies no general Unicode matching default.

Index pagination defaults to startIndex 1 and count 100, with maximum 1,000. Negative count becomes zero and startIndex below one becomes one. Index counts clamp to the configured maximum. The original requested count remains available. Enabling cursor pagination requires an explicit timeout commitment. Cursor counts exceeding the maximum reject; cursor plus startIndex rejects. Empty or omitted cursor denotes the first cursor page. Cursor strings use unreserved ASCII. The application authenticates and binds cursors to tenant, caller, permissions, resource type, approved query, sort, projection, page size and expiry.

Build `ScimListPage` with its originating query, actual resources and accurate page metadata. Index pages require totalResults. Cursor pages declare more results exactly when nextCursor is present; a short page alone does not prove exhaustion. The first cursor page cannot have previousCursor. A count-zero cursor response is a count-only operation: accurate totalResults, empty Resources and no traversal cursors. This exact-total requirement is the selected Revetsec profile.

`parseResourceResult` prepares a create candidate. It ignores submitted readOnly fields before checking required values. `parseReplacementResult` applies PUT semantics to an immutable current resource: preserve readOnly and assigned immutable values, clear omitted readWrite values, reject immutable changes, then check required fields and extensions. Failure preserves the original. A supplied complex object clears omitted writable children while retaining protected children.

Group member replacement reconciles protected metadata by exact member `value`, allowing add, remove and reorder without transferring metadata between IDs. For custom multi-valued complex attributes containing assigned protected descendants, replacement accepts the unchanged sequence and rejects ambiguous changes; it does not guess element identity from array position. Applications needing different semantics must define an explicit identity contract in a later API extension.

Wire INTEGER values reject fraction and exponent syntax, including `1.0` and `1e0`, at every bound position. INTEGER values are exact bounded integers, without an invented 64-bit restriction on resource attributes. DATE_TIME follows XML Schema dateTime, including optional timezone, valid calendar dates and legal 24:00 notation; server metadata exposed as `Instant` additionally requires an offset and representable range. Relative references are allowed and never fetched. Binary padding is optional. Canonical values are suggestions, not a mandatory whitelist.

After authorization, uniqueness/reference checks, password handling and atomic persistence, use `createdResponseResult` or `replacementResponseResult` with the parse result's actually supplied canonical paths. This bare path set is trusted application provenance: the renderer validates its paths against the target schema, but the set does not retain its originating parser or configuration. Assign authoritative IDs, versions and timestamps in trusted resource construction. GET uses `resourceResponseResult` without write provenance. Projection always removes `returned:never`, retains `returned:always`, and reveals `returned:request` only when explicitly selected or actually supplied for that write. A broad supplied complex parent does not expose unrelated stored request-only children. Response preparation requires an assigned ID, checks resource/type/selection associations, emits defensive bytes and headers, and enforces output, header and aggregate work bounds before buffer growth.

Create responses use status 201 and a Location derived from the trusted base, type endpoint and one encoded ID segment. Submitted Host/Forwarded/meta values do not choose the location. An existing meta.location must agree; the response carries the authoritative location. Responses include ETag from meta.version when enabled and use private/no-store. `notModifiedResponseResult` prepares bounded bodyless 304; fixed errors and 204 fit minimum output budgets. Adapters preserve the prepared bytes, status and original header occurrences.

If-Match and If-None-Match accept absent fields, an isolated wildcard, or valid tag lists across physical fields. Malformed or oversized lists reject. Both use weak opaque-version comparison by the approved SCIM profile; If-Match deliberately differs from general HTTP strong comparison. Wildcards test the existing resource even without a version. Tags cannot match a versionless resource. Applications must check write preconditions against the same locked or version-predicated resource they commit.

Discovery emits Schema, ResourceType and ServiceProviderConfig representations, including required capability subfields, disabled Bulk and RFC 9865 pagination metadata. Unknown schema/type returns 404; discovery filters return 403. The host owns GET-only routing and 405 handling. Schema descriptors reflect primary RFC text and selected errata with their actual status; reported or held proposals are not described as verified corrections.

Strict compatibility is the default. Explicit relaxations used by these operations include exact `"true"`/`"false"` boolean strings, narrow post-ValuePath subattribute comparisons rewritten into the same element predicate, inferred missing extension declarations, ignored undeclared schema URIs and ignored unknown attributes. Broader preset features pertaining to PATCH are reserved for its implementation. Scalar complex conversion remains outside the Entra preset. Observer events report fixed operation/outcome/feature names and never request values or exceptions.

Queries, selections and parsed resources, including resource copies, retain private registration and compatibility provenance. A base-URI-only copy can reuse them. A copy with changed compatibility requires fresh parsing; a relaxed result cannot be rendered through a stricter provider. Trusted application-authored resource construction is deliberate data construction, not a request or authorization proof. Builders and copiers perform no I/O or callbacks; null setters restore their documented defaults.
