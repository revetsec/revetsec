# Restrictive SCIM service clients

The complete Soklet Playground selects this volatile directory when at least one SCIM
credential is configured. ScimDirectoryPlayground runs the same policy and resource
configuration on its own. Build with the [example Maven setup](../examples/README.md#build-with-maven).

    export ORIGIN='https://localhost:8445'
    export SCIM_BEARER_TOKEN='<private random alpha administrator credential, 32–256 characters>'
    export SCIM_ALPHA_READER_TOKEN='<different private random alpha reader credential>'
    export SCIM_HTTP_HOST='127.0.0.1'
    export SCIM_HTTP_PORT='8082'
    java -cp "examples/playground/target/playground-1.0.0.jar:examples/playground/target/lib/*" \
      example.playground.ScimDirectoryPlayground

Supply credentials through the host's secret configuration. The values above are
placeholders, not credentials to deploy. Duplicate credentials or inconsistent trusted
registrations refuse startup. An absent setting registers no client.

| Setting | Tenant | Role | Credential changes |
| --- | --- | --- | --- |
| SCIM_BEARER_TOKEN | alpha | Provisioner | Allowed |
| SCIM_ALPHA_LIMITED_TOKEN | alpha | Provisioner | Denied |
| SCIM_ALPHA_READER_TOKEN | alpha | Reader | Denied |
| SCIM_BETA_BEARER_TOKEN | beta | Provisioner | Allowed |
| SCIM_BETA_READER_TOKEN | beta | Reader | Denied |

Roles and tenants come from these trusted registrations. Headers, cookies, query
parameters and submitted resource fields cannot assign them. Resource and discovery
operations require one bounded Authorization field using the Bearer grammar. Soklet
answers OPTIONS from static route configuration before application authentication;
that response grants no resource or state access. Unknown credentials receive
401; a registered caller outside its tenant or write authority receives 403. The
recipe provides service clients; it ships no account self-service role or enrollment
mechanism.

Canonical bases are ORIGIN/scim/alpha/v2/ and ORIGIN/scim/beta/v2/ for registered
tenants. /scim/v2/ aliases alpha while resource locations remain canonical.
SCIM_BASE_URI, if supplied, must be the same origin's canonical alpha base or legacy
alpha alias. Custom bases are rejected explicitly. The separate administrative
ScimPlayground interoperability fixture retains its earlier schema and base
configuration and rejects these tenant aliases.

Use an HTTPS edge with verified hostname/chain, exact public Host, raw-target and
duplicate-header rejection, bounded connection/body time and an isolated internal
HTTP route. This example does not establish HTTPS from a forwarded header. Cookies
are rejected; an optional Origin must equal the configured HTTPS origin.

Readers can use discovery, get, list and resource-specific POST .search.
Provisioners can create, replace, PATCH and delete within their registered tenant.
Attempted and effective field changes are checked. User writes allow externalId,
userName, displayName, selected name components, active and separately authorized
password. Privilege fields such as roles, entitlements and userType are denied.
Group writes allow bounded display/external IDs and distinct same-tenant User IDs.
Referenced Users cannot be deleted. This profile registers the DirectoryLabels
extension whose ordinary password label is explicitly not a credential; do not
put secrets there. It does not register the administrative fixture's Enterprise
extension or its extension-object PATCH path profile.

New resources require an external ID. External IDs are unique per resource type;
User names use one synthetic ASCII case-folding/uniqueness rule. Selected textual
fields are bounded to 256 printable ASCII characters. This is an explicit example
profile, not a Unicode preparation default. Filters permit EQ/NE and presence on
selected fields, with AND/OR/NOT, at most eight comparisons, 32 nodes and depth eight.
User fields are id, externalId, userName, displayName and active; Groups use id,
externalId and displayName. Sorting and index pagination are bounded; a requested
page above 20 is capped to 20. Password/privilege fields are not query capabilities.

Mutations of an existing resource require its exact weak ETag; a missing, malformed
or stale precondition receives 412. Each tenant holds at most 64 combined resources,
32 members per Group and 256KiB of charged state including stored hashes. Body,
request, query and response ceilings are 16KiB, 32KiB, 2KiB and 64KiB respectively.
The application admits at most eight concurrent operations. Its eight-second budget
starts at application entry and never resets; the framework bounds body materialization
and handler admission, and the edge must bound time before that entry.

Credential-enabled provisioners use the example's minimum-eight-character policy,
maximum 256 characters, Argon2id 19,456KiB/two passes/one lane, and a shared two-work,
38,912KiB gate. Password policy and hashing run outside directory protection. A
verified identical password is a no-op; credential removal through a PATCH remove
is rejected. Stored hashes are separate from SCIM resources and never returned.
The borrowed char array is wiped; parsed immutable JSON/body objects remain part
of the bounded request lifecycle. A deployment must choose its own password policy,
work profile, secret handling and credential service.

The directory confirms the original immutable snapshot and current principal under
one short lock after response preparation. Policy changes, conflicting state, clock
rollback, interruption or an exhausted original budget withhold prepared output.
An unavailable write with known no effect and a possibly applied UNKNOWN both yield
fixed 503 responses; neither permits automatic replay. A later GET reports current
facts and does not recover a lost acknowledgement. This is not a durable transaction
provider, shared deployment or distributed rate limiter. Restart loses resources;
service-client credential changes require controlled configuration/restart. Qualify
an actual deployment's persistence and admission policy before using this shape
beyond the local example.
