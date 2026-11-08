# Soklet edge and browser component verification

This is a bounded, disposable verification fixture for the selected logout (R2)
and Google/browser plus Apple/native provider-token (R9/R10) recipes. It does not
install or configure a production edge. The two route profiles are independent:
`/logout` has a different request contract in each application.

`edge.py` inspects the original HTTP/1 request target before one backend dispatch.
It rejects every query delimiter, including a bare `?`, on the selected start,
provider and resource routes. Logout's callback permits only its bounded singleton
canonical state. The edge also checks exact Host, path/method, security-header
multiplicity, untrusted forwarding/private headers, framing, complete bounded
bodies and chunked overflow. It never substitutes a valid prefix, retries a
backend request, or treats an arbitrary Forwarded header as authority. The private
backend fixture credential is injected after these checks. Sixteen nonqueued
connection permits, timeouts and an original eight-second edge budget bound this
fixture. An owned socket-shutdown watchdog enforces that original budget even
when bytes keep arriving; slow progress cannot renew it. It closes connections after a single response.

An ephemeral CA signs a one-day leaf with `DNS:app.example`. Python's normal TLS
client uses only that CA, requires chain validation and hostname checks, and has
separate untrusted-CA and wrong-host negative controls. Chrome uses its normal
sandbox, a fresh disposable profile, and an exception scoped to that leaf's SPKI.
**The Chrome exception is not proof of normal chain or hostname validation.** No
system/browser trust store, DNS, privileged port or machine configuration changes.
The fixture-only CONNECT tunnel accepts exactly `app.example:443` and maps it to
the owned dynamic loopback TLS listener; browser URL, Host and Origin remain
`https://app.example`. A foreign destination is refused.

The static verification page permits same-origin fetch only. Browser results
exercise real Origin/cookie behavior, Google signed-token validation and session
rotation, resource policy and local logout. R2 bootstraps a cookie from genuine
core authentication in the private fixture, verifies its original attributes,
and installs that issued cookie into the fresh browser. It exercises local close,
prepared FORM delivery and correlated return; it does not submit the OP form.
The prepared OP action remains the original **HTTP loopback fixture** endpoint.
There is no provider-HTTPS, hosted-provider UI, Google widget, Apple-device or
provider-session-termination claim. The Apple native flow separately uses normal
verified TLS without ambient cookies/Origin. An ordinary browser native POST is
denied; this is not an oracle for arbitrary browser or device provenance.

`run.py` requires a selected-input JSON containing explicit JAR paths and SHA-256,
normal reactor receipt/source manifest identities, selected Java source hashes,
and exact test-only socket-fixture class closure hashes. It measures actual JAR
origins with an annotation/JUnit-free Java17 checker and rejects classpath shadowing.
The unused Soklet helper may be identity-checked in the selection; these two raw
Soklet recipes do not thereby exercise its APIs. Historical differently rebuilt
JARs do not inherit proof from a new selection.

On the qualification host (JDK21/27, OpenSSL, Chrome and Node with native WebSocket):

```sh
python3 -m unittest -v test_edge test_edge_budget
python3 run.py --selected /absolute/selected-inputs.json --output /absolute/new-output --profile logout --jdk 21
python3 run.py --selected /absolute/selected-inputs.json --output /absolute/new-output-provider --profile provider --jdk 21
python3 calibrate.py --selected /absolute/selected-inputs.json --output /absolute/new-calibration
```

The selected profile is run again on JDK27. Core/common artifacts remain release17;
Soklet's listener requires21 or newer. The runner's JDK homes are the qualification
host's `/Users/agents/Java/amazon-corretto-{21,27}.jdk/Contents/Home`.

Named receipts contain statuses, counts, hashes and fixed checks. Tokens, cookies,
HTML, request bodies, CDP messages, debugger endpoints and private fixture
credentials stay in process memory. Raw Chrome logs are hashed then removed.
Temporary private CA/leaf keys, runtime copies and browser profiles are removed;
owned JVM, Chrome process group, TLS workers and CONNECT listener are checked for
cleanup. Public CA/leaf certificates are the only retained certificate material.

`calibrate.py` copies only this verification source to private directories. Seven
pure parser plants, an actual slow-progress budget plant, two genuine current-engine bare-query effect plants and two
TLS/tunnel guard plants must fail named assertions with green controls. Import,
compile, setup and timeout failures do not count as detection. The genuine query
plants demonstrate why the raw guard is required: pinned Soklet drops a bare
query before creating Request, allowing an otherwise authorized logout close or
signed provider completion when the edge guard is removed. No recipe/framework
fix or production failing-before claim is made.

These component receipts do not certify a deployed ingress, durable stores,
external provider/browser combinations, other recipes or the final merged RC.
Pre-dispatch parser/transport failures cannot promise application cookie clearing.
