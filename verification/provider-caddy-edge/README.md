# Provider Soklet through pinned Caddy

This bounded verification runs the current provider recipe artifacts behind exact
Caddy 2.11.4 in fresh, isolated container network namespaces. The provider backend,
its fake JWKS listener, Caddy, the request observer and the probe bind only namespace
loopback. No port is published. The live desktop/SAML harness is never joined,
reconfigured or restarted.

The Caddy guard uses `{orig_uri}`, which is backed by the original Go `RequestURI`,
and rejects every provider-route target containing `?` before reverse proxy dispatch.
Checking `{orig_query}` is insufficient because it is empty for a bare delimiter.
The private calibration copy makes exactly that mistake: it must still reject
`?x=1`, then fail the named non-dispatch assertion when a valid signed Google
completion with a bare `?` reaches PIN56 and creates a session.

After building the current core and provider example artifacts and test classes:

```sh
python3 verification/provider-caddy-edge/run.py --output /absolute/new/output
```

The control covers raw HTTP/1.1 and HTTP/2 on all ten fixed provider routes, both
bare and nonempty queries, exact dispatch and provider-state nonmutation, normal
query-free Google completions on both protocols, direct PIN56 failing-before,
private CA/SAN verification, untrusted CA, wrong hostname, foreign Host and private
fixture-header spoofing. Receipts retain only statuses, counts and hashes. Generated
credentials, tokens, cookies, bodies, private keys and raw process logs are removed.
Process-log receipts hash a versioned, length-prefixed UTF-8 framing of stdout and
stderr and retain only the digest and per-stream byte counts. The framing controls
run with:

```sh
python3 -m unittest verification/provider-caddy-edge/test_run.py
```

A pass is local implementation evidence only. It does not designate or certify an
owner deployment, hosted Google/Apple account or device, distributed recovery, or
the final merged release candidate. The actual deployment/owner-designation gate
must remain open until the owner binds an approved ingress and private-backend
topology to this rule and its deployment-specific limits.
