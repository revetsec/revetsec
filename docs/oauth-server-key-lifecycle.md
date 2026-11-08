# Issuer key publication across processes and restarts

An OAuth issuer's `OAuthIssuerKeyProvider` supplies trusted lifecycle declarations. The application owns publication, retained verification keys and recovery of those declarations across every signing node and restart. The issuer checks the snapshots it observes; it does not store a distributed key history or discover which keys an earlier process used.

Use this recipe with the [issuer application contracts](oauth-server-application-contracts.md#issuer-signing-keys-and-public-metadata) and [configuration rollout procedure](oauth-server-application-contracts.md#configuration-changes-across-restarts-and-nodes). It concerns the issuer's RS256 keys. [Standalone JWKS publication](jwks-publication.md) has its own API and does not supply the issuer's lifecycle history.

## Persist the lifecycle declaration

Keep one authoritative application record for each issuer, protected by the application's normal authorization, durability, concurrency and restore controls. A suitable record contains:

| Durable fact | Purpose |
|---|---|
| Current generation and its publication instant | Rebuild the same immutable `generation` / `publishedAt` declaration on every node. New generations have strictly later publication instants. |
| Current active key ID and reference to its private signer | Select the same active key everywhere without putting private material into public metadata. |
| Published key IDs and their exact public material | Preserve the verification set and reject assigning an existing ID to different material. Keep the material binding after a key leaves the current set. |
| Publication acknowledgement for the generation's exact public representation | Establish that its keys reached every serving JWKS path and required distribution destination before declaring publication. |
| First publication history and retention obligations for each key | Preserve publication age and required verification overlap after a process stops. |
| Recovery/fencing identity for the authoritative record | Prevent an older backup, stale writer or isolated node from silently replacing current history. |

`getSnapshot(remainingBudget)` receives a remaining time budget. It receives neither the candidate access-token expiry nor a durable notification of successful issuance. A provider cannot reconstruct a global retention floor by watching callback invocations. Persist a conservative retention promise **before** permitting the issuance that depends on it. Failed signing or uncertain issuance can still require the conservative promise to remain.

One workable policy is to declare finite `retirementNotBefore` values in advance. For a candidate expiry E, a key must remain published through at least:

`ceil-to-whole-second(E + clockSkew + totalDeadline + publicMetadataHttpCacheMaxAge)`

Choose E to cover the latest expiry any serving node or already admitted operation may issue under the applicable configuration. Account for in-flight work when changing the active key; if that bound is uncertain, quiesce and drain issuance first. The issuer refuses a candidate whose configured requirement exceeds the declared retirement boundary. It does not extend the provider's durable promise automatically. Increasing a boundary requires a new consistent generation; keep any older, longer promise.

A key with no declared retirement boundary cannot simply disappear from the next observed snapshot. An application that previously allowed indefinite overlap must establish its actual outstanding obligations before declaring finite retirement. Absence of a local in-memory reservation after restart is not evidence that no tokens remain.

## Publish, activate and retain

1. Generate or load the next key through application-owned key management. Use a fresh key ID, retain its exact public-material binding, and keep private material out of JWKS and diagnostic logs.
2. Create a new immutable generation containing the old verification keys plus the new public key. Persist the retained-key obligations. Publish the exact public set through all serving JWKS routes and other required destinations. Only after those destinations are ready may the provider declare that generation published. `publishedAt` is the actual publication declaration; setting it to an earlier time does not distribute a key.
3. Keep the new key available for the full configured `publicMetadataHttpCacheMaxAge` before signing with it. A node that observed the staged key remembers its first publication and can activate it after that wait. An activation changes the generation's facts, so give it a new generation and strictly later publication instant even if the public set is unchanged.
4. Retain the old public keys and their previously promised boundaries in the activation generation. Every node returns that same declaration under the original operation budget. Do not let one node recreate a snapshot from an isolated local key directory or an older deployment configuration.
5. Remove an old verification key only after its durable retention obligations have ended and no old node or in-flight operation can still depend on it. Publish a later generation without it. Keep the retired ID/material history; retirement does not authorize assigning that ID to different material.

The current snapshot can be constructed using the existing API:

```java
// These values come from one checked application-owned lifecycle record.
OAuthIssuerKeySnapshot snapshot = OAuthIssuerKeySnapshot
    .withActiveKey(activeSigningKey)
    .generation(generation)
    .publishedAt(actualPublicationInstant)
    .verificationKeys(publishedPublicKeys)
    .retirementNotBefore(retainedKeyBoundaries)
    .build();
```

This construction checks the declaration's shape and public projections. It does not acknowledge external publication, write durable history or discover a missing prior key. `OAuthIssuerKeyProvider.fromSnapshot(snapshot)` is appropriate for an intentionally fixed declaration; it does not add persistence or coordinate rotation.

## Starting a new process

Read the current authoritative declaration and its recovery state before admitting signing traffic. Return its original generation and publication instant. Rebuilding an unchanged generation must not reset its publication time to startup time, or backdate a new generation to avoid waiting.

A fresh lifecycle instance has no per-key observation history. If the current generation activated an already-staged key, the fresh instance conservatively waits from **that generation's** `publishedAt`; it cannot inherit another process's remembered earlier staging observation. A warm node may therefore sign while a correctly configured replacement node is still unavailable. Allow for that wait in readiness and rollout scheduling. Do not change the timestamp to force readiness.

Publication and overlap checks also run when an admitted signing operation uses store-authority time. Provisional metadata observations and admitted signing/status observations have separate histories. A successful metadata request does not transfer publication history into a different process or prove that the required external destinations received the key.

For example, with a 60-second public metadata cache age:

| Logical time | Durable declaration | Expected behavior |
|---|---|---|
| T−120 | g1: A active; A retained through T+1000 | Nodes may sign A at T. |
| T+40 | g2: A active; A and B published | A node that reads g2 observes B's staging time. |
| T+100 | g3: B active; A and B retained | The node that observed g2 can sign B. A node that missed g2 waits. |
| T+160 | g3 unchanged | A restarted process can sign B after the complete 60-second g3 wait. |
| T+1000 | g4: B active; A removed after its promise ends | Existing processes accept A's removal. A fresh process still has its own generation publication wait before signing. |

The example assumes the declared bounds cover all issuance in the scenario and the publication destinations satisfy the application's distribution contract. The logical times illustrate the calculation; a real deployment needs its actual publication acknowledgements and trusted time/recovery evidence.

## Concurrent provider responses

Provider callbacks run outside the local lifecycle lock and use the original operation's shrinking budget. If a response from one callback has been overtaken by a newer accepted generation in that same history, the issuer releases the lock and reads the provider once more. It validates that response against the latest accepted history. A second overtake, ordinary rollback, changed facts for one generation, backward time, or invalid publication/retirement obligations still refuses the operation. The guard never replaces newer history with the older response.

This is one bounded provider read for local ordering; it does not retry a token request, signing operation or store mutation. Signing still reserves the selected key's retention and checks the provider again after signing before output can be prepared. Provisional and admitted histories remain separate. The re-read adds no durable distribution, cross-node ordering or restore guarantee.

## Recognition and lifecycle failures

Resource admission first recognizes the token's signature and fixed profile against the public keys in the provider's current snapshot. This step does not consult remembered temporal lifecycle history, read the authoritative store or release a proof. If a token's `kid` is absent, recognition returns the fixed `UNKNOWN_KEY`/`INVALID_TOKEN` rejection. The self-issued MCP application maps that rejection to 401 with a bearer invalid_token challenge. No historical-key fallback is used to make an otherwise unrecognized token reach storage.

A token signed by a key still present in the snapshot can reach the admitted lifecycle checks under store-authority time. If the provider has removed another previously observed key before its promised boundary, those checks fail as infrastructure unavailability. The self-issued application maps that failure to 503 with no bearer challenge; JWKS publication also refuses the invalid declaration. Recognition success alone grants no token or resource authority, and neither failure releases a checked proof.

The status therefore depends on the checkpoint reached. A 401 for a removed-key token is not evidence that the provider declaration or backend is healthy, and no operation promises to diagnose every infrastructure fault before rejecting unrecognized input. Providers must still preserve durable publication/retention facts and restore admission. The disposable [PostgreSQL application fixture](../examples/postgresql-pending-store/README.md) checks removed-key rejection, retained-key lifecycle failure and recovery of both tokens when the overlap is restored. These are local fixture/source boundaries, not a new production deployment guarantee.

## Unavailable history and restore

If the provider cannot load its durable declaration, cannot verify the associated publication acknowledgement, or finds a conflicting key/material binding, fail the callback. Keep signing traffic closed while the application reconciles the authoritative state. Do not fall back to a newly invented initial snapshot, an empty history, the current public JWKS alone, or the active private key alone. Public JWKS does not describe historical retention obligations, activation authority or recovery state.

A fresh issuer can accept a well-formed but incomplete initial snapshot. For example, if a provider omits A while an older A-signed token and its retention promise remain outstanding, a fresh process cannot infer A from a declaration containing only B. A warm process may reject the omission because it remembers A; that local guard does not repair the provider's lost history. Such an initial declaration violates the provider contract even when construction or signing succeeds.

After key-store or issuer-store restoration, fence stale writers and reconcile the application lifecycle record with actual issuance and publication obligations before reopening traffic. Follow the issuer's explicit revocation/recovery procedure when required; a withheld acknowledgement or UNKNOWN result still requires factual reconciliation. Preserve required public verification keys while doing so. Revocation fences do not erase retention promises or replace distribution to verifiers that depend on the published keys.

This recipe leaves repository choice, publication acknowledgements, private-key storage, cross-node fencing and backup recovery with the application. Validate those controls for the deployed backend and serving topology; process-local observation history cannot supply them.
