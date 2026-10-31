# Private shared-clock witness components

**Closed migration integration — 2026-10-30:** the [migration/restore fixture](../shared-clock-migration/README.md) uses this component's privileged administrative observations under a matching closed intent. The [native PostgreSQL interlock](../shared-clock-postgresql/README.md) supplies the separate SQL control boundary. These component uses do not establish approved UTC, platform durability or a qualified shared profile; the original SCP-04 scope below remains historical.

This unpublished verification helper is the SCP-04 candidate for the selected one-host Linux fixture. It adds no core API, store, background worker, daemon, socket server, SQL change or active application integration. Explicit fixture control owns its lifecycle. Existing normal store reads and writes still use their existing implementations.

Run the component checks with Python 3.13 or newer and a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 verification/shared-clock/run_checks.py --output /absolute/fresh-output
```

The runner records actual unittest cases, failures, errors, skips, source hashes, JUnit XML and host identity. A skipped case, empty discovery or source change during the run fails acceptance. Scripted captures establish component behavior only. Real Linux CLOCK_BOOTTIME reads establish availability of that primitive only.

## Components and trusted boundaries

`witness_capture.py` defines the read-only Linux clock adapter and checked-capture boundary. A deployment-owned, bounded `reader(deadline_ns)` supplies contemporaneous UTC plus conservative error terms. `SourcePolicy` pins source, daemon, configuration, source-evidence, clock-configuration and step identities. The identity reader must establish those facts before and after capture; they cannot come from untrusted request fields. The live continuity provider must continue to establish the pinned elapsed/rate/step assumptions through publication.

The complete uncertainty is the sum of absolute remaining correction, root dispersion, half root delay rounded upward, separately justified upstream error, reference-age drift rounded upward, the full capture bracket and conversion/quantization. This deliberately permits conservative double counting. The adapter rejects a bracket above 25 ms, reference age above 16 s, update interval above 8 s, non-Normal leap state, local fallback, missing external authentication or complete uncertainty above 125 ms. It checks the UTC uncertainty endpoints against the common range and uses integer nanoseconds throughout.

No chrony reader or approved upstream is installed by this slice. A configured identity, authentication flag or evidence commitment does not establish UTC accuracy. The real reader must justify its source custody/authentication, contemporaneous error and freshness bounds, source/configuration/step race handling and bounded subprocess calls. This is an explicit qualification dependency. Synchronous Python rejects a late return; it cannot interrupt arbitrary blocked reader/identity/continuity code. Those trusted providers must obey their original deadlines.

`witness_storage.py` opens an explicitly provisioned private directory without following symlink components. `DirectoryOwner` retains a nonblocking OS lock until close/process exit, checks process and inode identity, and shares one control-writer lock and rollback high-water state across its store wrappers. The final directory must be owned by the current identity with mode 0700; lock, temporary and manifest files must be owned regular single-link files with mode 0600. Same-UID privileged control is trusted and must not fork a replacement owner while retaining inherited descriptors.

`ManifestStore` accepts a bounded canonical JSON manifest of at most 16384 bytes, exact fields/types, unique keys and a uint64 control sequence. CAS compares the complete expected manifest, advances the sequence exactly once, never lowers the reserved ceiling and never silently rebinds the selected scopes/profile. Identity changes require a closed pending transition. Writes use an exclusive temporary file, complete write, file fsync, atomic rename and directory fsync. A failure without known durable acknowledgement never grants the proposed entitlement. Genesis provisioning requires an explicit never-used assertion; missing files are never repaired by a read or a CAS.

Live-owner sequence/ceiling/content rollback is detected. A new process cannot infer that a syntactically valid older manifest was restored. Prevention of fresh-process rollback, witness loss, co-restoration, directory replacement and device power-loss failures requires the separately protected external custody/durability evidence. Neither a new UTC capture nor the authentication database reconstructs a lost prior maximum.

`witness.py` holds the runtime anchor, elapsed identity, exclusive health end and publication lock only in memory. It projects `T(b) = A + (b - b0)` without reanchoring a generation. Explicit renewal is due each 10 seconds and reserves a 30-second exclusive horizon. The published profile remains UTC error 250 ms, authority rate 2 and worker offset 5 seconds. At capture, projection offset must be at most 100 ms, with the separately attested elapsed error at most 500 ppm.

Every ordinary/query/admin point is freshly sampled under the publication lock and is below a ceiling already acknowledged durable. Control capture and fsync occur outside that lock. While a reservation is pending, concurrent reads can consume only the old window while its own health remains valid; an unacknowledged visible higher ceiling grants no extension. Ordinary observations perform no witness write. Requests use the shrinking original BOOTTIME deadline and a maximum 100 ms request interval; lock waits count. Explicit control calls create no automatic retry or scheduler thread.

A failed capture closes health. Same-owner resumption requires the original in-memory projection, continuous elapsed/boot/rate identity, matching current admission and no pending transition. Lost elapsed/owner/boot/rate continuity requires a new generation. A fresh runtime never reads an anchor from disk and requires checked UTC's lower endpoint to reach the durable prior ceiling. It never clamps UTC upward. Authority and recovery identity are not reset by clock restart.

Ordinary `sample` accepts only its own allowlisted scope mirror plus the exact authority/recovery/clock/profile tuple. `administrative_sample` returns a separate type only in MIGRATING with the exact closed-intent commitment and the same projection/reservation rules. It cannot authorize ordinary timed writes, issue credentials or bypass retained-data checks. RECOVERY_CLOSED and pending transitions admit no sample. This slice supplies no issuer FENCE_ONLY dispatch.

## Control checkpoint for the next slice

`Witness.start` consumes an already prepared UTC_CLOSED manifest (MIGRATING for privileged administrative time), current owner/boot identity and known old clock generation. Only explicitly provisioned genesis accepts no previous generation. The caller supplies exact all-scope admission commitments after the external/SQL checkpoint; ordinary calls need only their own scope. These private inputs are trusted component fixtures, not capabilities proving SQL commitment or writer exclusion.

SCP-05 must implement and test the actual all-scope exclusive SQL admission transition, old-role/session quarantine and external/SQL agreement before activation. The control owner must retain closed pending intent while outcomes are uncertain. This helper does not perform that transition, provision database roles, close routes or certify a supplied metadata list. It also does not perform migration, restore or inventory.

The component suite covers strict encodings, real OS owner exclusion, crash/syscall fault boundaries, projection/capture limits, publication ordering and continuity controls. Actual authenticated chrony 4.9 source accuracy, Linux clocksource/frequency/slew calibration, worker elapsed/suspend behavior, genuine cold-start custody, device durability and PostgreSQL interlock remain open. No complete witness profile, conformance case group, lane C/D or release gate passes from these checks.
