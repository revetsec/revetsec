# Packaged public result handling

This unpublished consumer executes all 84 permitted variants across 16 TOTP and
WebAuthn mutation-result families. Each value comes from a genuine public service
call and must originate in the selected core JAR. It creates no library result or
proof through a private factory or access bypass.

Run `python3 run.py --output <fresh-private-directory> --java-home <jdk-home>
--core-jar <exact-core.jar> --core-sha256 <sha256>`. JDK 21 or 27 uses the default
`--consumer-release 21`: 16 exhaustive switches and 84 explicit arms, with no
fallback. JDK 17 uses `--consumer-release 17` and 84 explicit `instanceof` branches.
Java 17 does not compile the pattern-switch source. The core targets Java 17.

The original 109 service executions and 15-family producers are retained. Eleven
additional checked reauthentication executions reuse the public signed producer
and authenticator in `../webauthn-reauthentication`. They cover its nine existing
modes plus distinct post-commit time unavailability and permit-close failure.
The standalone producer still runs its original nine modes. No parser is copied.
The joined consumer checks exact callback, physical-mutation, read and close counts,
the original credential and ceremony tuple, all six proof fields, and payload
access only on eligible success. The 120 executions cover 84 unique leaves and
33 reconciliation results across all 16 families. The evidence has 101 distinct
counter rows; modes with different effects remain separate.

Every family supplies genuine reconciliation, uncertainty, prewrite unavailability
and eligible outcomes. Context rejection after checked completion may retain known
ceremony consumption. UNKNOWN is never retried or rescued by a read. Reconciliation
leaves have no inherited or declared payload fields or methods. The 21+ entry point
retains the earlier 11 ordinary TOTP routes.

Fixture stores use public SPIs and provide controlled timing metadata. These checks
do not establish trusted UTC, persistence, physical authenticator compatibility or
nonblocking backend contention. The existing default-worker WebAuthn fixtures retain
their measured three-second drift ceiling; a fixture stall is a failed precondition,
not permission to widen a product window.

The runner binds the core, preserved annotation dependencies, both producer source
sets and compiled classfiles. It downloads nothing. Sixteen omission plants remove
one reconciliation arm each: Java 21+ compilation must fail for nonexhaustiveness;
Java 17 source remains valid and genuine dispatch must reject the missing branch.
Earlier 15/79/109 receipts keep their historical source and artifact scope. Complete
native profiles, UTC/witness custody, hosted CI and release qualification remain
separate.
