# Password hashing

`com.revetsec.password` hashes new application passwords with Argon2id and
verifies stored password hashes on the calling thread. It is independent of
OAuth, account storage and HTTP frameworks. The application owns password
enrollment policy, account lookup, per-account and network admission, sessions,
CSRF protection, durable credential updates and account recovery. A successful
password check does not commit a login or override an MFA requirement.
The [runnable Java 17 example](../examples/password-hashing/README.md) shows an
ephemeral pepper and a versioned rehash transition.

## Configure one shared hasher and work gate

```java
PasswordWorkGate workGate = PasswordWorkGate.withLimits(4, 262_144);

PasswordHasher passwords = PasswordHasher
    .withArgon2id(Argon2idParameters.withCosts(65_536, 3, 4))
    .workGate(workGate)
    .verificationLimits(PasswordVerificationLimits.fromDefaults())
    .build();
```

The example uses 64 MiB, three passes and four lanes per hash, the
[memory-constrained recommendation in RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4).
Benchmark the complete operation on production-class hosts and choose a
concurrent memory budget that leaves headroom for the rest of the process. Share
one gate across every password hasher and account population in the process.
The [synthetic workload probe](../verification/password/README.md) reports
per-call timings and gate refusals for selected Argon2id and bcrypt profiles;
its local sample is not a production sizing result.
Provision equivalent admission on every node and enforce account and trusted-edge
rate limits before submitting work. The gate limits local concurrent KDF work;
it is not a distributed login-attempt ledger. Builders perform no I/O and core
starts no worker threads.

The default `PasswordVerificationLimits` cap stored forms at 512 characters,
input at 1,024 UTF-16 code units and 4,096 normalized UTF-8 bytes, and Argon2id
verification at 128 MiB, six passes and eight lanes. A builder can narrow or
widen these ceilings within the library's fixed caps. A stored form is untrusted
input even when loaded from the
credential database. Its length, grammar, salt, tag and cost fields are checked
before allocating memory or performing the KDF. A stored cost over the configured
verification ceiling is rejected; the stored form cannot ask the verifier to
raise the ceiling. Keep a migration window only for bounded hashes you can
actually verify, then narrow or remove it.
Passing null to a limit-builder property restores its finite default.
`PasswordHasher.Builder.workGate(null)` clears a required setting, so `build()`
fails until a gate is supplied again; it never creates an unbounded gate.

## Enroll or replace a password

After the application approves a new password, calls its own blocklist and
policy checks, and confirms the authorized account, hash the supplied `char[]`:

```java
var result = passwords.hashResult(password);
if (result instanceof PasswordHashResult.Succeeded success) {
    String storedForm = success.getPasswordHash().getStoredForm();
    credentialStore.compareAndSet(accountId, expectedVersion, storedForm);
}
```

Only a confirmed `Succeeded` result releases a new `PasswordHash` stored form.
The application must check the compare-and-set result before treating password
replacement as committed. A failed or uncertain write cannot be reported as a
completed password change. Do not log the password, pepper or stored form. Treat
the stored form as a credential verifier: an attacker with a copy can attempt
offline guessing.

The method borrows the caller's `char[]` only for the call and does not retain
it. The caller clears it when finished. The new-hash profile applies NFC
normalization and strict UTF-8 encoding without trimming, case folding or silent
truncation. Its bounds are measured before expensive work. Legacy verification
must reproduce the historical application's password preparation exactly; do
not normalize a legacy password retroactively and assume the old hash will
still match.

Normalization and encoding create transient immutable Java string copies of the
password. Core cannot deterministically wipe those copies; they can remain in
memory until garbage collection. Clearing the caller's `char[]` and core's
temporary byte arrays reduces retention but does not guarantee erasure from the
JVM heap. Avoid additional string conversions, logs and heap dumps containing
passwords.

## Verify and upgrade during login

Select the account and enforce application-owned admission before calling the
hasher. Read the account's current credential version, stored form, disabled
state and MFA policy from authoritative storage:

```java
var result = passwords.verifyResult(password, storedForm);

if (result instanceof PasswordVerificationResult.Matched match) {
    if (match.isRehashRecommended()) {
        var upgrade = passwords.hashResult(password);
        if (upgrade instanceof PasswordHashResult.Succeeded success) {
            credentialStore.compareAndSet(
                accountId, expectedVersion, success.getPasswordHash().getStoredForm());
        }
    }
    // Recheck account state and complete the application's MFA/session flow.
} else if (result instanceof PasswordVerificationResult.Unavailable) {
    deferLogin();
} else {
    denyLogin();
}
```

The exact application flow must avoid granting a session from an obsolete
credential snapshot. A compare-and-set upgrade is opportunistic: its loss to a
concurrent password change must not overwrite that change. If the upgrade hash
cannot be produced or stored, continue only if the original verification and
fresh account-state check still permit login; retry the upgrade after a later
successful login. The library never writes account credentials or creates a
session. Recheck pending-login expiry, account status and any required second
factor when completing the application transaction.

`NotMatched` means the submitted password did not verify. `Rejected` means the
input or stored form is malformed, unsupported or outside the configured bounds; it
must not become a successful fallback path. `Unavailable` means the operation
could not make a safe determination, such as when admission or a required pepper
key is unavailable. Collapse these outcomes to a generic remote login response
while retaining bounded internal diagnostics. In particular, avoid exposing
account existence, hash format or upgrade policy through response text or
noticeable timing differences.

## Legacy migration is explicit

New credentials use Argon2id. Existing bcrypt and PBKDF2 hashes are accepted
only when the application explicitly enables the corresponding verify-only
operation:

```java
PasswordHasher migratingPasswords = PasswordHasher
    .withArgon2id(Argon2idParameters.withCosts(65_536, 3, 4))
    .workGate(workGate)
    .legacyBcrypt(LegacyPasswordPreparation.EXACT_UTF8, 14)
    .legacyPbkdf2(LegacyPasswordPreparation.EXACT_UTF8, 1_000_000)
    .build();

var bcryptResult = migratingPasswords.verifyLegacyBcryptResult(
    password, historicalBcryptStoredForm);
var pbkdf2Result = migratingPasswords.verifyLegacyPbkdf2Result(
    password, Pbkdf2Hmac.SHA256, historicalIterations,
    historicalSalt, historicalDerivedValue);
```

The application selects the call from a trusted credential-format field, not
from an attacker-chosen prefix. The bcrypt path accepts a bounded modular-crypt
stored form. PBKDF2 takes the historical salt, derived value, iteration count
and HMAC selection from the application's trusted schema; there is no generic
PBKDF2 string parser. `EXACT_UTF8` or `NFC_UTF8` must reproduce the actual
historical password preparation. The configured bcrypt cost and PBKDF2
iteration ceilings are checked before work. No API creates a new bcrypt or
PBKDF2 hash.

Benchmark the largest enabled legacy cost on production-class hosts before
opening migration. PBKDF2 checks thread interruption during its iteration
loop. The pinned bcrypt verifier checks interruption before and after its
calculation, but cannot stop a calculation already in progress; a cancelled
request keeps its caller thread and work-gate permit until that bounded bcrypt
cost finishes. Set the bcrypt cost ceiling and shared concurrent-call limit to
fit that worst-case time, and remove the migration path when it is no longer
needed.

On a confirmed legacy match, create a new Argon2id stored form and use an exact
credential-version compare-and-set. Keep the old stored form on a failed upgrade
write and let a future successful login retry. Bcrypt commonly uses only the
first 72 password bytes; do not treat a longer submitted value as an unqualified
full-password match or silently upgrade it. An application may require a
password reset for accounts affected by that historical truncation. Legacy
formats and excessive cost values must be rejected before expensive work.

## Pepper and rotation

Peppering is optional. If configured, the application supplies a coherent
snapshot through `PasswordPepperSource`: one active 32-byte
`PasswordPepperKey` for new hashes and the retained verification keys for
existing stored forms. The key is Argon2id's secret input `K` as specified in
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1), not an
extra unkeyed tag stored alongside the hash. A versioned envelope identifies
the key ID but never contains key material. Keep the key outside the credential
database and out of logs. Rotate by distributing the new key,
promoting it for new hashes, retaining old keys for verification, then upgrading
verified credentials. Retire an old key only after all relevant records and
backups are accounted for, or require resets for remaining accounts.
If the current policy has less memory or fewer passes than an old record,
verification suppresses rehash advice even for an old pepper key to avoid a
cost downgrade; raise the current policy to at least those costs or explicitly
reset or otherwise account for those records before retiring that key.

Pepper policy comes from trusted hasher configuration. A stored form cannot
disable pepper verification: a pepper-enabled hasher requires a peppered native
stored form, and missing or unavailable old keys fail closed as `Unavailable`.
There is no unpeppered fallback. Use a coordinated snapshot provider across
nodes so the same key ID always names the same material. Raw PHC forms are
accepted only by a deployment deliberately configured without pepper.

To adopt pepper for old unpeppered accounts, select an unpeppered hasher only
for a trusted old credential cohort. After a confirmed match, hash with the
pepper-enabled hasher and replace the exact credential version. Never let an
untrusted stored form choose which hasher or migration path to call.

```java
PasswordPepperKey active = PasswordPepperKey.fromBytes(
    "2026-10", activeKeyBytes);
PasswordPepperSnapshot snapshot = PasswordPepperSnapshot
    .withActiveKey(active)
    .retainedKeys(List.of(previousKey))
    .build();

PasswordHasher pepperedPasswords = PasswordHasher
    .withArgon2id(Argon2idParameters.withCosts(65_536, 3, 4))
    .workGate(workGate)
    .pepperSource(PasswordPepperSource.fromSnapshot(snapshot))
    .build();
```

The fixed source is suitable when the application replaces hasher configuration
to rotate keys. A dynamic source may return a fresh coherent `Available`
snapshot through `snapshotResult()`; inability to do so returns `Unavailable`.
`retainedKeys(...)` replaces the complete retained-key set; pass null to clear
it. An invalid replacement leaves the builder's previous set intact.
The application owns key provisioning and persistence. Explicit legacy
verification remains separately configured even on a pepper-enabled hasher;
use it only for a trusted historical credential format and policy.

## Deployment responsibilities

Use an authenticated encrypted channel for password submission. Permit long
passwords and all supported characters; apply a known-compromised-password
blocklist at creation or change. Keep a generous but finite input-byte limit to
protect the service. NIST recommends NFC for Unicode passwords, full-password
comparison, and account-based rate limiting; the library's local work gate does
not replace those controls. See [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
and the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Argon2id protects a stolen verifier against offline guessing to the strength
allowed by the chosen parameters and user password. It does not prevent online
guessing, credential stuffing, phishing, database rollback or a compromised
application runtime. Keep account recovery and MFA downgrade policy outside a
restorable password-hash record.

The [password primitive provenance and verification record](password-vendored-source.md)
identifies the pinned Argon2 and bcrypt sources, vectors and differential checks.
Those checks are not an independent audit. The
[external-review packet](reviews/password-primitive-external-review-packet.md)
states the remaining Argon2id/BLAKE2b review gate and how to reproduce the
source-bound evidence.
