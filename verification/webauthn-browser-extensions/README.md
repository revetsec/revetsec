# Disposable WebAuthn extension evidence

This test-only harness joins native browser JSON APIs with the current public relying-party
registration/authentication API. It uses a CTAP2.1 virtual USB authenticator, disposable profiles,
a loopback HTTPS edge and leaf-SPKI pin. It does not access the OS authenticator or a physical key.
The Java peer uses the existing test-only atomic store and controlled test authority/worker time.
It has no production server endpoint and is not a store/recovery implementation.

Compile core and test classes first. Compile `java/com/revetsec/webauthn/BrowserExtensionWorker.java`
into a private output directory with those classes and the pinned annotation dependencies on its
classpath. Prepare private TLS with the passkey recipe's `prepare_tls.py`, including exact SANs
for `passkeys.example.test` and `login.passkeys.example.test`. Keep `leaf.crt`/`leaf.key` in the
private work directory's `private-tls` subdirectory; never add them to source or system trust.

Set `REVETSEC_PLAYWRIGHT_MODULE` to an installed Playwright Core module, `REVETSEC_CHROME` and
`REVETSEC_CHROMIUM` to the two explicit browser executables, and `REVETSEC_JAVA` to Java 21.
The harness does not download or install these dependencies. Run:

```sh
node verification/webauthn-browser-extensions/browser-evidence.mjs \
  /absolute/private-work /absolute/worker-and-core-test-classpath
```

The private report contains browser versions, API capabilities, allowlisted output shapes and
typed outcomes. Raw credential IDs, client/authenticator bytes, signatures, public/private keys,
user handles, TLS files and payload hashes are not retained in it. The script removes its Chrome
profiles, removes each virtual authenticator and closes owned peers/browsers; remove the private
TLS/output directories after checking.
Never use its fixed synthetic sealing key for real account data.

At this checkpoint four native profiles pass: exact RP host and explicitly configured child
origin in Chrome 156 and Chromium 149. Both registration and authentication succeed in each,
with twelve no-mutation injected rejections per profile (48 total). Parent and child profiles
use singleton exact allowlists, proving that another eligible origin is not implicitly trusted.
The report status is `PASS_NATIVE_ORIGIN_PROFILES`. Firefox/WebKit runs are capability-only
and deliberately use context-local TLS verification bypass; they claim no WebAuthn ceremony or
interop and patched WebKit is not installed Safari. Conditional mediation availability is only a
feature probe. Physical/platform/synced providers and installed Safari remain unproven; the
passing native-profile status is not full browser qualification.
See the [current policy and target matrix](../../docs/webauthn-browser-compatibility.md).
