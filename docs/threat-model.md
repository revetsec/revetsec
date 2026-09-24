# Threat Model

**Status: skeleton.** RevetSec contains no protocol code yet. This page is filled in as each protocol area lands, and it is complete before 1.0.0.

## Actors

The design considers these attackers:

- a malicious browser user attempting login CSRF, code or response injection, mix-up, or open redirects;
- a malicious tenant identity provider or OpenID Provider: in a multi-tenant application, one customer's IdP is hostile to every other customer and can assert any email, NameID or attribute;
- a network attacker (TLS is assumed, and RevetSec never downgrades it);
- an authenticated but hostile SCIM client;
- an attacker sending oversized, deeply nested or otherwise pathological input to exhaust resources;
- server-side request forgery through tenant-supplied issuer or metadata URLs;
- an operator who has changed JVM-wide security settings.

## Assets

Account identity (who is logged in, and as which tenant), session establishment, tokens and authorization codes, service-provider private keys and sealing keys, and provisioning integrity (which users exist and which groups they belong to).

## Trust boundaries

Browser to application; application to authorization server, OpenID Provider or identity provider (outbound HTTPS); identity provider to application (front-channel POST); SCIM client to application.

## Invariants and tests

Each security invariant is listed here with its stable ID and the tests or build checks that enforce it. Every listed invariant must map to at least one of them, and CI will check the map. Protocol invariants are added as the code that upholds them lands. The "Security Invariants" section of [SECURITY.md](../SECURITY.md) will carry the same list.

### Packaging

| ID | Invariant | Checked by |
|---|---|---|
| INV-L1 | The RevetSec JAR has zero compile or runtime dependencies, and it needs no JDK modules other than `java.base`, `java.net.http`, `java.xml`, `java.xml.crypto` and `java.logging`. | The Maven Enforcer `bannedDependencies` rule in `pom.xml`, which fails the build on any compile- or runtime-scope dependency. [`verification/verify-published-pom.py`](../verification/verify-published-pom.py), which checks the installed POM. [`verification/packaged-consumer/verify-packaged-consumer.py`](../verification/packaged-consumer/verify-packaged-consumer.py), which requires a Maven consumer's runtime class path to be exactly the RevetSec JAR and `jdeps` to list only those modules. CI's `packaged-consumer` job runs both scripts on JDK 17 and 27; see [verification/README.md](../verification/README.md). |

## Non-claims

See "Security Boundary and Non-Claims" in [SECURITY.md](../SECURITY.md).
