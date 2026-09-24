# Supported Algorithms

**Status: skeleton.** RevetSec contains no protocol code yet. Each table is added when its protocol area lands, and the page is complete before 1.0.0.

Algorithms come from allowlists configured on the validating object, never from the message being validated. Names are compared exactly: JOSE `alg` values case-sensitively, and XML Signature and XML Encryption algorithms as exact URIs.

For each area, the table will have three columns:

- **Default:** accepted without configuration.
- **Opt-in:** accepted only after the application names it explicitly, sometimes as a [compatibility mode](compatibility-modes.md).
- **Never:** rejected under every configuration.

Planned areas:

- JWS for ID tokens and JWT access tokens
- JWS signing for client assertions
- XML Signature: SignatureMethod, DigestMethod, canonicalization and transforms
- SAML HTTP-Redirect binding signatures
- XML Encryption: content encryption and key transport
- Key types and sizes
