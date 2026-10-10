# Offline SAML schema sources

These six XSD files are unmodified copies fetched on 2026-10-10. They are used only
inside the unpublished scripted IdP test image to validate Revetsec-generated
AuthnRequests and SP metadata. `scripted_idp/schema.py` verifies their SHA-256 values
at startup and resolves imports only to this directory. Runtime network fetches are
disabled.

| File | Official source | SHA-256 |
| --- | --- | --- |
| `saml-schema-protocol-2.0.xsd` | [OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd) | `554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e` |
| `saml-schema-assertion-2.0.xsd` | [OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd) | `006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b` |
| `saml-schema-metadata-2.0.xsd` | [OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd) | `204bc7991055dbb889307abbd2ff58022753897dd7064a4d1ca13eb737d2617a` |
| `xmldsig-core-schema.xsd` | [W3C](https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd) | `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c` |
| `xenc-schema.xsd` | [W3C](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd) | `5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e` |
| `xml.xsd` | [W3C](https://www.w3.org/2001/xml.xsd) | `61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c` |

The OASIS SAML 2.0 schemas are part of the [OASIS SAML 2.0 standard](https://www.oasis-open.org/standard/saml/).
The W3C XMLDSig schema carries the Internet Society and W3C copyright notice in
its source and points to [W3C legal notices](https://www.w3.org/Consortium/Legal/).
