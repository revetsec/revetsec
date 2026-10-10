#
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Small, strict on-demand SAML Response producer for the scripted test IdP.

The output is deliberately expired by default when committed as a fixture. Every caller
supplies an absolute clock, and the test-only signing keys are mounted, never baked into
the image. This module is a producer, not a source of authority for Revetsec's verifier.
"""

import base64
import copy
import datetime
import html
import pathlib
import secrets
import urllib.parse

import xmlsec
from lxml import etree

from . import selftest as x


class SpecError(ValueError):
    pass


SIGNATURES = {
    "rsa-sha1": ("idp-signing-rsa-2048", x.C.TransformRsaSha1, x.C.TransformSha1),
    "rsa-sha256": ("idp-signing-rsa-2048", x.C.TransformRsaSha256, x.C.TransformSha256),
    "rsa-sha384": ("idp-signing-rsa-3072", x.C.TransformRsaSha384, x.C.TransformSha384),
    "rsa-sha512": ("idp-signing-rsa-3072", x.C.TransformRsaSha512, x.C.TransformSha512),
    "ecdsa-sha256": ("idp-signing-ec-p256", x.C.TransformEcdsaSha256, x.C.TransformSha256),
    "ecdsa-sha384": ("idp-signing-ec-p384", x.C.TransformEcdsaSha384, x.C.TransformSha384),
    "ecdsa-sha512": ("idp-signing-ec-p521", x.C.TransformEcdsaSha512, x.C.TransformSha512),
}

DIGESTS = {
    "sha1": x.C.TransformSha1,
    "sha256": x.C.TransformSha256,
    "sha384": x.C.TransformSha384,
    "sha512": x.C.TransformSha512,
}

ENCRYPTION_TRANSPORTS = {
    "rsa-1_5": (x.RSA_1_5, None, None),
    "rsa-oaep-mgf1p": (x.RSA_OAEP_MGF1P, None, None),
    "rsa-oaep-mgf1p-sha1": (x.RSA_OAEP_MGF1P, x.OAEP_DIGEST_SHA1, None),
    "rsa-oaep-mgf1p-sha256": (x.RSA_OAEP_MGF1P, x.OAEP_DIGEST_SHA256, None),
    "rsa-oaep-sha256-mgf1sha256": (x.RSA_OAEP_11, x.OAEP_DIGEST_SHA256, x.MGF1_SHA256),
    "rsa-oaep-sha1-mgf1sha1": (x.RSA_OAEP_11, x.OAEP_DIGEST_SHA1, x.MGF1_SHA1),
    "rsa-oaep-sha256-mgf1sha1": (x.RSA_OAEP_11, x.OAEP_DIGEST_SHA256, x.MGF1_SHA1),
}


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise SpecError("invalid or unknown spec fields")
    return value


def _string(value, name, maximum=2048):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise SpecError(f"invalid {name}")
    return value


def _https(value, name):
    value = _string(value, name)
    uri = urllib.parse.urlsplit(value)
    if uri.scheme != "https" or not uri.hostname or uri.username or uri.password or uri.fragment:
        raise SpecError(f"invalid {name}")
    return value


def _instant(value):
    value = _string(value, "clock.now", 64)
    try:
        if not value.endswith("Z"):
            raise ValueError()
        instant = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exception:
        raise SpecError("clock.now must be an absolute UTC instant") from exception
    return instant


def _format(instant):
    return instant.isoformat(timespec="seconds").replace("+00:00", "Z")


def _identifier(value, name):
    if value is None:
        return "_" + secrets.token_hex(16)
    value = _string(value, name, 128)
    if not value.startswith("_") or not all(c.isalnum() or c in "._-" for c in value):
        raise SpecError(f"invalid {name}")
    return value


def _credential(key_directory, algorithm):
    name, signature_method, digest_method = SIGNATURES[algorithm]
    credential = x.Credential.from_files(name, pathlib.Path(key_directory))
    return credential, signature_method, digest_method


class _CertificateRecipient:
    """Encryption needs only the SP's public certificate, never its private key."""

    def __init__(self, key_directory):
        self.cert_pem = (pathlib.Path(key_directory)
                         / "sp-encryption-rsa-2048-cert.pem").read_bytes()

    def xmlsec_certificate(self):
        return xmlsec.Key.from_memory(self.cert_pem, x.C.KeyDataFormatCertPem)


def _sign(element, key_directory, algorithm, engine, digest):
    credential, signature_method, default_digest = _credential(key_directory, algorithm)
    digest_method = DIGESTS[digest] if digest is not None else default_digest
    if engine == "signxml":
        if algorithm != "rsa-sha256" or digest_method != default_digest:
            raise SpecError("signxml currently supports rsa-sha256 with SHA-256 digest only")
        return x.signxml_sign(element, credential)
    x.xmlsec_sign(element, credential, signature_method, digest_method)
    return element


def _place_keys(wrapper, placement, extra):
    if placement == "inline" and extra == 0:
        return wrapper
    if placement not in ("inline", "sibling-retrieval", "sibling-implicit") or \
            not isinstance(extra, int) or isinstance(extra, bool) or extra < 0 or extra > 2 or \
            (placement == "inline" and extra):
        raise SpecError("invalid encrypted key placement")
    data = wrapper.find(x._q(x.XENC, "EncryptedData"))
    key_info = data.find(x._q(x.DS, "KeyInfo"))
    key = key_info.find(x._q(x.XENC, "EncryptedKey"))
    if key is None:
        raise SpecError("producer did not create an EncryptedKey")
    key_info.remove(key)
    if placement == "sibling-retrieval":
        key.set("Id", "_scripted_key")
        etree.SubElement(key_info, x._q(x.DS, "RetrievalMethod"),
                         URI="#_scripted_key", Type=x.XENC + "EncryptedKey")
    elif placement == "sibling-implicit":
        data.remove(key_info)
    else:
        key_info.append(key)
        return wrapper
    for index in range(extra):
        bogus = copy.deepcopy(key)
        bogus.set("Id", f"_scripted_bogus_key_{index}")
        value = bogus.find(f"{x._q(x.XENC, 'CipherData')}/{x._q(x.XENC, 'CipherValue')}")
        # The candidate is well-shaped, but its RSA ciphertext cannot unwrap.
        value.text = base64.b64encode(bytes(len(base64.b64decode(value.text)))).decode("ascii")
        wrapper.append(bogus)
    wrapper.append(key)
    return wrapper


def _malform_encryption(wrapper, variant):
    if variant == "none":
        return wrapper
    data = wrapper.find(x._q(x.XENC, "EncryptedData"))
    key = wrapper.find(f"{x._q(x.XENC, 'EncryptedData')}/{x._q(x.DS, 'KeyInfo')}/"
                       f"{x._q(x.XENC, 'EncryptedKey')}")
    if key is None:
        key = wrapper.find(x._q(x.XENC, "EncryptedKey"))
    if key is None:
        raise SpecError("encrypted key is missing")
    method = key.find(x._q(x.XENC, "EncryptionMethod"))
    if variant == "mgf-under-mgf1p":
        if method.get("Algorithm") != x.RSA_OAEP_MGF1P:
            raise SpecError("MGF-child variant requires mgf1p")
        etree.SubElement(method, x._q(x.XENC11, "MGF"),
                         nsmap={"xenc11": x.XENC11}).set("Algorithm", x.MGF1_SHA256)
    elif variant == "nonempty-oaep-params":
        etree.SubElement(method, x._q(x.XENC, "OAEPparams")).text = base64.b64encode(b"x").decode("ascii")
    elif variant == "cipher-bit-flip":
        value = data.find(f"{x._q(x.XENC, 'CipherData')}/{x._q(x.XENC, 'CipherValue')}")
        ciphertext = bytearray(base64.b64decode(value.text))
        ciphertext[-1] ^= 1
        value.text = base64.b64encode(ciphertext).decode("ascii")
    else:
        raise SpecError("invalid encryption variant")
    return wrapper


def mint_response(spec, key_directory):
    """Mint one response from an exact-schema JSON object; return serialized output fields."""
    spec = _object(spec, ("clock", "sp", "subject", "signing", "encryption", "ids"),
                   ("clock", "sp"))
    clock = _object(spec["clock"], ("now",), ("now",))
    now = _instant(clock["now"])
    sp = _object(spec["sp"], ("entity_id", "acs_url", "request_id", "relay_state"),
                 ("entity_id", "acs_url"))
    entity_id = _string(sp["entity_id"], "sp.entity_id")
    acs = _https(sp["acs_url"], "sp.acs_url")
    request_id = sp.get("request_id")
    if request_id is not None:
        request_id = _identifier(request_id, "sp.request_id")
    relay_state = sp.get("relay_state")
    if relay_state is not None:
        _string(relay_state, "sp.relay_state", 80)
    subject = _object(spec.get("subject", {}), ("name_id", "session_index", "attributes"))
    subject_name = _string(subject.get("name_id", "user-1"), "subject.name_id", 4096)
    session_index = _string(subject.get("session_index", "_session-1"),
                            "subject.session_index", 128)
    attributes = subject.get("attributes", {})
    if not isinstance(attributes, dict) or len(attributes) > 32:
        raise SpecError("invalid subject.attributes")
    for name, values in attributes.items():
        _string(name, "attribute name", 256)
        if not isinstance(values, list) or len(values) > 16:
            raise SpecError("invalid attribute values")
        for value in values:
            _string(value, "attribute value", 4096)
    signing = _object(spec.get("signing", {}), ("placement", "algorithm", "engine", "digest"))
    placement = signing.get("placement", "assertion")
    if placement not in ("none", "response", "assertion", "both"):
        raise SpecError("invalid signing.placement")
    algorithm = signing.get("algorithm", "rsa-sha256")
    if algorithm not in SIGNATURES:
        raise SpecError("invalid signing.algorithm")
    engine = signing.get("engine", "xmlsec")
    if engine not in ("xmlsec", "signxml"):
        raise SpecError("invalid signing.engine")
    digest = signing.get("digest")
    if digest is not None and digest not in DIGESTS:
        raise SpecError("invalid signing.digest")
    encryption = _object(spec.get("encryption", {}),
                         ("assertion", "name_id", "data_algorithm", "key_transport",
                          "key_placement", "extra_encrypted_keys", "variant"))
    encrypt_assertion = encryption.get("assertion", False)
    encrypt_name_id = encryption.get("name_id", False)
    if not isinstance(encrypt_assertion, bool) or not isinstance(encrypt_name_id, bool):
        raise SpecError("invalid encryption flag")
    data_algorithm = {
        "aes128-gcm": x.XENC11 + "aes128-gcm",
        "aes192-gcm": x.XENC11 + "aes192-gcm",
        "aes256-gcm": x.XENC11 + "aes256-gcm",
        "aes128-cbc": x.XENC + "aes128-cbc",
        "aes192-cbc": x.XENC + "aes192-cbc",
        "aes256-cbc": x.XENC + "aes256-cbc",
    }.get(encryption.get("data_algorithm", "aes256-gcm"))
    transport = ENCRYPTION_TRANSPORTS.get(
        encryption.get("key_transport", "rsa-oaep-sha256-mgf1sha256"))
    if data_algorithm is None or transport is None:
        raise SpecError("unsupported encryption algorithm")
    key_placement = encryption.get("key_placement", "inline")
    extra_keys = encryption.get("extra_encrypted_keys", 0)
    if key_placement not in ("inline", "sibling-retrieval", "sibling-implicit") or \
            not isinstance(extra_keys, int) or isinstance(extra_keys, bool) or \
            extra_keys < 0 or extra_keys > 2 or key_placement == "inline" and extra_keys:
        raise SpecError("invalid encrypted key placement")
    variant = encryption.get("variant", "none")
    if variant not in ("none", "mgf-under-mgf1p", "nonempty-oaep-params", "cipher-bit-flip"):
        raise SpecError("invalid encryption variant")
    ids = _object(spec.get("ids", {}), ("response", "assertion"))
    response_id = _identifier(ids.get("response"), "ids.response")
    assertion_id = _identifier(ids.get("assertion"), "ids.assertion")
    if response_id == assertion_id or response_id == request_id or assertion_id == request_id:
        raise SpecError("duplicate SAML IDs")

    expiry = now + datetime.timedelta(minutes=5)
    assertion = x._root(x.SAML, "Assertion", {"saml": x.SAML}, ID=assertion_id,
                        Version="2.0", IssueInstant=_format(now))
    x._sub(assertion, x.SAML, "Issuer", x.IDP)
    person = x._sub(assertion, x.SAML, "Subject")
    name_id = x._root(x.SAML, "NameID", {"saml": x.SAML},
                      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                      NameQualifier=x.IDP, SPNameQualifier=entity_id)
    name_id.text = subject_name
    if encrypt_name_id:
        recipient = _CertificateRecipient(key_directory)
        person.append(_malform_encryption(_place_keys(x.xmlsec_encrypt(x.wrapped("EncryptedID", name_id), transport[0],
                                  recipient, data_algorithm, transport[1], transport[2]),
                                  key_placement, extra_keys), variant))
    else:
        person.append(name_id)
    confirmation = x._sub(person, x.SAML, "SubjectConfirmation",
                          Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    confirmation_attributes = {"Recipient": acs, "NotOnOrAfter": _format(expiry)}
    if request_id is not None:
        confirmation_attributes["InResponseTo"] = request_id
    x._sub(confirmation, x.SAML, "SubjectConfirmationData", **confirmation_attributes)
    conditions = x._sub(assertion, x.SAML, "Conditions",
                        NotBefore=_format(now - datetime.timedelta(minutes=1)),
                        NotOnOrAfter=_format(expiry))
    x._sub(x._sub(conditions, x.SAML, "AudienceRestriction"), x.SAML, "Audience", entity_id)
    authn = x._sub(assertion, x.SAML, "AuthnStatement", AuthnInstant=_format(now),
                   SessionIndex=session_index)
    x._sub(x._sub(authn, x.SAML, "AuthnContext"), x.SAML, "AuthnContextClassRef",
           "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    if attributes:
        statement = x._sub(assertion, x.SAML, "AttributeStatement")
        for name, values in attributes.items():
            attribute = x._sub(statement, x.SAML, "Attribute", Name=name,
                               NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            for value in values:
                x._sub(attribute, x.SAML, "AttributeValue", value)
    if placement in ("assertion", "both"):
        assertion = _sign(assertion, key_directory, algorithm, engine, digest)
    if encrypt_assertion:
        recipient = _CertificateRecipient(key_directory)
        assertion = _malform_encryption(_place_keys(x.xmlsec_encrypt(x.wrapped("EncryptedAssertion", assertion), transport[0],
                                recipient, data_algorithm, transport[1], transport[2]),
                                key_placement, extra_keys), variant)
    response = x._root(x.SAMLP, "Response", {"samlp": x.SAMLP, "saml": x.SAML},
                       ID=response_id, Version="2.0", IssueInstant=_format(now), Destination=acs)
    if request_id is not None:
        response.set("InResponseTo", request_id)
    x._sub(response, x.SAML, "Issuer", x.IDP)
    x._sub(x._sub(response, x.SAMLP, "Status"), x.SAMLP, "StatusCode",
           Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    response.append(assertion)
    if placement in ("response", "both"):
        response = _sign(response, key_directory, algorithm, engine, digest)
    serialized = etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    encoded = base64.b64encode(serialized).decode("ascii")
    form = ("<!doctype html><html><head><meta charset=\"utf-8\"></head><body>"
            "<form method=\"post\" action=\"" + html.escape(acs, quote=True) + "\">"
            "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + encoded + "\">"
            + ("<input type=\"hidden\" name=\"RelayState\" value=\""
               + html.escape(relay_state, quote=True) + "\">" if relay_state is not None else "")
            + "<noscript><button type=\"submit\">Continue</button></noscript></form>"
            "<script>document.forms[0].submit()</script></body></html>")
    return {"saml_response": encoded, "xml": serialized.decode("utf-8"),
            "response_id": response_id, "assertion_id": assertion_id,
            "relay_state": relay_state, "form": form}
