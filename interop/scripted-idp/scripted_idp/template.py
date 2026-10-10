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

"""Bounded template signing and an independent libxmlsec1 signature oracle.

These controls operate on caller-supplied test XML without applying SAML semantics.
The oracle reports a cryptographic verdict only; it is not an SP acceptance oracle.
"""

import pathlib
import os

import xmlsec
from lxml import etree

from . import mint
from . import selftest as x


MAX_XML = 256 * 1024
KEY_NAMES = frozenset(name for name, _, _ in mint.SIGNATURES.values())
ORACLE_KEY_ENV = "SCRIPTED_IDP_ORACLE_DECRYPTION_KEY"


class OracleUnavailable(RuntimeError):
    pass


def _fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise mint.SpecError("invalid or unknown template fields")
    return value


def _tree(value):
    if not isinstance(value, str):
        raise mint.SpecError("xml must be a string")
    data = value.encode("utf-8")
    if len(data) > MAX_XML or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise mint.SpecError("invalid or oversized XML")
    try:
        return etree.fromstring(data, x.PARSER)
    except etree.XMLSyntaxError as exception:
        raise mint.SpecError("invalid XML") from exception


def _target(root, target_id):
    target_id = mint._identifier(target_id, "target_id")
    all_ids = [element.get("ID") for element in root.iter() if element.get("ID") is not None]
    if len(all_ids) != len(set(all_ids)):
        raise mint.SpecError("duplicate XML ID")
    targets = [element for element in root.iter() if element.get("ID") == target_id]
    if len(targets) != 1:
        raise mint.SpecError("target_id must name one element")
    return targets[0]


def _clock(spec):
    mint._instant(_fields(spec["clock"], ("now",), ("now",))["now"])


def sign(spec, key_directory):
    """Sign the selected element in the supplied XML, preserving the surrounding template."""
    _fields(spec, ("clock", "xml", "target_id", "signing"),
            ("clock", "xml", "target_id", "signing"))
    _clock(spec)
    root = _tree(spec["xml"])
    target = _target(root, spec["target_id"])
    if target.tag not in (x._q(x.SAML, "Assertion"), x._q(x.SAMLP, "Response")):
        raise mint.SpecError("signing target must be a SAML Assertion or Response")
    if target.find(x._q(x.DS, "Signature")) is not None:
        raise mint.SpecError("target already has a direct Signature")
    signing = _fields(spec["signing"], ("algorithm", "digest", "engine"), ("algorithm",))
    algorithm = signing["algorithm"]
    digest = signing.get("digest")
    engine = signing.get("engine", "xmlsec")
    if algorithm not in mint.SIGNATURES or digest is not None and digest not in mint.DIGESTS or \
            engine not in ("xmlsec", "signxml"):
        raise mint.SpecError("unsupported template signing option")
    parent = target.getparent()
    index = parent.index(target) if parent is not None else None
    signed = mint._sign(target, key_directory, algorithm, engine, digest)
    if signed is not target:
        if parent is None:
            root = signed
        else:
            parent.remove(target)
            parent.insert(index, signed)
    serialized = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return {"xml": serialized.decode("utf-8"), "target_id": spec["target_id"],
            "algorithm": algorithm, "digest": digest or algorithm.rsplit("-", 1)[1],
            "engine": engine}


def verify(spec, key_directory):
    """Verify one direct XMLDSig signature against a named, pinned test certificate."""
    _fields(spec, ("clock", "xml", "target_id", "credential"),
            ("clock", "xml", "target_id", "credential"))
    _clock(spec)
    root = _tree(spec["xml"])
    target = _target(root, spec["target_id"])
    name = spec["credential"]
    if name not in KEY_NAMES:
        raise mint.SpecError("unsupported oracle credential")
    signature = target.find(x._q(x.DS, "Signature"))
    if signature is None or len(target.findall(x._q(x.DS, "Signature"))) != 1:
        return {"valid": False, "reason": "missing_or_multiple_signature"}
    signed_info = signature.find(x._q(x.DS, "SignedInfo"))
    references = [] if signed_info is None else signed_info.findall(x._q(x.DS, "Reference"))
    reference_uri = references[0].get("URI") if len(references) == 1 else None
    certificate = (pathlib.Path(key_directory) / f"{name}-cert.pem").read_bytes()
    try:
        context = xmlsec.SignatureContext()
        context.key = xmlsec.Key.from_memory(certificate, x.C.KeyDataFormatCertPem)
        for element in root.iter():
            if element.get("ID") is not None:
                context.register_id(element, "ID")
        context.verify(signature)
    except xmlsec.Error:
        return {"valid": False, "reason": "signature_invalid", "reference_uri": reference_uri}
    return {"valid": True, "reference_uri": reference_uri,
            "covers_target": reference_uri == "#" + spec["target_id"]}


def encrypt(spec, key_directory):
    """Encrypt a selected Assertion or NameID with the test SP's public certificate."""
    _fields(spec, ("clock", "xml", "target_id", "element", "encryption"),
            ("clock", "xml", "target_id", "element", "encryption"))
    _clock(spec)
    root = _tree(spec["xml"])
    owner = _target(root, spec["target_id"])
    element_name = spec["element"]
    if element_name == "Assertion":
        if owner.tag != x._q(x.SAML, "Assertion"):
            raise mint.SpecError("Assertion selector does not name an Assertion")
        target, wrapper_name = owner, "EncryptedAssertion"
    elif element_name == "NameID":
        if owner.tag != x._q(x.SAML, "Assertion"):
            raise mint.SpecError("NameID selector must name its Assertion")
        names = owner.findall(f"{x._q(x.SAML, 'Subject')}/{x._q(x.SAML, 'NameID')}")
        if len(names) != 1:
            raise mint.SpecError("NameID selector is ambiguous")
        target, wrapper_name = names[0], "EncryptedID"
    else:
        raise mint.SpecError("unsupported template encryption element")
    encryption = _fields(spec["encryption"], ("data_algorithm", "key_transport",
                                            "key_placement", "extra_encrypted_keys", "variant"),
                         ("data_algorithm", "key_transport"))
    data_algorithm = {
        "aes128-gcm": x.XENC11 + "aes128-gcm", "aes192-gcm": x.XENC11 + "aes192-gcm",
        "aes256-gcm": x.XENC11 + "aes256-gcm", "aes128-cbc": x.XENC + "aes128-cbc",
        "aes192-cbc": x.XENC + "aes192-cbc", "aes256-cbc": x.XENC + "aes256-cbc",
    }.get(encryption["data_algorithm"])
    transport = mint.ENCRYPTION_TRANSPORTS.get(encryption["key_transport"])
    if data_algorithm is None or transport is None:
        raise mint.SpecError("unsupported template encryption option")
    parent = target.getparent()
    index = parent.index(target) if parent is not None else None
    wrapper = mint._malform_encryption(mint._place_keys(x.xmlsec_encrypt(x.wrapped(wrapper_name, target), transport[0],
                               mint._CertificateRecipient(key_directory), data_algorithm,
                               transport[1], transport[2]),
                               encryption.get("key_placement", "inline"),
                               encryption.get("extra_encrypted_keys", 0)),
                               encryption.get("variant", "none"))
    if parent is None:
        root = wrapper
    else:
        parent.remove(target)
        parent.insert(index, wrapper)
    return {"xml": etree.tostring(root, xml_declaration=True, encoding="UTF-8").decode("utf-8"),
            "element": element_name, "target_id": spec["target_id"]}


def decrypt(spec):
    """Check one ciphertext with libxmlsec1 in a separately key-enabled oracle process."""
    _fields(spec, ("clock", "xml"), ("clock", "xml"))
    _clock(spec)
    key_path = os.environ.get(ORACLE_KEY_ENV)
    if not key_path:
        raise OracleUnavailable("decryption oracle key is not configured")
    root = _tree(spec["xml"])
    encrypted = [element for element in root.iter() if element.tag == x._q(x.XENC, "EncryptedData")]
    if len(encrypted) != 1:
        raise mint.SpecError("decryption oracle requires exactly one EncryptedData")
    try:
        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_memory(pathlib.Path(key_path).read_bytes(),
                                               x.C.KeyDataFormatPem))
        plaintext = xmlsec.EncryptionContext(manager).decrypt(encrypted[0])
    except (OSError, xmlsec.Error):
        return {"valid": False}
    return {"valid": True, "xml": etree.tostring(plaintext, encoding="UTF-8").decode("utf-8")}
