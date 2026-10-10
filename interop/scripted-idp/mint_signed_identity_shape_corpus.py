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

"""Mint signed identity/authorization-shape fixtures with a libxmlsec oracle.

Mount /fixtures and /run/keys read-only, mount /out writable, and set
PYTHONPATH=/app in the network-none scripted IdP image. The oracle proves the
cryptographic signature, not XSD validity: several cases intentionally carry
malformed SAML structure under a valid IdP signature.
"""

import argparse
import hashlib
import pathlib

from lxml import etree

from scripted_idp import selftest as x
from scripted_idp import template


NOW = "2026-09-01T00:00:00Z"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSD = "http://www.w3.org/2001/XMLSchema"
NEGATIVES = (
    "assertion-version-old", "assertion-version-missing",
    "subject-nameid-nil", "subject-nameid-type-string",
    "assertion-issuer-nil", "assertion-issuer-type-string",
    "audience-nil", "audience-type-string", "authn-class-ref-nil",
    "subject-nameid-after-confirmation", "authn-locality-after-context",
    "authn-duplicate-locality", "authn-unknown-child",
)
POSITIVES = (
    "clean", "subject-nameid-type", "assertion-issuer-type",
    "audience-type", "authn-class-ref-type", "subject-nameid-nil-false",
    "authn-locality-before-context",
)
NS = {"saml": x.SAML}


def _one(root, path):
    found = root.xpath(path, namespaces=NS)
    if len(found) != 1:
        raise ValueError(f"fixture shape changed: {path}")
    return found[0]


def _typed(element, name, hint):
    parent = element.getparent()
    replacement = etree.Element(element.tag,
                                nsmap={"xsi": XSI, "xs": XSD, "saml": x.SAML})
    replacement.attrib.update(element.attrib)
    replacement.text = element.text
    replacement.tail = element.tail
    for child in list(element):
        replacement.append(child)
    parent.replace(element, replacement)
    replacement.set(f"{{{XSI}}}{name}", hint)


def _mutate(root, name):
    assertion = _one(root, "./saml:Assertion")
    issuer = _one(assertion, "./saml:Issuer")
    subject = _one(assertion, "./saml:Subject")
    name_id = _one(subject, "./saml:NameID")
    audience = _one(assertion, "./saml:Conditions/saml:AudienceRestriction/saml:Audience")
    authn = _one(assertion, "./saml:AuthnStatement")
    context = _one(authn, "./saml:AuthnContext")
    class_ref = _one(context, "./saml:AuthnContextClassRef")
    if name == "assertion-version-old":
        assertion.set("Version", "1.1")
    elif name == "assertion-version-missing":
        del assertion.attrib["Version"]
    elif name == "subject-nameid-nil":
        _typed(name_id, "nil", "true")
    elif name == "subject-nameid-type-string":
        _typed(name_id, "type", "xs:string")
    elif name == "assertion-issuer-nil":
        _typed(issuer, "nil", "true")
    elif name == "assertion-issuer-type-string":
        _typed(issuer, "type", "xs:string")
    elif name == "audience-nil":
        _typed(audience, "nil", "true")
    elif name == "audience-type-string":
        _typed(audience, "type", "xs:string")
    elif name == "authn-class-ref-nil":
        _typed(class_ref, "nil", "true")
    elif name == "subject-nameid-after-confirmation":
        subject.remove(name_id)
        subject.append(name_id)
    elif name == "authn-locality-after-context":
        etree.SubElement(authn, f"{{{x.SAML}}}SubjectLocality", Address="127.0.0.1")
    elif name == "authn-duplicate-locality":
        authn.insert(0, etree.Element(f"{{{x.SAML}}}SubjectLocality"))
        authn.insert(0, etree.Element(f"{{{x.SAML}}}SubjectLocality"))
    elif name == "authn-unknown-child":
        authn.insert(0, etree.Element("{urn:attacker:shadow}AuthnContext"))
    elif name == "subject-nameid-type":
        _typed(name_id, "type", "saml:NameIDType")
    elif name == "assertion-issuer-type":
        _typed(issuer, "type", "saml:NameIDType")
    elif name == "audience-type":
        _typed(audience, "type", "xs:anyURI")
    elif name == "authn-class-ref-type":
        _typed(class_ref, "type", "xs:anyURI")
    elif name == "subject-nameid-nil-false":
        _typed(name_id, "nil", "false")
    elif name == "authn-locality-before-context":
        authn.insert(0, etree.Element(f"{{{x.SAML}}}SubjectLocality",
                                     Address="127.0.0.1"))
    elif name != "clean":
        raise ValueError(name)
    return assertion.get("ID")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path,
                        default=pathlib.Path("/fixtures/scripted-idp/unsigned.xml"))
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    source = args.fixture.read_bytes()
    for name in POSITIVES + NEGATIVES:
        root = etree.fromstring(source, x.PARSER)
        target_id = _mutate(root, name)
        signed = template.sign({"clock": {"now": NOW},
                                "xml": etree.tostring(root, encoding="unicode"),
                                "target_id": target_id,
                                "signing": {"algorithm": "rsa-sha256"}}, args.keys)["xml"]
        oracle = template.verify({"clock": {"now": NOW}, "xml": signed,
                                  "target_id": target_id,
                                  "credential": "idp-signing-rsa-2048"}, args.keys)
        if not oracle["valid"] or not oracle["covers_target"]:
            raise ValueError(f"oracle did not verify {name}: {oracle}")
        encoded = signed.encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest.append(f"{name} {hashlib.sha256(encoded).hexdigest()}")
    (args.out / "sha256.txt").write_text("\n".join(manifest) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
