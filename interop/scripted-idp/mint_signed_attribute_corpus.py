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

"""Mint signed AttributeValue type-confusion fixtures with a libxmlsec oracle.

Run in the network-none scripted IdP image with /fixtures and /run/keys read-only
and /out writable. The transient NameID makes the scoped attribute the only stable
subject-key source, so opaque values cannot be mistaken for an account key.
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
SCOPED = "urn:oasis:names:tc:SAML:attribute:subject-id"
TEXT = ("clean", "type-xs-string", "type-alias-string", "nil-false", "nil-zero")
OPAQUE = ("nil-true", "nil-one", "nil-invalid", "type-boolean",
          "type-and-nil", "spoof-string-type", "mixed-element")
NS = {"saml": x.SAML}


def _one(root, path):
    found = root.xpath(path, namespaces=NS)
    if len(found) != 1:
        raise ValueError(f"fixture shape changed: {path}")
    return found[0]


def _hint(value, name):
    if name == "type-xs-string":
        value.set(f"{{{XSI}}}type", "xs:string")
    elif name == "type-alias-string":
        value.set(f"{{{XSI}}}type", "schema:string")
    elif name == "nil-false":
        value.set(f"{{{XSI}}}nil", "false")
    elif name == "nil-zero":
        value.set(f"{{{XSI}}}nil", "0")
    elif name == "nil-true":
        value.set(f"{{{XSI}}}nil", "true")
    elif name == "nil-one":
        value.set(f"{{{XSI}}}nil", "1")
    elif name == "nil-invalid":
        value.set(f"{{{XSI}}}nil", "sometimes")
    elif name == "type-boolean":
        value.set(f"{{{XSI}}}type", "xs:boolean")
    elif name == "type-and-nil":
        value.set(f"{{{XSI}}}type", "xs:string")
        value.set(f"{{{XSI}}}nil", "true")
    elif name == "spoof-string-type":
        value.set(f"{{{XSI}}}type", "shadow:string")
    elif name == "mixed-element":
        value.text = "minted@"
        nested = etree.SubElement(value, "{urn:attacker:shadow}Part")
        nested.text = "attacker"
        nested.tail = "example.test"
    elif name != "clean":
        raise ValueError(name)


def _mutate(root, name):
    assertion = _one(root, "./saml:Assertion")
    name_id = _one(assertion, "./saml:Subject/saml:NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
    statement = etree.SubElement(assertion, f"{{{x.SAML}}}AttributeStatement")
    for attribute_name in (SCOPED, "urn:example:display-email"):
        attribute = etree.SubElement(statement, f"{{{x.SAML}}}Attribute",
                                     Name=attribute_name)
        value = etree.SubElement(attribute, f"{{{x.SAML}}}AttributeValue",
                                 nsmap={"xsi": XSI, "xs": XSD,
                                        "schema": XSD, "shadow": "urn:attacker:shadow"})
        value.text = "minted@example.test"
        _hint(value, name)
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
    for name in TEXT + OPAQUE:
        root = etree.fromstring(args.fixture.read_bytes(), x.PARSER)
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
