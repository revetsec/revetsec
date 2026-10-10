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

"""Mint valid-signature, hostile-shape SSO responses with the pinned test IdP.

Run in the scripted-IdP container with /run/keys read-only, the core fixture tree
at /fixtures read-only, and the destination mounted at /out. No network is needed.
The libxmlsec oracle verifies every signed output before it is written.
"""

import argparse
import copy
import hashlib
import pathlib

from lxml import etree

from scripted_idp import selftest as x
from scripted_idp import template


NOW = "2026-09-01T00:00:00Z"
NS = {"saml": x.SAML, "samlp": x.SAMLP, "ds": x.DS}
CASES = (
    "duplicate-assertion-before", "duplicate-assertion-after",
    "nested-assertion-advice", "attacker-assertion-extension",
    "duplicate-status", "duplicate-issuer", "assertion-before-status",
    "qualified-response-id", "qualified-assertion-id", "saml1-assertion-shadow",
    "duplicate-subject", "duplicate-nameid", "duplicate-status-code",
    "signature-under-extension",
)


def _one(root, path):
    found = root.xpath(path, namespaces=NS)
    if len(found) != 1:
        raise ValueError(f"fixture shape changed: {path}")
    return found[0]


def _attacker(assertion):
    clone = copy.deepcopy(assertion)
    clone.set("ID", "_attacker_assertion")
    _one(clone, "./saml:Subject/saml:NameID").text = "attacker-user"
    return clone


def _mutate(root, name):
    assertion = _one(root, "./saml:Assertion")
    status = _one(root, "./samlp:Status")
    issuer = _one(root, "./saml:Issuer")
    if name == "duplicate-assertion-before":
        root.insert(root.index(assertion), _attacker(assertion))
    elif name == "duplicate-assertion-after":
        root.append(_attacker(assertion))
    elif name == "nested-assertion-advice":
        etree.SubElement(assertion, x._q(x.SAML, "Advice")).append(_attacker(assertion))
    elif name == "attacker-assertion-extension":
        extension = etree.Element(x._q(x.SAMLP, "Extensions"))
        extension.append(_attacker(assertion))
        root.insert(root.index(status), extension)
    elif name == "duplicate-status":
        root.insert(root.index(status), copy.deepcopy(status))
    elif name == "duplicate-issuer":
        root.insert(root.index(status), copy.deepcopy(issuer))
    elif name == "assertion-before-status":
        root.remove(assertion)
        root.insert(root.index(status), assertion)
    elif name == "qualified-response-id":
        root.set(x._q(x.SAMLP, "ID"), "_attacker_response")
    elif name == "qualified-assertion-id":
        assertion.set(x._q(x.SAML, "ID"), "_attacker_assertion")
    elif name == "saml1-assertion-shadow":
        old = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:1.0:assertion}Assertion")
        etree.SubElement(old, "{urn:oasis:names:tc:SAML:1.0:assertion}NameIdentifier").text = "attacker-user"
    elif name == "duplicate-subject":
        subject = _one(assertion, "./saml:Subject")
        attacker = copy.deepcopy(subject)
        _one(attacker, "./saml:NameID").text = "attacker-user"
        assertion.insert(assertion.index(subject), attacker)
    elif name == "duplicate-nameid":
        subject = _one(assertion, "./saml:Subject")
        name_id = _one(subject, "./saml:NameID")
        attacker = copy.deepcopy(name_id)
        attacker.text = "attacker-user"
        subject.insert(subject.index(name_id), attacker)
    elif name == "duplicate-status-code":
        status.insert(0, copy.deepcopy(_one(status, "./samlp:StatusCode")))
    elif name == "signature-under-extension":
        extension = etree.Element(x._q(x.SAMLP, "Extensions"))
        etree.SubElement(extension, x._q(x.DS, "Signature"))
        root.insert(root.index(status), extension)
    else:
        raise ValueError(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path,
                        default=pathlib.Path("/fixtures/scripted-idp/unsigned.xml"))
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
    args = parser.parse_args()
    source = args.fixture.read_bytes()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name in ("clean",) + CASES:
        root = etree.fromstring(source, x.PARSER)
        if name != "clean":
            _mutate(root, name)
        unsigned = etree.tostring(root, encoding="unicode")
        target_id = root.get("ID")
        signed = template.sign({"clock": {"now": NOW}, "xml": unsigned,
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
