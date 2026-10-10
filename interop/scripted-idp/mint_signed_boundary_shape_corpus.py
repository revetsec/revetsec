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

"""Mint bearer/conditions shape fixtures in the network-none pinned IdP image.

Mount /fixtures and /run/keys read-only, /out writable, and set
PYTHONPATH=/app. The libxmlsec oracle proves cryptographic coverage only;
deliberately malformed signed SAML is expected to fail Revetsec's SP policy.
"""

import argparse
import copy
import hashlib
import pathlib

from lxml import etree

from scripted_idp import selftest as x
from scripted_idp import template


NOW = "2026-09-01T00:00:00Z"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSD = "http://www.w3.org/2001/XMLSchema"
POSITIVES = (
    "clean", "matching-confirmation-nameid", "one-time-and-proxy",
    "typed-confirmation-data",
)
NEGATIVES = (
    "subject-nil", "confirmation-nil", "data-nil", "data-wrong-type",
    "confirmation-extra-child", "data-direct-text", "inverted-bearer-window",
    "mismatched-confirmation-nameid", "conditions-nil", "conditions-wrong-type",
    "audience-restriction-nil", "one-time-child", "proxy-negative-count",
    "proxy-child", "proxy-nil",
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
    subject = _one(assertion, "./saml:Subject")
    subject_name = _one(subject, "./saml:NameID")
    confirmation = _one(subject, "./saml:SubjectConfirmation")
    data = _one(confirmation, "./saml:SubjectConfirmationData")
    conditions = _one(assertion, "./saml:Conditions")
    restriction = _one(conditions, "./saml:AudienceRestriction")
    if name == "subject-nil":
        _typed(subject, "nil", "true")
    elif name == "confirmation-nil":
        _typed(confirmation, "nil", "true")
    elif name == "data-nil":
        _typed(data, "nil", "true")
    elif name == "data-wrong-type":
        _typed(data, "type", "xs:string")
    elif name == "confirmation-extra-child":
        etree.SubElement(confirmation, "{urn:attacker:shadow}Extra")
    elif name == "data-direct-text":
        data.text = "shadow"
    elif name == "inverted-bearer-window":
        data.set("NotBefore", "2026-09-01T00:03:00Z")
        data.set("NotOnOrAfter", "2026-09-01T00:02:00Z")
    elif name in ("matching-confirmation-nameid", "mismatched-confirmation-nameid"):
        confirmed_name = copy.deepcopy(subject_name)
        if name == "mismatched-confirmation-nameid":
            confirmed_name.text = "mallory"
        confirmation.insert(0, confirmed_name)
    elif name == "conditions-nil":
        _typed(conditions, "nil", "true")
    elif name == "conditions-wrong-type":
        _typed(conditions, "type", "xs:string")
    elif name == "audience-restriction-nil":
        _typed(restriction, "nil", "true")
    elif name == "one-time-child":
        etree.SubElement(etree.SubElement(conditions, f"{{{x.SAML}}}OneTimeUse"),
                         "{urn:attacker:shadow}Extra")
    elif name in ("proxy-negative-count", "proxy-child", "proxy-nil"):
        proxy = etree.SubElement(conditions, f"{{{x.SAML}}}ProxyRestriction")
        if name == "proxy-negative-count":
            proxy.set("Count", "-1")
        elif name == "proxy-child":
            etree.SubElement(proxy, "{urn:attacker:shadow}Extra")
        else:
            proxy.set(f"{{{XSI}}}nil", "true")
    elif name == "one-time-and-proxy":
        etree.SubElement(conditions, f"{{{x.SAML}}}OneTimeUse")
        proxy = etree.SubElement(conditions, f"{{{x.SAML}}}ProxyRestriction", Count="0")
        etree.SubElement(proxy, f"{{{x.SAML}}}Audience").text = \
            "https://downstream.example.test/"
    elif name == "typed-confirmation-data":
        _typed(data, "type", "saml:SubjectConfirmationDataType")
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
