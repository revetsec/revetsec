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

"""Mint assertion-signed SSO ambiguity fixtures in the network-none scripted IdP.

Mount /fixtures and /run/keys read-only, mount /out writable, and set PYTHONPATH=/app.
Each output is checked by the independent libxmlsec signature oracle.
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
NS = {"saml": x.SAML, "samlp": x.SAMLP}
NEGATIVES = (
    "duplicate-issuer", "duplicate-subject", "duplicate-nameid",
    "nested-nameid", "duplicate-confirmation-data", "duplicate-conditions",
    "contradictory-audience-restriction", "duplicate-authn-statement",
    "duplicate-authn-context", "duplicate-class-ref", "nested-class-ref",
    "assertion-nil", "assertion-type-string", "issuer-after-subject",
    "conditions-before-subject", "advice-after-authn", "duplicate-advice",
    "attribute-before-conditions", "attribute-statement-nil", "attribute-nil",
    "attribute-type-string", "attribute-direct-text", "authn-statement-nil",
)
POSITIVES = (
    "comment-split-nameid", "cdata-nameid", "advice-before-authn",
    "typed-attribute-statement", "attribute-before-authn",
)


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


def _attribute_statement():
    statement = etree.Element(f"{{{x.SAML}}}AttributeStatement")
    attribute = etree.SubElement(statement, f"{{{x.SAML}}}Attribute",
                                 Name="urn:oasis:names:tc:SAML:attribute:subject-id")
    etree.SubElement(attribute, f"{{{x.SAML}}}AttributeValue").text = \
        "minted@example.test"
    return statement, attribute


def _mutate(assertion, name):
    issuer = _one(assertion, "./saml:Issuer")
    subject = _one(assertion, "./saml:Subject")
    name_id = _one(subject, "./saml:NameID")
    conditions = _one(assertion, "./saml:Conditions")
    authn = _one(assertion, "./saml:AuthnStatement")
    context = _one(authn, "./saml:AuthnContext")
    class_ref = _one(context, "./saml:AuthnContextClassRef")
    if name == "duplicate-issuer":
        attacker = copy.deepcopy(issuer)
        attacker.text = "https://attacker.example.test/"
        assertion.insert(assertion.index(subject), attacker)
    elif name == "duplicate-subject":
        attacker = copy.deepcopy(subject)
        _one(attacker, "./saml:NameID").text = "attacker-user"
        assertion.insert(assertion.index(subject), attacker)
    elif name == "duplicate-nameid":
        attacker = copy.deepcopy(name_id)
        attacker.text = "attacker-user"
        subject.insert(subject.index(name_id), attacker)
    elif name == "nested-nameid":
        name_id.text = "minted-"
        etree.SubElement(name_id, "{urn:attacker:shadow}NameID").text = "attacker-user"
    elif name == "duplicate-confirmation-data":
        confirmation = _one(subject, "./saml:SubjectConfirmation")
        data = _one(confirmation, "./saml:SubjectConfirmationData")
        attacker = copy.deepcopy(data)
        attacker.set("Recipient", "https://attacker.example.test/acs")
        confirmation.insert(0, attacker)
    elif name == "duplicate-conditions":
        attacker = copy.deepcopy(conditions)
        _one(attacker, "./saml:AudienceRestriction/saml:Audience").text = "https://attacker.example.test/sp"
        assertion.insert(assertion.index(conditions), attacker)
    elif name == "contradictory-audience-restriction":
        restriction = _one(conditions, "./saml:AudienceRestriction")
        attacker = copy.deepcopy(restriction)
        _one(attacker, "./saml:Audience").text = "https://attacker.example.test/sp"
        conditions.insert(0, attacker)
    elif name == "duplicate-authn-statement":
        attacker = copy.deepcopy(authn)
        attacker.set("SessionIndex", "_attacker_session")
        assertion.insert(assertion.index(authn), attacker)
    elif name == "duplicate-authn-context":
        attacker = copy.deepcopy(context)
        _one(attacker, "./saml:AuthnContextClassRef").text = "urn:attacker:weak-context"
        authn.insert(0, attacker)
    elif name == "duplicate-class-ref":
        attacker = copy.deepcopy(class_ref)
        attacker.text = "urn:attacker:weak-context"
        context.insert(0, attacker)
    elif name == "nested-class-ref":
        context.remove(class_ref)
        etree.SubElement(context, "{urn:attacker:shadow}ClassRef").append(class_ref)
    elif name == "assertion-nil":
        assertion.set(f"{{{XSI}}}nil", "true")
    elif name == "assertion-type-string":
        _typed(assertion, "type", "xs:string")
    elif name == "issuer-after-subject":
        assertion.remove(issuer)
        assertion.insert(assertion.index(conditions), issuer)
    elif name == "conditions-before-subject":
        assertion.remove(conditions)
        assertion.insert(assertion.index(subject), conditions)
    elif name == "advice-after-authn":
        etree.SubElement(assertion, f"{{{x.SAML}}}Advice")
    elif name == "duplicate-advice":
        assertion.insert(assertion.index(authn), etree.Element(f"{{{x.SAML}}}Advice"))
        assertion.insert(assertion.index(authn), etree.Element(f"{{{x.SAML}}}Advice"))
    elif name in ("attribute-before-conditions", "attribute-statement-nil",
                  "attribute-nil", "attribute-type-string", "attribute-direct-text",
                  "typed-attribute-statement", "attribute-before-authn"):
        statement, attribute = _attribute_statement()
        if name == "attribute-before-conditions":
            assertion.insert(assertion.index(conditions), statement)
        elif name == "attribute-before-authn":
            assertion.insert(assertion.index(authn), statement)
        else:
            assertion.append(statement)
        if name == "attribute-statement-nil":
            statement.set(f"{{{XSI}}}nil", "true")
        elif name == "attribute-nil":
            attribute.set(f"{{{XSI}}}nil", "true")
        elif name == "attribute-type-string":
            _typed(attribute, "type", "xs:string")
        elif name == "attribute-direct-text":
            attribute.text = "shadow"
        elif name == "typed-attribute-statement":
            _typed(statement, "type", "saml:AttributeStatementType")
    elif name == "authn-statement-nil":
        authn.set(f"{{{XSI}}}nil", "true")
    elif name == "advice-before-authn":
        assertion.insert(assertion.index(authn), etree.Element(f"{{{x.SAML}}}Advice"))
    elif name == "comment-split-nameid":
        name_id.text = "minted-"
        name_id.append(etree.Comment("split"))
        name_id[-1].tail = "user"
    elif name == "cdata-nameid":
        name_id.text = etree.CDATA("minted-user")
    else:
        raise ValueError(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path,
                        default=pathlib.Path("/fixtures/scripted-idp/unsigned.xml"))
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source = args.fixture.read_bytes()
    manifest = []
    for name in ("clean",) + NEGATIVES + POSITIVES:
        root = etree.fromstring(source, x.PARSER)
        assertion = _one(root, "./saml:Assertion")
        if name != "clean":
            _mutate(assertion, name)
        target_id = assertion.get("ID")
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
