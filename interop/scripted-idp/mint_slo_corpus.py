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

"""Mint deterministic independent signatures for Redirect or POST SLO fixtures."""

import argparse
import pathlib

from lxml import etree

from scripted_idp import schema, slo
from scripted_idp import selftest as x


SP = "https://sp.test/Selftest"
SLO = "https://sp.test/logout"
IDP = "https://idp.scripted-idp.test/"
RELAY = "AAAAAAAAAAAAAAAAAAAAAA"  # Base64url of the SP test's sixteen zero bytes.
SP_REQUEST_ID = "_" + "00" * 20
PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
XSI = "http://www.w3.org/2001/XMLSchema-instance"


def _changed(original, replacement):
    if original == replacement:
        raise ValueError("SLO corpus mutation was inert")
    return replacement


def _swap_children(xml, first, second):
    root = etree.fromstring(xml.encode("utf-8"))
    children = list(root)
    children[first], children[second] = children[second], children[first]
    root[:] = children
    return etree.tostring(root, encoding="unicode")


def _nilled(xml, namespace, local_name):
    root = etree.fromstring(xml.encode("utf-8"))
    target = root.find(f"{{{namespace}}}{local_name}")
    if target is None:
        raise ValueError(f"missing SLO fixture element: {local_name}")
    target.set(f"{{{XSI}}}nil", "true")
    return etree.tostring(root, encoding="unicode")


def _root_text(xml):
    root = etree.fromstring(xml.encode("utf-8"))
    root.text = "attacker-text"
    return etree.tostring(root, encoding="unicode")


def _nested_failure(xml):
    root = etree.fromstring(xml.encode("utf-8"))
    code = root.find(f"{{{PROTOCOL}}}Status/{{{PROTOCOL}}}StatusCode")
    if code is None:
        raise ValueError("missing SLO status code")
    etree.SubElement(code, f"{{{PROTOCOL}}}StatusCode",
                     Value="urn:oasis:names:tc:SAML:2.0:status:Responder")
    return etree.tostring(root, encoding="unicode")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
    parser.add_argument("--binding", choices=("redirect", "post"), default="redirect")
    args = parser.parse_args()
    if not args.keys.is_dir():
        raise SystemExit("test key directory is missing")
    request = slo.logout_request({
        "clock": {"now": "2026-09-01T00:00:00Z"},
        "sp": {"entity_id": SP, "slo_url": SLO},
        "subject": {"name_id": "minted-user", "session_index": "session-123"},
        "ids": {"request": "_slo_idp_request"},
        "relay_state": RELAY,
    }, args.keys)
    request_xml = request["xml"]
    response_xml = (
        "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
        "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_slo_idp_response' "
        "Version='2.0' IssueInstant='2026-09-01T00:00:00Z' "
        "Destination='https://sp.test/logout' InResponseTo='" + SP_REQUEST_ID + "'>"
        "<a:Issuer>https://idp.scripted-idp.test/</a:Issuer>"
        "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
        "</p:Status></p:LogoutResponse>"
    )
    candidates = {
        "request-valid": request_xml,
        "request-wrong-destination": _changed(request_xml, request_xml.replace(
            SLO, "https://sp.test/wrong-logout")),
        "request-wrong-issuer": _changed(request_xml, request_xml.replace(
            "<a:Issuer>" + IDP + "</a:Issuer>", "<a:Issuer>https://attacker.test/</a:Issuer>")),
        "request-future-issue": _changed(request_xml, request_xml.replace(
            "2026-09-01T00:00:00Z", "2026-09-01T00:10:00Z")),
        "request-expired": _changed(request_xml, request_xml.replace(
            'NotOnOrAfter="2026-09-01T00:05:00Z"',
            'NotOnOrAfter="2026-09-01T00:00:00Z"')),
        "request-duplicate-nameid": _changed(request_xml, request_xml.replace(
            "</p:LogoutRequest>", "<a:NameID>attacker</a:NameID></p:LogoutRequest>")),
        "request-unknown-extension": _changed(request_xml, request_xml.replace(
            "</p:LogoutRequest>", "<p:Extensions/></p:LogoutRequest>")),
        "request-nameid-before-issuer": _swap_children(request_xml, 0, 1),
        "request-session-before-nameid": _swap_children(request_xml, 1, 2),
        "request-nilled-nameid": _nilled(request_xml, ASSERTION, "NameID"),
        "request-nilled-session": _nilled(request_xml, PROTOCOL, "SessionIndex"),
        "request-root-text": _root_text(request_xml),
        "response-valid": response_xml,
        "response-wrong-destination": _changed(response_xml, response_xml.replace(
            SLO, "https://sp.test/wrong-logout")),
        "response-wrong-correlation": _changed(response_xml, response_xml.replace(
            SP_REQUEST_ID, "_unrelated_request")),
        "response-wrong-issuer": _changed(response_xml, response_xml.replace(
            "<a:Issuer>" + IDP + "</a:Issuer>", "<a:Issuer>https://attacker.test/</a:Issuer>")),
        "response-stale-issue": _changed(response_xml, response_xml.replace(
            "2026-09-01T00:00:00Z", "2026-08-31T00:00:00Z")),
        "response-duplicate-status": _changed(response_xml, response_xml.replace(
            "</p:LogoutResponse>", "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:"
            "status:Success'/></p:Status></p:LogoutResponse>")),
        "response-empty-status": _changed(response_xml, response_xml.replace(
            "Value='urn:oasis:names:tc:SAML:2.0:status:Success'", "Value=''")),
        "response-status-before-issuer": _swap_children(response_xml, 0, 1),
        "response-nilled-status": _nilled(response_xml, PROTOCOL, "Status"),
        "response-nested-failure": _nested_failure(response_xml),
        "response-root-text": _root_text(response_xml),
    }
    official_schema = schema.load()["authn_request"]
    for name in ("request-nameid-before-issuer", "request-session-before-nameid",
                 "request-nilled-nameid", "request-nilled-session", "request-root-text",
                 "response-status-before-issuer", "response-nilled-status", "response-root-text"):
        if official_schema.validate(etree.fromstring(candidates[name].encode("utf-8"))):
            raise ValueError(f"hostile SLO shape unexpectedly passes OASIS XSD: {name}")
    if not official_schema.validate(etree.fromstring(
            candidates["response-nested-failure"].encode("utf-8"))):
        raise ValueError("nested SLO status should be valid XSD but rejected by the SP profile")
    producer = "libxmlsec RSA-SHA256 XML POST" if args.binding == "post" else "Python cryptography RSA-SHA256 Redirect"
    lines = ["# " + producer + " signatures from the pinned scripted IdP.",
             "# Regenerate inside its image with this script and the fixed test key directory."]
    for name, xml in candidates.items():
        result = slo.sign_fixture({"xml": xml, "destination": SLO, "relay_state": RELAY,
                                   "binding": args.binding},
                                  args.keys)
        if args.binding == "post":
            x.xmlsec_verify(etree.fromstring(result["xml"].encode("utf-8")),
                            x.Credential.from_files("idp-signing-rsa-2048", args.keys),
                            x.C.TransformRsaSha256, x.C.TransformSha256)
        lines.append(name + "=" + result["form_body" if args.binding == "post" else "raw_query"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"wrote {len(candidates)} signed SLO fixtures to {args.out}")


if __name__ == "__main__":
    main()
