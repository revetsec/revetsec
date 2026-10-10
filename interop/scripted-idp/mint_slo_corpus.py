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

"""Mint deterministic Python-signed HTTP-Redirect SLO differential fixtures."""

import argparse
import pathlib

from scripted_idp import slo


SP = "https://sp.test/Selftest"
SLO = "https://sp.test/logout"
IDP = "https://idp.scripted-idp.test/"
RELAY = "AAAAAAAAAAAAAAAAAAAAAA"  # Base64url of the SP test's sixteen zero bytes.
SP_REQUEST_ID = "_" + "00" * 20


def _changed(original, replacement):
    if original == replacement:
        raise ValueError("SLO corpus mutation was inert")
    return replacement


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
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
    }
    lines = ["# Python cryptography RSA-SHA256 Redirect signatures from the pinned scripted IdP.",
             "# Regenerate inside its image with this script and the fixed test key directory."]
    for name, xml in candidates.items():
        result = slo.sign_fixture({"xml": xml, "destination": SLO, "relay_state": RELAY},
                                  args.keys)
        lines.append(name + "=" + result["raw_query"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"wrote {len(candidates)} signed SLO fixtures to {args.out}")


if __name__ == "__main__":
    main()
