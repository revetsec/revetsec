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

"""Test IdP Single Logout producer: Redirect octets or POST XML signatures."""

import base64
import datetime
import html
import pathlib
import urllib.parse
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from . import mint
from . import selftest as x


SIGALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def _signed(root, field, relay, destination, key_directory, binding="redirect"):
    credential = x.Credential.from_files("idp-signing-rsa-2048", pathlib.Path(key_directory))
    if binding == "post":
        x.xmlsec_sign(root, credential, x.C.TransformRsaSha256, x.C.TransformSha256)
        serialized = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        fields = {field: base64.b64encode(serialized).decode("ascii")}
        if relay is not None:
            fields["RelayState"] = relay
        form = ('<!doctype html><html><head><meta charset="utf-8"></head><body>'
                '<form method="post" action="' + html.escape(destination, quote=True) + '">'
                + ''.join('<input type="hidden" name="' + name + '" value="'
                          + html.escape(value, quote=True) + '">' for name, value in fields.items())
                + '<noscript><button type="submit">Continue</button></noscript></form>'
                '<script>document.forms[0].submit()</script></body></html>')
        return {"action": destination, "fields": fields, "form": form,
                "form_body": urllib.parse.urlencode(fields), "xml": serialized.decode("utf-8")}
    if binding != "redirect":
        raise mint.SpecError("invalid logout binding")
    serialized = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    compressor = zlib.compressobj(wbits=-15)
    compressed = compressor.compress(serialized) + compressor.flush()
    query = field + "=" + urllib.parse.quote(base64.b64encode(compressed).decode("ascii"), safe="")
    if relay is not None:
        query += "&RelayState=" + urllib.parse.quote(relay, safe="")
    query += "&SigAlg=" + urllib.parse.quote(SIGALG, safe="")
    signature = credential.private_key.sign(query.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    query += "&Signature=" + urllib.parse.quote(base64.b64encode(signature).decode("ascii"), safe="")
    return {"redirect_url": destination + "?" + query, "raw_query": query,
            "xml": serialized.decode("utf-8")}


def logout_request(spec, key_directory):
    spec = mint._object(spec, ("clock", "sp", "subject", "ids", "relay_state", "binding"),
                        ("clock", "sp", "subject"))
    now = mint._instant(mint._object(spec["clock"], ("now",), ("now",))["now"])
    sp = mint._object(spec["sp"], ("entity_id", "slo_url"), ("entity_id", "slo_url"))
    entity_id = mint._string(sp["entity_id"], "sp.entity_id")
    destination = mint._https(sp["slo_url"], "sp.slo_url")
    subject = mint._object(spec["subject"], ("name_id", "session_index"), ("name_id",))
    name_id = mint._string(subject["name_id"], "subject.name_id")
    session_index = subject.get("session_index")
    if session_index is not None:
        mint._string(session_index, "subject.session_index")
    ids = mint._object(spec.get("ids", {}), ("request",))
    request_id = mint._identifier(ids.get("request"), "ids.request")
    relay = spec.get("relay_state")
    if relay is not None:
        mint._string(relay, "relay_state", 80)
    root = x._root(x.SAMLP, "LogoutRequest", {"p": x.SAMLP, "a": x.SAML},
                   ID=request_id, Version="2.0", IssueInstant=mint._format(now),
                   NotOnOrAfter=mint._format(now + datetime.timedelta(minutes=5)),
                   Destination=destination)
    x._sub(root, x.SAML, "Issuer", x.IDP)
    x._sub(root, x.SAML, "NameID", name_id,
           Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
           NameQualifier=x.IDP, SPNameQualifier=entity_id)
    if session_index is not None:
        x._sub(root, x.SAMLP, "SessionIndex", session_index)
    result = _signed(root, "SAMLRequest", relay, destination, key_directory,
                     spec.get("binding", "redirect"))
    result["request_id"] = request_id
    result["relay_state"] = relay
    return result


def logout_response(now, destination, in_response_to, relay, status, key_directory,
                    binding="redirect"):
    if status not in ("Success", "Responder"):
        raise mint.SpecError("invalid logout status")
    root = x._root(x.SAMLP, "LogoutResponse", {"p": x.SAMLP, "a": x.SAML},
                   ID=mint._identifier(None, "response ID"), Version="2.0",
                   IssueInstant=mint._format(now), Destination=destination,
                   InResponseTo=in_response_to)
    x._sub(root, x.SAML, "Issuer", x.IDP)
    x._sub(x._sub(root, x.SAMLP, "Status"), x.SAMLP, "StatusCode",
           Value="urn:oasis:names:tc:SAML:2.0:status:" + status)
    return _signed(root, "SAMLResponse", relay, destination, key_directory, binding)


def sign_fixture(spec, key_directory):
    """Sign caller-supplied logout XML for hostile SP acceptance tests only."""
    spec = mint._object(spec, ("xml", "destination", "relay_state", "binding"),
                        ("xml", "destination"))
    xml = mint._string(spec["xml"], "xml", 65536).encode("utf-8")
    if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
        raise mint.SpecError("invalid logout XML")
    try:
        root = etree.fromstring(xml, x.PARSER)
    except etree.XMLSyntaxError as exception:
        raise mint.SpecError("invalid logout XML") from exception
    if root.tag == x._q(x.SAMLP, "LogoutRequest"):
        field = "SAMLRequest"
    elif root.tag == x._q(x.SAMLP, "LogoutResponse"):
        field = "SAMLResponse"
    else:
        raise mint.SpecError("not a logout message")
    # The hostile-fixture endpoint signs the caller's current contents anew.
    # Removing the old signature lets tests distinguish semantic failures from
    # a broken signature, using the independent libxmlsec implementation.
    for signature in root.findall(x._q(x.DS, "Signature")):
        root.remove(signature)
    destination = mint._https(spec["destination"], "destination")
    relay = spec.get("relay_state")
    if relay is not None:
        relay = mint._string(relay, "relay_state", 80)
    return _signed(root, field, relay, destination, key_directory,
                   spec.get("binding", "redirect"))
