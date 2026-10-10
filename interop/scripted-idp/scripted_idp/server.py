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

"""HTTPS scripted SAML test partner and strict JSON control surface.

The TLS certificate chain and key are PEM files named by SCRIPTED_IDP_TLS_CERT and
SCRIPTED_IDP_TLS_KEY. There is no plaintext fallback: startup fails without them.
"""

import http.server
import base64
import binascii
import copy
import json
import os
import pathlib
import signal
import ssl
import sys
import threading
import urllib.parse
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from lxml import etree
import xmlsec

from . import versions
from . import mint
from . import slo
from . import template
from . import schema
from . import selftest as x

PORT = 8443
TLS_CERT_ENV = "SCRIPTED_IDP_TLS_CERT"
TLS_KEY_ENV = "SCRIPTED_IDP_TLS_KEY"
READY_MARKER = "SCRIPTED_IDP_READY"
KEYS_ENV = "SCRIPTED_IDP_KEYS_DIR"
MAX_BODY = 512 * 1024
MAX_QUERY = 32 * 1024
MAX_REQUEST = 256 * 1024


class InputError(ValueError):
    pass


def _fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise InputError("invalid or unknown fields")
    return value


def _param_pairs(raw):
    if len(raw) > MAX_QUERY or not raw.isascii():
        raise InputError("invalid query")
    parts = raw.split("&")
    result = {}
    for part in parts:
        if "=" not in part:
            raise InputError("invalid query parameter")
        key, value = part.split("=", 1)
        if key not in ("SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature") or key in result:
            raise InputError("unknown or duplicate query parameter")
        if not value or "%" in value and any(
                len(value[i + 1:i + 3]) != 2 or
                not all(c in "0123456789abcdefABCDEF" for c in value[i + 1:i + 3])
                for i, c in enumerate(value) if c == "%"):
            raise InputError("invalid query encoding")
        try:
            decoded = urllib.parse.unquote(value, encoding="utf-8", errors="strict")
        except UnicodeError as exception:
            raise InputError("invalid query encoding") from exception
        result[key] = (part, decoded)
    return result


def _request_xml(raw, binding):
    if binding == "redirect":
        parameters = _param_pairs(raw)
        if "SAMLRequest" not in parameters:
            raise InputError("missing SAMLRequest")
        try:
            compressed = base64.b64decode(parameters["SAMLRequest"][1], validate=True)
            inflater = zlib.decompressobj(-15)
            payload = inflater.decompress(compressed, MAX_REQUEST + 1)
            if inflater.unconsumed_tail or not inflater.eof or len(payload) > MAX_REQUEST:
                raise InputError("oversized or truncated AuthnRequest")
            payload += inflater.flush()
            if len(payload) > MAX_REQUEST:
                raise InputError("oversized AuthnRequest")
        except (ValueError, binascii.Error, zlib.error) as exception:
            raise InputError("malformed AuthnRequest") from exception
    else:
        parameters = _param_pairs(raw)
        try:
            payload = base64.b64decode(parameters["SAMLRequest"][1], validate=True)
        except (KeyError, ValueError, binascii.Error) as exception:
            raise InputError("malformed AuthnRequest") from exception
    if len(payload) > MAX_REQUEST or b"<!DOCTYPE" in payload.upper():
        raise InputError("invalid AuthnRequest XML")
    try:
        root = etree.fromstring(payload, x.PARSER)
    except etree.XMLSyntaxError as exception:
        raise InputError("invalid AuthnRequest XML") from exception
    if root.tag != x._q(x.SAMLP, "AuthnRequest") or root.get("Version") != "2.0":
        raise InputError("not a SAML 2.0 AuthnRequest")
    issuer = root.find(x._q(x.SAML, "Issuer"))
    if issuer is None or not issuer.text or not root.get("ID"):
        raise InputError("AuthnRequest missing Issuer or ID")
    return root, parameters, payload


def _verify_redirect(parameters, certificate):
    field = "SAMLRequest" if "SAMLRequest" in parameters else "SAMLResponse"
    signed = field + "=" + parameters[field][0].split("=", 1)[1]
    if "RelayState" in parameters:
        signed += "&RelayState=" + parameters["RelayState"][0].split("=", 1)[1]
    signed += "&SigAlg=" + parameters["SigAlg"][0].split("=", 1)[1]
    algorithms = {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256(),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": hashes.SHA384(),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512(),
    }
    algorithm = algorithms.get(parameters["SigAlg"][1])
    if algorithm is None:
        raise InputError("unsupported request signature algorithm")
    try:
        signature = base64.b64decode(parameters["Signature"][1], validate=True)
        public_key = x509.load_pem_x509_certificate(certificate.encode("ascii")).public_key()
        public_key.verify(signature, signed.encode("ascii"), padding.PKCS1v15(), algorithm)
    except (ValueError, TypeError, AttributeError) as exception:
        raise InputError("invalid request signature") from exception
    except Exception as exception:
        raise InputError("invalid request signature") from exception


def _slo_xml(parameters):
    if ("SAMLRequest" in parameters) == ("SAMLResponse" in parameters):
        raise InputError("exactly one SAML logout message required")
    field = "SAMLRequest" if "SAMLRequest" in parameters else "SAMLResponse"
    try:
        compressed = base64.b64decode(parameters[field][1], validate=True)
        inflater = zlib.decompressobj(-15)
        payload = inflater.decompress(compressed, MAX_REQUEST + 1)
        if inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
            raise InputError("invalid logout message")
        payload += inflater.flush()
        if len(payload) > MAX_REQUEST:
            raise InputError("oversized logout message")
        root = etree.fromstring(payload, x.PARSER)
    except (binascii.Error, zlib.error, etree.XMLSyntaxError) as exception:
        raise InputError("invalid logout message") from exception
    expected = "LogoutRequest" if field == "SAMLRequest" else "LogoutResponse"
    if root.tag != x._q(x.SAMLP, expected) or root.get("Version") != "2.0" or not root.get("ID"):
        raise InputError("invalid logout structure")
    return root, payload, field


def _verify_post(root, certificate):
    signature = root.find(x._q(x.DS, "Signature"))
    if signature is None:
        raise InputError("missing request XML signature")
    try:
        context = x.xmlsec.SignatureContext()
        context.key = x.xmlsec.Key.from_memory(certificate.encode("ascii"), x.C.KeyDataFormatCertPem)
        context.register_id(root, "ID")
        context.verify(signature)
    except Exception as exception:
        raise InputError("invalid request XML signature") from exception


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def version_string(self):
        return "scripted-idp"

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == "/health" and not path.query:
            self._send_json(200, {"status": "ok", "versions": self.server.health})
        elif path.path == "/control/received" and not path.query:
            with self.server.state_lock:
                self._send_json(200, {"received": copy.deepcopy(self.server.received)})
        elif path.path == "/metadata":
            self._metadata(path.query)
        elif path.path == "/sso":
            self._sso(path.query, "redirect")
        elif path.path == "/slo":
            self._slo(path.query)
        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        try:
            payload = self._json_body()
            if self.path == "/control/config":
                _fields(payload, ("base_url",), ("base_url",))
                base_url = mint._https(payload["base_url"], "base_url").rstrip("/")
                with self.server.state_lock:
                    self.server.base_url = base_url
                self._send_json(200, {"base_url": base_url})
            elif self.path == "/control/sps":
                _fields(payload, ("entity_id", "acs_url", "slo_url", "signing_certificate_pem",
                                  "metadata_xml",
                                  "require_signed_requests"), ("entity_id", "acs_url"))
                entity_id = mint._string(payload["entity_id"], "entity_id")
                mint._https(payload["acs_url"], "acs_url")
                if "slo_url" in payload:
                    mint._https(payload["slo_url"], "slo_url")
                certificate = payload.get("signing_certificate_pem")
                if certificate is not None:
                    x509.load_pem_x509_certificate(certificate.encode("ascii"))
                require = payload.get("require_signed_requests", False)
                if not isinstance(require, bool) or require and certificate is None:
                    raise InputError("invalid signing requirement")
                metadata_xml = payload.get("metadata_xml")
                if metadata_xml is not None:
                    metadata_root = template._tree(metadata_xml)
                    md = "urn:oasis:names:tc:SAML:2.0:metadata"
                    if metadata_root.tag != x._q(md, "EntityDescriptor") or \
                            metadata_root.get("entityID") != entity_id or \
                            not schema.validate(self.server.schemas, "sp_metadata", metadata_root):
                        raise InputError("SP metadata fails OASIS schema or entity match")
                    acs_locations = [element.get("Location") for element in metadata_root.iter(
                        x._q(md, "AssertionConsumerService"))]
                    if payload["acs_url"] not in acs_locations:
                        raise InputError("SP metadata ACS mismatch")
                    if "slo_url" in payload and payload["slo_url"] not in [
                            element.get("Location") for element in metadata_root.iter(
                                x._q(md, "SingleLogoutService"))]:
                        raise InputError("SP metadata logout endpoint mismatch")
                with self.server.state_lock:
                    self.server.sps[entity_id] = {key: value for key, value in payload.items()
                                                  if key != "metadata_xml"}
                    if metadata_xml is not None:
                        self.server.received.append({"entity_id": entity_id, "binding": "sp-metadata",
                                                     "xml": metadata_xml, "schema_valid": True})
                self._send_json(200, {"entity_id": entity_id})
            elif self.path == "/control/armed/sso":
                _fields(payload, ("entity_id", "spec"), ("entity_id", "spec"))
                entity_id = mint._string(payload["entity_id"], "entity_id")
                _fields(payload["spec"], ("clock", "sp", "subject", "signing", "encryption", "ids"),
                        ("clock",))
                with self.server.state_lock:
                    if entity_id not in self.server.sps:
                        raise InputError("SP is not registered")
                    self.server.armed[entity_id] = copy.deepcopy(payload["spec"])
                self._send_json(200, {"armed": entity_id})
            elif self.path == "/control/armed/slo":
                _fields(payload, ("entity_id", "clock", "status"), ("entity_id", "clock"))
                entity_id = mint._string(payload["entity_id"], "entity_id")
                mint._instant(_fields(payload["clock"], ("now",), ("now",))["now"])
                if payload.get("status", "Success") not in ("Success", "Responder"):
                    raise InputError("invalid logout status")
                with self.server.state_lock:
                    if entity_id not in self.server.sps or "slo_url" not in self.server.sps[entity_id]:
                        raise InputError("SP logout endpoint is not registered")
                    self.server.armed_slo[entity_id] = copy.deepcopy(payload)
                self._send_json(200, {"armed": entity_id})
            else:
                self._send_json(404, {"error": "not found"})
        except (InputError, mint.SpecError, ValueError, UnicodeError) as exception:
            self._send_json(400, {"error": str(exception)})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path)
        if self.path in ("/control/sign", "/control/encrypt", "/control/logout-sign",
                         "/control/oracle/verify", "/control/oracle/decrypt"):
            try:
                spec = self._json_body()
                result = {
                    "/control/sign": lambda: template.sign(spec, self.server.key_directory),
                    "/control/encrypt": lambda: template.encrypt(spec, self.server.key_directory),
                    "/control/logout-sign": lambda: slo.sign_fixture(spec, self.server.key_directory),
                    "/control/oracle/verify": lambda: template.verify(spec, self.server.key_directory),
                    "/control/oracle/decrypt": lambda: template.decrypt(spec),
                }[self.path]()
                self._send_json(200, result)
            except template.OracleUnavailable as exception:
                self._send_json(409, {"error": str(exception)})
            except (InputError, mint.SpecError, ValueError, UnicodeError, xmlsec.Error) as exception:
                self._send_json(400, {"error": str(exception)})
            return
        if path.path == "/control/reset":
            try:
                params = urllib.parse.parse_qs(path.query, strict_parsing=True)
                if set(params) != {"sp"} or len(params["sp"]) != 1:
                    raise InputError("one sp parameter required")
                entity_id = mint._string(params["sp"][0], "sp")
                if self.headers.get("Content-Length") != "0":
                    raise InputError("reset body must be empty")
                with self.server.state_lock:
                    self.server.sps.pop(entity_id, None)
                    self.server.armed.pop(entity_id, None)
                    self.server.armed_slo.pop(entity_id, None)
                    self.server.issued_slo.pop(entity_id, None)
                    self.server.received = [entry for entry in self.server.received
                                            if entry["entity_id"] != entity_id]
                self._send_json(200, {"reset": entity_id})
            except (InputError, mint.SpecError, ValueError) as exception:
                self._send_json(400, {"error": str(exception)})
            return
        if self.path == "/sso":
            try:
                body = self._body()
                if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                    raise InputError("invalid POST binding content type")
                self._sso(body.decode("ascii"), "post")
            except (InputError, UnicodeError) as exception:
                self._send_json(400, {"error": str(exception)})
            return
        if self.path == "/control/logout-requests":
            try:
                spec = self._json_body()
                result = slo.logout_request(spec, self.server.key_directory)
                entity_id = spec["sp"]["entity_id"]
                with self.server.state_lock:
                    if entity_id not in self.server.sps:
                        raise InputError("SP is not registered")
                    self.server.issued_slo[entity_id] = (result["request_id"], result["relay_state"])
                self._send_json(200, result)
            except (InputError, mint.SpecError, ValueError) as exception:
                self._send_json(400, {"error": str(exception)})
            return
        if self.path != "/control/responses":
            self._send_json(404, {"error": "not found"})
            return
        try:
            result = mint.mint_response(self._json_body(), self.server.key_directory)
            self._send_json(200, result)
        except (InputError, mint.SpecError, ValueError) as exception:
            self._send_json(400, {"error": str(exception)})

    def _metadata(self, raw_query):
        try:
            params = urllib.parse.parse_qs(raw_query, strict_parsing=True)
            if set(params) - {"now", "variant"} or "now" not in params or \
                    len(params["now"]) != 1 or len(params.get("variant", ["default"])) != 1:
                raise InputError("one absolute now and optional variant required")
            variant = params.get("variant", ["default"])[0]
            if variant not in ("default", "rollover", "aggregate", "expired", "scopes",
                               "no-slo", "signed", "aggregate-signed"):
                raise InputError("unknown metadata variant")
            now = mint._instant(params["now"][0]).replace(microsecond=0)
            with self.server.state_lock:
                base_url = self.server.base_url
            if base_url is None:
                raise InputError("IdP URL is not configured")
            certificate = x.Credential.from_files("idp-signing-rsa-2048",
                                                  self.server.key_directory).cert_pem
            cert = x509.load_pem_x509_certificate(certificate)
            md = "urn:oasis:names:tc:SAML:2.0:metadata"
            descriptor = etree.Element(x._q(md, "EntityDescriptor"),
                                       nsmap={"md": md, "ds": x.DS}, entityID=x.IDP,
                                       validUntil=mint._format(now + mint.datetime.timedelta(
                                           days=-1 if variant == "expired" else 1)))
            if variant in ("signed", "aggregate-signed"):
                descriptor.set("ID", "_scripted_metadata_entity")
            role = etree.SubElement(descriptor, x._q(md, "IDPSSODescriptor"),
                                    protocolSupportEnumeration=x.SAMLP,
                                    WantAuthnRequestsSigned="false")
            signing = etree.SubElement(role, x._q(md, "KeyDescriptor"), use="signing")
            key_info = etree.SubElement(signing, x._q(x.DS, "KeyInfo"))
            cert_data = etree.SubElement(key_info, x._q(x.DS, "X509Data"))
            etree.SubElement(cert_data, x._q(x.DS, "X509Certificate")).text = \
                base64.b64encode(cert.public_bytes(x.serialization.Encoding.DER)).decode("ascii")
            if variant == "rollover":
                second = x509.load_pem_x509_certificate((self.server.key_directory /
                        "idp-signing-rsa-3072-cert.pem").read_bytes())
                second_descriptor = etree.SubElement(role, x._q(md, "KeyDescriptor"), use="signing")
                second_data = etree.SubElement(etree.SubElement(second_descriptor,
                        x._q(x.DS, "KeyInfo")), x._q(x.DS, "X509Data"))
                etree.SubElement(second_data, x._q(x.DS, "X509Certificate")).text = \
                    base64.b64encode(second.public_bytes(x.serialization.Encoding.DER)).decode("ascii")
            if variant == "scopes":
                shibmd = "urn:mace:shibboleth:metadata:1.0"
                extensions = etree.Element(x._q(md, "Extensions"), nsmap={"shibmd": shibmd})
                etree.SubElement(extensions, x._q(shibmd, "Scope")).text = "example.test"
                etree.SubElement(extensions, x._q(shibmd, "Scope"), regexp="true").text = ".*"
                role.insert(0, extensions)
            if variant != "no-slo":
                etree.SubElement(role, x._q(md, "SingleLogoutService"),
                                 Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                                 Location=base_url + "/slo")
            etree.SubElement(role, x._q(md, "SingleSignOnService"),
                             Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                             Location=base_url + "/sso")
            etree.SubElement(role, x._q(md, "SingleSignOnService"),
                             Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                             Location=base_url + "/sso")
            if variant == "signed":
                x.xmlsec_sign(descriptor, x.Credential.from_files("idp-signing-rsa-2048",
                              self.server.key_directory), x.C.TransformRsaSha256,
                              x.C.TransformSha256, insert_at=0)
            if variant in ("aggregate", "aggregate-signed"):
                aggregate = etree.Element(x._q(md, "EntitiesDescriptor"), nsmap={"md": md, "ds": x.DS},
                                          ID="_scripted_metadata_aggregate",
                                          validUntil=mint._format(now + mint.datetime.timedelta(days=2)))
                decoy = copy.deepcopy(descriptor)
                decoy.set("entityID", "https://decoy.example.test/")
                decoy.attrib.pop("ID", None)
                aggregate.append(decoy)
                aggregate.append(descriptor)
                if variant == "aggregate-signed":
                    x.xmlsec_sign(aggregate, x.Credential.from_files("idp-signing-rsa-2048",
                                  self.server.key_directory), x.C.TransformRsaSha256,
                                  x.C.TransformSha256, insert_at=0)
                descriptor = aggregate
            body = etree.tostring(descriptor, xml_declaration=True, encoding="UTF-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/samlmetadata+xml")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (InputError, mint.SpecError, ValueError) as exception:
            self._send_json(400, {"error": str(exception)})

    def _sso(self, raw, binding):
        try:
            root, parameters, serialized = _request_xml(raw, binding)
            if not schema.validate(self.server.schemas, "authn_request", root):
                raise InputError("AuthnRequest fails OASIS schema")
            issuer = root.findtext(x._q(x.SAML, "Issuer"))
            with self.server.state_lock:
                sp = copy.deepcopy(self.server.sps.get(issuer))
                base_url = self.server.base_url
            if sp is None or base_url is None:
                raise InputError("SP or IdP URL is not configured")
            if root.get("Destination") != base_url + "/sso":
                raise InputError("wrong AuthnRequest destination")
            if root.get("AssertionConsumerServiceURL") != sp["acs_url"]:
                raise InputError("wrong AuthnRequest ACS")
            certificate = sp.get("signing_certificate_pem")
            signed = "SigAlg" in parameters or "Signature" in parameters if binding == "redirect" \
                     else root.find(x._q(x.DS, "Signature")) is not None
            if signed:
                if certificate is None:
                    raise InputError("no SP signing certificate")
                if binding == "redirect":
                    if "SigAlg" not in parameters or "Signature" not in parameters:
                        raise InputError("partial request signature")
                    _verify_redirect(parameters, certificate)
                else:
                    _verify_post(root, certificate)
            elif sp.get("require_signed_requests", False):
                raise InputError("unsigned AuthnRequest")
            with self.server.state_lock:
                self.server.received.append({"entity_id": issuer, "binding": binding,
                                             "xml": serialized.decode("utf-8"),
                                             "signature_valid": signed, "schema_valid": True})
                spec = self.server.armed.pop(issuer, None)
            if spec is None:
                self._send_json(409, {"error": "no armed SSO response"})
                return
            spec["sp"] = {"entity_id": issuer, "acs_url": sp["acs_url"],
                          "request_id": root.get("ID"),
                          "relay_state": parameters.get("RelayState", (None, None))[1]}
            if spec["sp"]["relay_state"] is None:
                del spec["sp"]["relay_state"]
            result = mint.mint_response(spec, self.server.key_directory)
            payload = result["form"].encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; form-action "
                             + sp["acs_url"])
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (InputError, mint.SpecError, ValueError) as exception:
            self._send_json(400, {"error": str(exception)})

    def _slo(self, raw):
        try:
            parameters = _param_pairs(raw)
            if "SigAlg" not in parameters or "Signature" not in parameters:
                raise InputError("unsigned logout message")
            root, payload, field = _slo_xml(parameters)
            issuer = root.findtext(x._q(x.SAML, "Issuer"))
            with self.server.state_lock:
                sp = copy.deepcopy(self.server.sps.get(issuer))
                base_url = self.server.base_url
            if sp is None or "slo_url" not in sp or base_url is None:
                raise InputError("SP logout endpoint is not registered")
            if root.get("Destination") != base_url + "/slo":
                raise InputError("wrong logout destination")
            certificate = sp.get("signing_certificate_pem")
            if certificate is None:
                raise InputError("SP signing certificate is missing")
            _verify_redirect(parameters, certificate)
            with self.server.state_lock:
                self.server.received.append({"entity_id": issuer, "binding": "redirect-slo",
                                             "xml": payload.decode("utf-8"),
                                             "signature_valid": True})
                armed = self.server.armed_slo.pop(issuer, None) if field == "SAMLRequest" else None
                issued = self.server.issued_slo.pop(issuer, None) if field == "SAMLResponse" else None
            if field == "SAMLResponse":
                if issued is None or root.get("InResponseTo") != issued[0] or \
                        parameters.get("RelayState", (None, None))[1] != issued[1]:
                    raise InputError("unmatched LogoutResponse")
                self._send_json(200, {"verified": "LogoutResponse"})
                return
            if armed is None:
                self._send_json(409, {"error": "no armed SLO response"})
                return
            now = mint._instant(armed["clock"]["now"])
            response = slo.logout_response(now, sp["slo_url"], root.get("ID"),
                    parameters.get("RelayState", (None, None))[1],
                    armed.get("status", "Success"), self.server.key_directory)
            self.send_response(302)
            self.send_header("Location", response["redirect_url"])
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (InputError, mint.SpecError, ValueError, KeyError) as exception:
            self._send_json(400, {"error": str(exception)})

    def _body(self):
        length = self.headers.get("Content-Length")
        if length is None or not length.isascii() or not length.isdecimal() or int(length) > MAX_BODY:
            raise InputError("invalid Content-Length")
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            raise InputError("truncated body")
        return body

    def _json_body(self):
        if self.headers.get_content_type() != "application/json":
            raise InputError("JSON content type required")
        try:
            return json.loads(self._body().decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exception:
            raise InputError("invalid JSON") from exception

    def _send_json(self, status, body):
        payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, tls_context, health, key_directory, schemas):
        super().__init__(address, Handler)
        self.tls_context = tls_context
        self.health = health
        self.key_directory = key_directory
        self.schemas = schemas
        self.state_lock = threading.Lock()
        self.base_url = None
        self.sps = {}
        self.armed = {}
        self.armed_slo = {}
        self.issued_slo = {}
        self.received = []

    def get_request(self):
        # Wrap per connection and handshake on the handler thread, so one slow client
        # cannot stall accept().
        connection, address = self.socket.accept()
        return self.tls_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address

    def handle_error(self, request, client_address):
        # One line per failed connection (for example a TLS handshake), not a traceback.
        print(f"connection from {client_address[0]} failed: {sys.exc_info()[1]!r}", file=sys.stderr, flush=True)


def tls_context():
    cert, key = os.environ.get(TLS_CERT_ENV), os.environ.get(TLS_KEY_ENV)
    if not cert or not key:
        raise SystemExit(f"{TLS_CERT_ENV} and {TLS_KEY_ENV} must name the TLS certificate chain and key (PEM)")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def _exit_on_sigterm(signum, frame):
    # As PID 1 in a container, Python would otherwise ignore docker stop's SIGTERM.
    raise SystemExit(0)


def main(argv):
    if argv:
        raise SystemExit("usage: python -m scripted_idp serve")
    versions.check_libxml2_pairing()
    key_path = os.environ.get(KEYS_ENV)
    key_directory = pathlib.Path(key_path) if key_path else None
    if key_directory is None or not key_directory.is_dir():
        raise SystemExit(f"{KEYS_ENV} must name the mounted test-only key directory")
    x.Credential.from_files("idp-signing-rsa-2048", key_directory)
    sp_certificate = x509.load_pem_x509_certificate(
        (key_directory / "sp-encryption-rsa-2048-cert.pem").read_bytes())
    oracle_key_path = os.environ.get(template.ORACLE_KEY_ENV)
    if oracle_key_path:
        oracle_key = x.serialization.load_pem_private_key(
            pathlib.Path(oracle_key_path).read_bytes(), password=None)
        encoding = x.serialization.Encoding.DER
        public_format = x.serialization.PublicFormat.SubjectPublicKeyInfo
        if oracle_key.public_key().public_bytes(encoding, public_format) != \
                sp_certificate.public_key().public_bytes(encoding, public_format):
            raise SystemExit("oracle decryption key does not match the test SP certificate")
    server = Server(("0.0.0.0", PORT), tls_context(), versions.versions(), key_directory,
                    schema.load())
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
    print(f"{READY_MARKER} port={PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
