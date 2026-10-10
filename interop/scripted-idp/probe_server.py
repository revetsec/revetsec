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

"""Bounded local HTTPS probe of the scripted IdP. Requires a cached image and Docker."""

import base64
import json
import pathlib
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS = ROOT / "src/test/resources/fixtures/keys"
TLS = ROOT / "src/test/resources/tls"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=20).strip()


def request(url, context, method="GET", payload=None, content_type="application/json"):
    data = None if payload is None else (json.dumps(payload).encode("utf-8") if isinstance(payload, dict)
                                         else payload)
    headers = {} if data is None else {"Content-Type": content_type}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, method=method,
                                                           headers=headers), context=context,
                                    timeout=5) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


def main():
    image = "revetsec-scripted-idp:ci"
    container = docker("run", "--rm", "-d", "-p", "127.0.0.1::8443",
                       "-v", f"{ROOT / 'interop/scripted-idp'}:/app:ro",
                       "-v", f"{KEYS}:/run/keys:ro", "-v", f"{TLS}:/run/tls:ro",
                       "-e", "SCRIPTED_IDP_TLS_CERT=/run/tls/server.pem",
                       "-e", "SCRIPTED_IDP_TLS_KEY=/run/tls/server-key.pem",
                       "-e", "SCRIPTED_IDP_KEYS_DIR=/run/keys",
                       "-e", "SCRIPTED_IDP_ORACLE_DECRYPTION_KEY=/run/keys/sp-encryption-rsa-2048-key.pem",
                       image, "serve")
    try:
        port = docker("port", container, "8443/tcp").rsplit(":", 1)[1]
        base = f"https://127.0.0.1:{port}"
        context = ssl.create_default_context(cafile=str(TLS / "test-ca.pem"))
        for _ in range(40):
            try:
                status, _ = request(base + "/health", context)
                if status == 200:
                    break
            except (OSError, TimeoutError):
                time.sleep(.1)
        else:
            raise AssertionError("IdP did not become ready: " + docker("logs", container))
        assert request(base + "/control/config", context, "PUT",
                       {"base_url": base})[0] == 200
        status, metadata = request(base + "/metadata?now=2026-09-01T00%3A00%3A00Z", context)
        assert status == 200 and "IDPSSODescriptor" in metadata, (status, metadata)
        for variant, marker in (("rollover", "KeyDescriptor"),
                                ("aggregate", "EntitiesDescriptor"),
                                ("expired", "2026-08-31"),
                                ("scopes", "example.test"),
                                ("no-slo", "SingleSignOnService"),
                                ("signed", "SignatureValue"),
                                ("aggregate-signed", "SignatureValue")):
            status, value = request(base + "/metadata?now=2026-09-01T00%3A00%3A00Z"
                                    + "&variant=" + variant, context)
            assert status == 200 and marker in value, (variant, status, value)
            if variant in ("signed", "aggregate-signed"):
                target_id = ("_scripted_metadata_entity" if variant == "signed"
                             else "_scripted_metadata_aggregate")
                status, verdict = request(base + "/control/oracle/verify", context, "POST", {
                    "clock": {"now": "2026-09-01T00:00:00Z"}, "xml": value,
                    "target_id": target_id, "credential": "idp-signing-rsa-2048"})
                assert status == 200 and json.loads(verdict)["valid"], (variant, status, verdict)
        entity_id = "https://sp.test/Probe"
        cert = (KEYS / "sp-signing-rsa-2048-cert.pem").read_text()
        assert request(base + "/control/sps", context, "PUT", {
            "entity_id": entity_id, "acs_url": "https://sp.test/acs",
            "signing_certificate_pem": cert, "require_signed_requests": True})[0] == 200
        assert request(base + "/control/armed/sso", context, "PUT", {
            "entity_id": entity_id,
            "spec": {"clock": {"now": "2026-09-01T00:00:00Z"},
                     "signing": {"placement": "both", "algorithm": "rsa-sha256"}}})[0] == 200
        xml = (f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
               f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
               f'ID="_probe1" Version="2.0" IssueInstant="2026-09-01T00:00:00Z" '
               f'Destination="{base}/sso" AssertionConsumerServiceURL="https://sp.test/acs">'
               f'<saml:Issuer>{entity_id}</saml:Issuer></samlp:AuthnRequest>').encode()
        deflater = zlib.compressobj(wbits=-15)
        compressed = deflater.compress(xml) + deflater.flush()
        query = ("SAMLRequest=" + urllib.parse.quote(base64.b64encode(compressed).decode(), safe="")
                 + "&RelayState=" + urllib.parse.quote("probe-handle", safe="")
                 + "&SigAlg=" + urllib.parse.quote(
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", safe=""))
        signature = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign",
             str(KEYS / "sp-signing-rsa-2048-key.pem")], input=query.encode("ascii"),
            timeout=10)
        signed_query = query + "&Signature=" + urllib.parse.quote(
            base64.b64encode(signature).decode(), safe="")
        status, page = request(base + "/sso?" + signed_query, context)
        assert status == 200 and "SAMLResponse" in page and "probe-handle" in page, (status, page)
        status, received = request(base + "/control/received", context)
        assert status == 200 and json.loads(received)["received"][0]["signature_valid"]
        status, _ = request(base + "/sso?" + signed_query + "&RelayState=duplicate", context)
        assert status == 400
        status, _ = request(base + "/control/responses", context, "POST",
                            {"clock": {"now": "2026-09-01T00:00:00Z"},
                             "sp": {"entity_id": entity_id, "acs_url": "https://sp.test/acs"},
                             "typo": True})
        assert status == 400
        status, body = request(base + "/control/responses", context, "POST",
                               {"clock": {"now": "2026-09-01T00:00:00Z"},
                                "sp": {"entity_id": entity_id, "acs_url": "https://sp.test/acs"}})
        assert status == 200 and "saml_response" in json.loads(body)
        unsigned_spec = {"clock": {"now": "2026-09-01T00:00:00Z"},
                         "sp": {"entity_id": entity_id, "acs_url": "https://sp.test/acs"},
                         "signing": {"placement": "none"}}
        status, body = request(base + "/control/responses", context, "POST", unsigned_spec)
        assert status == 200, body
        unsigned = json.loads(body)
        signing_spec = {"clock": unsigned_spec["clock"], "xml": unsigned["xml"],
                        "target_id": unsigned["response_id"],
                        "signing": {"algorithm": "rsa-sha256", "engine": "xmlsec"}}
        status, body = request(base + "/control/sign", context, "POST", signing_spec)
        assert status == 200, body
        signed = json.loads(body)["xml"]
        oracle_spec = {"clock": unsigned_spec["clock"], "xml": signed,
                       "target_id": unsigned["response_id"],
                       "credential": "idp-signing-rsa-2048"}
        status, body = request(base + "/control/oracle/verify", context, "POST", oracle_spec)
        assert status == 200 and json.loads(body) == {
            "valid": True, "reference_uri": "#" + unsigned["response_id"],
            "covers_target": True}, (status, body)
        oracle_spec["xml"] = signed.replace("user-1", "attacker-user")
        status, body = request(base + "/control/oracle/verify", context, "POST", oracle_spec)
        assert status == 200 and json.loads(body)["valid"] is False, (status, body)
        for algorithm, credential in (("rsa-sha384", "idp-signing-rsa-3072"),
                                      ("rsa-sha512", "idp-signing-rsa-3072"),
                                      ("ecdsa-sha256", "idp-signing-ec-p256"),
                                      ("ecdsa-sha384", "idp-signing-ec-p384"),
                                      ("ecdsa-sha512", "idp-signing-ec-p521")):
            signing_spec["signing"] = {"algorithm": algorithm, "digest": "sha512"}
            status, body = request(base + "/control/sign", context, "POST", signing_spec)
            assert status == 200, (algorithm, body)
            oracle_spec["xml"] = json.loads(body)["xml"]
            oracle_spec["credential"] = credential
            status, body = request(base + "/control/oracle/verify", context, "POST", oracle_spec)
            assert status == 200 and json.loads(body)["valid"], (algorithm, status, body)
        signing_spec["signing"] = {"algorithm": "rsa-sha256", "engine": "signxml"}
        status, body = request(base + "/control/sign", context, "POST", signing_spec)
        assert status == 200, body
        oracle_spec["xml"] = json.loads(body)["xml"]
        oracle_spec["credential"] = "idp-signing-rsa-2048"
        status, body = request(base + "/control/oracle/verify", context, "POST", oracle_spec)
        assert status == 200 and json.loads(body)["valid"], (status, body)
        encryption_spec = {"clock": unsigned_spec["clock"], "xml": unsigned["xml"],
                           "target_id": unsigned["assertion_id"], "element": "Assertion",
                           "encryption": {"data_algorithm": "aes256-gcm",
                                          "key_transport": "rsa-oaep-sha256-mgf1sha256"}}
        status, body = request(base + "/control/encrypt", context, "POST", encryption_spec)
        assert status == 200, body
        encrypted = json.loads(body)["xml"]
        assert "EncryptedAssertion" in encrypted and "EncryptedData" in encrypted
        status, body = request(base + "/control/oracle/decrypt", context, "POST",
                               {"clock": unsigned_spec["clock"], "xml": encrypted})
        assert status == 200 and json.loads(body)["valid"] and \
            unsigned["assertion_id"] in json.loads(body)["xml"], (status, body)
        ciphertext = re.search(r"(<xenc:CipherValue>)([^<]+)", encrypted)
        assert ciphertext is not None
        modified = ciphertext.group(1) + ("A" if ciphertext.group(2)[0] != "A" else "B") \
            + ciphertext.group(2)[1:]
        tampered = encrypted.replace(ciphertext.group(0), modified, 1)
        status, body = request(base + "/control/oracle/decrypt", context, "POST",
                               {"clock": unsigned_spec["clock"], "xml": tampered})
        assert status == 200 and not json.loads(body)["valid"], (status, body)
        for transport in ("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                          "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"):
            encryption_spec["encryption"]["key_transport"] = transport
            status, body = request(base + "/control/encrypt", context, "POST", encryption_spec)
            assert status == 200, (transport, body)
            status, verdict = request(base + "/control/oracle/decrypt", context, "POST",
                                      {"clock": unsigned_spec["clock"],
                                       "xml": json.loads(body)["xml"]})
            assert status == 200 and json.loads(verdict)["valid"], (transport, status, verdict)
        encryption_spec["element"] = "NameID"
        encryption_spec["encryption"] = {"data_algorithm": "aes128-cbc",
                                         "key_transport": "rsa-oaep-mgf1p"}
        status, body = request(base + "/control/encrypt", context, "POST", encryption_spec)
        assert status == 200 and "EncryptedID" in json.loads(body)["xml"], (status, body)
        status, body = request(base + "/control/oracle/decrypt", context, "POST",
                               {"clock": unsigned_spec["clock"], "xml": json.loads(body)["xml"]})
        assert status == 200 and json.loads(body)["valid"] and \
            "user-1" in json.loads(body)["xml"], (status, body)
        encryption_spec["element"] = "Assertion"
        for placement, extras in (("sibling-retrieval", 0),
                                  ("sibling-implicit", 0),
                                  ("sibling-implicit", 1)):
            encryption_spec["encryption"] = {
                "data_algorithm": "aes256-gcm", "key_transport": "rsa-oaep-sha256-mgf1sha256",
                "key_placement": placement, "extra_encrypted_keys": extras}
            status, body = request(base + "/control/encrypt", context, "POST", encryption_spec)
            assert status == 200, (placement, extras, body)
            output = json.loads(body)["xml"]
            assert output.count("<xenc:EncryptedKey") == 1 + extras, (placement, extras, output)
            assert ("<ds:RetrievalMethod" in output) == (placement == "sibling-retrieval")
        bad_signing = dict(signing_spec, typo=True)
        assert request(base + "/control/sign", context, "POST", bad_signing)[0] == 400
        signing_spec["xml"] = unsigned["xml"].replace("<samlp:Response ", "<!DOCTYPE bad><samlp:Response ")
        assert request(base + "/control/sign", context, "POST", signing_spec)[0] == 400
        status, _ = request(base + "/control/reset?sp=" + urllib.parse.quote(entity_id, safe=""),
                            context, "POST", b"")
        assert status == 200
        print("PASS scripted IdP HTTPS, metadata, signed Redirect intake, template signer/oracle")
    finally:
        subprocess.run(["docker", "stop", container], check=False, capture_output=True,
                       text=True, timeout=20)


if __name__ == "__main__":
    main()
