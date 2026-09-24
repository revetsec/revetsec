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

"""Build-time selftest: the M0 spike cases 1-6 (see SPIKE-RESULTS.md).

Each case builds a SAML Response, signs or encrypts it with libxmlsec1 (python-xmlsec),
serializes it once to <out>/<case>.xml, then parses those bytes back and verifies or
decrypts them with libxmlsec1. Encrypted cases are also decrypted with pyca/cryptography,
and the plaintext must parse on its own. A final smoke step signs with signxml, the second
signer. spike/Crosscheck.java re-checks every output file using only the JDK.

The keys are throwaway, generated on every run and written to <out>/keys/ so the JDK
cross-check can use them. They are not fixtures.
"""

import argparse
import base64
import datetime
import json
import pathlib
import traceback

import signxml
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from lxml import etree

from . import versions

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
XENC = "http://www.w3.org/2001/04/xmlenc#"
XENC11 = "http://www.w3.org/2009/xmlenc11#"

EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
AES256_GCM = XENC11 + "aes256-gcm"
RSA_OAEP_11 = XENC11 + "rsa-oaep"
RSA_1_5 = XENC + "rsa-1_5"
OAEP_DIGEST_SHA256 = XENC + "sha256"
MGF1_SHA256 = XENC11 + "mgf1sha256"

C = xmlsec.constants
SIGNATURE_URIS = {
    C.TransformRsaSha1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    C.TransformRsaSha256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    C.TransformEcdsaSha256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    C.TransformEcdsaSha384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    C.TransformEcdsaSha512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
}
DIGEST_URIS = {
    C.TransformSha1: "http://www.w3.org/2000/09/xmldsig#sha1",
    C.TransformSha256: "http://www.w3.org/2001/04/xmlenc#sha256",
    C.TransformSha384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
    C.TransformSha512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

NOW = "2026-09-01T00:00:00Z"
NOT_ON_OR_AFTER = "2026-09-01T00:05:00Z"
IDP = "https://idp.scripted-idp.test/"
SP = "https://sp.test/Selftest"
ACS = "https://sp.test/acs"

# The one parser for XML this package reads: no entities, DTDs, network or huge trees.
PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)


class Credential:
    """A throwaway key pair with a self-signed certificate."""

    def __init__(self, name, private_key):
        self.name = name
        self.private_key = private_key
        self.key_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.cert_pem = _self_signed(name, private_key).public_bytes(serialization.Encoding.PEM)

    def xmlsec_private_key(self):
        key = xmlsec.Key.from_memory(self.key_pem, C.KeyDataFormatPem)
        key.load_cert_from_memory(self.cert_pem, C.KeyDataFormatCertPem)
        return key

    def xmlsec_certificate(self):
        return xmlsec.Key.from_memory(self.cert_pem, C.KeyDataFormatCertPem)


def _self_signed(name, private_key):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    is_rsa = isinstance(private_key, rsa.RSAPrivateKey)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=is_rsa, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(private_key, hashes.SHA256())
    )


def _q(namespace, tag):
    return f"{{{namespace}}}{tag}"


def _root(namespace, tag, nsmap, **attributes):
    element = etree.Element(_q(namespace, tag), nsmap=nsmap)
    for name, value in attributes.items():
        element.set(name, value)
    return element


def _sub(parent, namespace, tag, text=None, **attributes):
    element = etree.SubElement(parent, _q(namespace, tag))
    for name, value in attributes.items():
        element.set(name, value)
    if text is not None:
        element.text = text
    return element


# --- SAML builders ---------------------------------------------------------------------

def name_id(value):
    element = _root(SAML, "NameID", {"saml": SAML},
                    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier=IDP,
                    SPNameQualifier=SP)
    element.text = value
    return element


def assertion(assertion_id, subject_id):
    element = _root(SAML, "Assertion", {"saml": SAML}, ID=assertion_id, Version="2.0", IssueInstant=NOW)
    _sub(element, SAML, "Issuer", IDP)
    subject = _sub(element, SAML, "Subject")
    subject.append(subject_id)
    confirmation = _sub(subject, SAML, "SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    _sub(confirmation, SAML, "SubjectConfirmationData", Recipient=ACS, NotOnOrAfter=NOT_ON_OR_AFTER)
    conditions = _sub(element, SAML, "Conditions", NotBefore=NOW, NotOnOrAfter=NOT_ON_OR_AFTER)
    _sub(_sub(conditions, SAML, "AudienceRestriction"), SAML, "Audience", SP)
    authn = _sub(element, SAML, "AuthnStatement", AuthnInstant=NOW, SessionIndex="_session-1")
    _sub(_sub(authn, SAML, "AuthnContext"), SAML, "AuthnContextClassRef",
         "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    attribute = _sub(_sub(element, SAML, "AttributeStatement"), SAML, "Attribute",
                     Name="urn:oid:0.9.2342.19200300.100.1.3", FriendlyName="mail",
                     NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
    _sub(attribute, SAML, "AttributeValue", "user@example.test")
    return element


def response(response_id, child):
    element = _root(SAMLP, "Response", {"samlp": SAMLP, "saml": SAML},
                    ID=response_id, Version="2.0", IssueInstant=NOW, Destination=ACS)
    _sub(element, SAML, "Issuer", IDP)
    _sub(_sub(element, SAMLP, "Status"), SAMLP, "StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    element.append(child)
    return element


def wrapped(wrapper_tag, plaintext_element):
    """Parses <saml:wrapper_tag> around a standalone serialization of plaintext_element.

    Appending the element with lxml would drop its now-redundant xmlns:saml, and libxmlsec1
    encrypts the node's plain serialization, so the plaintext would not parse on its own.
    """
    inner = etree.tostring(plaintext_element, encoding="UTF-8")
    return etree.fromstring(
        f'<saml:{wrapper_tag} xmlns:saml="{SAML}">'.encode("utf-8") + inner + f"</saml:{wrapper_tag}>".encode("utf-8"),
        PARSER)


# --- libxmlsec1 operations -------------------------------------------------------------

def xmlsec_sign(element, credential, signature_method, digest_method):
    """Enveloped signature over element (by its ID), placed right after its saml:Issuer."""
    signature = xmlsec.template.create(element, C.TransformExclC14N, signature_method, ns="ds")
    element.insert(1, signature)
    reference = xmlsec.template.add_reference(signature, digest_method, uri="#" + element.get("ID"))
    xmlsec.template.add_transform(reference, C.TransformEnveloped)
    xmlsec.template.add_transform(reference, C.TransformExclC14N)
    xmlsec.template.add_x509_data(xmlsec.template.ensure_key_info(signature))
    context = xmlsec.SignatureContext()
    context.key = credential.xmlsec_private_key()
    context.register_id(element, "ID")
    context.sign(signature)


def xmlsec_verify(signed_element, credential, signature_method, digest_method):
    """Verifies the enveloped signature of signed_element and checks its algorithms."""
    signature = signed_element.find(_q(DS, "Signature"))
    _expect(signature is not None, f"no ds:Signature child of {signed_element.tag}")
    signed_info = signature.find(_q(DS, "SignedInfo"))
    reference = signed_info.find(_q(DS, "Reference"))
    _expect(reference.get("URI") == "#" + signed_element.get("ID"), "Reference URI does not name its parent")
    _expect_algorithm(signed_info, "CanonicalizationMethod", EXC_C14N)
    _expect_algorithm(signed_info, "SignatureMethod", SIGNATURE_URIS[signature_method])
    _expect_algorithm(reference, "DigestMethod", DIGEST_URIS[digest_method])
    context = xmlsec.SignatureContext()
    context.key = credential.xmlsec_certificate()
    for element in signed_element.getroottree().iter():
        if element.get("ID") is not None:
            context.register_id(element, "ID")
    context.verify(signature)
    return base64.b64decode(signature.findtext(_q(DS, "SignatureValue")))


def encrypted_data_template(key_transport):
    """A hand-built EncryptedData template; python-xmlsec has no helper for xmlenc11#rsa-oaep."""
    data = _root(XENC, "EncryptedData", {"xenc": XENC, "ds": DS}, Type=XENC + "Element")
    _sub(data, XENC, "EncryptionMethod", Algorithm=AES256_GCM)
    encrypted_key = _sub(_sub(data, DS, "KeyInfo"), XENC, "EncryptedKey")
    method = _sub(encrypted_key, XENC, "EncryptionMethod", Algorithm=key_transport)
    if key_transport == RSA_OAEP_11:
        _sub(method, DS, "DigestMethod", Algorithm=OAEP_DIGEST_SHA256)
        etree.SubElement(method, _q(XENC11, "MGF"), nsmap={"xenc11": XENC11}).set("Algorithm", MGF1_SHA256)
    _sub(_sub(encrypted_key, XENC, "CipherData"), XENC, "CipherValue")
    _sub(_sub(data, XENC, "CipherData"), XENC, "CipherValue")
    return data


def signxml_sign(element, credential):
    """signxml (the second, independent signer): enveloped RSA-SHA256, exclusive c14n, after saml:Issuer."""
    element.insert(1, etree.Element(_q(DS, "Signature"), nsmap={"ds": DS}, Id="placeholder"))
    signer = signxml.XMLSigner(
        method=signxml.methods.enveloped, signature_algorithm=signxml.SignatureMethod.RSA_SHA256,
        digest_algorithm=signxml.DigestAlgorithm.SHA256,
        c14n_algorithm=signxml.CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)
    return signer.sign(element, key=credential.key_pem, cert=credential.cert_pem.decode("ascii"),
                       reference_uri=element.get("ID"), id_attribute="ID")


def xmlsec_encrypt(wrapper, key_transport, recipient):
    """Replaces the wrapper's only child with EncryptedData (AES-256-GCM, key for recipient)."""
    manager = xmlsec.KeysManager()
    manager.add_key(recipient.xmlsec_certificate())
    context = xmlsec.EncryptionContext(manager)
    context.key = xmlsec.Key.generate(C.KeyDataAes, 256, C.KeyDataTypeSession)
    context.encrypt_xml(encrypted_data_template(key_transport), wrapper[0])
    return wrapper


def xmlsec_decrypt(encrypted_data, recipient):
    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_memory(recipient.key_pem, C.KeyDataFormatPem))
    return xmlsec.EncryptionContext(manager).decrypt(encrypted_data)


def check_encryption_methods(encrypted_data, key_transport):
    _expect_algorithm(encrypted_data, "EncryptionMethod", AES256_GCM, XENC)
    method = encrypted_data.find(f"{_q(DS, 'KeyInfo')}/{_q(XENC, 'EncryptedKey')}/{_q(XENC, 'EncryptionMethod')}")
    _expect(method is not None and method.get("Algorithm") == key_transport, "wrong key transport")
    if key_transport == RSA_OAEP_11:
        _expect_algorithm(method, "DigestMethod", OAEP_DIGEST_SHA256)
        _expect_algorithm(method, "MGF", MGF1_SHA256, XENC11)


def pyca_decrypt(encrypted_data, recipient):
    """Decrypts with pyca/cryptography (not libxmlsec1); the plaintext must parse on its own."""
    encrypted_key = encrypted_data.find(f"{_q(DS, 'KeyInfo')}/{_q(XENC, 'EncryptedKey')}")
    key_transport = encrypted_key.find(_q(XENC, "EncryptionMethod")).get("Algorithm")
    wrapped_key = base64.b64decode(encrypted_key.findtext(f"{_q(XENC, 'CipherData')}/{_q(XENC, 'CipherValue')}"))
    if key_transport == RSA_OAEP_11:
        oaep_sha256 = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        session_key = recipient.private_key.decrypt(wrapped_key, oaep_sha256)
        oaep_sha1 = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        try:
            recipient.private_key.decrypt(wrapped_key, oaep_sha1)
        except ValueError:
            pass
        else:
            raise AssertionError("the key also unwraps under OAEP SHA-1/MGF1-SHA1, so the parameters were ignored")
    else:
        session_key = recipient.private_key.decrypt(wrapped_key, padding.PKCS1v15())
    _expect(len(session_key) == 32, f"session key is {len(session_key)} bytes, not 32")
    ciphertext = base64.b64decode(encrypted_data.findtext(f"{_q(XENC, 'CipherData')}/{_q(XENC, 'CipherValue')}"))
    plaintext = AESGCM(session_key).decrypt(ciphertext[:12], ciphertext[12:], None)
    return etree.fromstring(plaintext, PARSER)


def _expect(condition, message):
    if not condition:
        raise AssertionError(message)


def _expect_algorithm(parent, tag, uri, namespace=DS):
    child = parent.find(_q(namespace, tag))
    _expect(child is not None and child.get("Algorithm") == uri,
            f"{tag} is {None if child is None else child.get('Algorithm')}, expected {uri}")


# --- Cases -----------------------------------------------------------------------------

class Selftest:
    def __init__(self, out):
        self.out = out
        self.idp_rsa = Credential("idp-rsa-2048", rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.idp_ec = {
            bits: Credential(f"idp-ec-p{bits}", ec.generate_private_key(curve))
            for bits, curve in ((256, ec.SECP256R1()), (384, ec.SECP384R1()), (521, ec.SECP521R1()))
        }
        self.sp = Credential("sp-rsa-2048", rsa.generate_private_key(public_exponent=65537, key_size=2048))

    def write_keys(self):
        keys = self.out / "keys"
        keys.mkdir(parents=True, exist_ok=True)
        for credential in (self.idp_rsa, *self.idp_ec.values(), self.sp):
            (keys / f"{credential.name}.crt").write_bytes(credential.cert_pem)
        (keys / f"{self.sp.name}.key").write_bytes(self.sp.key_pem)

    def _write_and_parse(self, name, root):
        data = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        (self.out / f"{name}.xml").write_bytes(data)
        return etree.fromstring(data, PARSER)

    def case1(self):
        """Signed Response and Assertion, RSA-SHA256, exclusive c14n."""
        signed_assertion = assertion("_a1", name_id("user-1"))
        xmlsec_sign(signed_assertion, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        root = response("_r1", signed_assertion)
        xmlsec_sign(root, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        parsed = self._write_and_parse("case1-response-assertion-rsa-sha256", root)
        xmlsec_verify(parsed, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        xmlsec_verify(parsed.find(_q(SAML, "Assertion")), self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        return "Response and Assertion signatures verified by libxmlsec1"

    def case2(self):
        """RSA-SHA1 signing through the wheel's bundled OpenSSL."""
        signed_assertion = assertion("_a2", name_id("user-2"))
        xmlsec_sign(signed_assertion, self.idp_rsa, C.TransformRsaSha1, C.TransformSha1)
        parsed = self._write_and_parse("case2-assertion-rsa-sha1", response("_r2", signed_assertion))
        xmlsec_verify(parsed.find(_q(SAML, "Assertion")), self.idp_rsa, C.TransformRsaSha1, C.TransformSha1)
        return "RSA-SHA1/SHA-1 Assertion signature verified by libxmlsec1"

    def case3(self):
        """ECDSA P-256/P-384/P-521 with SHA-256/384/512; SignatureValue must be raw r||s."""
        details = []
        for bits, signature_method, digest_method in (
                (256, C.TransformEcdsaSha256, C.TransformSha256),
                (384, C.TransformEcdsaSha384, C.TransformSha384),
                (521, C.TransformEcdsaSha512, C.TransformSha512)):
            credential = self.idp_ec[bits]
            signed_assertion = assertion(f"_a3-p{bits}", name_id("user-3"))
            xmlsec_sign(signed_assertion, credential, signature_method, digest_method)
            parsed = self._write_and_parse(f"case3-assertion-ecdsa-p{bits}", response(f"_r3-p{bits}", signed_assertion))
            value = xmlsec_verify(parsed.find(_q(SAML, "Assertion")), credential, signature_method, digest_method)
            expected = 2 * ((bits + 7) // 8)
            _expect(len(value) == expected, f"P-{bits} SignatureValue is {len(value)} bytes, expected r||s of {expected}")
            details.append(f"P-{bits} r||s {len(value)} bytes")
        return "verified by libxmlsec1: " + ", ".join(details)

    def _encrypted_assertion_case(self, name, key_transport, number):
        assertion_id = f"_a{number}"
        signed_assertion = assertion(assertion_id, name_id(f"user-{number}"))
        xmlsec_sign(signed_assertion, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        encrypted = xmlsec_encrypt(wrapped("EncryptedAssertion", signed_assertion), key_transport, self.sp)
        parsed = self._write_and_parse(name, response(f"_r{number}", encrypted))
        encrypted_data = parsed.find(f"{_q(SAML, 'EncryptedAssertion')}/{_q(XENC, 'EncryptedData')}")
        check_encryption_methods(encrypted_data, key_transport)
        standalone = pyca_decrypt(encrypted_data, self.sp)
        _expect(standalone.tag == _q(SAML, "Assertion") and standalone.get("ID") == assertion_id,
                "pyca plaintext is not the Assertion")
        decrypted = xmlsec_decrypt(encrypted_data, self.sp)
        _expect(decrypted.tag == _q(SAML, "Assertion"), "libxmlsec1 plaintext is not an Assertion")
        xmlsec_verify(decrypted, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)

    def case4(self):
        """AES-256-GCM EncryptedAssertion, xmlenc11#rsa-oaep with SHA-256 and MGF1-SHA256."""
        self._encrypted_assertion_case("case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256", RSA_OAEP_11, 4)
        return ("decrypted by libxmlsec1 and by pyca (OAEP SHA-256/MGF1-SHA256; SHA-1 params rejected); "
                "inner Assertion signature verified")

    def case5(self):
        """An rsa-1_5 EncryptedKey (a producer for RevetSec's negative tests)."""
        self._encrypted_assertion_case("case5-encrypted-assertion-gcm-rsa-1_5", RSA_1_5, 5)
        return "decrypted by libxmlsec1 and by pyca (PKCS#1 v1.5); inner Assertion signature verified"

    def case6(self):
        """EncryptedID (AES-256-GCM, xmlenc11#rsa-oaep SHA-256/MGF1-SHA256) in a signed Assertion."""
        encrypted_id = xmlsec_encrypt(wrapped("EncryptedID", name_id("user-6")), RSA_OAEP_11, self.sp)
        signed_assertion = assertion("_a6", encrypted_id)
        xmlsec_sign(signed_assertion, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        parsed = self._write_and_parse("case6-encrypted-id-gcm-rsa-oaep-sha256-mgf1sha256", response("_r6", signed_assertion))
        parsed_assertion = parsed.find(_q(SAML, "Assertion"))
        xmlsec_verify(parsed_assertion, self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        encrypted_data = parsed_assertion.find(f"{_q(SAML, 'Subject')}/{_q(SAML, 'EncryptedID')}/{_q(XENC, 'EncryptedData')}")
        check_encryption_methods(encrypted_data, RSA_OAEP_11)
        standalone = pyca_decrypt(encrypted_data, self.sp)
        _expect(standalone.tag == _q(SAML, "NameID") and standalone.text == "user-6", "pyca plaintext is not the NameID")
        decrypted = xmlsec_decrypt(encrypted_data, self.sp)
        _expect(decrypted.tag == _q(SAML, "NameID") and decrypted.text == "user-6", "libxmlsec1 plaintext is not the NameID")
        return "Assertion signature verified; EncryptedID decrypted by libxmlsec1 and by pyca"

    def signxml_smoke(self):
        """Not a numbered spike case: the pinned signxml signs, and libxmlsec1 verifies it."""
        signed_assertion = signxml_sign(assertion("_a7", name_id("user-7")), self.idp_rsa)
        parsed = self._write_and_parse("extra-signxml-assertion-rsa-sha256", response("_r7", signed_assertion))
        xmlsec_verify(parsed.find(_q(SAML, "Assertion")), self.idp_rsa, C.TransformRsaSha256, C.TransformSha256)
        return "signxml RSA-SHA256 Assertion signature verified by libxmlsec1"


def main(argv):
    parser = argparse.ArgumentParser(prog="scripted_idp selftest", description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=pathlib.Path, help="directory for the case outputs")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    results = {}
    try:
        libxml2 = versions.check_libxml2_pairing()
        results["libxml2-pairing"] = {"ok": True, "detail": f"lxml and xmlsec both use libxml2 {libxml2}"}
    except RuntimeError as e:
        results["libxml2-pairing"] = {"ok": False, "detail": str(e)}
    selftest = Selftest(args.out)
    selftest.write_keys()
    for name in ("case1", "case2", "case3", "case4", "case5", "case6", "signxml_smoke"):
        try:
            results[name] = {"ok": True, "detail": getattr(selftest, name)()}
        except Exception as e:  # noqa: BLE001 - every case reports, then the run fails
            results[name] = {"ok": False, "detail": f"{type(e).__name__}: {e}"}
            traceback.print_exc()

    (args.out / "versions.json").write_text(json.dumps(versions.versions(), indent=2, sort_keys=True) + "\n")
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    for name, result in results.items():
        print(f"{'PASS' if result['ok'] else 'FAIL'} {name}: {result['detail']}")
    return 0 if all(result["ok"] for result in results.values()) else 1
