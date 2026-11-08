# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Owned ephemeral test CA/SAN key material; never modify a system or browser trust store."""
from pathlib import Path
import base64,hashlib,ssl,subprocess

def prepare(directory,public_output):
    directory.mkdir(mode=0o700);public_output.mkdir()
    def run(*args,input_bytes=None):
        result=subprocess.run(['openssl',*args],input=input_bytes,capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError('Owned test certificate preparation failed')
        return result.stdout
    ca_key=directory/'ca.key';ca=directory/'ca.pem';leaf_key=directory/'leaf.key';csr=directory/'leaf.csr';leaf=directory/'leaf.pem';extensions=directory/'extensions.cnf'
    run('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(ca_key))
    run('req','-x509','-new','-key',str(ca_key),'-sha256','-days','1','-subj','/CN=Revetsec-owned-verification-CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash','-out',str(ca))
    run('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(leaf_key))
    run('req','-new','-key',str(leaf_key),'-subj','/CN=app.example','-out',str(csr))
    extensions.write_text('[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:app.example\n')
    run('x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-days','1','-sha256','-extfile',str(extensions),'-extensions','leaf','-out',str(leaf))
    public=run('x509','-in',str(leaf),'-pubkey','-noout');der=run('pkey','-pubin','-outform','DER',input_bytes=public)
    for path in [ca,leaf]:(public_output/path.name).write_bytes(path.read_bytes())
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(leaf,leaf_key)
    client=ssl.create_default_context(cafile=str(ca));client.check_hostname=True;client.verify_mode=ssl.CERT_REQUIRED;client.set_alpn_protocols(['http/1.1'])
    return context,client,{'caSha256':hashlib.sha256(ca.read_bytes()).hexdigest(),'leafSha256':hashlib.sha256(leaf.read_bytes()).hexdigest(),'leafSpkiSha256Base64':base64.b64encode(hashlib.sha256(der).digest()).decode(),'subjectAltName':'DNS:app.example','systemTrustChanged':False,'normalClient':'privateCA+check_hostname+CERT_REQUIRED','chromeTrust':'OnlyscopedleafSPKIexception;notnormalchain/hostnameproof'}
