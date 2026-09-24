#!/usr/bin/env bash
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

# ---------------------------------------------------------------------------------------------------------------------
# regenerate-test-pki.sh: RevetSec's TEST-ONLY PKI and signing keys.
#
# TEST ONLY. Everything this script writes is committed to a public repository, including every private key and the
# test CA's private key. Anyone can mint certificates with it. Never trust, install, deploy or reuse any of it outside
# RevetSec's own tests and local test containers, and never add the test CA to an OS, browser or JDK trust store.
#
# Outputs (file names are stable and documented in each directory's README.md):
#   src/test/resources/tls/            test CA (PKCS#12 + PEM), server leaf (PEM + PKCS#12), truststore (PKCS#12)
#   src/test/resources/fixtures/keys/  IdP, SP and negative signing/encryption keys (PKCS#8 PEM) + self-signed certs
#
# The structure is deterministic: file names, subjects, serial numbers, validity window, key types and extensions are
# fixed below. Only the key material and the PKCS#12 salts and IVs change on each run.
#
# Usage:
#   scripts/regenerate-test-pki.sh check                 verify the checked-in material (read-only)
#   scripts/regenerate-test-pki.sh tls  [--force]        regenerate src/test/resources/tls/
#   scripts/regenerate-test-pki.sh keys [--force]        regenerate src/test/resources/fixtures/keys/
#   scripts/regenerate-test-pki.sh all  [--force]        both of the above
#   scripts/regenerate-test-pki.sh leaf --out-dir DIR [--san DNS:name|IP:address]... [--force]
#                                                        issue an extra server leaf from the checked-in test CA, for
#                                                        example for a remote Docker host; never writes into the repo's
#                                                        tls/ directory
#
# --force is required to overwrite existing files. Regenerating keys/ invalidates every committed fixture that was
# signed with, or encrypted to, those keys (for example the scripted-IdP minted corpus), so re-mint those in the same
# change. Regenerating tls/ only changes the TLS material; nothing embeds it.
#
# Requirements: bash 3.2+; OpenSSL 3.4+ to generate (for -not_before/-not_after), 3.0+ for check; a JDK keytool
# for tls, all and check.
# Environment:  OPENSSL (default: openssl on PATH); KEYTOOL, else $JAVA_HOME/bin/keytool, else keytool on PATH.
# ---------------------------------------------------------------------------------------------------------------------

set -euo pipefail
umask 022
export LC_ALL=C
# A deterministic OpenSSL environment: no system openssl.cnf, no provider or default-extension surprises.
export OPENSSL_CONF=/dev/null

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
TLS_DIR="$PROJECT_ROOT/src/test/resources/tls"
KEYS_DIR="$PROJECT_ROOT/src/test/resources/fixtures/keys"

# ---------------------------------------------------------------------------------------------------------------------
# Fixed profile. Changing anything here changes the documented structure: update both README.md files too.
# ---------------------------------------------------------------------------------------------------------------------

# Password for every PKCS#12 file (store and key). Public on purpose.
readonly P12_PASSWORD='changeit'

# One fixed 100-year validity window for every certificate, so fixtures never expire and fixed-Clock tests from
# 2026 onward see valid certificates.
readonly NOT_BEFORE='20260101000000Z'
readonly NOT_AFTER='21260101000000Z'
# The same instants as OpenSSL prints them (-startdate/-enddate, default format).
readonly NOT_BEFORE_PRINTED='Jan  1 00:00:00 2026 GMT'
readonly NOT_AFTER_PRINTED='Jan  1 00:00:00 2126 GMT'

readonly SUBJECT_O='RevetSec test fixtures - TEST ONLY'

readonly CA_SUBJECT="/O=$SUBJECT_O/CN=RevetSec Test CA - DO NOT TRUST"
readonly CA_SERIAL=1000
readonly CA_ALIAS='test-ca'
readonly SERVER_SUBJECT="/O=$SUBJECT_O/CN=localhost"
readonly SERVER_SERIAL=1001
readonly SERVER_ALIAS='server'
readonly TRUSTSTORE_ALIAS='revetsec-test-ca'

# Server leaf SANs, in this order.
readonly SERVER_SANS='DNS:localhost, IP:127.0.0.1, DNS:host.testcontainers.internal, DNS:host.docker.internal'
# The same list as OpenSSL prints it.
readonly SERVER_SANS_PRINTED='DNS:localhost, IP Address:127.0.0.1, DNS:host.testcontainers.internal, DNS:host.docker.internal'

# The test CA's private key is public, so its certificate limits the damage if someone wrongly trusts it:
#   - extendedKeyUsage serverAuth only. OpenSSL (and so Python, Node and curl) applies a CA's EKU to its TLS and S/MIME
#     purposes, so it rejects TLS client and S/MIME certificates issued by this CA;
#   - critical name constraints. DNS names and IP addresses must be loopback, private or CGNAT ranges, or special-use
#     or private-use names. Email addresses and URIs must be in the reserved domain "invalid", which no real address
#     uses. There is deliberately no directory-name constraint: LibreSSL 3.3.6 (macOS's /usr/bin/curl) rejected every
#     leaf under a permitted dirName subtree that OpenSSL accepted (observed 2026-09-23).
# Verifiers that apply trust-anchor name constraints (OpenSSL, and so Python, Node and curl) then reject its leaves
# for public DNS names, IP addresses, email addresses and URIs.
# Two cases are NOT protected, so never trust this CA for anything:
#   - code signing. OpenSSL's codesign purpose checks only that the issuer is a CA and ignores the CA's EKU (so do
#     timestampsign, ocsphelper and a verify with no -purpose), and without a dirName constraint the subject is free.
#     So OpenSSL accepts a code-signing leaf from this CA for any subject, such as O=Big Bank; only its SANs, and a CN
#     that looks like a host name, are held to the name constraints (observed with OpenSSL 3.6.3 on 2026-09-24).
#     check_ca_limits prints a note for this case instead of failing;
#   - the JDK, which applies neither a trust anchor's name constraints nor its EKU (observed on Corretto 17-27), so a
#     JDK trust store that contains this CA trusts it for every name and purpose.
# Leaves must stay inside these subtrees. Single-label names such as a bare "docker" are outside every DNS subtree: use
# a *.test or *.internal alias, or an IP address, instead.
readonly CA_NAME_CONSTRAINTS='permitted;DNS.1 = localhost
permitted;DNS.2 = internal
permitted;DNS.3 = test
permitted;DNS.4 = example
permitted;DNS.5 = local
permitted;DNS.6 = home.arpa
permitted;IP.1 = 127.0.0.0/255.0.0.0
permitted;IP.2 = 10.0.0.0/255.0.0.0
permitted;IP.3 = 172.16.0.0/255.240.0.0
permitted;IP.4 = 192.168.0.0/255.255.0.0
permitted;IP.5 = 100.64.0.0/255.192.0.0
permitted;IP.6 = ::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
permitted;IP.7 = fc00::/fe00::
permitted;email.1 = invalid
permitted;URI.1 = invalid'

# Signing and encryption fixtures, one per line:
#   name|algorithm|size or curve|certificate digest|serial|keyUsage|CN
# Each yields <name>-key.pem (PKCS#8) and <name>-cert.pem (self-signed X.509).
readonly KEY_SPECS='idp-signing-rsa-2048|RSA|2048|sha256|2001|digitalSignature|RevetSec test IdP signing RSA-2048
idp-signing-rsa-3072|RSA|3072|sha256|2002|digitalSignature|RevetSec test IdP signing RSA-3072
idp-signing-ec-p256|EC|P-256|sha256|2003|digitalSignature|RevetSec test IdP signing EC P-256
idp-signing-ec-p384|EC|P-384|sha384|2004|digitalSignature|RevetSec test IdP signing EC P-384
idp-signing-ec-p521|EC|P-521|sha512|2005|digitalSignature|RevetSec test IdP signing EC P-521
negative-attacker-rsa-2048|RSA|2048|sha256|2101|digitalSignature|RevetSec test attacker RSA-2048 - never trusted
negative-rsa-1024|RSA|1024|sha256|2102|digitalSignature|RevetSec test weak RSA-1024 - below every key-size floor
negative-unconfigured-ec-p256|EC|P-256|sha256|2103|digitalSignature|RevetSec test unconfigured EC P-256 - never configured
sp-signing-rsa-2048|RSA|2048|sha256|2201|digitalSignature|RevetSec test SP signing RSA-2048
sp-encryption-rsa-2048|RSA|2048|sha256|2202|keyEncipherment|RevetSec test SP encryption RSA-2048'

# The same constraints as OpenSSL prints them (-ext nameConstraints, lines joined with "; ").
readonly CA_NAME_CONSTRAINTS_PRINTED='Permitted:; DNS:localhost; DNS:internal; DNS:test; DNS:example; DNS:local; DNS:home.arpa; IP:127.0.0.0/255.0.0.0; IP:10.0.0.0/255.0.0.0; IP:172.16.0.0/255.240.0.0; IP:192.168.0.0/255.255.0.0; IP:100.64.0.0/255.192.0.0; IP:0:0:0:0:0:0:0:1/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF; IP:FC00:0:0:0:0:0:0:0/FE00:0:0:0:0:0:0:0; email:invalid; URI:invalid'

readonly TLS_FILES='test-ca.pem test-ca-key.pem test-ca.p12 server.pem server-key.pem server.p12 truststore.p12'

# ---------------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------------

OPENSSL_BIN=${OPENSSL:-openssl}
KEYTOOL_BIN=''
FAILURES=0
STAGE=''
PROBE=''

die() {
	echo "error: $*" >&2
	exit 1
}

usage() {
	sed -n '/^# Usage:/,/^# --force/p' "$0" | sed -e 's/^# \{0,1\}//' -e '$d' >&2
	exit 64
}

cleanup() {
	if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
		rm -rf -- "$STAGE"
	fi
	if [ -n "$PROBE" ] && [ -d "$PROBE" ]; then
		rm -rf -- "$PROBE"
	fi
}
trap cleanup EXIT

ossl() {
	"$OPENSSL_BIN" "$@"
}

# require_openssl <minimum minor version of OpenSSL 3>
require_openssl() {
	local minimum_minor=$1
	command -v "$OPENSSL_BIN" >/dev/null 2>&1 || die "OpenSSL not found (set OPENSSL=/path/to/openssl)"
	local version
	version=$(ossl version 2>/dev/null) || die "cannot run $OPENSSL_BIN"
	local major minor
	major=$(printf '%s\n' "$version" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\)\..*/\1/p')
	minor=$(printf '%s\n' "$version" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\)\..*/\2/p')
	if [ -z "$major" ] || [ -z "$minor" ] || [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt "$minimum_minor" ]; }; then
		die "OpenSSL 3.$minimum_minor or later is required; found: $version (LibreSSL is not supported; set OPENSSL=...)"
	fi
}

require_keytool() {
	if [ -n "${KEYTOOL:-}" ]; then
		KEYTOOL_BIN=$KEYTOOL
	elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ]; then
		KEYTOOL_BIN="$JAVA_HOME/bin/keytool"
	elif command -v keytool >/dev/null 2>&1; then
		KEYTOOL_BIN=$(command -v keytool)
	else
		die "keytool not found (set JAVA_HOME or KEYTOOL)"
	fi
	[ -x "$KEYTOOL_BIN" ] || die "keytool is not executable: $KEYTOOL_BIN"
	"$KEYTOOL_BIN" -help >/dev/null 2>&1 || die "keytool does not run: $KEYTOOL_BIN (set JAVA_HOME or KEYTOOL)"
}

# keytool with English output and a PKCS#12 format that every supported JDK (17.0.3+) can read, whatever the
# running JDK's defaults are.
ktool() {
	"$KEYTOOL_BIN" -J-Duser.language=en -J-Duser.country=US \
		-J-Dkeystore.pkcs12.certProtectionAlgorithm=PBEWithHmacSHA256AndAES_256 \
		-J-Dkeystore.pkcs12.keyProtectionAlgorithm=PBEWithHmacSHA256AndAES_256 \
		-J-Dkeystore.pkcs12.macAlgorithm=HmacPBESHA256 \
		"$@"
}

new_stage() {
	STAGE=$(mktemp -d "${TMPDIR:-/tmp}/revetsec-test-pki.XXXXXXXX")
}

# genkey <RSA|EC> <bits|curve> <out>: unencrypted PKCS#8 PEM ("BEGIN PRIVATE KEY").
genkey() {
	local algorithm=$1 parameter=$2 out=$3
	case "$algorithm" in
		RSA)
			ossl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$parameter" -pkeyopt rsa_keygen_pubexp:65537 \
				-out "$out" 2>/dev/null
			;;
		EC)
			ossl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$parameter" -pkeyopt ec_param_enc:named_curve \
				-out "$out" 2>/dev/null
			;;
		*) die "unknown key algorithm $algorithm" ;;
	esac
}

# write_config <file> [extra server SANs]: every X.509 extension profile this script uses.
write_config() {
	local file=$1 extra_sans=${2:-}
	{
		printf '%s\n' '[ req ]' 'distinguished_name = req_dn' 'prompt = no' 'string_mask = utf8only' ''
		printf '%s\n' '[ req_dn ]' ''
		printf '%s\n' '[ ca_ext ]' \
			'basicConstraints = critical, CA:TRUE, pathlen:0' \
			'keyUsage = critical, keyCertSign, cRLSign' \
			'extendedKeyUsage = serverAuth' \
			'subjectKeyIdentifier = hash' \
			'nameConstraints = critical, @ca_name_constraints' ''
		printf '%s\n' '[ ca_name_constraints ]' "$CA_NAME_CONSTRAINTS" ''
		printf '%s\n' '[ server_ext ]' \
			'basicConstraints = critical, CA:FALSE' \
			'keyUsage = critical, digitalSignature, keyEncipherment' \
			'extendedKeyUsage = serverAuth' \
			'subjectKeyIdentifier = hash' \
			'authorityKeyIdentifier = keyid:always' \
			"subjectAltName = $SERVER_SANS$extra_sans" ''
		printf '%s\n' '[ fixture_digitalSignature ]' \
			'basicConstraints = critical, CA:FALSE' \
			'keyUsage = critical, digitalSignature' \
			'subjectKeyIdentifier = hash' ''
		printf '%s\n' '[ fixture_keyEncipherment ]' \
			'basicConstraints = critical, CA:FALSE' \
			'keyUsage = critical, keyEncipherment' \
			'subjectKeyIdentifier = hash' ''
	} >"$file"
}

# issue_server_leaf <dir> <ca cert> <ca key> <serial> <config>: server-key.pem, server.pem, server.p12 in <dir>.
issue_server_leaf() {
	local dir=$1 ca_cert=$2 ca_key=$3 serial=$4 config=$5
	genkey RSA 2048 "$dir/server-key.pem"
	ossl req -new -config "$config" -key "$dir/server-key.pem" -subj "$SERVER_SUBJECT" -out "$dir/server.csr"
	ossl x509 -req -in "$dir/server.csr" -CA "$ca_cert" -CAkey "$ca_key" -set_serial "$serial" \
		-not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -sha256 \
		-extfile "$config" -extensions server_ext -out "$dir/server.pem" 2>/dev/null
	rm -f -- "$dir/server.csr"
	export_p12 "$dir/server.p12" "$dir/server-key.pem" "$dir/server.pem" "$SERVER_ALIAS" "$ca_cert"
}

# export_p12 <out> <key> <cert> <alias> [chain cert]: AES-256-CBC + HMAC-SHA256 MAC, readable by JDK 17.0.3+.
export_p12() {
	local out=$1 key=$2 cert=$3 alias=$4 chain=${5:-}
	if [ -n "$chain" ]; then
		ossl pkcs12 -export -out "$out" -inkey "$key" -in "$cert" -certfile "$chain" -name "$alias" -caname "$CA_ALIAS" \
			-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 -passout "pass:$P12_PASSWORD"
	else
		ossl pkcs12 -export -out "$out" -inkey "$key" -in "$cert" -name "$alias" \
			-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 -passout "pass:$P12_PASSWORD"
	fi
}

# refuse_overwrite <dir> <files...>
refuse_overwrite() {
	local dir=$1 file
	shift
	for file in "$@"; do
		if [ -e "$dir/$file" ]; then
			die "$dir/$file exists; pass --force to overwrite (read the warning in $0 first)"
		fi
	done
}

# install_files <from> <to> <files...>: 0644 copies, each replaced by rename.
install_files() {
	local from=$1 to=$2 file
	shift 2
	mkdir -p -- "$to"
	for file in "$@"; do
		cp -- "$from/$file" "$to/.$file.tmp"
		chmod 0644 "$to/.$file.tmp"
		mv -f -- "$to/.$file.tmp" "$to/$file"
	done
}

key_spec_names() {
	printf '%s\n' "$KEY_SPECS" | cut -d'|' -f1
}

key_files() {
	local name
	for name in $(key_spec_names); do
		printf '%s %s ' "$name-key.pem" "$name-cert.pem"
	done
}

# ---------------------------------------------------------------------------------------------------------------------
# Checks. Each failed check prints FAIL and increments FAILURES; callers decide when to stop.
# ---------------------------------------------------------------------------------------------------------------------

fail() {
	echo "FAIL: $*" >&2
	FAILURES=$((FAILURES + 1))
}

# expect <description> <actual> <expected>
expect() {
	if [ "$2" != "$3" ]; then
		fail "$1: expected '$3', got '$2'"
		return 1
	fi
}

pem_block_count() {
	grep -c -- "-----BEGIN $2-----" "$1" || true
}

# check_pkcs8_key <file> <RSA|EC> <bits|curve>
check_pkcs8_key() {
	local file=$1 algorithm=$2 parameter=$3 text
	[ -f "$file" ] || { fail "$file is missing"; return 0; }
	expect "$file first line" "$(head -n 1 "$file")" '-----BEGIN PRIVATE KEY-----' || true
	expect "$file PEM blocks" "$(grep -c -- '-----BEGIN ' "$file" || true)" 1 || true
	ossl pkey -in "$file" -check -noout >/dev/null 2>&1 || fail "$file: openssl pkey -check failed"
	text=$(ossl pkey -in "$file" -noout -text_pub 2>/dev/null) || { fail "$file: unreadable key"; return 0; }
	case "$algorithm" in
		RSA)
			expect "$file size" "$(printf '%s\n' "$text" | sed -n 's/^Public-Key: (\([0-9]*\) bit)$/\1/p')" "$parameter" || true
			printf '%s\n' "$text" | grep -q '^Modulus:' || fail "$file is not an RSA key"
			printf '%s\n' "$text" | grep -q '^Exponent: 65537 ' || fail "$file: public exponent is not 65537"
			;;
		EC)
			expect "$file curve" "$(printf '%s\n' "$text" | sed -n 's/^NIST CURVE: //p')" "$parameter" || true
			;;
	esac
}

# check_cert <file> <serial> <subject RFC 2253> <signature algorithm>
check_cert() {
	local file=$1 serial=$2 subject=$3 signature=$4
	[ -f "$file" ] || { fail "$file is missing"; return 0; }
	expect "$file PEM blocks" "$(pem_block_count "$file" CERTIFICATE)" 1 || true
	expect "$file first line" "$(head -n 1 "$file")" '-----BEGIN CERTIFICATE-----' || true
	expect "$file serial" "$(ossl x509 -in "$file" -noout -serial | sed 's/^serial=//')" \
		"$(printf '%X' "$serial" | sed 's/^\(.\(..\)*\)$/0\1/')" || true
	expect "$file subject" "$(ossl x509 -in "$file" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" \
		"$subject" || true
	expect "$file notBefore" "$(ossl x509 -in "$file" -noout -startdate | sed 's/^notBefore=//')" \
		"$NOT_BEFORE_PRINTED" || true
	expect "$file notAfter" "$(ossl x509 -in "$file" -noout -enddate | sed 's/^notAfter=//')" \
		"$NOT_AFTER_PRINTED" || true
	expect "$file signature algorithm" \
		"$(ossl x509 -in "$file" -noout -text | sed -n 's/^    Signature Algorithm: //p' | head -n 1)" "$signature" || true
	expect "$file version" "$(ossl x509 -in "$file" -noout -text | sed -n 's/^ *Version: \([0-9]\).*/\1/p')" 3 || true
}

# cert_matches_key <cert> <key>
cert_matches_key() {
	local cert_pub key_pub
	cert_pub=$(ossl x509 -in "$1" -noout -pubkey 2>/dev/null) || { fail "$1: no public key"; return 0; }
	key_pub=$(ossl pkey -in "$2" -pubout 2>/dev/null) || { fail "$2: no public key"; return 0; }
	[ "$cert_pub" = "$key_pub" ] || fail "$1 does not match $2"
}

# extension_text <cert> <extension name>: the extension's value lines, trimmed and joined with "; ".
extension_text() {
	ossl x509 -in "$1" -noout -ext "$2" 2>/dev/null | sed -n '2,$p' | sed -e 's/^ *//' -e 's/ *$//' |
		awk 'NF { printf "%s%s", sep, $0; sep = "; " }'
}

extension_criticality() {
	ossl x509 -in "$1" -noout -ext "$2" 2>/dev/null | head -n 1 | grep -q 'critical' && echo critical || echo non-critical
}

# check_p12 <file> <alias> <entry type> <certificate PEM> [key PEM] [chain length]
check_p12() {
	local file=$1 alias=$2 entry_type=$3 cert=$4 key=${5:-} chain_length=${6:-} info listing
	[ -f "$file" ] || { fail "$file is missing"; return 0; }
	info=$(ossl pkcs12 -in "$file" -passin "pass:$P12_PASSWORD" -info -noout 2>&1) ||
		{ fail "$file: openssl cannot open it with the documented password"; return 0; }
	printf '%s\n' "$info" | grep -q '^MAC: sha256,' ||
		fail "$file: MAC is not HMAC-SHA256 (JDK 17 cannot read PBMAC1): $(printf '%s\n' "$info" | grep '^MAC' || true)"
	listing=$(ktool -list -v -keystore "$file" -storetype PKCS12 -storepass "$P12_PASSWORD" 2>&1) ||
		{ fail "$file: keytool cannot open it with the documented password"; return 0; }
	expect "$file entry count" "$(printf '%s\n' "$listing" | sed -n 's/^Your keystore contains \([0-9]*\) entr.*/\1/p')" 1 || true
	expect "$file alias" "$(printf '%s\n' "$listing" | sed -n 's/^Alias name: //p')" "$alias" || true
	expect "$file entry type" "$(printf '%s\n' "$listing" | sed -n 's/^Entry type: //p')" "$entry_type" || true
	if [ -n "$chain_length" ]; then
		expect "$file chain length" "$(printf '%s\n' "$listing" | sed -n 's/^Certificate chain length: //p')" \
			"$chain_length" || true
	fi
	# The PKCS#12 entry's own certificate must be the documented PEM certificate.
	local p12_cert filter=-clcerts
	[ "$entry_type" != 'trustedCertEntry' ] || filter=-nokeys
	p12_cert=$(ossl pkcs12 -in "$file" -passin "pass:$P12_PASSWORD" -nokeys "$filter" 2>/dev/null |
		ossl x509 -outform DER 2>/dev/null | ossl dgst -sha256 -r | cut -d' ' -f1)
	expect "$file certificate" "$p12_cert" \
		"$(ossl x509 -in "$cert" -outform DER | ossl dgst -sha256 -r | cut -d' ' -f1)" || true
	if [ -n "$key" ]; then
		local p12_pub key_pub
		p12_pub=$(ossl pkcs12 -in "$file" -passin "pass:$P12_PASSWORD" -nocerts -nodes 2>/dev/null |
			ossl pkey -pubout 2>/dev/null) || true
		key_pub=$(ossl pkey -in "$key" -pubout)
		[ -n "$p12_pub" ] && [ "$p12_pub" = "$key_pub" ] || fail "$file: private key does not match $key"
	fi
}

# probe_leaf <dir> <name> <subject> <extendedKeyUsage> <subjectAltName, or '' for none>: a one-day P-256 leaf from
# the test CA in $PROBE, for checking what the CA's limits reject.
probe_leaf() {
	local dir=$1 name=$2 subject=$3 eku=$4 sans=$5
	{
		printf '%s\n' 'basicConstraints = critical, CA:FALSE' 'keyUsage = critical, digitalSignature' \
			"extendedKeyUsage = $eku" 'subjectKeyIdentifier = hash' 'authorityKeyIdentifier = keyid:always'
		[ -z "$sans" ] || printf 'subjectAltName = %s\n' "$sans"
	} >"$PROBE/$name.ext"
	genkey EC P-256 "$PROBE/$name-key.pem"
	ossl req -new -key "$PROBE/$name-key.pem" -subj "$subject" -out "$PROBE/$name.csr" 2>/dev/null &&
		ossl x509 -req -in "$PROBE/$name.csr" -CA "$dir/test-ca.pem" -CAkey "$dir/test-ca-key.pem" -set_serial 1 \
			-days 1 -sha256 -extfile "$PROBE/$name.ext" -out "$PROBE/$name.pem" 2>/dev/null ||
		fail "could not issue the $name probe leaf from test-ca.pem"
}

# expect_rejected <dir> <description> <purpose> <expected OpenSSL error line> <leaf>. The error line names the
# verify error by its stable number (26 X509_V_ERR_INVALID_PURPOSE, 47 X509_V_ERR_PERMITTED_VIOLATION) and depth,
# because the error texts differ between OpenSSL 3 releases.
expect_rejected() {
	local dir=$1 description=$2 purpose=$3 expected=$4 leaf=$5 output
	[ -f "$leaf" ] || return 0
	if output=$(ossl verify -x509_strict -purpose "$purpose" -CAfile "$dir/test-ca.pem" "$leaf" 2>&1); then
		fail "test-ca.pem accepts $description (-purpose $purpose)"
	elif ! printf '%s\n' "$output" | grep -qF -- "$expected"; then
		fail "test-ca.pem rejects $description, but not with '$expected': $(printf '%s\n' "$output" | tr '\n' ' ')"
	fi
}

# note_unprotected <dir> <description> <purpose> <leaf>: documents a case the CA's limits do not cover, instead of
# enforcing one. It prints a note and never fails: if OpenSSL starts rejecting the leaf, the list of unprotected
# cases in this script and in tls/README.md is out of date.
note_unprotected() {
	local dir=$1 description=$2 purpose=$3 leaf=$4
	[ -f "$leaf" ] || return 0
	if ossl verify -x509_strict -purpose "$purpose" -CAfile "$dir/test-ca.pem" "$leaf" >/dev/null 2>&1; then
		echo "note: unprotected, as documented: test-ca.pem accepts $description (-purpose $purpose)"
	else
		echo "note: test-ca.pem now rejects $description (-purpose $purpose); update the unprotected cases in" \
			"tls/README.md and this script"
	fi
}

# check_ca_limits <dir>: the test CA's EKU and name constraints reject leaves outside its test-only profile. Signs
# throwaway leaves with the (public) test CA key in a temporary directory; nothing is written to <dir>.
check_ca_limits() {
	local dir=$1 good_subject="/O=$SUBJECT_O/CN=localhost"
	PROBE=$(mktemp -d "${TMPDIR:-/tmp}/revetsec-test-pki-probe.XXXXXXXX")
	probe_leaf "$dir" smime "$good_subject" emailProtection 'email:ceo@bank.example.com'
	probe_leaf "$dir" client "$good_subject" clientAuth 'DNS:localhost'
	probe_leaf "$dir" email "$good_subject" serverAuth 'DNS:localhost, email:ceo@bank.example.com'
	probe_leaf "$dir" uri "$good_subject" serverAuth 'DNS:localhost, URI:https://bank.example.com/'
	probe_leaf "$dir" codesign '/O=Big Bank/CN=Big Bank Code Signing' codeSigning ''
	# The CA's EKU fails the chain at depth 1; a name outside the constraints fails the leaf at depth 0.
	expect_rejected "$dir" 'an S/MIME leaf' smimesign 'error 26 at 1 depth' "$PROBE/smime.pem"
	expect_rejected "$dir" 'a TLS client leaf' sslclient 'error 26 at 1 depth' "$PROBE/client.pem"
	expect_rejected "$dir" 'a server leaf with an email SAN' sslserver 'error 47 at 0 depth' "$PROBE/email.pem"
	expect_rejected "$dir" 'a server leaf with a URI SAN' sslserver 'error 47 at 0 depth' "$PROBE/uri.pem"
	# Not a limit: OpenSSL's codesign purpose ignores the CA's EKU, and no dirName constraint restricts the subject.
	note_unprotected "$dir" 'a code-signing leaf for O=Big Bank' codesign "$PROBE/codesign.pem"
	rm -rf -- "$PROBE"
	PROBE=''
}

check_readme_lists() {
	local dir=$1 file
	shift
	[ -f "$dir/README.md" ] || { fail "$dir/README.md is missing"; return 0; }
	grep -q 'TEST ONLY' "$dir/README.md" || fail "$dir/README.md does not say TEST ONLY"
	for file in "$@"; do
		grep -qF -- "\`$file\`" "$dir/README.md" || fail "$dir/README.md does not document $file"
	done
}

# check_tls <dir> [readme]: the whole tls/ profile.
check_tls() {
	local dir=$1 readme=${2:-readme} ca_subject server_subject
	ca_subject="CN=RevetSec Test CA - DO NOT TRUST,O=$SUBJECT_O"
	server_subject="CN=localhost,O=$SUBJECT_O"

	check_pkcs8_key "$dir/test-ca-key.pem" RSA 3072
	check_cert "$dir/test-ca.pem" "$CA_SERIAL" "$ca_subject" sha256WithRSAEncryption
	cert_matches_key "$dir/test-ca.pem" "$dir/test-ca-key.pem"
	expect "test-ca.pem issuer" "$(ossl x509 -in "$dir/test-ca.pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')" \
		"$ca_subject" || true
	expect "test-ca.pem basicConstraints" "$(extension_criticality "$dir/test-ca.pem" basicConstraints) $(extension_text "$dir/test-ca.pem" basicConstraints)" \
		'critical CA:TRUE, pathlen:0' || true
	expect "test-ca.pem keyUsage" "$(extension_criticality "$dir/test-ca.pem" keyUsage) $(extension_text "$dir/test-ca.pem" keyUsage)" \
		'critical Certificate Sign, CRL Sign' || true
	expect "test-ca.pem extendedKeyUsage" "$(extension_criticality "$dir/test-ca.pem" extendedKeyUsage) $(extension_text "$dir/test-ca.pem" extendedKeyUsage)" \
		'non-critical TLS Web Server Authentication' || true
	expect "test-ca.pem nameConstraints" "$(extension_criticality "$dir/test-ca.pem" nameConstraints) $(extension_text "$dir/test-ca.pem" nameConstraints)" \
		"critical $CA_NAME_CONSTRAINTS_PRINTED" || true
	ossl verify -x509_strict -check_ss_sig -CAfile "$dir/test-ca.pem" "$dir/test-ca.pem" >/dev/null 2>&1 ||
		fail "test-ca.pem does not verify as a self-signed CA"

	check_pkcs8_key "$dir/server-key.pem" RSA 2048
	check_cert "$dir/server.pem" "$SERVER_SERIAL" "$server_subject" sha256WithRSAEncryption
	cert_matches_key "$dir/server.pem" "$dir/server-key.pem"
	expect "server.pem SANs" "$(extension_text "$dir/server.pem" subjectAltName)" "$SERVER_SANS_PRINTED" || true
	expect "server.pem basicConstraints" "$(extension_criticality "$dir/server.pem" basicConstraints) $(extension_text "$dir/server.pem" basicConstraints)" \
		'critical CA:FALSE' || true
	expect "server.pem extendedKeyUsage" "$(extension_text "$dir/server.pem" extendedKeyUsage)" \
		'TLS Web Server Authentication' || true
	local name
	for name in localhost host.testcontainers.internal host.docker.internal; do
		ossl verify -x509_strict -purpose sslserver -CAfile "$dir/test-ca.pem" -verify_hostname "$name" \
			"$dir/server.pem" >/dev/null 2>&1 || fail "server.pem does not verify for $name against test-ca.pem"
	done
	ossl verify -x509_strict -purpose sslserver -CAfile "$dir/test-ca.pem" -verify_ip 127.0.0.1 \
		"$dir/server.pem" >/dev/null 2>&1 || fail "server.pem does not verify for 127.0.0.1 against test-ca.pem"
	if ossl verify -x509_strict -purpose sslserver -CAfile "$dir/test-ca.pem" -verify_hostname example.com \
		"$dir/server.pem" >/dev/null 2>&1; then
		fail "server.pem unexpectedly verifies for example.com"
	fi
	check_ca_limits "$dir"

	check_p12 "$dir/test-ca.p12" "$CA_ALIAS" PrivateKeyEntry "$dir/test-ca.pem" "$dir/test-ca-key.pem" 1
	check_p12 "$dir/server.p12" "$SERVER_ALIAS" PrivateKeyEntry "$dir/server.pem" "$dir/server-key.pem" 2
	check_p12 "$dir/truststore.p12" "$TRUSTSTORE_ALIAS" trustedCertEntry "$dir/test-ca.pem"

	if [ "$readme" = readme ]; then
		# shellcheck disable=SC2086
		check_readme_lists "$dir" $TLS_FILES
	fi
}

# check_keys <dir> [readme]
check_keys() {
	local dir=$1 readme=${2:-readme} name algorithm parameter digest serial usage cn signature expected_usage
	while IFS='|' read -r name algorithm parameter digest serial usage cn; do
		[ -n "$name" ] || continue
		if [ ! -f "$dir/$name-key.pem" ] || [ ! -f "$dir/$name-cert.pem" ]; then
			fail "$dir/$name-key.pem or $dir/$name-cert.pem is missing"
			continue
		fi
		check_pkcs8_key "$dir/$name-key.pem" "$algorithm" "$parameter"
		case "$algorithm" in
			RSA) signature="${digest}WithRSAEncryption" ;;
			EC) signature="ecdsa-with-$(printf '%s' "$digest" | tr '[:lower:]' '[:upper:]')" ;;
		esac
		check_cert "$dir/$name-cert.pem" "$serial" "CN=$cn,O=$SUBJECT_O" "$signature"
		cert_matches_key "$dir/$name-cert.pem" "$dir/$name-key.pem"
		case "$usage" in
			digitalSignature) expected_usage='Digital Signature' ;;
			keyEncipherment) expected_usage='Key Encipherment' ;;
		esac
		expect "$name-cert.pem keyUsage" \
			"$(extension_criticality "$dir/$name-cert.pem" keyUsage) $(extension_text "$dir/$name-cert.pem" keyUsage)" \
			"critical $expected_usage" || true
		expect "$name-cert.pem basicConstraints" "$(extension_text "$dir/$name-cert.pem" basicConstraints)" 'CA:FALSE' || true
		# Self-signed: the certificate verifies its own signature.
		ossl verify -check_ss_sig -partial_chain -no-CAfile -no-CApath -trusted "$dir/$name-cert.pem" \
			"$dir/$name-cert.pem" >/dev/null 2>&1 || fail "$name-cert.pem self-signature does not verify"
	done <<EOF
$KEY_SPECS
EOF
	if [ "$readme" = readme ]; then
		# shellcheck disable=SC2046
		check_readme_lists "$dir" $(key_files)
	fi
}

finish_checks() {
	if [ "$FAILURES" -ne 0 ]; then
		die "$FAILURES check(s) failed"
	fi
}

summarize_cert() {
	local file=$1 text
	text=$(ossl x509 -in "$file" -noout -pubkey | ossl pkey -pubin -noout -text 2>/dev/null)
	printf '  %-38s %-10s %-24s %s .. %s\n' "$(basename "$file")" \
		"$(printf '%s\n' "$text" | sed -n 's/^Public-Key: (\([0-9]*\) bit)$/\1 bit/p')" \
		"$(printf '%s\n' "$text" | sed -n 's/^NIST CURVE: //p')$(printf '%s\n' "$text" | grep -q '^Modulus:' && echo RSA)" \
		"$(ossl x509 -in "$file" -noout -startdate | sed 's/^notBefore=//')" \
		"$(ossl x509 -in "$file" -noout -enddate | sed 's/^notAfter=//')"
}

# ---------------------------------------------------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------------------------------------------------

generate_tls() {
	new_stage
	local config="$STAGE/pki.cnf"
	write_config "$config"

	genkey RSA 3072 "$STAGE/test-ca-key.pem"
	ossl req -x509 -config "$config" -extensions ca_ext -key "$STAGE/test-ca-key.pem" -subj "$CA_SUBJECT" \
		-set_serial "$CA_SERIAL" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -sha256 -out "$STAGE/test-ca.pem"
	export_p12 "$STAGE/test-ca.p12" "$STAGE/test-ca-key.pem" "$STAGE/test-ca.pem" "$CA_ALIAS"

	issue_server_leaf "$STAGE" "$STAGE/test-ca.pem" "$STAGE/test-ca-key.pem" "$SERVER_SERIAL" "$config"

	ktool -importcert -noprompt -alias "$TRUSTSTORE_ALIAS" -file "$STAGE/test-ca.pem" \
		-keystore "$STAGE/truststore.p12" -storetype PKCS12 -storepass "$P12_PASSWORD" >/dev/null 2>&1 ||
		die "keytool -importcert failed"

	check_tls "$STAGE" no-readme
	finish_checks
	# shellcheck disable=SC2086
	install_files "$STAGE" "$TLS_DIR" $TLS_FILES
	cleanup
	STAGE=''
	echo "wrote $TLS_DIR (TEST ONLY)"
}

generate_keys() {
	new_stage
	local config="$STAGE/pki.cnf" name algorithm parameter digest serial usage cn
	write_config "$config"
	while IFS='|' read -r name algorithm parameter digest serial usage cn; do
		[ -n "$name" ] || continue
		genkey "$algorithm" "$parameter" "$STAGE/$name-key.pem"
		ossl req -x509 -config "$config" -extensions "fixture_$usage" -key "$STAGE/$name-key.pem" \
			-subj "/O=$SUBJECT_O/CN=$cn" -set_serial "$serial" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
			"-$digest" -out "$STAGE/$name-cert.pem"
	done <<EOF
$KEY_SPECS
EOF
	check_keys "$STAGE" no-readme
	finish_checks
	# shellcheck disable=SC2046
	install_files "$STAGE" "$KEYS_DIR" $(key_files)
	cleanup
	STAGE=''
	echo "wrote $KEYS_DIR (TEST ONLY)"
}

run_check() {
	echo "Checking $TLS_DIR"
	check_tls "$TLS_DIR"
	echo "Checking $KEYS_DIR"
	check_keys "$KEYS_DIR"
	finish_checks
	echo 'Certificates (public key, curve or RSA, validity):'
	local file
	for file in "$TLS_DIR/test-ca.pem" "$TLS_DIR/server.pem" "$KEYS_DIR"/*-cert.pem; do
		summarize_cert "$file"
	done
	echo "server.pem SANs: $(extension_text "$TLS_DIR/server.pem" subjectAltName)"
	echo 'OK: all test PKI checks passed (TEST ONLY material)'
}

issue_extra_leaf() {
	local out_dir=$1 extra_sans=$2 force=$3
	[ -n "$out_dir" ] || die "leaf requires --out-dir DIR"
	[ -n "$extra_sans" ] || die "leaf requires at least one --san (the default SANs are already in tls/server.pem)"
	[ -f "$TLS_DIR/test-ca.pem" ] && [ -f "$TLS_DIR/test-ca-key.pem" ] || die "missing test CA in $TLS_DIR"
	mkdir -p -- "$out_dir"
	out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
	[ "$out_dir" != "$TLS_DIR" ] || die "leaf never writes into $TLS_DIR; choose another --out-dir"
	[ "$force" = true ] || refuse_overwrite "$out_dir" server.pem server-key.pem server.p12
	new_stage
	local config="$STAGE/pki.cnf" serial
	write_config "$config" "$extra_sans"
	# A random positive serial, so issuer+serial never collides with the checked-in leaf.
	serial="0x7$(ossl rand -hex 15 | cut -c2-)"
	issue_server_leaf "$STAGE" "$TLS_DIR/test-ca.pem" "$TLS_DIR/test-ca-key.pem" "$serial" "$config"
	if ! ossl verify -x509_strict -purpose sslserver -CAfile "$TLS_DIR/test-ca.pem" "$STAGE/server.pem" >/dev/null 2>&1; then
		ossl verify -x509_strict -purpose sslserver -CAfile "$TLS_DIR/test-ca.pem" "$STAGE/server.pem" >&2 || true
		die "the new leaf does not verify against the test CA; every SAN must be inside the CA's name constraints (see $0)"
	fi
	install_files "$STAGE" "$out_dir" server.pem server-key.pem server.p12
	echo "wrote $out_dir/{server.pem,server-key.pem,server.p12} (TEST ONLY) with SANs: $(extension_text "$out_dir/server.pem" subjectAltName)"
}

main() {
	[ "$#" -ge 1 ] || usage
	local command=$1 force=false out_dir='' extra_sans=''
	shift
	case "$command" in
		check | tls | keys | all | leaf) ;;
		*) usage ;;
	esac
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--force) force=true ;;
			--out-dir)
				[ "$#" -ge 2 ] || usage
				out_dir=$2
				shift
				;;
			--san)
				[ "$#" -ge 2 ] || usage
				printf '%s\n' "$2" | grep -Eq '^(DNS:[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|IP:[0-9A-Fa-f:.]+)$' ||
					die "--san must be DNS:<hostname> or IP:<address>, got: $2"
				extra_sans="$extra_sans, $2"
				shift
				;;
			*) usage ;;
		esac
		shift
	done
	if [ "$command" != leaf ] && { [ -n "$out_dir" ] || [ -n "$extra_sans" ]; }; then
		usage
	fi

	if [ "$command" = check ]; then
		require_openssl 0
	else
		require_openssl 4
	fi
	if [ "$force" = false ]; then
		# Refuse before generating anything, so "all" never replaces one directory and then stops.
		case "$command" in
			# shellcheck disable=SC2086
			tls | all) refuse_overwrite "$TLS_DIR" $TLS_FILES ;;
		esac
		case "$command" in
			# shellcheck disable=SC2046
			keys | all) refuse_overwrite "$KEYS_DIR" $(key_files) ;;
		esac
	fi
	case "$command" in
		check)
			[ "$force" = false ] || usage
			require_keytool
			run_check
			;;
		tls)
			require_keytool
			generate_tls
			check_tls "$TLS_DIR"
			finish_checks
			;;
		keys)
			generate_keys
			check_keys "$KEYS_DIR"
			finish_checks
			;;
		all)
			require_keytool
			generate_tls
			generate_keys
			run_check
			;;
		leaf)
			issue_extra_leaf "$out_dir" "$extra_sans" "$force"
			;;
		*) usage ;;
	esac
}

main "$@"
