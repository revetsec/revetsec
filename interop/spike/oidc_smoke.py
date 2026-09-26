#!/usr/bin/env python3
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

"""Headless OIDC authorization-code + PKCE smoke check for the Tier-1 spike.

Standard library only. It proves that a freshly started test OP is usable,
not just "up": discovery, the authorization endpoint (auto-login, or a
Keycloak-style login form POST), and a code exchange that returns an ID token
whose iss/aud/nonce match. It does NOT verify the ID token signature; that is
Revetsec's job, and this spike runs before any Revetsec code exists.

The redirect URI is never contacted: the flow stops when the OP redirects to it.
Exit status 0 means the flow completed; anything else prints the reason.
"""

import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# Keycloak's login form (keycloak.v2 theme). Pinned on purpose: when the theme
# changes, this fails loudly instead of posting somewhere unexpected.
KEYCLOAK_FORM_ACTION = re.compile(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', re.S)


class _LoopbackIsSecurePolicy(http.cookiejar.DefaultCookiePolicy):
	"""Sends Secure cookies to http://localhost, as browsers do.

	Keycloak 26 marks its login cookies Secure even over plain HTTP. Browsers
	treat loopback as a secure context and send them; CookieJar does not, and
	neither does java.net.CookieManager. A headless driver against a plain-HTTP
	Keycloak fails with "cookie_not_found" unless it does this (or uses TLS).
	"""

	def return_ok_secure(self, cookie, request):
		host = urllib.parse.urlsplit(request.get_full_url()).hostname
		if cookie.secure and host in ("localhost", "127.0.0.1", "::1"):
			return True
		return super().return_ok_secure(cookie, request)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		return None


def _b64url(data):
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
	return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _opener(cafile, insecure):
	if insecure:
		# Only for the OIDF suite, whose nginx serves its own self-signed
		# certificate. Never used for an OP that runs with our test CA.
		context = ssl._create_unverified_context()
	else:
		context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
	jar = http.cookiejar.CookieJar(policy=_LoopbackIsSecurePolicy())
	return urllib.request.build_opener(
		urllib.request.HTTPSHandler(context=context),
		urllib.request.HTTPCookieProcessor(jar),
		_NoRedirect(),
	)


def _request(opener, url, data=None, headers=None):
	"""Returns (status, headers, body) without following redirects."""
	request = urllib.request.Request(url, data=data, headers=headers or {})
	try:
		with opener.open(request, timeout=15) as response:
			return response.status, response.headers, response.read()
	except urllib.error.HTTPError as error:
		return error.code, error.headers, error.read()


def run(args):
	opener = _opener(args.cafile, args.insecure)
	issuer = args.issuer

	status, _, body = _request(opener, issuer.rstrip("/") + "/.well-known/openid-configuration")
	if status != 200:
		raise SystemExit(f"discovery returned HTTP {status}")
	discovery = json.loads(body)
	if discovery.get("issuer") != issuer:
		raise SystemExit(f"discovery issuer {discovery.get('issuer')!r} != {issuer!r}")

	verifier = _b64url(secrets.token_bytes(32))
	state = _b64url(secrets.token_bytes(16))
	nonce = _b64url(secrets.token_bytes(16))
	query = urllib.parse.urlencode({
		"response_type": "code",
		"client_id": args.client_id,
		"redirect_uri": args.redirect_uri,
		"scope": "openid email profile",
		"state": state,
		"nonce": nonce,
		"code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
		"code_challenge_method": "S256",
	})
	url = discovery["authorization_endpoint"] + "?" + query
	data = None
	callback = None

	for _ in range(12):
		status, headers, body = _request(opener, url, data=data)
		data = None
		if status in (301, 302, 303, 307, 308):
			location = urllib.parse.urljoin(url, headers["Location"])
			if location.split("?", 1)[0] == args.redirect_uri:
				callback = location
				break
			url = location
			continue
		if status == 200 and args.username:
			match = KEYCLOAK_FORM_ACTION.search(body.decode("utf-8", "replace"))
			if not match:
				raise SystemExit("HTTP 200 without the expected login form")
			url = urllib.parse.urljoin(url, html.unescape(match.group(1)))
			data = urllib.parse.urlencode({
				"username": args.username,
				"password": args.password,
				"credentialId": "",
			}).encode("ascii")
			continue
		raise SystemExit(f"unexpected HTTP {status} at {url.split('?', 1)[0]}")

	if callback is None:
		raise SystemExit("never reached the redirect URI")
	params = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
	if "error" in params:
		raise SystemExit(f"authorization error: {params['error'][0]}")
	if params.get("state") != [state]:
		raise SystemExit("state mismatch")
	if "iss" in params and params["iss"] != [issuer]:
		raise SystemExit(f"RFC 9207 iss mismatch: {params['iss'][0]!r}")

	credentials = base64.b64encode(
		f"{urllib.parse.quote(args.client_id, safe='')}:{urllib.parse.quote(args.client_secret, safe='')}".encode("utf-8")
	).decode("ascii")
	status, _, body = _request(
		opener,
		discovery["token_endpoint"],
		data=urllib.parse.urlencode({
			"grant_type": "authorization_code",
			"code": params["code"][0],
			"redirect_uri": args.redirect_uri,
			"code_verifier": verifier,
		}).encode("ascii"),
		headers={
			"Authorization": "Basic " + credentials,
			"Content-Type": "application/x-www-form-urlencoded",
		},
	)
	if status != 200:
		raise SystemExit(f"token endpoint returned HTTP {status}: {body[:200]!r}")
	tokens = json.loads(body)
	id_token = tokens.get("id_token")
	if not id_token:
		raise SystemExit("token response has no id_token")
	header = json.loads(_b64url_decode(id_token.split(".")[0]))
	claims = json.loads(_b64url_decode(id_token.split(".")[1]))
	aud = claims.get("aud")
	if claims.get("iss") != issuer or args.client_id not in (aud if isinstance(aud, list) else [aud]):
		raise SystemExit("id_token iss/aud mismatch")
	if claims.get("nonce") != nonce:
		raise SystemExit("id_token nonce mismatch")
	print(
		f"ok: code flow + PKCE, id_token alg={header.get('alg')},"
		f" RFC 9207 iss parameter {'present' if 'iss' in params else 'absent'}"
	)


def main():
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("--issuer", required=True)
	parser.add_argument("--client-id", required=True)
	parser.add_argument("--client-secret", required=True)
	parser.add_argument("--redirect-uri", required=True)
	parser.add_argument("--cafile", help="PEM trust anchor for an HTTPS issuer")
	parser.add_argument("--insecure", action="store_true", help="skip TLS verification (OIDF suite only)")
	parser.add_argument("--username", help="submit a Keycloak-style login form as this user")
	parser.add_argument("--password", help="test-only password for --username")
	run(parser.parse_args())


if __name__ == "__main__":
	sys.exit(main())
