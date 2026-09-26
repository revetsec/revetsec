/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// TEST-ONLY OpenID Provider for Revetsec's Tier-1 interop legs.
//
// It is built on oidc-provider (https://github.com/panva/node-oidc-provider,
// MIT, Copyright Filip Skokan), which is installed unmodified from the npm
// registry through the committed package-lock.json.
//
// NEVER expose this server outside a throwaway test network. Its interaction
// handler logs every browser in as the fixed test account and grants every
// requested scope without asking. That is what a headless java.net.http test
// driver needs, and it is exactly what a real OP must never do.
//
// Configuration (environment):
//   PORT                        listen port inside the container (default 3000)
//   ISSUER                      issuer URL as the test driver sees it
//                               (default http(s)://localhost:PORT)
//   TLS_CERT_FILE, TLS_KEY_FILE PEM server certificate and key; when both are
//                               set the server speaks HTTPS only
//   TEST_CLIENT_REDIRECT_URIS   comma-separated redirect URIs for the test client

import { readFileSync } from 'node:fs';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import Provider from 'oidc-provider';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const tlsCertFile = process.env.TLS_CERT_FILE;
const tlsKeyFile = process.env.TLS_KEY_FILE;
const tlsEnabled = Boolean(tlsCertFile && tlsKeyFile);
const issuer = process.env.ISSUER ?? `${tlsEnabled ? 'https' : 'http'}://localhost:${port}`;
const redirectUris = (process.env.TEST_CLIENT_REDIRECT_URIS
	?? 'http://localhost:8080/callback,http://127.0.0.1:8080/callback')
	.split(',')
	.map((uri) => uri.trim())
	.filter((uri) => uri.length > 0);

// The one test account. Every interactive login resolves to it.
const TEST_ACCOUNT_ID = 'test-user';
const TEST_ACCOUNT_CLAIMS = Object.freeze({
	sub: TEST_ACCOUNT_ID,
	email: 'test-user@example.test',
	email_verified: true,
	name: 'Test User',
	given_name: 'Test',
	family_name: 'User',
	preferred_username: TEST_ACCOUNT_ID,
});

// Signing keys are generated fresh at every start, so no private key is
// committed. Tests must fetch the JWKS; they must not pin key material.
function signingKeys() {
	const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
	const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
	return {
		keys: [
			{ ...rsa, use: 'sig', alg: 'RS256', kid: `rs256-${randomBytes(6).toString('hex')}` },
			{ ...ec, use: 'sig', alg: 'ES256', kid: `es256-${randomBytes(6).toString('hex')}` },
		],
	};
}

const configuration = {
	clients: [
		{
			// Test-only confidential client. The secret is a fixed, public test
			// value; it protects nothing.
			client_id: 'revetsec-test-client',
			client_secret: 'test-only-client-secret-not-a-real-secret',
			redirect_uris: redirectUris,
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			token_endpoint_auth_method: 'client_secret_basic',
		},
	],
	jwks: signingKeys(),
	cookies: {
		// Fresh per start; cookies never have to survive a restart.
		keys: [randomBytes(32).toString('base64url')],
	},
	claims: {
		openid: ['sub'],
		email: ['email', 'email_verified'],
		profile: ['name', 'given_name', 'family_name', 'preferred_username'],
	},
	// Strict by default: PKCE for every client, not only public ones.
	pkce: {
		required: () => true,
	},
	features: {
		// Replaced by the auto-login handler below.
		devInteractions: { enabled: false },
		introspection: { enabled: true },
		revocation: { enabled: true },
		// Placeholders for later milestones: M5/M6 turn on the
		// strict-spec legs here, e.g. resourceIndicators with
		// accessTokenFormat 'jwt' (RFC 9068), jwtIntrospection (RFC 9701),
		// and PAR/DPoP policy variants.
	},
	interactions: {
		url(_ctx, interaction) {
			return `/interaction/${interaction.uid}`;
		},
	},
	async findAccount(_ctx, sub) {
		if (sub !== TEST_ACCOUNT_ID) {
			return undefined;
		}
		return {
			accountId: TEST_ACCOUNT_ID,
			async claims() {
				return { ...TEST_ACCOUNT_CLAIMS };
			},
		};
	},
};

const provider = new Provider(issuer, configuration);
const providerCallback = provider.callback();

// Auto-login interaction policy (placeholder for the M5 handler).
//
// The provider's default policy still runs: it decides WHEN a login or a
// consent prompt is needed. This handler only answers every prompt at once,
// with the fixed test account and a grant for exactly the missing scopes and
// claims, and redirects back with 303. There is no HTML and no form, so a
// test driver just follows redirects with a cookie jar.
async function finishInteraction(req, res) {
	const details = await provider.interactionDetails(req, res);
	const { prompt: { name, details: missing }, params, session, grantId } = details;

	if (name === 'login') {
		await provider.interactionFinished(req, res, {
			login: { accountId: TEST_ACCOUNT_ID },
		}, { mergeWithLastSubmission: false });
		return;
	}

	if (name === 'consent') {
		const grant = grantId
			? await provider.Grant.find(grantId)
			: new provider.Grant({ accountId: session.accountId, clientId: params.client_id });

		if (missing.missingOIDCScope) {
			grant.addOIDCScope(missing.missingOIDCScope.join(' '));
		}
		if (missing.missingOIDCClaims) {
			grant.addOIDCClaims(missing.missingOIDCClaims);
		}
		if (missing.missingResourceScopes) {
			for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes)) {
				grant.addResourceScope(indicator, scopes.join(' '));
			}
		}

		await provider.interactionFinished(req, res, {
			consent: { grantId: await grant.save() },
		}, { mergeWithLastSubmission: true });
		return;
	}

	res.statusCode = 501;
	res.setHeader('Content-Type', 'text/plain; charset=utf-8');
	res.end(`unsupported prompt: ${name}\n`);
}

async function handle(req, res) {
	if (req.method === 'GET' && req.url?.startsWith('/interaction/')) {
		try {
			await finishInteraction(req, res);
		} catch (error) {
			res.statusCode = 400;
			res.setHeader('Content-Type', 'text/plain; charset=utf-8');
			res.end(`interaction failed: ${error?.name ?? 'Error'}\n`);
		}
		return;
	}
	providerCallback(req, res);
}

const server = tlsEnabled
	? createHttpsServer({ cert: readFileSync(tlsCertFile), key: readFileSync(tlsKeyFile) }, handle)
	: createHttpServer(handle);

server.listen(port, () => {
	console.log(`test-only oidc-provider listening on port ${port}; issuer ${issuer}`);
});

// Node as PID 1 ignores SIGTERM unless it is handled, which would turn every
// `docker stop` into a 10-second wait followed by SIGKILL.
function shutdown(signal) {
	console.log(`received ${signal}; shutting down`);
	server.close(() => process.exit(0));
	server.closeAllConnections();
	setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
