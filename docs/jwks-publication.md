# Standalone JWKS publication

`PublishedJwk` describes a public signature-verification key. `JwksPublisher` publishes an immutable set of those keys as JSON or prepared HTTP responses. Neither requires an OAuth authorization server, a private key, a store, or a running server.

## Publish an RSA key and certificate chain

For an application such as Cobalt that signs outbound RS384 assertions, publish the corresponding public key with the same `kid` used in those assertions:

```java
import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

// keyStore is an already loaded application-owned KeyStore.
// Its certificate chain must be leaf first, followed by its issuing certificates.
List<X509Certificate> chain = Arrays.stream(keyStore.getCertificateChain("epic-prod"))
    .map(certificate -> (X509Certificate) certificate)
    .toList();

PublishedJwk key = PublishedJwk.withPublicKey(chain.get(0).getPublicKey())
    .keyId("epic-prod")
    .algorithm(JwsAlgorithm.RS384)
    .certificateChain(chain)
    .build();

JwksPublisher publisher = JwksPublisher.withKeys(List.of(key))
    .cacheLifetime(Duration.ofHours(1))
    .build();

String publicJson = publisher.toJson();
```

Both the publisher and each published key expose JSON text through `toJson()` and a structured `JsonObject` through `toJsonObject()`:

```java
import com.revetsec.json.JsonObject;

JsonObject publicDocument = publisher.toJsonObject();
JsonObject publicKeyDocument = key.toJsonObject();
String publicKeyJson = key.toJson();
```

The public key is the only required key-builder input. `keyId`, `algorithm`, and `certificateChain` are optional; passing `null` to one of their setters clears it. `PublishedJwk.fromPublicKey(publicKey)` is shorthand for the minimal builder. Key type and public parameters are derived from the public key; no signing algorithm is inferred. Set `algorithm` explicitly when an integration requires it.

Publication supports:

| Public key | Optional `algorithm` |
| --- | --- |
| RSA, 2048–16384 bits under Revetsec's existing exponent and weak-key policy | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |
| EC P-521 | `ES512` |
| Ed25519 | `ED25519` or the legacy `EDDSA` identifier |

Incompatible key/algorithm combinations and unsupported key types are rejected. HMAC keys cannot be published: their shared secret is not public verification material. This API publishes signature-verification keys; it does not describe encryption keys.

## Certificate metadata

A configured chain emits `x5c` as standard base64 DER certificates, plus `x5t` and `x5t#S256` derived from the leaf certificate. The SHA-1 `x5t` field supports integrations that require that identifier; it does not select the assertion's signature algorithm. The leaf must match the supplied public key. Certificates are checked for chain order, signature links and applicable key usage. Publication does not establish PKIX trust or check current certificate validity; the application owns certificate lifecycle and trust policy. A single leaf certificate is allowed, including a self-signed application certificate.

Public parameters and certificate encodings are snapshotted, so later changes to caller-owned objects do not alter a published key. A chain contains at most 16 certificates, each at most 64 KiB DER, and at most 128 KiB DER in total.

## HTTP responses

```java
import com.revetsec.jose.JwksResponse;

// The application chooses and registers a fixed endpoint such as /jwks.
JwksResponse prepared = publisher.responseFor("GET", ifNoneMatchHeader);
Integer status = prepared.getStatusCode();
var headers = prepared.getHeaders();
byte[] body = prepared.toHttpBody();
var document = prepared.getDocument(); // Optional<JsonObject>, present for GET 200 only.
```

Emit the prepared status, headers and bytes together, without JSON serialization or additional body encoding. `responseFor(method)` also works when no conditional header is present. Multiple `If-None-Match` field occurrences must be joined with commas; the framework adapters do that for you.

- GET returns `application/jwk-set+json`, a strong SHA-256 ETag, and `Cache-Control: public, max-age=N, must-revalidate`.
- HEAD preserves GET's headers, including its representation length, and emits no body.
- A matching `If-None-Match` returns 304 without a body. Weak tags, lists, and the wildcard are supported. Malformed conditional syntax is ignored; a combined conditional value over 8192 characters receives a non-cacheable 400.
- Other methods receive 405 with `Allow: GET, HEAD` and `Cache-Control: no-store`.

Freshness defaults to 60 seconds. `cacheLifetime` accepts whole seconds from zero to 24 hours; `null` restores the default. A set contains at most 100 keys and at most 256 KiB of UTF-8 JSON. Duplicate configured key IDs are rejected. An empty set and keys without IDs are allowed.

## Soklet and Servlet routes

The adapters support standalone endpoints without any OAuth configuration:

```java
import com.revetsec.soklet.JwksMarshaledResponse;

// Soklet: prepared bytes, with the default response marshaler
return JwksMarshaledResponse.from(publisher, request);

// Soklet: typed Response body, serialized by the application
return com.revetsec.soklet.JwksResponse.from(publisher, request);

// Jakarta or javax Servlet: inside a servlet mapped to /jwks
ServletJwks.writeResponse(publisher, request, response);
```

The Soklet `Response` variant carries an immutable `com.revetsec.soklet.JwksResponse.Body` for successful GETs. It provides `getKeys()`, `toJsonObject()` and `toJson()` for inspection and application-owned serialization. It uses a weak ETag and leaves `Content-Length` to the application marshaler and transport. HEAD, 304 and error responses have no body object. The `MarshaledResponse` variant and both Servlet adapters preserve the strong ETag, prepared length and exact bytes.

See the adapter-specific examples in [Soklet](https://github.com/revetsec/revetsec-soklet/blob/main/docs/jwks.md), [Jakarta Servlet](https://github.com/revetsec/revetsec-servlet-jakarta/blob/main/docs/jwks.md), and [javax Servlet](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/jwks.md). Soklet's default response marshaler supports these prepared HEAD responses without custom configuration; use a build containing the default HEAD handling fix described in the Soklet guide. The application owns TLS, endpoint routing, ingress limits, and any discovery or partner registration that advertises the URL.

## Rotation

Construct a replacement publisher containing the new and retained public verification keys, then replace the application's publisher reference atomically. Use unique key IDs and retain old keys for all outstanding signatures plus the applicable cache lifetime. Replacing a snapshot changes the ETag when the published JSON changes; the publisher does not generate or rotate private keys.
