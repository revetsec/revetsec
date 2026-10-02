# Local provider presets

The parent [example README](../README.md) configures the locked node-provider preset with real code/client-credentials/resource issuance and public-client registration. Its automatic login/consent is confined to disposable loopback checks.

`keycloak-realm.json` is a separate public synthetic preset derived from the core resource integration fixture. Existing integration/OIDF realms are unchanged. It uses the already-pinned Keycloak image, a confidential client with PKCE S256, strict access-token headers, actual subject/client_id/resource audience mappers, and the introspecting-client audience required by this provider's policy. Optional `mcp:discover` and `mcp:whoami` scopes are explicit. No password/direct-access grant is enabled.

```sh
docker create --name revetsec-example-keycloak \
  -p 127.0.0.1:9443:8443 \
  -e KC_HOSTNAME=https://localhost:9443 \
  -e KC_HTTPS_CERTIFICATE_FILE=/tmp/localhost.crt \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/tmp/localhost.key \
  quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c \
  start-dev --import-realm --http-enabled=false
# Prepare copies readable by Keycloak's container user, inside a private host parent.
mkdir -p /private/provider-files/import
cp /private/tls/localhost.crt /private/provider-files/localhost.crt
cp /private/tls/localhost.key /private/provider-files/localhost.key
cp examples/providers/keycloak-realm.json /private/provider-files/import/realm.json
chmod 700 /private/provider-files
chmod 755 /private/provider-files/import
chmod 644 /private/provider-files/localhost.crt /private/provider-files/localhost.key /private/provider-files/import/realm.json
docker cp /private/provider-files/localhost.crt revetsec-example-keycloak:/tmp/localhost.crt
docker cp /private/provider-files/localhost.key revetsec-example-keycloak:/tmp/localhost.key
docker cp /private/provider-files/import revetsec-example-keycloak:/opt/keycloak/data
docker start revetsec-example-keycloak
```

Prepare the exact image first with `docker pull` if absent. The container's copied test key must be readable by its nonroot provider process; keep the host source directory private. Select issuer `https://localhost:9443/realms/revetsec-playground`, client ID `revetsec-playground`, and env/file secret reference to public synthetic secret `test-only-client-secret-not-a-real-secret`. Use that client for the explicit client-credentials probe and introspection. Login account is `test-user`, password `test-only-password-not-a-secret`. The redirect URIs are the two documented local HTTPS callbacks.

The node and Keycloak presets share port 9443 and are alternatives. Stop and remove only the named example container after use. Restart apps when switching issuer/strategy; in-memory app state is ephemeral. The resource audience remains exactly `https://localhost:8443/mcp`. This Keycloak client is preconfigured; the Inspector DCR qualification uses the separate node preset. Public synthetic passwords protect no external service.
