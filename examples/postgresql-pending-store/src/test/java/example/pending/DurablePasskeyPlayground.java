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
package example.pending;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.soklet.Soklet;
import example.passkeys.PasskeyApp;
import example.passkeys.PasskeyPlayground;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Test-only Soklet launcher with an independently provisioned PostgreSQL WebAuthn namespace. */
public final class DurablePasskeyPlayground {
    private static final String NAMESPACE = "fixture_wa_browser";

    private DurablePasskeyPlayground() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("No launcher arguments expected");
        Map<String, String> env = System.getenv();
        String origin = required(env, "REVETSEC_PASSKEY_ORIGIN");
        String rpId = required(env, "REVETSEC_PASSKEY_RP_ID");
        String sealKey = required(env, "REVETSEC_TEST_WA_SEAL_KEY");
        String accessKey = PasskeyPlayground.privateKeyFile(
                Path.of(required(env, "REVETSEC_PASSKEY_ACCESS_KEY_FILE")));
        byte[] accountHandle = Base64.getUrlDecoder().decode(
                required(env, "REVETSEC_TEST_WA_BROWSER_HANDLE"));
        int port = Integer.parseInt(required(env, "REVETSEC_PASSKEY_HTTP_PORT"));
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("fixture", sealKey)).build();
        WebAuthnRecoveryGate gate = new WebAuthnFixtureRecoveryGate(NAMESPACE,
                Path.of(required(env, "REVETSEC_TEST_WA_MARKER_FILE")),
                Path.of(required(env, "REVETSEC_TEST_WA_LOCK_FILE")), sealKey);
        WebAuthnRelyingParty party = WebAuthnRelyingParty.withRelyingPartyId(rpId)
                .relyingPartyName("Revetsec Passkey Demo").allowedOrigins(Set.of(origin))
                .credentialNamespace(NAMESPACE)
                .store(new PostgresqlWebAuthnStore(NAMESPACE, WebAuthnStoreProbe::connection, 256))
                .stateSealer(sealer)
                .recoveryGate(gate)
                .build();
        PasskeyApp app = new PasskeyApp(origin, rpId, accessKey, Clock.systemUTC(),
                accountHandle, party, gate);
        try (Soklet soklet = Soklet.fromConfig(PasskeyPlayground.config(app, port))) {
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close, "durable-passkey-shutdown"));
            soklet.start();
            soklet.awaitShutdown();
        }
    }

    private static @NonNull String required(@NonNull Map<@NonNull String, @NonNull String> env,
            @NonNull String name) {
        String value = env.get(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing fixture setting");
        return value;
    }
}
