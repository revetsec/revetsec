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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/** Separate-process driver for the test-only TOTP recovery controller. */
@NotThreadSafe
public final class TotpRecoveryControllerProbe {
    private static final @NonNull String NAMESPACE = "fixture_totp_flow";
    private static final @NonNull String KEY_ID = "fixture";
    private static final @NonNull String NEXT_KEY_ID = "fixture-next";
    private static final @NonNull String FIRST_EPOCH = "fixture-epoch-one";
    private static final @NonNull String SECOND_EPOCH = "fixture-epoch-two";
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(20);

    private TotpRecoveryControllerProbe() { }

    public static void main(java.lang.@NonNull String @NonNull [] arguments) throws Exception {
        if (arguments.length != 1) throw new IllegalArgumentException("Expected one fixture command");
        TotpFixtureRecoveryController controller = new TotpFixtureRecoveryController(
                Path.of(required("REVETSEC_TEST_TOTP_MARKER")),
                Path.of(required("REVETSEC_TEST_TOTP_LOCK")));
        String activeKeyId = System.getenv().getOrDefault("REVETSEC_TEST_TOTP_ACTIVE_KEY_ID", KEY_ID);
        Map<String, String> keys = Map.of(activeKeyId, required("REVETSEC_TEST_TOTP_SEAL_KEY_BASE64"));
        switch (arguments[0]) {
            case "initial" -> {
                controller.provisionFresh(NAMESPACE, FIRST_EPOCH, KEY_ID, keys);
                System.out.println("INITIALIZING");
            }
            case "open" -> {
                controller.openOrdinary(NAMESPACE, FIRST_EPOCH, BUDGET);
                System.out.println("OPEN");
            }
            case "rotate" -> transitionKeys(controller, NEXT_KEY_ID,
                    Map.of(KEY_ID, required("REVETSEC_TEST_TOTP_SEAL_KEY_BASE64"),
                            NEXT_KEY_ID, required("REVETSEC_TEST_TOTP_NEW_SEAL_KEY_BASE64")));
            case "retire" -> transitionKeys(controller, NEXT_KEY_ID,
                    Map.of(NEXT_KEY_ID, required("REVETSEC_TEST_TOTP_NEW_SEAL_KEY_BASE64")));
            case "restore" -> restore(controller, activeKeyId, keys);
            case "open-new" -> {
                controller.openOrdinary(NAMESPACE, SECOND_EPOCH, BUDGET);
                System.out.println("OPEN_NEW");
            }
            default -> throw new IllegalArgumentException("Unknown fixture command");
        }
    }

    private static void transitionKeys(@NonNull TotpFixtureRecoveryController controller,
            @NonNull String activeKeyId,
            @NonNull Map<@NonNull String, @NonNull String> keys) throws Exception {
        try (TotpFixtureRecoveryController.RestoreLease lease = controller.closeAndDrain(BUDGET)) {
            lease.changeOpeningKeys(activeKeyId, keys);
        }
        System.out.println("KEYS_CHANGED");
    }

    private static void restore(@NonNull TotpFixtureRecoveryController controller,
            @NonNull String activeKeyId,
            @NonNull Map<@NonNull String, @NonNull String> keys)
            throws Exception {
        try (TotpFixtureRecoveryController.RestoreLease lease = controller.closeAndDrain(BUDGET);
                BufferedReader commands = new BufferedReader(new InputStreamReader(System.in,
                        StandardCharsets.US_ASCII))) {
            System.out.println("DRAINED");
            System.out.flush();
            if (!"fresh".equals(commands.readLine()))
                throw new IllegalStateException("Restore command ended before fresh epoch");
            lease.beginFreshEpoch(NAMESPACE, SECOND_EPOCH, activeKeyId, keys);
            System.out.println("FRESH_MARKED");
            System.out.flush();
            if (!"release".equals(commands.readLine()))
                throw new IllegalStateException("Restore command ended before lease release");
        }
        System.out.println("RELEASED");
    }

    private static @NonNull String required(@NonNull String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty())
            throw new IllegalStateException("Missing TOTP fixture environment: " + name);
        return value;
    }
}
