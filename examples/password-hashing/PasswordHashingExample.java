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
import com.revetsec.password.Argon2idParameters;
import com.revetsec.password.PasswordHashResult;
import com.revetsec.password.PasswordHasher;
import com.revetsec.password.PasswordPepperKey;
import com.revetsec.password.PasswordPepperSnapshot;
import com.revetsec.password.PasswordPepperSource;
import com.revetsec.password.PasswordVerificationResult;
import com.revetsec.password.PasswordWorkGate;

import java.security.SecureRandom;
import java.util.Arrays;

/** A small Java 17 demonstration of local work admission and exact-version hash upgrades.
 * This volatile in-memory store is illustrative, not an application credential backend. */
public final class PasswordHashingExample {
    private PasswordHashingExample() { }

    public static void main(String[] args) {
        byte[] pepperBytes = new byte[32];
        new SecureRandom().nextBytes(pepperBytes);
        PasswordPepperKey pepper;
        try {
            pepper = PasswordPepperKey.fromBytes("example-key-1", pepperBytes);
        } finally {
            Arrays.fill(pepperBytes, (byte) 0);
        }

        PasswordPepperSource pepperSource = PasswordPepperSource.fromSnapshot(
                PasswordPepperSnapshot.withActiveKey(pepper).build());
        PasswordWorkGate workGate = PasswordWorkGate.withLimits(2, 131_072);
        PasswordHasher previousPolicy = PasswordHasher
                .withArgon2id(Argon2idParameters.withCosts(19_456, 2, 1))
                .workGate(workGate)
                .pepperSource(pepperSource)
                .build();
        PasswordHasher currentPolicy = PasswordHasher
                .withArgon2id(Argon2idParameters.withCosts(65_536, 3, 4))
                .workGate(workGate)
                .pepperSource(pepperSource)
                .build();

        CredentialStore credentialStore = new CredentialStore();
        char[] submittedPassword = "synthetic demo password".toCharArray();
        try {
            String original = requireHash(previousPolicy.hashResult(submittedPassword));
            if (!credentialStore.compareAndSet(0, original))
                throw new IllegalStateException("Initial credential write was not confirmed");

            CredentialSnapshot selected = credentialStore.read();
            PasswordVerificationResult verification = currentPolicy.verifyResult(
                    submittedPassword, selected.storedForm());
            if (!(verification instanceof PasswordVerificationResult.Matched matched))
                throw new IllegalStateException("The synthetic password did not verify");

            if (matched.isRehashRecommended()) {
                String upgraded = requireHash(currentPolicy.hashResult(submittedPassword));
                // A concurrent password change wins; never overwrite its newer version.
                credentialStore.compareAndSet(selected.version(), upgraded);
            }

            CredentialSnapshot current = credentialStore.read();
            if (!(currentPolicy.verifyResult(submittedPassword, current.storedForm())
                    instanceof PasswordVerificationResult.Matched verified)
                    || verified.isRehashRecommended()) {
                throw new IllegalStateException("The credential was not upgraded");
            }
            // A real app rechecks account state, admission, MFA, and this credential
            // generation in its session-creation transaction before granting access.
            System.out.println("Synthetic password verified and hash upgraded");
        } finally {
            Arrays.fill(submittedPassword, '\0');
        }
    }

    private static String requireHash(PasswordHashResult result) {
        if (result instanceof PasswordHashResult.Succeeded success)
            return success.getPasswordHash().getStoredForm();
        throw new IllegalStateException("Password work could not complete");
    }

    private record CredentialSnapshot(long version, String storedForm) { }

    private static final class CredentialStore {
        private long version;
        private String storedForm;

        synchronized CredentialSnapshot read() {
            return new CredentialSnapshot(version, storedForm);
        }

        synchronized boolean compareAndSet(long expectedVersion, String replacement) {
            if (version != expectedVersion) return false;
            storedForm = replacement;
            version++;
            return true;
        }
    }
}
