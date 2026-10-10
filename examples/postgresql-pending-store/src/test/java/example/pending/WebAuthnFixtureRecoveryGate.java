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

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Test-only one-host restore barrier. The control file is outside the restored PostgreSQL
 * database. A shared OS lock spans each RP operation; the runner takes its exclusive counterpart
 * to drain permits before changing the marker or restoring the database. Deployments need their
 * own independently durable, cross-host marker, admission lock and key lifecycle.
 */
@ThreadSafe
final class WebAuthnFixtureRecoveryGate implements WebAuthnRecoveryGate {
    /** One row mapped by Pyranid. */
    public record Marker(@NonNull String epoch, @NonNull String sealerDigest) { }

    private final @NonNull String namespace;
    private final @NonNull Path markerFile;
    private final @NonNull Path lockFile;
    private final @NonNull String expectedSealerDigest;
    private final @NonNull ThreadLocal<@NonNull Admission> active = new ThreadLocal<>();

    WebAuthnFixtureRecoveryGate(@NonNull String namespace, @NonNull Path markerFile,
            @NonNull Path lockFile, @NonNull String base64SealingKey) {
        this.namespace = requireNonNull(namespace);
        this.markerFile = requireNonNull(markerFile);
        this.lockFile = requireNonNull(lockFile);
        try {
            byte[] material = Base64.getDecoder().decode(requireNonNull(base64SealingKey));
            if (material.length != 32) throw new IllegalArgumentException("Invalid fixture sealing key");
            this.expectedSealerDigest = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(material));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }

    @Override public @Nullable Permit acquire(@NonNull Duration remainingBudget) {
        requireNonNull(remainingBudget);
        if (remainingBudget.isZero() || remainingBudget.isNegative() || Thread.currentThread().isInterrupted())
            return null;
        Admission existing = this.active.get();
        if (existing != null) {
            if (!existing.isCurrent()) return null;
            existing.retain();
            return existing;
        }
        long deadline = System.nanoTime() + remainingBudget.toNanos();
        FileChannel channel = null;
        FileLock lock = null;
        try {
            channel = FileChannel.open(this.lockFile, StandardOpenOption.READ, StandardOpenOption.WRITE);
            lock = channel.tryLock(0L, Long.MAX_VALUE, true);
            if (lock == null || !current(deadline)) return null;
            Admission admitted = new Admission(channel, lock, deadline);
            this.active.set(admitted);
            channel = null;
            lock = null;
            return admitted;
        } catch (IOException | RuntimeException failure) {
            return null;
        } finally {
            if (lock != null) {
                try { lock.release(); } catch (IOException ignored) { }
            }
            if (channel != null) {
                try { channel.close(); } catch (IOException ignored) { }
            }
        }
    }

    private boolean current(long deadline) {
        if (deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted()) return false;
        try {
            if (Files.size(this.markerFile) > 200) return false;
            String external = Files.readString(this.markerFile, StandardCharsets.US_ASCII);
            String[] fields = external.split("\\n", -1);
            if (fields.length != 3 || !fields[2].isEmpty() || fields[0].length() != 43
                    || !fields[1].equals(this.expectedSealerDigest)) return false;
            long nanos = deadline - System.nanoTime();
            if (nanos <= 0) return false;
            Database database = Database.withDataSource(new PostgresqlPyranidDataSource(
                    WebAuthnStoreProbe::connection, deadline)).databaseType(DatabaseType.POSTGRESQL).build();
            Optional<Marker> row = database.query("SELECT epoch,sealer_digest FROM webauthn_recovery_epoch "
                    + "WHERE namespace=:namespace")
                    .bind("namespace", this.namespace).fetchObject(Marker.class);
            return deadline - System.nanoTime() > 0 && row.isPresent()
                    && fields[0].equals(row.orElseThrow().epoch())
                    && fields[1].equals(row.orElseThrow().sealerDigest());
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private final class Admission implements Permit {
        private final @NonNull FileChannel channel;
        private final @NonNull FileLock lock;
        private final long deadline;
        private boolean closed;
        private int depth = 1;

        private Admission(@NonNull FileChannel channel, @NonNull FileLock lock, long deadline) {
            this.channel = channel;
            this.lock = lock;
            this.deadline = deadline;
        }

        @Override public boolean isCurrent() {
            return !this.closed && this.lock.isValid() && current(this.deadline);
        }

        private void retain() { this.depth++; }

        @Override public void close() {
            if (this.closed) return;
            if (--this.depth > 0) return;
            this.closed = true;
            active.remove();
            try {
                this.lock.release();
            } catch (IOException failure) {
                throw new IllegalStateException("Could not release fixture recovery permit", failure);
            } finally {
                try { this.channel.close(); } catch (IOException failure) {
                    throw new IllegalStateException("Could not close fixture recovery permit", failure);
                }
            }
        }
    }
}
