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

import com.revetsec.totp.TotpRecoveryContext;
import com.revetsec.totp.TotpStoreKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.LockSupport;

import static java.util.Objects.requireNonNull;

/**
 * Test-only, one-host recovery controller. Its marker lives outside the restorable database.
 * Closing admission atomically replaces the marker before waiting for an exclusive OS lock to
 * drain all live permits. The returned lease keeps writers drained during the SQL restore. After
 * writing a fresh, never-before-used fixture epoch, release the lease, explicitly initialize the
 * namespace, confirm that result and only then open ordinary admission. A production controller
 * must replace these local files with independently durable cross-host coordination.
 */
@ThreadSafe
final class TotpFixtureRecoveryController {
    private static final @NonNull String MAGIC = "REVETSEC-TOTP-FIXTURE-1";
    private static final int MAX_MARKER_BYTES = 32_768;
    private static final long OPERATION_OFFSET = 1L;
    private static final long OPERATION_LENGTH = Long.MAX_VALUE - 1L;

    private final @NonNull Path markerFile;
    private final @NonNull Path lockFile;

    TotpFixtureRecoveryController(@NonNull Path markerFile, @NonNull Path lockFile) {
        this.markerFile = requireNonNull(markerFile).toAbsolutePath().normalize();
        this.lockFile = requireNonNull(lockFile).toAbsolutePath().normalize();
        if (this.markerFile.equals(this.lockFile)) throw new IllegalArgumentException("Fixture paths overlap");
    }

    /** Creates the first closed-to-traffic generation; only explicit initialization is admitted. */
    void provisionFresh(@NonNull String namespace, @NonNull String epoch,
            @NonNull String activeKeyId,
            @NonNull Map<@NonNull String, @NonNull String> openingKeysBase64) throws IOException {
        try (ControlLock control = ControlLock.open(this.lockFile)) {
            long deadline = deadline(Duration.ofSeconds(20));
            control.acquireAdmin(deadline);
            control.acquireOperations(deadline);
            if (Files.exists(this.markerFile))
                throw new IllegalStateException("TOTP fixture epoch already provisioned");
            replaceMarker(this.markerFile, new Marker(Mode.INITIALIZING, namespace, epoch,
                    activeKeyId, digestKeys(openingKeysBase64), Set.of()));
        }
    }

    /**
     * Makes CLOSED durable before draining live permits. Failure leaves admission closed. Keep
     * the returned lease open during the database restore.
     */
    @NonNull RestoreLease closeAndDrain(@NonNull Duration budget) throws IOException {
        long deadline = deadline(budget);
        ControlLock control = ControlLock.open(this.lockFile);
        boolean transferred = false;
        try {
            control.acquireAdmin(deadline);
            Marker old = readMarker(this.markerFile);
            replaceMarker(this.markerFile, old.withMode(Mode.CLOSED));
            control.acquireOperations(deadline);
            RestoreLease lease = new RestoreLease(control, old);
            transferred = true;
            return lease;
        } finally {
            if (!transferred) control.close();
        }
    }

    /** Opens ordinary operations only after the caller has confirmed namespace initialization. */
    void openOrdinary(@NonNull String namespace, @NonNull String epoch,
            @NonNull Duration budget) throws IOException {
        try (ControlLock control = ControlLock.open(this.lockFile)) {
            long deadline = deadline(budget);
            control.acquireAdmin(deadline);
            control.acquireOperations(deadline);
            Marker marker = readMarker(this.markerFile);
            if (marker.mode() != Mode.INITIALIZING || !marker.namespace().equals(namespace)
                    || !marker.epoch().equals(epoch))
                throw new IllegalStateException("TOTP fixture epoch is not awaiting initialization");
            replaceMarker(this.markerFile, marker.withMode(Mode.OPEN));
        }
    }

    /** An exclusive, caller-thread restore lease. */
    @NotThreadSafe
    final class RestoreLease implements AutoCloseable {
        private final @NonNull ControlLock control;
        private final @NonNull Marker old;
        private final @NonNull Thread owner = Thread.currentThread();
        private boolean transitioned;
        private boolean closed;

        private RestoreLease(@NonNull ControlLock control, @NonNull Marker old) {
            this.control = control;
            this.old = old;
        }

        /** Writes INITIALIZING after the restore, while the exclusive drain lock is still held. */
        void beginFreshEpoch(@NonNull String namespace, @NonNull String newEpoch,
                @NonNull String activeKeyId,
                @NonNull Map<@NonNull String, @NonNull String> openingKeysBase64) throws IOException {
            checkOwner();
            if (this.closed || this.transitioned) throw new IllegalStateException("Restore lease is closed");
            if (!this.old.namespace().equals(namespace) || this.old.epoch().equals(newEpoch)
                    || this.old.retiredEpochs().contains(newEpoch))
                throw new IllegalArgumentException("Fixture recovery epoch must be fresh");
            Set<String> retired = new HashSet<>(this.old.retiredEpochs());
            retired.add(this.old.epoch());
            replaceMarker(markerFile, new Marker(Mode.INITIALIZING, namespace, newEpoch,
                    activeKeyId, digestKeys(openingKeysBase64), retired));
            this.transitioned = true;
        }

        /** Reopens the same epoch with a changed keyring only while ordinary operations are drained. */
        void changeOpeningKeys(@NonNull String activeKeyId,
                @NonNull Map<@NonNull String, @NonNull String> openingKeysBase64) throws IOException {
            checkOwner();
            if (this.closed || this.transitioned || this.old.mode() != Mode.OPEN)
                throw new IllegalStateException("Fixture key transition requires a drained open epoch");
            replaceMarker(markerFile, new Marker(Mode.OPEN, this.old.namespace(), this.old.epoch(),
                    activeKeyId, digestKeys(openingKeysBase64), this.old.retiredEpochs()));
            this.transitioned = true;
        }

        private void checkOwner() {
            if (Thread.currentThread() != this.owner)
                throw new IllegalStateException("Restore lease belongs to another thread");
        }

        @Override public void close() throws IOException {
            checkOwner();
            if (this.closed) return;
            this.closed = true;
            this.control.close();
        }
    }

    private enum Mode { CLOSED, INITIALIZING, OPEN }

    /** Canonical external marker with no plaintext sealing key material. */
    @Immutable
    static record Marker(@NonNull Mode mode, @NonNull String namespace, @NonNull String epoch,
            @NonNull String activeKeyId,
            @NonNull Map<@NonNull String, @NonNull String> keyDigests,
            @NonNull Set<@NonNull String> retiredEpochs) {
        Marker {
            requireNonNull(mode);
            TotpStoreKey.forNamespace(namespace, epoch);
            validateKeyId(activeKeyId);
            keyDigests = Map.copyOf(keyDigests);
            if (keyDigests.isEmpty() || keyDigests.size() > 17
                    || !keyDigests.containsKey(activeKeyId))
                throw new IllegalArgumentException("Invalid fixture sealing-key set");
            for (Map.Entry<String, String> entry : keyDigests.entrySet()) {
                validateKeyId(entry.getKey());
                validateDigest(entry.getValue());
            }
            retiredEpochs = Set.copyOf(retiredEpochs);
            if (retiredEpochs.size() > 128 || retiredEpochs.contains(epoch))
                throw new IllegalArgumentException("Invalid fixture epoch history");
            for (String retired : retiredEpochs) TotpStoreKey.forNamespace(namespace, retired);
        }

        @NonNull Marker withMode(@NonNull Mode newMode) {
            return new Marker(newMode, this.namespace, this.epoch, this.activeKeyId,
                    this.keyDigests, this.retiredEpochs);
        }

        boolean matches(@NonNull TotpRecoveryContext context,
                @NonNull Map<@NonNull String, @NonNull String> expectedDigests) {
            return ((this.mode == Mode.INITIALIZING
                    && context.getPurpose() == TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE)
                    || (this.mode == Mode.OPEN
                    && context.getPurpose() == TotpRecoveryContext.Purpose.OPERATION))
                    && this.namespace.equals(context.getCredentialNamespace())
                    && this.epoch.equals(context.getRecoveryEpoch())
                    && this.activeKeyId.equals(context.getActiveSealingKeyId())
                    && this.keyDigests.keySet().equals(context.getOpeningSealingKeyIds())
                    && this.keyDigests.equals(expectedDigests);
        }

        /** Same external admission fence for an application session transaction. */
        boolean matchesApplicationOperation(@NonNull String expectedNamespace,
                @NonNull String expectedEpoch, @NonNull String expectedActiveKeyId,
                @NonNull Set<@NonNull String> expectedOpeningKeyIds,
                @NonNull Map<@NonNull String, @NonNull String> expectedDigests) {
            return this.mode == Mode.OPEN && this.namespace.equals(expectedNamespace)
                    && this.epoch.equals(expectedEpoch)
                    && this.activeKeyId.equals(expectedActiveKeyId)
                    && this.keyDigests.keySet().equals(expectedOpeningKeyIds)
                    && this.keyDigests.equals(expectedDigests);
        }
    }

    static @NonNull Map<@NonNull String, @NonNull String> digestKeys(
            @NonNull Map<@NonNull String, @NonNull String> openingKeysBase64) {
        requireNonNull(openingKeysBase64);
        if (openingKeysBase64.isEmpty() || openingKeysBase64.size() > 17)
            throw new IllegalArgumentException("Invalid fixture sealing-key set");
        Map<String, String> digests = new HashMap<>();
        for (Map.Entry<String, String> entry : openingKeysBase64.entrySet()) {
            validateKeyId(entry.getKey());
            byte[] material = Base64.getDecoder().decode(requireNonNull(entry.getValue()));
            try {
                if (material.length != 32)
                    throw new IllegalArgumentException("Invalid fixture sealing key");
                String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(material));
                digests.put(entry.getKey(), digest);
            } catch (NoSuchAlgorithmException impossible) {
                throw new IllegalStateException(impossible);
            } finally {
                java.util.Arrays.fill(material, (byte) 0);
            }
        }
        return Map.copyOf(digests);
    }

    private static void validateKeyId(@NonNull String id) {
        requireNonNull(id);
        if (id.isEmpty() || id.length() > 128) throw new IllegalArgumentException("Invalid fixture key ID");
        for (int index = 0; index < id.length(); index++) {
            if (id.charAt(index) < 0x21 || id.charAt(index) > 0x7e)
                throw new IllegalArgumentException("Invalid fixture key ID");
        }
    }

    private static void validateDigest(@NonNull String digest) {
        requireNonNull(digest);
        if (digest.length() != 43) throw new IllegalArgumentException("Invalid fixture key digest");
        byte[] decoded = Base64.getUrlDecoder().decode(digest);
        if (decoded.length != 32 || !Base64.getUrlEncoder().withoutPadding()
                .encodeToString(decoded).equals(digest))
            throw new IllegalArgumentException("Invalid fixture key digest");
    }

    static @NonNull Marker readMarker(@NonNull Path markerFile) throws IOException {
        byte[] bytes;
        try (InputStream input = Files.newInputStream(markerFile)) {
            bytes = input.readNBytes(MAX_MARKER_BYTES + 1);
        }
        if (bytes.length == 0 || bytes.length > MAX_MARKER_BYTES)
            throw new IOException("Invalid fixture recovery marker");
        for (byte value : bytes) if (value < 0 || value > 0x7f)
            throw new IOException("Invalid fixture recovery marker");
        String source = new String(bytes, StandardCharsets.US_ASCII);
        try {
            String[] lines = source.split("\\n", -1);
            if (lines.length < 8 || !MAGIC.equals(lines[0]) || !lines[lines.length - 1].isEmpty())
                throw new IllegalArgumentException("Invalid fixture marker header");
            int cursor = 1;
            Mode mode = Mode.valueOf(lines[cursor++]);
            String namespace = decode(lines[cursor++]);
            String epoch = decode(lines[cursor++]);
            String active = decode(lines[cursor++]);
            int keyCount = Integer.parseInt(lines[cursor++]);
            if (keyCount < 1 || keyCount > 17 || cursor + keyCount >= lines.length)
                throw new IllegalArgumentException("Invalid fixture key count");
            Map<String, String> keys = new HashMap<>();
            for (int index = 0; index < keyCount; index++) {
                String[] parts = lines[cursor++].split(":", -1);
                if (parts.length != 2 || keys.putIfAbsent(decode(parts[0]), parts[1]) != null)
                    throw new IllegalArgumentException("Invalid fixture key entry");
            }
            int retiredCount = Integer.parseInt(lines[cursor++]);
            if (retiredCount < 0 || retiredCount > 128
                    || cursor + retiredCount != lines.length - 1)
                throw new IllegalArgumentException("Invalid fixture epoch history");
            Set<String> retired = new HashSet<>();
            for (int index = 0; index < retiredCount; index++) {
                if (!retired.add(decode(lines[cursor++])))
                    throw new IllegalArgumentException("Repeated fixture recovery epoch");
            }
            Marker marker = new Marker(mode, namespace, epoch, active, keys, retired);
            if (!render(marker).equals(source)) throw new IllegalArgumentException("Noncanonical marker");
            return marker;
        } catch (RuntimeException invalid) {
            throw new IOException("Invalid fixture recovery marker", invalid);
        }
    }

    private static @NonNull String render(@NonNull Marker marker) {
        StringBuilder text = new StringBuilder(MAGIC).append('\n')
                .append(marker.mode()).append('\n')
                .append(encode(marker.namespace())).append('\n')
                .append(encode(marker.epoch())).append('\n')
                .append(encode(marker.activeKeyId())).append('\n')
                .append(marker.keyDigests().size()).append('\n');
        marker.keyDigests().keySet().stream().sorted().forEach(id -> text.append(encode(id))
                .append(':').append(marker.keyDigests().get(id)).append('\n'));
        text.append(marker.retiredEpochs().size()).append('\n');
        marker.retiredEpochs().stream().sorted().forEach(epoch ->
                text.append(encode(epoch)).append('\n'));
        return text.toString();
    }

    private static @NonNull String encode(@NonNull String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull String decode(@NonNull String value) {
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        if (!encode(decoded).equals(value)) throw new IllegalArgumentException("Noncanonical fixture field");
        return decoded;
    }

    private static void replaceMarker(@NonNull Path markerFile, @NonNull Marker marker) throws IOException {
        byte[] bytes = render(marker).getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > MAX_MARKER_BYTES) throw new IOException("Fixture marker history exhausted");
        Path parent = requireNonNull(markerFile.getParent());
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".totp-recovery-", ".tmp");
        try {
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) output.write(buffer);
                output.force(true);
            }
            try {
                Files.move(temporary, markerFile, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unavailable) {
                throw new IOException("Atomic fixture marker replacement is unavailable", unavailable);
            }
            // Directory fsync is not supported by every filesystem. The file itself is always forced.
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            } catch (IOException | UnsupportedOperationException unsupported) {
                // Test-only fixture: a production controller must require its durability guarantee.
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static long deadline(@NonNull Duration budget) {
        requireNonNull(budget);
        if (budget.isNegative() || budget.isZero())
            throw new IllegalArgumentException("Recovery controller budget must be positive");
        long nanos;
        try { nanos = Math.min(budget.toNanos(), Duration.ofMinutes(5).toNanos()); }
        catch (ArithmeticException tooLarge) { nanos = Duration.ofMinutes(5).toNanos(); }
        return System.nanoTime() + nanos;
    }

    /** Separate byte-range admin lock serializes marker transitions without blocking shared ops. */
    @NotThreadSafe
    private static final class ControlLock implements AutoCloseable {
        private final @NonNull FileChannel channel;
        private @Nullable FileLock admin;
        private @Nullable FileLock operations;
        private boolean closed;

        private ControlLock(@NonNull FileChannel channel) { this.channel = channel; }

        private static @NonNull ControlLock open(@NonNull Path path) throws IOException {
            Files.createDirectories(requireNonNull(path.getParent()));
            return new ControlLock(FileChannel.open(path, StandardOpenOption.CREATE,
                    StandardOpenOption.READ, StandardOpenOption.WRITE));
        }

        private void acquireAdmin(long deadline) throws IOException {
            this.admin = acquire(0L, 1L, deadline);
        }

        private void acquireOperations(long deadline) throws IOException {
            if (this.admin == null) throw new IllegalStateException("Admin lock is absent");
            this.operations = acquire(OPERATION_OFFSET, OPERATION_LENGTH, deadline);
        }

        private @NonNull FileLock acquire(long offset, long length, long deadline) throws IOException {
            while (deadline - System.nanoTime() > 0 && !Thread.currentThread().isInterrupted()) {
                try {
                    FileLock acquired = this.channel.tryLock(offset, length, false);
                    if (acquired != null) return acquired;
                } catch (OverlappingFileLockException busy) {
                    // Another fixture caller in this JVM owns this range.
                }
                long wait = Math.min(5_000_000L, deadline - System.nanoTime());
                if (wait > 0) LockSupport.parkNanos(wait);
            }
            if (Thread.currentThread().isInterrupted())
                throw new IOException("Interrupted while draining TOTP fixture admission");
            throw new IOException("Timed out draining TOTP fixture admission");
        }

        @Override public void close() throws IOException {
            if (this.closed) return;
            this.closed = true;
            IOException failure = null;
            try {
                if (this.operations != null) this.operations.release();
            } catch (IOException failed) { failure = failed; }
            try {
                if (this.admin != null) this.admin.release();
            } catch (IOException failed) { if (failure == null) failure = failed; else failure.addSuppressed(failed); }
            try {
                this.channel.close();
            } catch (IOException failed) { if (failure == null) failure = failed; else failure.addSuppressed(failed); }
            if (failure != null) throw failure;
        }
    }
}
