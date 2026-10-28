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

package com.revetsec.totp;

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Strict, bounded, version-and-address-authenticated permanent TOTP records. */
@ThreadSafe
final class TotpRecords {
    private static final int LEGACY_MAGIC = 0x54545231;
    private static final int MAGIC = 0x54545232;
    private final @NonNull StateSealer sealer;
    TotpRecords(@NonNull StateSealer sealer) { this.sealer = sealer; }
    @NonNull String freshId() {
        byte[] bytes = EntropySource.fromDefaults().nextBytes(32);
        try { return Base64Url.encode(bytes); } finally { Arrays.fill(bytes, (byte) 0); }
    }
    @NonNull TotpStoreRecord seal(@NonNull TotpStoreKey key, @NonNull Namespace namespace,
            @Nullable Account account) {
        String version = freshId();
        byte[] bytes;
        try (PlaintextBuffer buffer = new PlaintextBuffer();
                DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(MAGIC);
            text(out, key.getStorageKey()); text(out, version);
            if (key.getKind() == TotpStoreKey.Kind.NAMESPACE_STATE) instant(out, namespace.observedAt);
            else writeAccount(out, java.util.Objects.requireNonNull(account));
            out.flush(); bytes = buffer.toByteArray();
        } catch (IOException failure) { throw new IllegalStateException("Unable to encode record", failure); }
        try {
            if (bytes.length > 32_000) throw new IllegalArgumentException("TOTP record too large");
            String encoded = SealedStateAccess.get().sealDurable(this.sealer, Base64Url.encode(bytes), context(key));
            return TotpStoreRecord.fromStoredForm(key, version, encoded.getBytes(StandardCharsets.US_ASCII));
        } finally { Arrays.fill(bytes, (byte) 0); }
    }
    @NonNull Decoded open(@NonNull TotpStoreRecord record) throws IOException {
        byte[] raw = record.getSealedBytes();
        byte[] bytes = null;
        Account account = null;
        try {
            for (byte value : raw) if (value < 0 || !Base64Url.isAlphabet((char) value)) throw invalid();
            String sealed = new String(raw, StandardCharsets.US_ASCII);
            String text = SealedStateAccess.get().unsealDurable(this.sealer, sealed, context(record.getKey()));
            bytes = Base64Url.decode(text);
            if (bytes.length > 32_000) throw invalid();
            try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
                int magic = in.readInt();
                if ((magic != MAGIC && magic != LEGACY_MAGIC)
                        || !text(in).equals(record.getKey().getStorageKey())
                        || !text(in).equals(record.getVersion())) throw invalid();
                Namespace namespace;
                if (record.getKey().getKind() == TotpStoreKey.Kind.NAMESPACE_STATE) namespace = new Namespace(instant(in));
                else {
                    account = readAccount(in, magic == LEGACY_MAGIC);
                    if (!record.getKey().equals(TotpStoreKey.forAccount(record.getKey().getCredentialNamespace(),
                            record.getKey().getRecoveryEpoch(), account.accountId))) throw invalid();
                    namespace = new Namespace(account.observedAt);
                }
                if (in.read() != -1) throw invalid();
                byte[] wire = Base64Url.decode(sealed);
                String keyId;
                try { keyId = new String(wire, 2, wire[1] & 255, StandardCharsets.US_ASCII); }
                finally { Arrays.fill(wire, (byte) 0); }
                Decoded decoded = new Decoded(namespace, account, keyId);
                account = null;
                return decoded;
            }
        } catch (UnsealException | EncodingException | RuntimeException failure) { throw invalid(); }
        finally {
            Arrays.fill(raw, (byte) 0);
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
            if (account != null) account.erase();
        }
    }
    private static @NonNull String context(@NonNull TotpStoreKey key) {
        byte[] hash = TotpPrimitives.digest("revetsec/totp/address/v1", key.getStorageKey());
        try { return "revetsec/totp/durable/v1:" + Base64Url.encode(hash); }
        finally { Arrays.fill(hash, (byte) 0); }
    }
    private static void writeAccount(@NonNull DataOutputStream out, @NonNull Account account) throws IOException {
        text(out, account.accountId); text(out, account.fence); instant(out, account.observedAt);
        out.writeBoolean(account.active != null);
        Active active = account.active;
        if (active != null) {
            text(out, active.factorId); blob(out, active.secret); instant(out, active.enrolledAt); out.writeLong(active.usedStep);
        }
        out.writeBoolean(account.pending != null);
        Pending pending = account.pending;
        if (pending != null) {
            text(out, pending.enrollmentId); text(out, pending.factorId); blob(out, pending.secret);
            blob(out, pending.browserHash); instant(out, pending.expiresAt);
            text(out, pending.expectedFactorId == null ? "" : pending.expectedFactorId);
        }
        text(out, account.batchId == null ? "" : account.batchId);
        out.writeInt(account.recoveryHashes.size());
        for (byte[] hash : account.recoveryHashes) blob(out, hash);
        out.writeInt(account.charges.size());
        for (Charge charge : account.charges) { text(out, charge.id); instant(out, charge.at); }
        out.writeInt(account.totpCharges.size());
        for (Charge charge : account.totpCharges) { text(out, charge.id); instant(out, charge.at); }
    }
    private static @NonNull Account readAccount(@NonNull DataInputStream in, boolean legacy) throws IOException {
        Account account = new Account(text(in), identifier(in), instant(in));
        boolean accepted = false;
        try {
            if (flag(in)) {
                String factorId = identifier(in);
                byte[] secret = blob(in, 20);
                boolean transferred = false;
                try {
                    Instant enrolled = instant(in);
                    long used = in.readLong();
                    if (used < 0) throw invalid();
                    account.active = new Active(factorId, secret, enrolled, used);
                    transferred = true;
                } finally { if (!transferred) Arrays.fill(secret, (byte) 0); }
            }
            if (flag(in)) {
                String id = identifier(in); String factor = identifier(in);
                byte[] secret = blob(in, 20);
                byte @Nullable [] browser = null;
                boolean transferred = false;
                try {
                    browser = blob(in, 32);
                    Instant expires = instant(in); String expected = text(in);
                    if (!expected.isEmpty()) requireIdentifier(expected);
                    account.pending = new Pending(id, factor, secret, browser, expires, expected.isEmpty() ? null : expected);
                    transferred = true;
                } finally {
                    if (!transferred) {
                        Arrays.fill(secret, (byte) 0);
                        if (browser != null) Arrays.fill(browser, (byte) 0);
                    }
                }
            }
            String batch = text(in);
            if (!batch.isEmpty()) { requireIdentifier(batch); account.batchId = batch; }
            int hashes = count(in, 10);
            for (int i = 0; i < hashes; i++) account.recoveryHashes.add(blob(in, 32));
            int charges = count(in, 5);
            for (int i = 0; i < charges; i++) {
                String id = identifier(in); Instant at = instant(in);
                if (at.isAfter(account.observedAt)) throw invalid();
                for (Charge previous : account.charges) if (previous.id.equals(id)) throw invalid();
                account.charges.add(new Charge(id, at));
            }
            if (legacy) {
                // A format upgrade must not silently forgive currently charged attempts.
                for (Charge charge : account.charges) account.totpCharges.add(new Charge(charge.id, charge.at));
            } else {
                int totpCharges = count(in, 10);
                for (int i = 0; i < totpCharges; i++) {
                    String id = identifier(in); Instant at = instant(in);
                    if (at.isAfter(account.observedAt)) throw invalid();
                    for (Charge previous : account.totpCharges) if (previous.id.equals(id)) throw invalid();
                    account.totpCharges.add(new Charge(id, at));
                }
            }
            if ((account.active == null && (account.batchId != null || hashes != 0))
                    || (account.active != null && account.batchId == null)) throw invalid();
            accepted = true; return account;
        } finally { if (!accepted) account.erase(); }
    }
    private static boolean flag(@NonNull DataInputStream in) throws IOException {
        int value = in.readUnsignedByte(); if (value > 1) throw invalid(); return value == 1;
    }
    private static int count(@NonNull DataInputStream in, int maximum) throws IOException {
        int value = in.readInt(); if (value < 0 || value > maximum) throw invalid(); return value;
    }
    private static @NonNull String identifier(@NonNull DataInputStream in) throws IOException {
        String value = text(in); requireIdentifier(value); return value;
    }
    private static void requireIdentifier(@NonNull String value) throws IOException {
        try { if (value.length() != 43 || Base64Url.decode(value).length != 32) throw invalid(); }
        catch (EncodingException failure) { throw invalid(); }
    }
    private static void text(@NonNull DataOutputStream out, @NonNull String value) throws IOException {
        byte[] bytes;
        try { bytes = StrictUtf8.encode(value); } catch (EncodingException failure) { throw invalid(); }
        try { if (bytes.length > 4096) throw invalid(); out.writeInt(bytes.length); out.write(bytes); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }
    private static @NonNull String text(@NonNull DataInputStream in) throws IOException {
        int length = count(in, 4096); if (length > in.available()) throw invalid();
        byte[] bytes = in.readNBytes(length);
        try { return StrictUtf8.decode(bytes); } catch (EncodingException failure) { throw invalid(); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }
    private static void blob(@NonNull DataOutputStream out, byte @NonNull [] bytes) throws IOException {
        out.writeInt(bytes.length); out.write(bytes);
    }
    private static byte @NonNull [] blob(@NonNull DataInputStream in, int length) throws IOException {
        if (in.readInt() != length || length > in.available()) throw invalid(); return in.readNBytes(length);
    }
    private static void instant(@NonNull DataOutputStream out, @NonNull Instant value) throws IOException {
        out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano());
    }
    private static @NonNull Instant instant(@NonNull DataInputStream in) throws IOException {
        long seconds = in.readLong(); int nanos = in.readInt();
        if (seconds < 0 || seconds > 253_402_300_799L || nanos < 0 || nanos > 999_999_999) throw invalid();
        return Instant.ofEpochSecond(seconds, nanos);
    }
    private static @NonNull IOException invalid() { return new IOException("Invalid TOTP stored state"); }

    @NotThreadSafe private static final class PlaintextBuffer extends ByteArrayOutputStream {
        @Override public void close() { Arrays.fill(this.buf, (byte) 0); reset(); }
        @Override public @NonNull String toString() { return "PlaintextBuffer{<redacted>}"; }
    }
    @NotThreadSafe static final class Namespace {
        @NonNull Instant observedAt;
        Namespace(@NonNull Instant observedAt) { this.observedAt = observedAt; }
    }
    @NotThreadSafe static final class Account {
        final @NonNull String accountId;
        @NonNull String fence;
        @NonNull Instant observedAt;
        @Nullable Active active;
        @Nullable Pending pending;
        @Nullable String batchId;
        final @NonNull List<byte @NonNull []> recoveryHashes = new ArrayList<>();
        final @NonNull List<@NonNull Charge> charges = new ArrayList<>();
        final @NonNull List<@NonNull Charge> totpCharges = new ArrayList<>();
        Account(@NonNull String accountId, @NonNull String fence, @NonNull Instant observedAt) {
            this.accountId = accountId; this.fence = fence; this.observedAt = observedAt;
        }
        void erase() {
            Active a = this.active; if (a != null) Arrays.fill(a.secret, (byte) 0);
            Pending p = this.pending; if (p != null) { Arrays.fill(p.secret, (byte) 0); Arrays.fill(p.browserHash, (byte) 0); }
            for (byte[] hash : this.recoveryHashes) Arrays.fill(hash, (byte) 0);
        }
    }
    @NotThreadSafe static final class Active {
        final @NonNull String factorId;
        final byte @NonNull [] secret;
        final @NonNull Instant enrolledAt;
        long usedStep;
        Active(@NonNull String factorId, byte @NonNull [] secret, @NonNull Instant enrolledAt, long usedStep) {
            this.factorId = factorId; this.secret = secret; this.enrolledAt = enrolledAt; this.usedStep = usedStep;
        }
    }
    @NotThreadSafe static final class Pending {
        final @NonNull String enrollmentId;
        final @NonNull String factorId;
        final byte @NonNull [] secret;
        final byte @NonNull [] browserHash;
        final @NonNull Instant expiresAt;
        final @Nullable String expectedFactorId;
        Pending(@NonNull String enrollmentId, @NonNull String factorId, byte @NonNull [] secret,
                byte @NonNull [] browserHash, @NonNull Instant expiresAt, @Nullable String expectedFactorId) {
            this.enrollmentId = enrollmentId; this.factorId = factorId; this.secret = secret;
            this.browserHash = browserHash; this.expiresAt = expiresAt; this.expectedFactorId = expectedFactorId;
        }
    }
    @NotThreadSafe static final class Charge {
        final @NonNull String id;
        final @NonNull Instant at;
        Charge(@NonNull String id, @NonNull Instant at) { this.id = id; this.at = at; }
    }
    @NotThreadSafe static final class Decoded implements AutoCloseable {
        final @NonNull Namespace namespace;
        final @Nullable Account account;
        final @NonNull String keyId;
        Decoded(@NonNull Namespace namespace, @Nullable Account account, @NonNull String keyId) {
            this.namespace = namespace; this.account = account; this.keyId = keyId;
        }
        @Override public void close() { Account a = this.account; if (a != null) a.erase(); }
    }
}
