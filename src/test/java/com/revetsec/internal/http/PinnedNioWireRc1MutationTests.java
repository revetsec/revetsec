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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.lang.reflect.Constructor;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/** Private wire wait progress with an owned in-memory selector and no connected socket. */
final class PinnedNioWireRc1MutationTests {
    @Test
    void interruptionAtEntryPreventsSelectorWork() throws Exception {
        try (Fixture fixture = fixture()) {
            // Warm guarded classes before interrupting: PIT may perform class-loader I/O on first use.
            PinnedHttpsTransport.checkBudget(Deadline.fromNow(Duration.ofSeconds(10)));
            assertEquals(HttpExchangeException.Kind.INTERRUPTED,
                    new HttpExchangeException(HttpExchangeException.Kind.INTERRUPTED).getKind());
            HttpExchangeException observed = null;
            try {
                Thread.currentThread().interrupt();
                fixture.wire.await(SelectionKey.OP_READ);
            } catch (HttpExchangeException failure) { observed = failure; }
            finally { Thread.interrupted(); }
            assertEquals(HttpExchangeException.Kind.INTERRUPTED,
                    java.util.Objects.requireNonNull(observed).getKind());
            assertEquals(0, fixture.key.interestCalls);
            assertEquals(0, fixture.selector.selectCalls);
        }
    }

    @Test
    void interruptionDuringSelectionIsReportedBeforeReturn() throws Exception {
        try (Fixture fixture = fixture()) {
            fixture.selector.afterSelect = () -> Thread.currentThread().interrupt();
            try {
                HttpExchangeException failure = assertThrows(HttpExchangeException.class,
                        () -> fixture.wire.await(SelectionKey.OP_READ));
                assertEquals(HttpExchangeException.Kind.INTERRUPTED, failure.getKind());
                assertEquals(1, fixture.selector.selectCalls);
            } finally { Thread.interrupted(); }
        }
    }

    @Test
    void completedSelectionConsumesPreviouslySelectedKeys() throws Exception {
        try (Fixture fixture = fixture()) {
            fixture.selector.selected.add(fixture.key);
            fixture.wire.await(SelectionKey.OP_READ);
            assertTrue(fixture.selector.selected.isEmpty());
            assertEquals(1, fixture.selector.selectCalls);
            assertTrue(fixture.selector.timeoutMillis > 0);
        }
    }

    @Test
    void closingReleasesBothOwnedResourcesOnce() throws Exception {
        try (Fixture fixture = fixture()) {
            assertTrue(fixture.key.channel.isOpen());
            assertTrue(fixture.selector.isOpen());
            fixture.wire.close();
            assertFalse(fixture.key.channel.isOpen());
            assertFalse(fixture.selector.isOpen());
            fixture.wire.close();
            assertEquals(1, fixture.selector.closeCalls);
        }
    }

    @Test
    void readsAndWritesPreserveByteCountsAndContent() {
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
            try (ServerSocketChannel listener = ServerSocketChannel.open()) {
                listener.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0));
                try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
                     SocketChannel peer = listener.accept(); Fixture fixture = fixture(client)) {
                    assertEquals(1, peer.write(ByteBuffer.wrap(new byte[] {42})));
                    ByteBuffer inbound = ByteBuffer.allocate(1);
                    assertEquals(1, fixture.wire.read(inbound));
                    assertEquals(42, inbound.get(0));
                    assertEquals(1, fixture.wire.write(ByteBuffer.wrap(new byte[] {53})));
                    ByteBuffer received = ByteBuffer.allocate(1);
                    assertEquals(1, peer.read(received));
                    assertEquals(53, received.get(0));
                }
            }
        });
    }

    private static @NonNull Fixture fixture() throws Exception {
        return fixture(SocketChannel.open());
    }

    private static @NonNull Fixture fixture(@NonNull SocketChannel channel) throws Exception {
        RecordingSelector selector = new RecordingSelector();
        try {
            RecordingKey key = new RecordingKey(channel, selector);
            selector.registered.add(key);
            Constructor<?> constructor = Class.forName("com.revetsec.internal.http.PinnedHttpsTransport$NioWire")
                    .getDeclaredConstructor(SocketChannel.class, Selector.class, SelectionKey.class, Deadline.class);
            constructor.setAccessible(true);
            PinnedTlsChannel.Wire wire = (PinnedTlsChannel.Wire) constructor.newInstance(channel, selector, key,
                    Deadline.fromNow(Duration.ofSeconds(10)));
            return new Fixture(wire, selector, key);
        } catch (Exception | Error failure) { channel.close(); throw failure; }
    }

    private record Fixture(PinnedTlsChannel.@NonNull Wire wire, @NonNull RecordingSelector selector,
                           @NonNull RecordingKey key) implements AutoCloseable {
        @Override public void close() throws IOException {
            try { this.wire.close(); }
            finally { try { this.key.channel.close(); } finally { this.selector.close(); } }
        }
    }

    private static final class RecordingSelector extends Selector {
        private final @NonNull Set<@NonNull SelectionKey> registered = new HashSet<>();
        private final @NonNull Set<@NonNull SelectionKey> selected = new HashSet<>();
        private @NonNull Runnable afterSelect = () -> {};
        private int selectCalls;
        private int closeCalls;
        private long timeoutMillis;
        private boolean open = true;
        @Override public boolean isOpen() { return this.open; }
        @Override public @NonNull SelectorProvider provider() { return SelectorProvider.provider(); }
        @Override public @NonNull Set<@NonNull SelectionKey> keys() { return Set.copyOf(this.registered); }
        @Override public @NonNull Set<@NonNull SelectionKey> selectedKeys() { return this.selected; }
        @Override public int selectNow() { return 0; }
        @Override public int select(long timeout) {
            this.selectCalls++; this.timeoutMillis = timeout; this.afterSelect.run(); return 0;
        }
        @Override public int select() { return select(0); }
        @Override public @NonNull Selector wakeup() { return this; }
        @Override public void close() { this.closeCalls++; this.open = false; }
    }

    private static final class RecordingKey extends SelectionKey {
        private final @NonNull SocketChannel channel;
        private final @NonNull RecordingSelector selector;
        private int interestCalls;
        private int interests;
        private boolean valid = true;
        private RecordingKey(@NonNull SocketChannel channel, @NonNull RecordingSelector selector) {
            this.channel = channel; this.selector = selector;
        }
        @Override public @NonNull SelectableChannel channel() { return this.channel; }
        @Override public @NonNull Selector selector() { return this.selector; }
        @Override public boolean isValid() { return this.valid; }
        @Override public void cancel() { this.valid = false; }
        @Override public int interestOps() { return this.interests; }
        @Override public @NonNull SelectionKey interestOps(int operations) {
            this.interestCalls++; this.interests = operations; return this;
        }
        @Override public int readyOps() { return SelectionKey.OP_READ; }
    }
}
