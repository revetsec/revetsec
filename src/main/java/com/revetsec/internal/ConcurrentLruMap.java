/*
 * Copyright 2022-2026 Revetware LLC.
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

package com.revetsec.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import java.util.AbstractCollection;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * A high-performance thread-safe approximate LRU {@link Map} using buffered access recording.
 * <p>
 * Design notes:
 * <ul>
 *   <li>Reads record access into a lossy ring buffer.</li>
 *   <li>Writes enqueue lossless tasks.</li>
 *   <li>Maintenance drains buffers, updates an intrusive doubly-linked list, and evicts.</li>
 * </ul>
 * <p>
 * LRU ordering is approximate under high contention (read events may be overwritten).
 *
 * @param <K> key type
 * @param <V> value type
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class ConcurrentLruMap<@NonNull K, @NonNull V> implements Map<@NonNull K, @NonNull V> {

	// ===================================================================================
	// Configuration
	// ===================================================================================

	/**
	 * Size of the read buffer.
	 * Must be a power of two (masking is used).
	 */
	private static final int READ_BUFFER_SIZE = 64;

	/**
	 * Number of pending write tasks that triggers maintenance.
	 */
	private static final int WRITE_BUFFER_DRAIN_THRESHOLD = 16;

	private static final int READ_BUFFER_MASK = READ_BUFFER_SIZE - 1;

	static {
		if (Integer.bitCount(READ_BUFFER_SIZE) != 1)
			throw new ExceptionInInitializerError("READ_BUFFER_SIZE must be a power of two");
		if (WRITE_BUFFER_DRAIN_THRESHOLD <= 0)
			throw new ExceptionInInitializerError("WRITE_BUFFER_DRAIN_THRESHOLD must be > 0");
	}

	// ===================================================================================
	// Core State
	// ===================================================================================

	private final int capacity;
	private final ConcurrentHashMap<K, Node<@NonNull K, @NonNull V>> map;
	private final BiConsumer<@NonNull K, @NonNull V> evictionListener;

	// ===================================================================================
	// LRU Tracking (Intrusive Doubly-Linked List)
	// ===================================================================================

	/**
	 * Sentinel head; head.next is MRU.
	 */
	@GuardedBy("maintenanceLock")
	private final Node<@NonNull K, @NonNull V> head;

	/**
	 * Sentinel tail; tail.prev is LRU.
	 */
	@GuardedBy("maintenanceLock")
	private final Node<@NonNull K, @NonNull V> tail;

	// ===================================================================================
	// Buffers
	// ===================================================================================

	/**
	 * Lossy ring buffer for recording read accesses.
	 * Entries may be overwritten under contention (dropping older access events).
	 */
	private final AtomicReferenceArray<Node<@NonNull K, @NonNull V>> readBuffer;
	private final AtomicInteger readBufferWriteIndex;

	/**
	 * Lossless MPSC queue for write operations.
	 */
	private final ConcurrentLinkedQueue<WriteTask<@NonNull K, @NonNull V>> writeBuffer;

	/**
	 * Approximate count of queued write tasks.
	 * This is used only for heuristics/triggering maintenance.
	 * <p>
	 * Important: we increment BEFORE enqueue to avoid "poll before increment" races going negative.
	 */
	private final AtomicInteger writeBufferSize;

	// ===================================================================================
	// Maintenance
	// ===================================================================================

	/**
	 * Lock protecting all maintenance operations:
	 * - Draining read/write buffers
	 * - Updating the LRU linked list
	 * - Evicting entries
	 */
	private final ReentrantLock maintenanceLock;

	// ===================================================================================
	// Node States
	// ===================================================================================

	private static final int ALIVE = 0;
	private static final int RETIRED = 1;
	private static final int DEAD = 2;

	// ===================================================================================
	// Constructors
	// ===================================================================================

	public ConcurrentLruMap(int capacity) {
		this(capacity, null);
	}

	public ConcurrentLruMap(int capacity, @Nullable BiConsumer<@NonNull K, @NonNull V> evictionListener) {
		if (capacity <= 0)
			throw new IllegalArgumentException("Capacity must be greater than zero");

		this.capacity = capacity;
		this.map = new ConcurrentHashMap<>(capacity);
		this.evictionListener = evictionListener != null ? evictionListener : (k, v) -> {};

		this.head = new Node<>();
		this.tail = new Node<>();
		this.head.next = this.tail;
		this.tail.prev = this.head;

		this.readBuffer = new AtomicReferenceArray<>(READ_BUFFER_SIZE);
		this.readBufferWriteIndex = new AtomicInteger(0);

		this.writeBuffer = new ConcurrentLinkedQueue<>();
		this.writeBufferSize = new AtomicInteger(0);

		this.maintenanceLock = new ReentrantLock();
	}

	// ===================================================================================
	// Map Interface - Read Operations
	// ===================================================================================

	@Override
	public int size() {
		return map.size();
	}

	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	@Override
	public boolean containsKey(@NonNull Object key) {
		// Note: does not count as access for LRU purposes
		return map.containsKey(key);
	}

	@Override
	public boolean containsValue(@Nullable Object value) {
		for (Node<@NonNull K, @NonNull V> node : map.values()) {
			if (Objects.equals(node.value, value))
				return true;
		}
		return false;
	}

	@Override
	@Nullable
	public V get(@NonNull Object key) {
		Node<@NonNull K, @NonNull V> node = map.get(key);
		if (node == null)
			return null;

		recordRead(node);
		return node.value;
	}

	@Override
	public @Nullable V getOrDefault(@NonNull Object key, @Nullable V defaultValue) {
		Node<@NonNull K, @NonNull V> node = map.get(key);
		if (node == null)
			return defaultValue;

		recordRead(node);
		return node.value;
	}

	// ===================================================================================
	// Map Interface - Write Operations
	// ===================================================================================

	@Override
	@Nullable
	public V put(@NonNull K key, @NonNull V value) {
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(value, "value");

		Node<@NonNull K, @NonNull V> newNode = new Node<>(key, value);
		Node<@NonNull K, @NonNull V> oldNode = map.put(key, newNode);

		if (oldNode != null) {
			oldNode.state = RETIRED;
			scheduleWrite(WriteTask.update(oldNode, newNode));
			return oldNode.value;
		}

		scheduleWrite(WriteTask.add(newNode));
		return null;
	}

	@Override
	@Nullable
	public V putIfAbsent(@NonNull K key, @NonNull V value) {
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(value, "value");

		Node<@NonNull K, @NonNull V> newNode = new Node<>(key, value);
		Node<@NonNull K, @NonNull V> existing = map.putIfAbsent(key, newNode);

		if (existing == null) {
			scheduleWrite(WriteTask.add(newNode));
			return null;
		}

		recordRead(existing);
		return existing.value;
	}

	@Override
	@Nullable
	public V computeIfAbsent(@NonNull K key, @NonNull Function<? super @NonNull K, ? extends @Nullable V> mappingFunction) {
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(mappingFunction, "mappingFunction");

		Node<@NonNull K, @NonNull V> existing = map.get(key);
		if (existing != null) {
			recordRead(existing);
			return existing.value;
		}

		final boolean[] inserted = {false};

		Node<@NonNull K, @NonNull V> node = map.computeIfAbsent(key, k -> {
			V newValue = mappingFunction.apply(k);
			if (newValue == null)
				return null;

			inserted[0] = true;
			return new Node<>(k, newValue);
		});

		if (node == null)
			return null;

		if (inserted[0]) {
			scheduleWrite(WriteTask.add(node));
		} else {
			recordRead(node);
		}

		return node.value;
	}

	@Override
	@Nullable
	public V remove(@NonNull Object key) {
		Node<@NonNull K, @NonNull V> node = map.remove(key);
		if (node == null)
			return null;

		retire(node);
		return node.value;
	}

	@Override
	public boolean remove(@NonNull Object key, @Nullable Object value) {
		Node<@NonNull K, @NonNull V> node = map.get(key);
		if (node == null || !Objects.equals(node.value, value))
			return false;

		if (map.remove(key, node)) {
			retire(node);
			return true;
		}

		return false;
	}

	@Override
	public void putAll(@NonNull Map<? extends @NonNull K, ? extends @NonNull V> m) {
		for (Entry<? extends K, ? extends V> entry : m.entrySet())
			put(entry.getKey(), entry.getValue());
	}

	@Override
	public void clear() {
		maintenanceLock.lock();
		try {
			map.clear();

			// Unlink everything currently on the list
			Node<@NonNull K, @NonNull V> current = Objects.requireNonNull(head.next);
			while (current != tail) {
				Node<@NonNull K, @NonNull V> next = Objects.requireNonNull(current.next);
				current.prev = null;
				current.next = null;
				current.state = DEAD;
				current = next;
			}
			head.next = tail;
			tail.prev = head;

			// Clear read buffer
			for (int i = 0; i < READ_BUFFER_SIZE; i++)
				readBuffer.set(i, null);

			// Drain (discard) pending write tasks safely and keep the counter sane
			WriteTask<@NonNull K, @NonNull V> task;
			while ((task = writeBuffer.poll()) != null)
				writeBufferSize.decrementAndGet();

			// No eviction callbacks on clear (Map.clear semantics)
			// (evicted remains empty)
		} finally {
			maintenanceLock.unlock();
		}
	}

	// ===================================================================================
	// Map Interface - Backed Views (contract-correct)
	// ===================================================================================

	@Override
	public @NonNull Set<@NonNull K> keySet() {
		return new KeySetView();
	}

	@Override
	public @NonNull Collection<@NonNull V> values() {
		return new ValuesView();
	}

	@Override
	public @NonNull Set<@NonNull Entry<@NonNull K, @NonNull V>> entrySet() {
		return new EntrySetView();
	}

	@Override
	public boolean equals(@Nullable Object o) {
		if (o == this)
			return true;
		if (!(o instanceof Map))
			return false;

		Map<?, ?> other = (Map<?, ?>) o;
		return this.entrySet().equals(other.entrySet());
	}

	@Override
	public int hashCode() {
		return entrySet().hashCode();
	}

	// ===================================================================================
	// Read Buffer (Lossy)
	// ===================================================================================

	private void recordRead(@NonNull Node<@NonNull K, @NonNull V> node) {
		// Claim a slot in the ring buffer
		int writeIndex = readBufferWriteIndex.getAndIncrement();
		int slot = writeIndex & READ_BUFFER_MASK;

		// Overwrite the slot (dropping any prior recorded access event for that slot)
		readBuffer.lazySet(slot, node);

		// Help out if there are pending writes (but don't do it on every read).
		// This keeps reads cheap while ensuring small write bursts still get processed.
		if (writeBufferSize.get() != 0 && slot == READ_BUFFER_MASK)
			tryMaintenance();
	}

	// ===================================================================================
	// Write Buffer (Lossless)
	// ===================================================================================

	private void scheduleWrite(@NonNull WriteTask<@NonNull K, @NonNull V> task) {
		// Increment first to avoid "poll before increment" going negative.
		int pending = writeBufferSize.incrementAndGet();
		writeBuffer.offer(task);

		// If we're over capacity, trigger maintenance immediately.
		// Also trigger when the write backlog is getting large.
		if (pending >= WRITE_BUFFER_DRAIN_THRESHOLD || map.size() > capacity)
			tryMaintenance();
	}

	private void retire(@NonNull Node<@NonNull K, @NonNull V> node) {
		node.state = RETIRED;
		scheduleWrite(WriteTask.remove(node));
	}

	// ===================================================================================
	// Maintenance
	// ===================================================================================

	private void tryMaintenance() {
		if (!maintenanceLock.tryLock())
			return;

		List<@NonNull Node<@NonNull K, @NonNull V>> evicted;
		try {
			evicted = performMaintenanceLocked();
		} finally {
			maintenanceLock.unlock();
		}

		notifyEvictionListener(evicted);
	}

	private void forceMaintenance() {
		List<@NonNull Node<@NonNull K, @NonNull V>> evicted;

		maintenanceLock.lock();
		try {
			evicted = performMaintenanceLocked();
		} finally {
			maintenanceLock.unlock();
		}

		notifyEvictionListener(evicted);
	}

	@GuardedBy("maintenanceLock")
	private @NonNull List<@NonNull Node<@NonNull K, @NonNull V>> performMaintenanceLocked() {
		drainReadBufferLocked();
		drainWriteBufferLocked();
		return evictLocked();
	}

	@GuardedBy("maintenanceLock")
	private void drainReadBufferLocked() {
		for (int i = 0; i < READ_BUFFER_SIZE; i++) {
			Node<@NonNull K, @NonNull V> node = readBuffer.getAndSet(i, null);
			if (node != null && node.state == ALIVE)
				promoteToHeadLocked(node);
		}
	}

	@GuardedBy("maintenanceLock")
	private void drainWriteBufferLocked() {
		WriteTask<@NonNull K, @NonNull V> task;
		while ((task = writeBuffer.poll()) != null) {
			writeBufferSize.decrementAndGet();
			processWriteTaskLocked(task);
		}
	}

	@GuardedBy("maintenanceLock")
	private void processWriteTaskLocked(@NonNull WriteTask<@NonNull K, @NonNull V> task) {
		switch (task.type) {
			case ADD:
				// Idempotent: promotes whether or not already linked
				promoteToHeadLocked(task.node);
				break;

			case REMOVE:
				unlinkNodeLocked(task.node);
				break;

			case UPDATE:
				unlinkNodeLocked(Objects.requireNonNull(task.oldNode));
				promoteToHeadLocked(task.node);
				break;
		}
	}

	@GuardedBy("maintenanceLock")
	private @NonNull List<@NonNull Node<@NonNull K, @NonNull V>> evictLocked() {
		List<@NonNull Node<@NonNull K, @NonNull V>> evicted = new ArrayList<>();

		while (map.size() > capacity) {
			Node<@NonNull K, @NonNull V> victim = Objects.requireNonNull(tail.prev);
			if (victim == head)
				break;

			// Remove from map first
			if (map.remove(victim.key, victim)) {
				unlinkNodeLocked(victim);
				evicted.add(victim);
			} else {
				// Not current in map anymore; just unlink stale list node
				unlinkNodeLocked(victim);
			}
		}

		return evicted;
	}

	private void notifyEvictionListener(@NonNull List<@NonNull Node<@NonNull K, @NonNull V>> evicted) {
		if (evicted.isEmpty())
			return;

		RuntimeException first = null;

		for (Node<@NonNull K, @NonNull V> node : evicted) {
			try {
				evictionListener.accept(node.key, node.value);
			} catch (RuntimeException e) {
				if (first == null)
					first = e;
				else
					first.addSuppressed(e);
			}
		}

		if (first != null)
			throw first;
	}

	// ===================================================================================
	// Linked List Operations
	// ===================================================================================

	/**
	 * Ensures the node is linked and is at the MRU position.
	 * Safe to call for nodes that are not yet linked, already linked, or linked in the wrong place.
	 */
	@GuardedBy("maintenanceLock")
	private void promoteToHeadLocked(@NonNull Node<@NonNull K, @NonNull V> node) {
		if (node.state != ALIVE)
			return;

		// Already MRU?
		if (node.prev == head)
			return;

		// If linked somewhere (or partially linked), unlink defensively
		if (node.prev != null)
			node.prev.next = node.next;
		if (node.next != null)
			node.next.prev = node.prev;

		// Link at head
		Node<@NonNull K, @NonNull V> first = Objects.requireNonNull(head.next);
		node.prev = head;
		node.next = first;
		head.next = node;
		first.prev = node;
	}

	@GuardedBy("maintenanceLock")
	private void unlinkNodeLocked(@NonNull Node<@NonNull K, @NonNull V> node) {
		if (node.state == DEAD)
			return;

		node.state = DEAD;

		if (node.prev != null)
			node.prev.next = node.next;
		if (node.next != null)
			node.next.prev = node.prev;

		node.prev = null;
		node.next = null;
	}

	// ===================================================================================
	// Internal Classes
	// ===================================================================================

	private static final class Node<@NonNull K, @NonNull V> {
		final K key;
		final V value;

		// Guarded by the owning ConcurrentLruMap's maintenanceLock.
		@Nullable
		Node<@NonNull K, @NonNull V> prev;

		// Guarded by the owning ConcurrentLruMap's maintenanceLock.
		@Nullable
		Node<@NonNull K, @NonNull V> next;

		volatile int state = ALIVE;

		@SuppressWarnings("NullAway")
		Node() {
			this.key = null;
			this.value = null;
		}

		Node(@NonNull K key, @NonNull V value) {
			this.key = key;
			this.value = value;
		}
	}

	private static final class WriteTask<@NonNull K, @NonNull V> {
		enum Type {ADD, REMOVE, UPDATE}

		final Type type;
		final Node<@NonNull K, @NonNull V> node;
		@Nullable
		final Node<@NonNull K, @NonNull V> oldNode; // only for UPDATE

		private WriteTask(@NonNull Type type, @NonNull Node<@NonNull K, @NonNull V> node, @Nullable Node<@NonNull K, @NonNull V> oldNode) {
			this.type = type;
			this.node = node;
			this.oldNode = oldNode;
		}

		static <K, V> @NonNull WriteTask<@NonNull K, @NonNull V> add(@NonNull Node<@NonNull K, @NonNull V> node) {
			return new WriteTask<>(Type.ADD, node, null);
		}

		static <K, V> @NonNull WriteTask<@NonNull K, @NonNull V> remove(@NonNull Node<@NonNull K, @NonNull V> node) {
			return new WriteTask<>(Type.REMOVE, node, null);
		}

		static <K, V> @NonNull WriteTask<@NonNull K, @NonNull V> update(@NonNull Node<@NonNull K, @NonNull V> oldNode, @NonNull Node<@NonNull K, @NonNull V> newNode) {
			return new WriteTask<>(Type.UPDATE, newNode, oldNode);
		}
	}

	// ===================================================================================
	// Backed Views
	// ===================================================================================

	private final class KeySetView extends AbstractSet<@NonNull K> {
		@Override
		public int size() {
			return ConcurrentLruMap.this.size();
		}

		@Override
		public boolean isEmpty() {
			return ConcurrentLruMap.this.isEmpty();
		}

		@Override
		public boolean contains(@NonNull Object o) {
			return ConcurrentLruMap.this.containsKey(o);
		}

		@Override
		public @NonNull Iterator<@NonNull K> iterator() {
			final Iterator<@NonNull K> it = map.keySet().iterator();

			return new Iterator<>() {
				@Nullable
				private K lastKey;
				@Nullable
				private Node<@NonNull K, @NonNull V> lastNode;

				@Override
				public boolean hasNext() {
					return it.hasNext();
				}

				@Override
				public @NonNull K next() {
					lastKey = it.next();
					lastNode = map.get(lastKey);
					return lastKey;
				}

				@Override
				public void remove() {
					if (lastKey == null)
						throw new IllegalStateException();

					if (lastNode != null && map.remove(lastKey, lastNode))
						retire(lastNode);

					lastKey = null;
					lastNode = null;
				}
			};
		}

		@Override
		public boolean remove(@NonNull Object o) {
			return ConcurrentLruMap.this.remove(o) != null;
		}

		@Override
		public void clear() {
			ConcurrentLruMap.this.clear();
		}

		@Override
		public boolean add(@NonNull K k) {
			throw new UnsupportedOperationException();
		}
	}

	private final class ValuesView extends AbstractCollection<@NonNull V> {
		@Override
		public int size() {
			return ConcurrentLruMap.this.size();
		}

		@Override
		public boolean isEmpty() {
			return ConcurrentLruMap.this.isEmpty();
		}

		@Override
		public boolean contains(@Nullable Object o) {
			return ConcurrentLruMap.this.containsValue(o);
		}

		@Override
		public @NonNull Iterator<@NonNull V> iterator() {
			final Iterator<@NonNull Entry<K, Node<@NonNull K, @NonNull V>>> it = map.entrySet().iterator();

			return new Iterator<>() {
				@Nullable
				private Entry<K, Node<@NonNull K, @NonNull V>> last;

				@Override
				public boolean hasNext() {
					return it.hasNext();
				}

				@Override
				public @NonNull V next() {
					last = it.next();
					return last.getValue().value;
				}

				@Override
				public void remove() {
					if (last == null)
						throw new IllegalStateException();

					K key = last.getKey();
					Node<@NonNull K, @NonNull V> node = last.getValue();
					last = null;

					if (map.remove(key, node))
						retire(node);
				}
			};
		}

		@Override
		public boolean remove(@Nullable Object o) {
			for (Entry<K, Node<@NonNull K, @NonNull V>> e : map.entrySet()) {
				Node<@NonNull K, @NonNull V> node = e.getValue();
				if (Objects.equals(node.value, o)) {
					if (map.remove(e.getKey(), node)) {
						retire(node);
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public void clear() {
			ConcurrentLruMap.this.clear();
		}
	}

	private final class EntrySetView extends AbstractSet<@NonNull Entry<@NonNull K, @NonNull V>> {
		@Override
		public int size() {
			return ConcurrentLruMap.this.size();
		}

		@Override
		public boolean isEmpty() {
			return ConcurrentLruMap.this.isEmpty();
		}

		@Override
		public void clear() {
			ConcurrentLruMap.this.clear();
		}

		@Override
		public boolean contains(@Nullable Object o) {
			if (!(o instanceof Entry))
				return false;

			Entry<?, ?> e = (Entry<?, ?>) o;
			Node<@NonNull K, @NonNull V> node = map.get(e.getKey());
			return node != null && Objects.equals(node.value, e.getValue());
		}

		@Override
		public boolean remove(@Nullable Object o) {
			if (!(o instanceof Entry))
				return false;

			Entry<?, ?> e = (Entry<?, ?>) o;
			return ConcurrentLruMap.this.remove(e.getKey(), e.getValue());
		}

		@Override
		public @NonNull Iterator<@NonNull Entry<@NonNull K, @NonNull V>> iterator() {
			final Iterator<@NonNull Entry<K, Node<@NonNull K, @NonNull V>>> it = map.entrySet().iterator();

			return new Iterator<>() {
				@Nullable
				private Entry<K, Node<@NonNull K, @NonNull V>> last;

				@Override
				public boolean hasNext() {
					return it.hasNext();
				}

				@Override
				public @NonNull Entry<@NonNull K, @NonNull V> next() {
					last = it.next();
					K key = last.getKey();
					return new WriteThroughEntry(key);
				}

				@Override
				public void remove() {
					if (last == null)
						throw new IllegalStateException();

					K key = last.getKey();
					Node<@NonNull K, @NonNull V> node = last.getValue();
					last = null;

					if (map.remove(key, node))
						retire(node);
				}
			};
		}

		@Override
		public boolean add(@NonNull Entry<@NonNull K, @NonNull V> kvEntry) {
			throw new UnsupportedOperationException();
		}
	}

	private final class WriteThroughEntry implements Entry<@NonNull K, @NonNull V> {
		private final K key;

		private WriteThroughEntry(@NonNull K key) {
			this.key = key;
		}

		@Override
		public @NonNull K getKey() {
			return key;
		}

		@Override
		@Nullable
		public V getValue() {
			Node<@NonNull K, @NonNull V> node = map.get(key);
			return node == null ? null : node.value;
		}

		/**
		 * Sets the value. Note: in concurrent scenarios, the returned previous value
		 * may differ from what was actually replaced.
		 */
		@Override
		@Nullable
		public V setValue(@NonNull V value) {
			Objects.requireNonNull(value, "value");
			Node<@NonNull K, @NonNull V> prior = map.get(key);
			V oldValue = prior == null ? null : prior.value;
			ConcurrentLruMap.this.put(key, value);
			return oldValue;
		}

		@Override
		public boolean equals(@Nullable Object o) {
			if (!(o instanceof Entry))
				return false;
			Entry<?, ?> e = (Entry<?, ?>) o;
			return Objects.equals(key, e.getKey()) && Objects.equals(getValue(), e.getValue());
		}

		@Override
		public int hashCode() {
			return Objects.hashCode(key) ^ Objects.hashCode(getValue());
		}
	}

	// ===================================================================================
	// Testing / Debugging Support
	// ===================================================================================

	public int capacity() {
		return capacity;
	}

	/**
	 * Forces all pending operations to be processed.
	 * Useful for tests.
	 */
	public void drain() {
		forceMaintenance();
	}

	/**
	 * Snapshot of keys in (approximate) MRU->LRU order. Primarily for tests/debugging.
	 */
	@NonNull
	public List<@NonNull K> keysInAccessOrder() {
		List<@NonNull K> keys = new ArrayList<>();
		List<@NonNull Node<@NonNull K, @NonNull V>> evicted;

		maintenanceLock.lock();
		try {
			evicted = performMaintenanceLocked();

			Node<@NonNull K, @NonNull V> current = Objects.requireNonNull(head.next);
			while (current != tail) {
				if (current.key != null)
					keys.add(current.key);
				current = Objects.requireNonNull(current.next);
			}
		} finally {
			maintenanceLock.unlock();
		}

		notifyEvictionListener(evicted);
		return keys;
	}

}
