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
package verification.sharedclock;

import org.jspecify.annotations.NonNull;
import com.pyranid.TransactionResult;

import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/** CAP-11 pure local contracts. No provider ever returns a connection or performs IPC. */
final class ClosedQuotaConstructorChecks {
	private static final String[] FAMILIES = {"TOTP", "ISSUER", "WEBAUTHN"};
	private static final String[] IDS = {identity(1), identity(2), identity(3), identity(4)};
	private static int assertions;

	private ClosedQuotaConstructorChecks() { }

	public static void main(@NonNull String @NonNull [] args) {
		if (args.length != 0) throw new IllegalArgumentException("No arguments supported");
		identities();
		scopes();
		allocations();
		servicePreflight();
		System.out.println("TOTAL " + assertions);
	}

	private static void identities() {
		String[] canonical = {identity(0), identity(255), IDS[0]};
		for (int i = 0; i < canonical.length; ++i)
			check(PgPrimitives.id(canonical[i]).equals(canonical[i]), "identity/canonical/" + i);
		for (int i = 0; i < malformed().size(); ++i) {
			String bad = malformed().get(i);
			reject(IllegalArgumentException.class, () -> PgPrimitives.id(bad), "identity/malformed/" + i);
		}
		reject(NullPointerException.class, () -> PgPrimitives.id(null), "identity/null");
		for (int format : new int[] {2, 3}) {
			PgPrimitives.Admission admission = admission(new String[] {IDS[0], IDS[1], IDS[2], IDS[3], identity(5), identity(6), identity(7), identity(8)}, format);
			check(admission.authority.equals(IDS[0]) && admission.recovery.equals(IDS[1])
					&& admission.clock.equals(IDS[2]) && admission.profile.equals(IDS[3])
					&& admission.schema.equals(identity(5)) && admission.metadata.equals(identity(6))
					&& admission.writer.equals(identity(7)) && admission.allocation.equals(identity(8))
					&& admission.format == format, "admission/canonical-all-identities/" + format);
		}
		for (int slot = 0; slot < 8; ++slot) {
			for (int i = 0; i < malformed().size(); ++i) {
				String[] ids = new String[8]; Arrays.fill(ids, IDS[0]); ids[slot] = malformed().get(i);
				reject(IllegalArgumentException.class, () -> admission(ids, 3), "admission/malformed-slot/" + slot + "/" + i);
			}
			String[] ids = new String[8]; Arrays.fill(ids, IDS[0]); ids[slot] = null;
			reject(NullPointerException.class, () -> admission(ids, 3), "admission/null-slot/" + slot);
		}
		for (int format : new int[] {Integer.MIN_VALUE, -1, 0, 1, 4, Integer.MAX_VALUE}) {
			String[] ids = new String[8]; Arrays.fill(ids, IDS[0]);
			reject(IllegalArgumentException.class, () -> admission(ids, format), "admission/format/" + format);
		}
	}

	private static PgPrimitives.Admission admission(String[] ids, int format) {
		return new PgPrimitives.Admission(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], format);
	}

	private static void scopes() {
		for (String family : FAMILIES) {
			for (String namespace : new String[] {IDS[0], "a".repeat(256), "é".repeat(128)}) {
				PgScope scope = PgScope.from(family, namespace);
				check(scope.getFamily().equals(family) && scope.getNamespace().equals(namespace)
						&& scope.equals(PgScope.from(new String(family), new String(namespace)))
						&& scope.hashCode() == PgScope.from(family, namespace).hashCode(),
						"scope/canonical/" + family + "/" + namespace.length());
			}
			int i = 0;
			for (String bad : new String[] {"", "a".repeat(257), "é".repeat(129), "a\0b", "\ud800", "\udc00"}) {
				reject(IllegalArgumentException.class, () -> PgScope.from(family, bad), "scope/invalid-namespace/" + family + "/" + i++);
			}
			reject(NullPointerException.class, () -> PgScope.from(family, null), "scope/null-namespace/" + family);
		}
		for (String family : new String[] {"", "totp", "Issuer", "WEBAUTHN ", "OTHER"})
			reject(IllegalArgumentException.class, () -> PgScope.from(family, IDS[0]), "scope/invalid-family/" + family);
		reject(NullPointerException.class, () -> PgScope.from(null, IDS[0]), "scope/null-family");
	}

	private static void allocations() {
		for (String family : FAMILIES) {
			long maximum = family.equals("TOTP") ? 65_536 : 1_000_000;
			long bytes = family.equals("TOTP") ? 1 : 0;
			for (long cap : new long[] {1, maximum}) {
				PgCapacity.Allocation allocation = allocate(family, cap, bytes, new long[4][256]);
				check(Arrays.stream(allocation.getEntryLimits()).sum() == cap
						&& Arrays.stream(allocation.getByteLimits()).sum() == bytes,
						"allocation/exact-entry-bound/" + family + "/" + cap);
			}
			for (long cap : new long[] {Long.MIN_VALUE, -1, 0, maximum + 1, Long.MAX_VALUE})
				reject(IllegalArgumentException.class, () -> allocate(family, cap, bytes, new long[4][256]), "allocation/entry-cap-refused/" + family + "/" + cap);
			for (long cap : family.equals("TOTP") ? new long[] {Long.MIN_VALUE, -1, 0, 268_435_457, Long.MAX_VALUE}
					: new long[] {Long.MIN_VALUE, -1, 1, Long.MAX_VALUE})
				reject(IllegalArgumentException.class, () -> allocate(family, 1, cap, new long[4][256]), "allocation/byte-cap-refused/" + family + "/" + cap);
			if (family.equals("TOTP"))
				check(Arrays.stream(allocate(family, 1, 268_435_456, new long[4][256]).getByteLimits()).sum() == 268_435_456,
						"allocation/exact-totp-byte-maximum");
		}
		for (String family : new String[] {"", "totp", "Issuer", "WEBAUTHN ", "OTHER"})
			reject(IllegalArgumentException.class, () -> allocate(family, 1, 1, new long[4][256]), "allocation/invalid-family/" + family);
		reject(NullPointerException.class, () -> allocate(null, 1, 1, new long[4][256]), "allocation/null-family");
		for (int slot = 0; slot < 4; ++slot) {
			for (int length : new int[] {0, 255, 257}) {
				long[][] arrays = new long[4][256]; arrays[slot] = new long[length];
				reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, arrays), "allocation/bucket-shape/" + slot + "/" + length);
			}
			long[][] missing = new long[4][256]; missing[slot] = null;
			reject(NullPointerException.class, () -> allocate("TOTP", 100, 100, missing), "allocation/null-array/" + slot);
			for (int bucket : new int[] {0, 255}) {
				long[][] negative = new long[4][256]; negative[slot][bucket] = -1;
				reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, negative), "allocation/negative-inventory/" + slot + "/" + bucket);
				long[][] insufficient = new long[4][256]; insufficient[slot][bucket] = 101;
				reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, insufficient), "allocation/inventory-over-cap/" + slot + "/" + bucket);
			}
		}
		for (int dimension = 0; dimension < 2; ++dimension) {
			long[][] pair = new long[4][256]; pair[dimension][0] = Long.MAX_VALUE; pair[dimension + 2][0] = 1;
			reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, pair), "allocation/seed-overflow/" + dimension);
			long[][] sum = new long[4][256]; sum[dimension][0] = Long.MAX_VALUE; sum[dimension][255] = 1;
			reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, sum), "allocation/sum-overflow/" + dimension);
			long[][] combined = new long[4][256]; combined[dimension][0] = 50; combined[dimension + 2][255] = 51;
			reject(IllegalArgumentException.class, () -> allocate("TOTP", 100, 100, combined), "allocation/combined-over-cap/" + dimension);
		}
		long[][] input = new long[4][256]; input[0][3] = 2; input[1][3] = 9; input[2][200] = 1; input[3][200] = 11;
		long[][] before = copy(input);
		PgCapacity.Allocation allocation = allocate("TOTP", 1000, 10000, input);
		long[][] saved = values(allocation);
		check(Arrays.deepEquals(input, before) && saved[2][3] == 2 && saved[3][3] == 9
				&& saved[2][200] == 0 && saved[3][200] == 0 && saved[0][200] >= 1 && saved[1][200] >= 11,
				"allocation/actual-bootstrap-separate-input-unchanged");
		for (long[] array : input) Arrays.fill(array, Long.MAX_VALUE);
		long[][] exposed = values(allocation);
		for (long[] array : exposed) Arrays.fill(array, Long.MIN_VALUE);
		check(Arrays.deepEquals(saved, values(allocation)), "allocation/all-input-and-getter-arrays-defensively-copied");
		check(Arrays.stream(PgCapacity.Allocation.class.getDeclaredConstructors()).allMatch(c -> Modifier.isPrivate(c.getModifiers()))
				&& Arrays.stream(PgCapacity.Allocation.class.getDeclaredFields()).allMatch(f -> Modifier.isPrivate(f.getModifiers()) && Modifier.isFinal(f.getModifiers())),
				"allocation/no-callable-malformed-carrier-constructor");
	}

	private static void servicePreflight() {
		for (String family : FAMILIES) {
			PgScope scope = PgScope.from(family, IDS[0]);
			PgCapacity.Allocation allocation = allocate(family, 1, family.equals("TOTP") ? 1 : 0, new long[4][256]);
			for (boolean bootstrap : new boolean[] {true, false}) {
				String prefix = "service/" + (bootstrap ? "bootstrap" : "reallocate") + "/" + family;
				for (Duration budget : new Duration[] {Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(-1), Duration.ofSeconds(Long.MIN_VALUE)}) {
					DenySource source = new DenySource(); long[][] saved = values(allocation);
					noEffect(call(bootstrap, source, budget, scope, IDS, allocation), source, 0, prefix + "/nonpositive-budget/" + budget);
					check(Arrays.deepEquals(saved, values(allocation)), prefix + "/nonpositive-inputs-unchanged/" + budget);
				}
				for (Duration budget : new Duration[] {Duration.ofSeconds(60, 1), Duration.ofSeconds(61), Duration.ofSeconds(Long.MAX_VALUE)}) {
					DenySource source = new DenySource();
					rejectNoLookup(IllegalArgumentException.class, () -> call(bootstrap, source, budget, scope, IDS, allocation), source,
							prefix + "/excessive-budget/" + budget);
				}
				for (int slot = 0; slot < 4; ++slot) {
					for (int i = 0; i < malformed().size(); ++i) {
						String[] ids = IDS.clone(); ids[slot] = malformed().get(i); DenySource source = new DenySource();
						rejectNoLookup(IllegalArgumentException.class, () -> call(bootstrap, source, Duration.ofSeconds(60), scope, ids, allocation), source,
								prefix + "/malformed-id/" + slot + "/" + i);
					}
					String[] ids = IDS.clone(); ids[slot] = null; DenySource source = new DenySource();
					rejectNoLookup(NullPointerException.class, () -> call(bootstrap, source, Duration.ofSeconds(60), scope, ids, allocation), source,
							prefix + "/null-id/" + slot);
				}
				for (String equal : new String[] {IDS[0], new String(IDS[0])}) {
					String[] ids = IDS.clone(); ids[1] = equal; DenySource source = new DenySource();
					rejectNoLookup(IllegalArgumentException.class, () -> call(bootstrap, source, Duration.ofSeconds(60), scope, ids, allocation), source,
							prefix + "/same-generation/" + (equal == IDS[0] ? "same-object" : "equal-content"));
				}
				DenySource nullBudget = new DenySource();
				rejectNoLookup(NullPointerException.class, () -> call(bootstrap, nullBudget, null, scope, IDS, allocation), nullBudget, prefix + "/null-budget");
				DenySource nullScope = new DenySource();
				rejectNoLookup(NullPointerException.class, () -> call(bootstrap, nullScope, Duration.ofSeconds(60), null, IDS, allocation), nullScope, prefix + "/null-scope");
				DenySource nullAllocation = new DenySource();
				rejectNoLookup(NullPointerException.class, () -> call(bootstrap, nullAllocation, Duration.ofSeconds(60), scope, IDS, null), nullAllocation, prefix + "/null-allocation");
				reject(NullPointerException.class, () -> call(bootstrap, null, Duration.ofSeconds(60), scope, IDS, allocation), prefix + "/null-provider");
				String other = family.equals("TOTP") ? "ISSUER" : "TOTP";
				PgCapacity.Allocation wrongFamily = allocate(other, 1, other.equals("TOTP") ? 1 : 0, new long[4][256]);
				DenySource crossFamily = new DenySource();
				rejectNoLookup(IllegalArgumentException.class, () -> call(bootstrap, crossFamily, Duration.ofSeconds(60), scope, IDS, wrongFamily), crossFamily,
						prefix + "/wrong-family-byte-shape");
				DenySource positive = new DenySource(); long[][] saved = values(allocation);
				noEffect(call(bootstrap, positive, Duration.ofSeconds(60), scope, IDS, allocation), positive, 1, prefix + "/canonical-positive-denied-provider");
				check(Arrays.deepEquals(saved, values(allocation)) && positive.budget != null && !positive.budget.isNegative()
						&& !positive.budget.isZero() && positive.budget.compareTo(Duration.ofSeconds(60)) <= 0,
						prefix + "/positive-shrinking-budget-and-inputs-unchanged");
				DenySource tiny = new DenySource();
				PgTransactions.Outcome<Boolean> tinyOutcome = call(bootstrap, tiny, Duration.ofNanos(1), scope, IDS, allocation);
				check(tiny.calls <= 1 && tinyOutcome.status() == PgTransactions.Status.NO_EFFECT && !tinyOutcome.callbackEntered()
						&& !tinyOutcome.possibleMutation() && tinyOutcome.value().isEmpty(), prefix + "/tiny-budget-never-callback-or-mutation");
			}
		}
	}

	private static PgTransactions.Outcome<Boolean> call(boolean bootstrap, PgTransactions.ConnectionSource source, Duration budget,
			PgScope scope, String[] ids, PgCapacity.Allocation allocation) {
		return bootstrap ? PgQuotaControl.bootstrap(source, budget, scope, ids[0], ids[1], ids[2], ids[3], allocation)
				: PgQuotaControl.reallocate(source, budget, scope, ids[0], ids[1], ids[2], ids[3], allocation);
	}

	private static void noEffect(PgTransactions.Outcome<Boolean> outcome, DenySource source, int expectedLookups, String label) {
		check(outcome.status() == PgTransactions.Status.NO_EFFECT && outcome.refusal().orElseThrow() == PgTransactions.Refusal.UNAVAILABLE
				&& outcome.value().isEmpty() && !outcome.callbackEntered() && !outcome.possibleMutation()
				&& (expectedLookups == 0 ? outcome.completion().isEmpty() : outcome.completion().orElseThrow() == TransactionResult.ROLLED_BACK)
				&& source.calls == expectedLookups, label);
	}

	private static PgCapacity.Allocation allocate(String family, long entries, long bytes, long[][] arrays) {
		return PgCapacity.allocate(family, entries, bytes, arrays[0], arrays[1], arrays[2], arrays[3]);
	}

	private static long[][] values(PgCapacity.Allocation allocation) {
		return new long[][] {allocation.getEntryLimits(), allocation.getByteLimits(), allocation.getUsedEntries(), allocation.getUsedBytes()};
	}

	private static long[][] copy(long[][] values) {
		return Arrays.stream(values).map(long[]::clone).toArray(long[][]::new);
	}

	private static List<String> malformed() {
		return List.of("", "A", "A".repeat(42), "A".repeat(44), IDS[0] + "=", "A".repeat(42) + "B",
				"+" + IDS[0].substring(1), "/" + IDS[0].substring(1), " " + IDS[0], IDS[0] + "\n", "é".repeat(43), "\ud800");
	}

	private static String identity(int value) {
		byte[] bytes = new byte[32]; Arrays.fill(bytes, (byte) value);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static void rejectNoLookup(Class<? extends RuntimeException> type, Runnable operation, DenySource source, String label) {
		reject(type, operation, label);
		check(source.calls == 0, label + "/no-provider-lookup");
	}

	private static void reject(Class<? extends RuntimeException> type, Runnable operation, String label) {
		try { operation.run(); }
		catch (RuntimeException expected) {
			if (type.isInstance(expected)) { check(true, label); return; }
			throw new AssertionError(label + "/unexpected-exception-type", expected);
		}
		throw new AssertionError(label + "/expected-local-rejection");
	}

	private static void check(boolean condition, String label) {
		if (!condition) throw new AssertionError(label);
		++assertions; System.out.println("PASS CAP11/" + label);
	}

	/** Pure sentinel: deliberately has no driver, address, credentials or connection. */
	private static final class DenySource implements PgTransactions.ConnectionSource {
		private int calls;
		private Duration budget;
		@Override public @NonNull Connection open(@NonNull Duration remaining) throws SQLException {
			++this.calls; this.budget = remaining;
			throw new SQLException("CAP11 pure provider denies every lookup");
		}
	}
}
