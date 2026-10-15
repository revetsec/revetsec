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

package com.revetsec.internal;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

/** The catalog's inclusive bounds, including a one-value range and a duration row without a default. */
final class LimitRc1MutationTests {
 @Test void zeroFloorAndBothInclusiveDefaultEndpointsAreAdmitted() {
  Limit floor=Limit.fromAmounts("fixture",Limit.Unit.COUNT,0,0,1);
  Limit cap=Limit.fromAmounts("fixture",Limit.Unit.COUNT,1,0,1);
  assertTrue(floor.isZeroAllowed());assertEquals(0,floor.getDefaultValue());assertEquals(1,cap.getDefaultValue());
  floor.require(0);floor.require(1);
  assertThrows(IllegalArgumentException.class,()->floor.require(-1));assertThrows(IllegalArgumentException.class,()->floor.require(2));
 }
 @Test void aPositiveSingleValueRangeIsValidAndItsNeighborsAreRejected() {
  Limit only=Limit.fromAmounts("fixture",Limit.Unit.COUNT,1,1,1);assertEquals(1,only.getDefaultValue());only.require(1);
  assertThrows(IllegalArgumentException.class,()->Limit.fromAmounts("fixture",Limit.Unit.COUNT,0,1,1));
  assertThrows(IllegalArgumentException.class,()->Limit.fromAmounts("fixture",Limit.Unit.COUNT,2,1,1));
  assertThrows(IllegalArgumentException.class,()->Limit.fromAmounts("fixture",Limit.Unit.COUNT,0,0,0));
 }
 @Test void durationFactoriesReturnUsableRowsWithAndWithoutDefaults() {
  Limit withDefault=Limit.fromDurations("fixture",Duration.ofNanos(1),Duration.ZERO,Duration.ofNanos(2));
  assertNotNull(withDefault);assertTrue(withDefault.hasDefault());assertEquals(Duration.ofNanos(1),withDefault.getDefaultDuration());withDefault.require(Duration.ofNanos(2));
  Limit withoutDefault=Limit.fromDurations("fixture",null,Duration.ZERO,Duration.ofNanos(2));assertNotNull(withoutDefault);assertFalse(withoutDefault.hasDefault());withoutDefault.require(Duration.ZERO);
  assertThrows(IllegalStateException.class,()->withoutDefault.getDefaultDuration());assertThrows(IllegalStateException.class,()->withoutDefault.getDefaultValue());
 }
}
