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

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** SC-CLK-02 exact deterministic interval parameterization; independent source/platform qualification is separate. */
final class StoreTimeHealthIntervalConformanceTests {
 private static final @NonNull Instant TIME=Instant.parse("2026-10-29T12:00:00Z");
 @TestFactory @NonNull List<@NonNull DynamicTest> everyErrorRttAndNanosecondEdgeUsesFullContainment(){
  List<DynamicTest> cells=new ArrayList<>();
  for(Duration error:List.of(Duration.ZERO,Duration.ofNanos(1),Duration.ofMillis(250)))for(Duration elapsed:List.of(Duration.ZERO,Duration.ofNanos(1),Duration.ofMillis(125),Duration.ofSeconds(1),Duration.ofSeconds(3),Duration.ofSeconds(5))){
   Duration first=error.plus(elapsed.multipliedBy(2)).minusSeconds(5),last=Duration.ofSeconds(5).minus(error);List<Duration> offsets=List.of(first.minusNanos(1),first,first.plusNanos(1),last.minusNanos(1),last,last.plusNanos(1));
   for(int index=0;index<offsets.size();index++){Duration offset=offsets.get(index);int edge=index;cells.add(DynamicTest.dynamicTest("SC-CLK-02/delta="+error+"/rtt="+elapsed+"/edge="+edge,()->{boolean expected=offset.compareTo(first)>=0&&offset.compareTo(last)<=0;assertEquals(expected,StoreTimeRules.isWorkerClockHealthy(observation(error),TIME.plus(offset),elapsed));}));}
  }return cells;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> aHealthyMidpointCannotAdmitEitherOverlappingOutsideInterval(){
  List<DynamicTest> cells=new ArrayList<>();for(Duration error:List.of(Duration.ZERO,Duration.ofNanos(1),Duration.ofMillis(250)))for(Duration offset:List.of(Duration.ZERO,Duration.ofSeconds(6)))cells.add(DynamicTest.dynamicTest("SC-CLK-02/ambiguous/delta="+error+"/offset="+offset,()->assertFalse(StoreTimeRules.isWorkerClockHealthy(observation(error),TIME.plus(offset),Duration.ofSeconds(3)))));return cells;
 }
 private static StoreTimeObservation.@NonNull Healthy observation(@NonNull Duration error){return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers("A".repeat(43),"E".repeat(42)+"A"),"I".repeat(42)+"A",TIME,error);}
}
