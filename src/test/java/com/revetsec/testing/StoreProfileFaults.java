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


package com.revetsec.testing;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import java.time.Duration;

/** Changes exactly one admitted observation domain; data and observed timestamp stay unchanged. */
public enum StoreProfileFaults {
 AUTHORITY, RECOVERY, CLOCK, ERROR;
 public @NonNull StoreTimeObservation apply(@NonNull StoreTimeObservation input){
  StoreAdmission admission=input.getAdmission();String authority=admission.getAuthorityId(),recovery=admission.getRecoveryGeneration();
  if(this==AUTHORITY)authority=other(authority);if(this==RECOVERY)recovery=other(recovery);StoreAdmission changed=StoreAdmission.fromIdentifiers(authority,recovery);
  if(input instanceof StoreTimeObservation.Unavailable){if(this==CLOCK||this==ERROR)throw new AssertionError("Unavailable time carries no clock profile");return StoreTimeObservation.Unavailable.fromAdmission(changed);}
  var healthy=(StoreTimeObservation.Healthy)input;String generation=this==CLOCK?other(healthy.getClockGeneration()):healthy.getClockGeneration();Duration error=this==ERROR?(healthy.getMaximumUtcError().isZero()?Duration.ofMillis(250):Duration.ZERO):healthy.getMaximumUtcError();return StoreTimeObservation.Healthy.fromObservation(changed,generation,healthy.getObservedAt(),error);
 }
 private static @NonNull String other(@NonNull String value){return value.equals("A".repeat(43))?"E".repeat(42)+"A":"A".repeat(43);}
}
