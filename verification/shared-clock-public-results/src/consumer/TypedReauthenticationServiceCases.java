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
package consumer;

import com.revetsec.webauthn.WebAuthnReauthenticationResult;
import java.util.Set;

/** Reuses the genuine signed producer, including two additional joined known-withheld phases. */
final class TypedReauthenticationServiceCases {
 private TypedReauthenticationServiceCases(){}
 static void run()throws Exception{
  var cases=PublicProofCases.producedForJoin();PublicServiceChecks.require(cases.size()==11,"Eleven actual checked producer modes required");
  Set<String> seen=new java.util.HashSet<>();
  for(var item:cases){String mode=item.mode();PublicServiceChecks.require(seen.add(mode),"Duplicate checked producer mode");String leaf=switch(mode){case "SUCCESS","MATCHING_EXPECTED_B_TO_A"->"Succeeded";case "REJECTED_CONTEXT","MUTATED_EXPECTED_A_TO_B"->"Rejected";case "UNAVAILABLE","CANCELLED"->"Unavailable";case "UNKNOWN_NO_EFFECT","UNKNOWN_APPLIED"->"Indeterminate";case "KNOWN_NOT_ADMITTED","KNOWN_TIME_OUTAGE","KNOWN_CLOSE_FAILURE"->"ReconciliationRequired";default->throw new AssertionError("Unreviewed checked producer mode");};
   int reads=switch(mode){case "CANCELLED"->0;case "UNAVAILABLE","UNKNOWN_NO_EFFECT","UNKNOWN_APPLIED","KNOWN_NOT_ADMITTED"->2;default->3;};int callbacks=mode.equals("CANCELLED")?0:1;int applied=Set.of("UNAVAILABLE","UNKNOWN_NO_EFFECT","CANCELLED").contains(mode)?0:2;int closes=mode.equals("CANCELLED")?0:1;
   PublicServiceChecks.require(item.reads()==reads&&item.callbacks()==callbacks&&item.applied()==applied&&item.closes()==closes,"Actual checked producer read/callback/effect/close counts changed: "+mode);
   PublicServiceChecks.context("CHECKED/"+mode);PublicServiceChecks.record("WebAuthnReauthenticationResult",leaf,item.result());PublicServiceChecks.countsScenario("WebAuthnReauthenticationResult","CHECKED_"+mode,item.reads(),item.callbacks(),item.applied(),item.closes());
   if(!leaf.equals("Succeeded"))PublicServiceChecks.require(!(item.result() instanceof WebAuthnReauthenticationResult.Succeeded),"A checked failure carried a proof");
  }
 }
}
