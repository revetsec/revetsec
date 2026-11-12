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
package com.revetsec.oauth.server;

import com.revetsec.testing.ScriptedOAuthStore;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@javax.annotation.concurrent.NotThreadSafe
final class ScriptedOAuthStoreConformanceTests extends OAuthStoreConformanceTests {
 @Override protected @NonNull OAuthAuthorizationServerStore newStore(){return new ScriptedOAuthStore(NOW);}
 @Override protected @NonNull OAuthAuthorizationServerStore newStoreWithEntryLimit(int maximumEntries){
  return new ScriptedOAuthStore(NOW,maximumEntries,268435456L);
 }
 @Override protected void setAuthorityHealthy(@NonNull OAuthAuthorizationServerStore store,boolean healthy){((ScriptedOAuthStore)store).setHealthy(healthy);}
 @Override protected void advanceAuthorityTo(@NonNull OAuthAuthorizationServerStore store,@NonNull Instant instant){
  ((ScriptedOAuthStore)store).setTime(instant);
 }
 @Override protected void rotateClockGeneration(@NonNull OAuthAuthorizationServerStore store){
  ((ScriptedOAuthStore)store).rotateClockGeneration();
 }
 @Override protected void rotateRecoveryGeneration(@NonNull OAuthAuthorizationServerStore store){
  ((ScriptedOAuthStore)store).rotateRecoveryGeneration();
 }
}
