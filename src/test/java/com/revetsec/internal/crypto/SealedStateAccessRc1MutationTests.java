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

package com.revetsec.internal.crypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import java.util.concurrent.locks.ReentrantLock;
/** State fault probes restore the singleton immediately; isolation prevents concurrent users during the probe. */
@Isolated("controlled sealed-state singleton installation probes")
final class SealedStateAccessRc1MutationTests {
 @Test void installedHookReportsBothActualStates()throws Exception{
  SealedStateAccess.Operations installed=SealedStateAccess.get();var field=SealedStateAccess.class.getDeclaredField("operations");field.setAccessible(true);
  try{Assertions.assertTrue(SealedStateAccess.isInstalled());field.set(null,null);Assertions.assertFalse(SealedStateAccess.isInstalled());}finally{field.set(null,installed);}
  Assertions.assertTrue(SealedStateAccess.isInstalled());
 }
 @Test void duplicateInstallationAlwaysReleasesItsLock()throws Exception{
  SealedStateAccess.Operations installed=SealedStateAccess.get();var field=SealedStateAccess.class.getDeclaredField("SET_LOCK");field.setAccessible(true);ReentrantLock lock=(ReentrantLock)field.get(null);
  try{Assertions.assertThrows(IllegalStateException.class,()->SealedStateAccess.set(installed));Assertions.assertFalse(lock.isHeldByCurrentThread());Assertions.assertFalse(lock.isLocked());}
  finally{while(lock.isHeldByCurrentThread())lock.unlock();}
 }
 @Test void jwtDeadlineOperationsDuplicateInstallationReleasesItsLock()throws Exception{
  var installed=com.revetsec.internal.jose.JwtValidationAccess.get();var field=com.revetsec.internal.jose.JwtValidationAccess.class.getDeclaredField("SET_LOCK");field.setAccessible(true);ReentrantLock lock=(ReentrantLock)field.get(null);
  try{Assertions.assertThrows(IllegalStateException.class,()->com.revetsec.internal.jose.JwtValidationAccess.set(installed));Assertions.assertFalse(lock.isHeldByCurrentThread());Assertions.assertFalse(lock.isLocked());}
  finally{while(lock.isHeldByCurrentThread())lock.unlock();}
 }

}
