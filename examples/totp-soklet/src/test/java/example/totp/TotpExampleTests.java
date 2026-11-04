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
package example.totp;

import org.junit.jupiter.api.Test;

/** Runs the route, lifecycle and loopback checks through the normal Maven test phase. */
final class TotpExampleTests {
  @Test void totpExampleChecks() throws Exception {
    TotpExampleChecks.main(new String[0]);
  }

  @Test void totpExampleLifecycleChecks() throws Exception {
    TotpExampleLifecycleChecks.main(new String[0]);
  }

  @Test void totpExampleSocketChecks() throws Exception {
    TotpExampleSocketChecks.main(new String[0]);
  }
}
