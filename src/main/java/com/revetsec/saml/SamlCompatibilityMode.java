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
package com.revetsec.saml;

import javax.annotation.concurrent.Immutable;

/**
 * Explicit per-connection SAML compatibility modes. All are disabled by default.
 *
 * @since 1.0.0
 */
@Immutable
public enum SamlCompatibilityMode {
    /** Accept RSA-SHA1 XML and Redirect signatures from this configured IdP. */
    SHA1_SIGNATURES,
    /** Accept AES-CBC encryption only under a verified signed Response. */
    AES_CBC_ENCRYPTION,
    /** Permit the separate unsolicited-login method with its tighter age bound. */
    UNSOLICITED_RESPONSES
}
