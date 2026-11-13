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
package com.revetsec.internal.webauthn;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** Constructor grammar calibration for malformed states that authenticated record decoding must reject. */
final class WebAuthnCredentialIndexBoundaryTests {
    @Test void stateRejectsEveryIndependentHandleCountIdAndOrderingBoundary() throws Exception {
        Constructor<WebAuthnCredentialIndex.State> constructor=WebAuthnCredentialIndex.State.class
                .getDeclaredConstructor(byte[].class,List.class);
        constructor.setAccessible(true);

        rejected(constructor,new byte[0],List.of());
        rejected(constructor,new byte[65],List.of());
        List<byte[]> tooMany=new ArrayList<>();
        for(int index=0;index<=WebAuthnCredentialIndex.MAXIMUM_CREDENTIALS;index++)
            tooMany.add(new byte[]{(byte)index});
        rejected(constructor,new byte[]{1},tooMany);
        rejected(constructor,new byte[]{1},List.of(new byte[0]));
        rejected(constructor,new byte[]{1},List.of(new byte[1_024]));
        rejected(constructor,new byte[]{1},List.of(new byte[]{2},new byte[]{1}));
        rejected(constructor,new byte[]{1},List.of(new byte[]{1},new byte[]{1}));
    }

    private static void rejected(
            @NonNull Constructor<WebAuthnCredentialIndex.@NonNull State> constructor,
            byte @NonNull [] handle,@NonNull List<byte @NonNull []> ids) {
        assertThrows(java.lang.reflect.InvocationTargetException.class,()->constructor.newInstance(handle,ids));
    }
}
