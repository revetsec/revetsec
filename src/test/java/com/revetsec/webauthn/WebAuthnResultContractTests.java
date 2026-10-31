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

package com.revetsec.webauthn;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exact public shape of confirmed-but-unreleased outcomes, without proof construction. */
final class WebAuthnResultContractTests {
	@Test void everyMutationFamilyHasOneRestrictedPayloadFreeReconciliationSingleton() throws ReflectiveOperationException {
		for(Class<?> family:List.of(WebAuthnRegistrationRequestResult.class,
                WebAuthnAuthenticationRequestResult.class,
                WebAuthnRegistrationResult.class,
                WebAuthnAuthenticationResult.class,
                WebAuthnCredentialRemovalResult.class,
                WebAuthnAccountDisableResult.class)) {
			Class<?> variant=List.of(family.getDeclaredClasses()).stream()
					.filter(type->type.getSimpleName().equals("ReconciliationRequired")).findFirst().orElseThrow();
			assertTrue(Modifier.isPublic(variant.getModifiers()));
			assertTrue(Modifier.isFinal(variant.getModifiers()));
			assertEquals(0,variant.getDeclaredFields().length);
			assertEquals(0,variant.getDeclaredMethods().length);
			assertEquals(0,variant.getConstructors().length);
			Constructor<?> constructor=variant.getDeclaredConstructors()[0];
			assertTrue(Modifier.isPrivate(constructor.getModifiers()));
			assertEquals(0,constructor.getParameterCount());
			Method factory=family.getDeclaredMethod("reconciliationRequired");
			assertTrue(Modifier.isStatic(factory.getModifiers()));
			assertFalse(Modifier.isPublic(factory.getModifiers()));
			assertFalse(Modifier.isProtected(factory.getModifiers()));
			Object first=factory.invoke(null),second=factory.invoke(null);
			assertSame(first,second);
			assertEquals(variant,first.getClass());
			assertEquals(family.getSimpleName()+"{<redacted>}",first.toString());
			assertTrue(Arrays.asList(family.getPermittedSubclasses()).contains(variant));
		}
	}

    @Test void pureListingKeepsItsTwoSnapshotVariants() {
        assertEquals(Set.of("Listed","Unavailable"),Arrays.stream(WebAuthnCredentialListResult.class.getPermittedSubclasses()).map(Class::getSimpleName).collect(Collectors.toSet()));
    }
}
