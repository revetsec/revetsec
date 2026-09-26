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

package com.revetsec.oauth;

import com.revetsec.CompliantFixture;
import com.revetsec.RogueFixtureException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

/**
 * Seeded violations: an observer interface with a constant, a disabledInstance() of the wrong type, another static
 * method, an abstract hook, a hook that returns a value, and hook parameters outside the allowlist.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface LeakyObserver {
	/**
	 * Seeded violation: observers declare no fields.
	 *
	 * @since 1.0.0
	 */
	@NonNull String NAME = "leaky";

	/**
	 * Seeded violation: it must return the observer itself.
	 *
	 * @return an object
	 * @since 1.0.0
	 */
	static @NonNull Object disabledInstance() {
		return NAME;
	}

	/**
	 * Seeded violation: a static method other than disabledInstance().
	 *
	 * @return never
	 * @since 1.0.0
	 */
	static @NonNull LeakyObserver fromDefaults() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Seeded violation: an abstract hook, which every application would have to implement.
	 *
	 * @param name a name
	 * @since 1.0.0
	 */
	void didStart(@Nullable String name);

	/**
	 * Seeded violation: a hook that returns a value, which Revetsec would have to act on.
	 *
	 * @return a value
	 * @since 1.0.0
	 */
	default @NonNull Boolean didFinish() {
		return Boolean.TRUE;
	}

	/**
	 * Seeded violations: one parameter of each kind outside the allowlist.
	 *
	 * @param attempts a primitive
	 * @param names    an array
	 * @param scopes   a collection
	 * @param state    an Optional
	 * @param detail   an Object
	 * @param cause    a JDK exception
	 * @param amount   a number that is not a boxed primitive
	 * @param flag     a boxed character, which is not a number
	 * @param fixture  a Revetsec type that is not an exception
	 * @param rogue    an exception that does not extend RevetsecException
	 * @since 1.0.0
	 */
	default void didFail(int attempts, @NonNull String @Nullable [] names, @Nullable List<@NonNull String> scopes,
			@Nullable Optional<@NonNull String> state, @Nullable Object detail, @Nullable IOException cause,
			@Nullable BigDecimal amount, @Nullable Character flag, @Nullable CompliantFixture fixture,
			@Nullable RogueFixtureException rogue) {
	}

	/**
	 * Seeded violation: a type variable can stand for any type.
	 *
	 * @param value a value
	 * @param <T>   its type
	 * @since 1.0.0
	 */
	default <T> void didSee(@Nullable T value) {
	}
}
