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

package com.revetsec;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.List;

public final class BuilderConventionsFixture {
	private BuilderConventionsFixture() { }
	public boolean isReady() { return false; }
	@Override public boolean equals(@Nullable Object value) { return this == value; }
	@Override public int hashCode() { return 0; }
	public static final class Builder {
		private Builder() { }
		public @NonNull Builder attempts(int value) { return this; }
		public @NonNull Builder token(@NonNull String value) { return this; }
		public @NonNull Builder values(@NonNull List<@Nullable String> value) { return this; }
		public @NonNull Builder put(@NonNull String value) { return this; }
		public @NonNull Builder route(@Nullable String value) { return this; }
		public @NonNull BuilderConventionsFixture build() { return new BuilderConventionsFixture(); }
	}
}
