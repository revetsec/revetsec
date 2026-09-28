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

package com.revetsec.jose;

import javax.annotation.concurrent.Immutable;

/**
 * An abstract sealed class that declares no constructor, so javac gives it an implicit public one. R1's implicit
 * constructor check reports it, and the sealed-constructor rule (M2-10 item 6), which checks constructors written in
 * the source, does not report it a second time. Control: its permitted subclass is final.
 *
 * @since 1.0.0
 */
@Immutable
public abstract sealed class ImplicitHolderFixture permits FinalHolderFixture {
}

/**
 * Control: final and package-private.
 */
final class FinalHolderFixture extends ImplicitHolderFixture {
}
