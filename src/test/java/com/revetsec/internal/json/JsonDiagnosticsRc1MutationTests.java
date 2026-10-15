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

package com.revetsec.internal.json;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Parser diagnostics stay useful without rendering parsed or malformed input. */
final class JsonDiagnosticsRc1MutationTests {
    @Test
    void documentsAndBothOutcomesHaveNonblankDiagnosticsWithoutInputData() {
        String secret = "TEST-ONLY-private-json-diagnostic-value";
        String valid = "{\"value\":\"" + secret + "\",\"number\":123.0}";
        String malformed = "{\"value\":\"" + secret + "\",\"bad\":[1,]}";
        JsonLimits limits = new JsonLimits(512, 4, 20, 128, 16, 20, false);
        JsonParseResult.Succeeded succeeded = assertInstanceOf(JsonParseResult.Succeeded.class,
                JsonCodec.parseResult(valid.getBytes(StandardCharsets.UTF_8), limits));
        JsonParseResult.Rejected rejected = assertInstanceOf(JsonParseResult.Rejected.class,
                JsonCodec.parseResult(malformed.getBytes(StandardCharsets.UTF_8), limits));
        for (String diagnostic : List.of(succeeded.getDocument().toString(),
                succeeded.toString(), rejected.toString())) {
            assertFalse(diagnostic.isBlank());
            assertFalse(diagnostic.contains(secret));
            assertFalse(diagnostic.contains(valid));
            assertFalse(diagnostic.contains(malformed));
        }
    }
}
