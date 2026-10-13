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

package com.revetsec.scim;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Registered limit replacement/reset contract and intentionally provider-authored matching outcomes. */
class ScimM10LimitsTests {
    @Test void limitsReplaceCompletelyResetToFreshDefaultsAndCheckEveryRange() {
        ScimFilterLimits filter=ScimFilterLimits.builder().maximumNodes(8).build();
        ScimLimits selected=ScimLimits.builder().maximumBodyBytes(16384).maximumPatchOperations(1).maximumJsonNodes(1000)
                .maximumRawQueryBytes(1).maximumQueryParameters(1).maximumParameterCharacters(256).maximumProjectionPaths(1)
                .maximumPageSize(1).maximumCursorCharacters(1).maximumConditionalHeaderBytes(256).maximumConditionalTags(1)
                .maximumResponseHeaderBytes(512).maximumResponseBytes(2048).maximumWorkUnits(10000).filterLimits(filter).build();
        assertEquals(16384,selected.getMaximumBodyBytes());assertEquals(1,selected.getMaximumPatchOperations());assertEquals(1000,selected.getMaximumJsonNodes());
        assertEquals(1,selected.getMaximumRawQueryBytes());assertEquals(1,selected.getMaximumQueryParameters());assertEquals(256,selected.getMaximumParameterCharacters());
        assertEquals(1,selected.getMaximumProjectionPaths());assertEquals(1,selected.getMaximumPageSize());assertEquals(1,selected.getMaximumCursorCharacters());
        assertEquals(256,selected.getMaximumConditionalHeaderBytes());assertEquals(1,selected.getMaximumConditionalTags());assertEquals(512,selected.getMaximumResponseHeaderBytes());
        assertEquals(2048,selected.getMaximumResponseBytes());assertEquals(10000,selected.getMaximumWorkUnits());assertSame(filter,selected.getFilterLimits());assertFalse(selected.toString().contains("16384"));
        ScimLimits reset=ScimLimits.builder().maximumBodyBytes(null).maximumPatchOperations(null).maximumJsonNodes(null)
                .maximumRawQueryBytes(null).maximumQueryParameters(null).maximumParameterCharacters(null).maximumProjectionPaths(null)
                .maximumPageSize(null).maximumCursorCharacters(null).maximumConditionalHeaderBytes(null).maximumConditionalTags(null)
                .maximumResponseHeaderBytes(null).maximumResponseBytes(null).maximumWorkUnits(null).filterLimits(null).build();
        assertEquals(1048576,reset.getMaximumBodyBytes());assertEquals(1000,reset.getMaximumPatchOperations());assertEquals(100000,reset.getMaximumJsonNodes());
        assertEquals(32768,reset.getMaximumRawQueryBytes());assertEquals(64,reset.getMaximumQueryParameters());assertEquals(8192,reset.getMaximumParameterCharacters());
        assertEquals(128,reset.getMaximumProjectionPaths());assertEquals(1000,reset.getMaximumPageSize());assertEquals(2048,reset.getMaximumCursorCharacters());
        assertEquals(8192,reset.getMaximumConditionalHeaderBytes());assertEquals(64,reset.getMaximumConditionalTags());assertEquals(16384,reset.getMaximumResponseHeaderBytes());
        assertEquals(8388608,reset.getMaximumResponseBytes());assertEquals(1000000,reset.getMaximumWorkUnits());assertEquals(128,reset.getFilterLimits().getMaximumNodes());
        for(ScimLimits.Builder invalid:List.of(ScimLimits.builder().maximumBodyBytes(16383),ScimLimits.builder().maximumPatchOperations(0),ScimLimits.builder().maximumJsonNodes(999),
                ScimLimits.builder().maximumRawQueryBytes(0),ScimLimits.builder().maximumQueryParameters(0),ScimLimits.builder().maximumParameterCharacters(255),ScimLimits.builder().maximumProjectionPaths(0),
                ScimLimits.builder().maximumPageSize(0),ScimLimits.builder().maximumCursorCharacters(0),ScimLimits.builder().maximumConditionalHeaderBytes(255),ScimLimits.builder().maximumConditionalTags(0),
                ScimLimits.builder().maximumResponseHeaderBytes(511),ScimLimits.builder().maximumResponseBytes(2047),ScimLimits.builder().maximumWorkUnits(9999)))assertThrows(IllegalArgumentException.class,invalid::build);
    }
    @Test @SuppressWarnings("NullAway") // Deliberate provider factory misuse is a programming error.
    void matchingOutcomesHaveClosedLeavesAndNoImplicitStringStrategy() {
        for(boolean matched:List.of(true,false)) {
            ScimStringMatchResult.Matched result=assertInstanceOf(ScimStringMatchResult.Matched.class,ScimStringMatchResult.fromMatched(matched));
            assertEquals(matched,result.isMatched());assertFalse(result.toString().contains("true"));assertFalse(result.toString().contains("false"));
        }
        assertInstanceOf(ScimStringMatchResult.Unsupported.class,ScimStringMatchResult.unsupportedInstance());assertNotNull(ScimStringMatchResult.unsupportedInstance().toString());
        assertThrows(NullPointerException.class,()->ScimStringMatchResult.fromMatched(null));
        for(Class<?> leaf:ScimStringMatchResult.class.getPermittedSubclasses())for(var constructor:leaf.getDeclaredConstructors())assertFalse(java.lang.reflect.Modifier.isPublic(constructor.getModifiers()));
    }
    @Test void fixedOutcomesRedactDiagnosticsAndUseIdentityEquality() {
        ScimError error=ScimError.invalidValueInstance();
        for(Object result:List.of(ScimContentTypeResult.Accepted.INSTANCE,ScimIfMatchResult.Satisfied.INSTANCE,ScimIfNoneMatchResult.Proceed.INSTANCE,ScimIfNoneMatchResult.NotModified.INSTANCE,
                new ScimQueryParseResult.Rejected(error),new ScimAttributeSelectionResult.Rejected(error),new ScimResponseResult.Rejected(error),new ScimIfMatchResult.Rejected(error),new ScimIfNoneMatchResult.Rejected(error),new ScimContentTypeResult.Rejected(error))) {
            assertFalse(result.toString().contains(error.getDetail()));assertFalse(result.toString().contains("cause"));
        }
        assertNotEquals(new ScimIfMatchResult.Rejected(error),new ScimIfMatchResult.Rejected(error));
    }
}
