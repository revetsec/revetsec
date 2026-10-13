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
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScimM10BindingTests {
    private static final @NonNull ScimFilterLimits LIMITS=ScimFilterLimits.builder().build();
    private static final @NonNull String GROUP="urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final @NonNull String USER="urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String ENTERPRISE="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    @Test void canonicalBindingMakesImplicitValueExplicitWithoutGrantingValuePathPermission() {
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("USERNAME",Set.of(ScimComparisonOperator.EQ),"emails",Set.of(ScimComparisonOperator.CO)))
                .allowedPresence(Set.of("name")).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).build();
        ScimFilterBinding binding=binding(ScimResourceType.userInstance(),policy,ScimCompatibility.strictInstance());
        assertEquals("userName eq \"Ada\" and emails.value co \"@example.invalid\"",accepted(binding,"USERNAME EQ \"Ada\" and emails CO \"@example.invalid\""));
        assertEquals("name pr",accepted(binding,"NAME PR"));
        rejected(binding,"emails[type eq \"work\"]");
        rejected(binding,"userName eq \"Ada\" or emails co \"x\"");
        rejected(binding,"name eq \"Ada\"");
    }

    @Test void schemaQualifiedPathsCanonicalizeAndUnknownExtensionAttributesNeverBind() {
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of(USER+":userName",Set.of(ScimComparisonOperator.EQ),ENTERPRISE+":department",Set.of(ScimComparisonOperator.EQ))).build();
        ScimFilterBinding binding=binding(ScimResourceType.userInstance(),policy,ScimCompatibility.strictInstance());
        assertEquals("userName eq \"a\"",accepted(binding,USER+":USERNAME eq \"a\""));
        assertEquals(ENTERPRISE+":department eq \"research\"",accepted(binding,ENTERPRISE.toUpperCase(java.util.Locale.ROOT)+":DEPARTMENT eq \"research\""));
        rejected(binding,"department eq \"research\"");
        rejected(binding,ENTERPRISE+":id eq \"a\"");
        rejected(binding,"urn:unknown:department eq \"research\"");
    }

    @Test void hiddenAndUnknownPolicyTargetsAreConfigurationErrorsAndAliasCollisionsReject() {
        for (String path : new String[]{"password","password.value","missing",ENTERPRISE+":id"})
            assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.userInstance(),ScimFilterPolicy.builder().allowedPresence(Set.of(path)).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.userInstance(),ScimFilterPolicy.builder().allowedComparisons(Map.of("userName",Set.of(ScimComparisonOperator.EQ),USER+":userName",Set.of(ScimComparisonOperator.EQ))).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.userInstance(),ScimFilterPolicy.builder().allowedComparisons(Map.of("active",Set.of(ScimComparisonOperator.CO))).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.userInstance(),ScimFilterPolicy.builder().allowedValuePaths(Map.of("name",ScimFilterPolicy.builder().allowedPresence(Set.of("givenName")).build())).build(),ScimCompatibility.strictInstance()));
    }

    @Test void literalsAreTypeBoundAndUnsupportedOperatorsCannotEnterApprovedTrees() {
        ScimResourceType type=typed();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("flag",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE),
                "integer",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.GE),"decimal",Set.of(ScimComparisonOperator.LT),
                "date",Set.of(ScimComparisonOperator.EQ),"binary",Set.of(ScimComparisonOperator.EQ),"link",Set.of(ScimComparisonOperator.EQ),
                "text",Set.of(ScimComparisonOperator.CO))).build();
        ScimFilterBinding binding=binding(type,policy,ScimCompatibility.strictInstance());
        for (String expression : new String[]{"flag eq true","flag ne null","integer ge 1e2","decimal lt 1.5","date eq \"2000-02-29T24:00:00+14:00\"","binary eq \"Zg\"","link eq \"../Users/1\"","text co \"x\""})
            assertNotNull(accepted(binding,expression));
        for (String expression : new String[]{"flag eq \"true\"","flag eq 1","flag ge true","integer eq 1.2","integer eq \"1\"","decimal lt null","date eq \"2001-02-29T00:00:00Z\"","binary eq \"Zh\"","link eq \"bad link\"","text co null"})
            rejected(binding,expression);
    }

    @Test void fullTreeAndEachNestedPolicyComparisonCapAreEnforced() {
        ScimFilterPolicy inner=ScimFilterPolicy.builder().allowedComparisons(Map.of("type",Set.of(ScimComparisonOperator.EQ),"value",Set.of(ScimComparisonOperator.CO)))
                .allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).maximumComparisons(1).build();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("userName",Set.of(ScimComparisonOperator.EQ)))
                .allowedLogicalOperators(Set.of(ScimLogicalOperator.AND,ScimLogicalOperator.OR,ScimLogicalOperator.NOT)).allowedValuePaths(Map.of("emails",inner)).maximumComparisons(2).build();
        ScimFilterBinding binding=binding(ScimResourceType.userInstance(),policy,ScimCompatibility.strictInstance());
        assertEquals("userName eq \"a\" and userName eq \"b\"",accepted(binding,"userName eq \"a\" and userName eq \"b\""));
        rejected(binding,"userName eq \"a\" and userName eq \"b\" and userName eq \"c\"");
        assertEquals("emails[type eq \"work\"]",accepted(binding,"emails[type eq \"work\"]"));
        rejected(binding,"emails[type eq \"work\" and value co \"x\"]");
        rejected(binding,"userName eq \"a\" or active eq true");
    }

    @Test void booleanStringsAreNarrowAndActualCompatibilityEventsOnlyDescribeRewrites() {
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("active",Set.of(ScimComparisonOperator.EQ),"userName",Set.of(ScimComparisonOperator.EQ))).build();
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS)).build();
        ScimFilterBinding binding=binding(ScimResourceType.userInstance(),policy,compatibility);
        Set<ScimCompatibilityFeature> used=new java.util.LinkedHashSet<>();
        assertEquals("active eq true",assertInstanceOf(ScimFilterParseResult.Succeeded.class,binding.bind("active eq \"true\"",used,new ScimWork(10000))).getFilter().toScimString());
        assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),used);
        used.clear();
        assertEquals("userName eq \"true\"",assertInstanceOf(ScimFilterParseResult.Succeeded.class,binding.bind("userName eq \"true\"",used,new ScimWork(10000))).getFilter().toScimString());
        assertTrue(used.isEmpty());
        for (String value : new String[]{"TRUE","False","yes","1"}) rejected(binding,"active eq \""+value+"\"");
    }

    @Test void rewriteKeepsPredicateAndComparisonWithinSameElementAndChecksNormalizedPolicy() {
        ScimFilterPolicy inner=ScimFilterPolicy.builder().allowedComparisons(Map.of("type",Set.of(ScimComparisonOperator.EQ),"value",Set.of(ScimComparisonOperator.CO)))
                .allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).build();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedValuePaths(Map.of("emails",inner)).build();
        ScimFilterBinding strict=binding(ScimResourceType.userInstance(),policy,ScimCompatibility.strictInstance());
        rejected(strict,"emails[type eq \"work\"].value co \"x\"");
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON)).build();
        ScimFilterBinding enabled=binding(ScimResourceType.userInstance(),policy,compatibility);
        Set<ScimCompatibilityFeature> used=new java.util.LinkedHashSet<>();
        assertEquals("emails[type eq \"work\" and value co \"x\"]",assertInstanceOf(ScimFilterParseResult.Succeeded.class,enabled.bind("emails[type eq \"work\"].value co \"x\"",used,new ScimWork(10000))).getFilter().toScimString());
        assertEquals(Set.of(ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON),used);
        rejected(enabled,"emails[type eq \"work\"].value.child co \"x\"");
        rejected(enabled,"emails[type eq \"work\"].missing co \"x\"");
        rejected(enabled,"emails[type eq \"work\"].value pr");
        rejected(enabled,"emails[type eq \"work\"].value co \"x\" ignored");
        ScimFilterPolicy noAnd=ScimFilterPolicy.builder().allowedValuePaths(Map.of("emails",ScimFilterPolicy.builder().allowedComparisons(inner.getAllowedComparisons()).build())).build();
        rejected(binding(ScimResourceType.userInstance(),noAnd,compatibility),"emails[type eq \"work\"].value co \"x\"");
    }

    @Test void sortingRejectsHiddenOrNonScalarPathsAndUnsupportedFilteringIsExplicit() {
        ScimFilterBinding binding=binding(ScimResourceType.userInstance(),ScimFilterPolicy.rejectAllInstance(),ScimCompatibility.strictInstance());
        assertEquals("emails.value",binding.sort(path("EMAILS")).orElseThrow().toScimString());
        assertEquals("userName",binding.sort(path("USERNAME")).orElseThrow().toScimString());
        assertTrue(binding.sort(path("password")).isEmpty());
        assertTrue(binding.sort(path("name")).isEmpty());
        assertTrue(binding.sort(path("unknown")).isEmpty());
        ScimFilterBinding unsupported=new ScimFilterBinding(ScimResourceType.userInstance(),LIMITS,ScimCompatibility.strictInstance(),ScimFilterPolicy.rejectAllInstance(),false);
        assertEquals(403,assertInstanceOf(ScimFilterParseResult.Rejected.class,unsupported.bind("userName eq \"a\"",new java.util.LinkedHashSet<>(),new ScimWork(10000))).getError().getStatusCode());
        assertInstanceOf(ScimFilterParseResult.Rejected.class,binding.bind("userName eq \"a\"",new java.util.LinkedHashSet<>(),new ScimWork(1)));
    }

    @Test void approvedNestedLogicalAndPresenceTreesRemainCanonicalAndPoliciesRejectEveryAliasScopeMismatch() {
        ScimFilterPolicy inner=ScimFilterPolicy.builder().allowedComparisons(Map.of("type",Set.of(ScimComparisonOperator.EQ),"value",Set.of(ScimComparisonOperator.CO),"$ref",Set.of(ScimComparisonOperator.EQ)))
                .allowedPresence(Set.of("$ref","value")).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND,ScimLogicalOperator.OR,ScimLogicalOperator.NOT)).build();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("displayName",Set.of(ScimComparisonOperator.EQ))).allowedPresence(Set.of("displayName"))
                .allowedValuePaths(Map.of("members",inner)).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND,ScimLogicalOperator.OR,ScimLogicalOperator.NOT)).build();
        ScimFilterBinding bound=binding(ScimResourceType.groupInstance(),policy,ScimCompatibility.strictInstance());
        assertEquals("not(displayName eq \"a\") or displayName pr",accepted(bound,"not(displayName eq \"a\") or displayName pr"));
        assertEquals("members[(type eq \"work\" or type eq \"home\") and not(value co \"spam\")]",accepted(bound,"members[(type eq \"work\" or type eq \"home\") and not(value co \"spam\")]"));
        assertEquals("members[$ref pr]",accepted(bound,"members[$REF pr]"));
        assertEquals("members[$ref eq \"Users/1\"]",accepted(bound,"members[$ref eq \"Users/1\"]"));
        rejected(bound,"members[missing pr]"); rejected(bound,"members[value.child eq \"x\"]"); rejected(bound,"members[type eq \"work\" and missing eq \"x\"]");
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.groupInstance(),ScimFilterPolicy.builder().allowedPresence(Set.of("displayName",GROUP+":displayName")).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.groupInstance(),ScimFilterPolicy.builder().allowedValuePaths(Map.of("members",inner,GROUP+":members",inner)).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.groupInstance(),ScimFilterPolicy.builder().allowedValuePaths(Map.of("members.value",inner)).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.groupInstance(),ScimFilterPolicy.builder().allowedValuePaths(Map.of("members",ScimFilterPolicy.builder().allowedPresence(Set.of(GROUP+":displayName")).build())).build(),ScimCompatibility.strictInstance()));
        assertThrows(IllegalArgumentException.class,() -> binding(ScimResourceType.groupInstance(),ScimFilterPolicy.builder().allowedValuePaths(Map.of("members",ScimFilterPolicy.builder().allowedValuePaths(Map.of("value",inner)).build())).build(),ScimCompatibility.strictInstance()));
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS)).build();
        ScimFilterBinding booleans=binding(ScimResourceType.userInstance(),ScimFilterPolicy.builder().allowedComparisons(Map.of("active",Set.of(ScimComparisonOperator.EQ))).build(),compatibility);
        assertEquals("active eq false",accepted(booleans,"active eq \"false\""));
        boolean succeeded=false;
        for (int available=0;available<=3000;available++) {
            ScimFilterParseResult result=bound.bind("members[(type eq \"work\" or type eq \"home\") and not(value co \"spam\")]",new java.util.LinkedHashSet<>(),new ScimWork(available));
            if (result instanceof ScimFilterParseResult.Succeeded success) { succeeded=true; assertEquals("members[(type eq \"work\" or type eq \"home\") and not(value co \"spam\")]",success.getFilter().toScimString()); }
            else assertFalse(succeeded);
        }
        assertTrue(succeeded);
    }

    private static @NonNull ScimResourceType typed() {
        return ScimResourceType.withName("Typed").endpoint("/Typed").schema(ScimSchema.withId("urn:example:Typed").name("Typed").attributes(List.of(
                ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),
                ScimAttributeDefinition.withName("integer").type(ScimAttributeType.INTEGER).build(),
                ScimAttributeDefinition.withName("decimal").type(ScimAttributeType.DECIMAL).build(),
                ScimAttributeDefinition.withName("date").type(ScimAttributeType.DATE_TIME).build(),
                ScimAttributeDefinition.withName("binary").type(ScimAttributeType.BINARY).caseExact(true).build(),
                ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).caseExact(true).build(),
                ScimAttributeDefinition.withName("text").build())).build()).build();
    }
    private static @NonNull ScimFilterBinding binding(@NonNull ScimResourceType type,@NonNull ScimFilterPolicy policy,@NonNull ScimCompatibility compatibility) { return new ScimFilterBinding(type,LIMITS,compatibility,policy,true); }
    private static @NonNull String accepted(@NonNull ScimFilterBinding binding,@NonNull String expression) { return assertInstanceOf(ScimFilterParseResult.Succeeded.class,binding.bind(expression,new java.util.LinkedHashSet<>(),new ScimWork(10000))).getFilter().toScimString(); }
    private static void rejected(@NonNull ScimFilterBinding binding,@NonNull String expression) { assertInstanceOf(ScimFilterParseResult.Rejected.class,binding.bind(expression,new java.util.LinkedHashSet<>(),new ScimWork(10000)),expression); }
    private static @NonNull ScimAttributePath path(@NonNull String expression) { return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult(expression)).getAttributePath(); }
}
