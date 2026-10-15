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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Hand-enumerated outcomes: no production transformation computes the oracle. */
class ScimM11PatchApplicationTests {
    private static final @NonNull Object CONTEXT=new Object();
    private static final @NonNull String USER=ScimSchema.userInstance().getId();
    private static final @NonNull String ENTERPRISE=ScimSchema.enterpriseUserInstance().getId();
    private static final @NonNull ScimStringMatching EXACT=(path,definition,operator,value,literal) -> {
        String a=definition.isCaseExact() ? value : value.toLowerCase(java.util.Locale.ROOT);
        String b=definition.isCaseExact() ? literal : literal.toLowerCase(java.util.Locale.ROOT);
        int comparison=a.compareTo(b);
        return ScimStringMatchResult.fromMatched(switch(operator) {
            case EQ -> comparison == 0; case NE -> comparison != 0; case CO -> a.contains(b);
            case SW -> a.startsWith(b); case EW -> a.endsWith(b); case GT -> comparison > 0;
            case GE -> comparison >= 0; case LT -> comparison < 0; case LE -> comparison <= 0;
        });
    };

    @Test void orderedOperationsAreAtomicAndLateFailureLeavesTheOriginalUntouched() {
        ScimResource old=user("\"displayName\":\"old\"");
        String original=old.getDocument().toJson();
        ScimPatchRequest request=request(old.getResourceType(),
                op(0,ScimPatchOperationType.REPLACE,"displayName","\"new\""),
                op(1,ScimPatchOperationType.REPLACE,"id","\"forged\""));
        rejected(apply(old,request),ScimErrorType.MUTABILITY);
        assertEquals(original,old.getDocument().toJson());
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),
                op(0,ScimPatchOperationType.REPLACE,"displayName","\"new\""),
                op(1,ScimPatchOperationType.REMOVE,"displayName",null),
                op(2,ScimPatchOperationType.ADD,"displayName","\"final\""))));
        assertEquals("final",result.getResource().getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        assertTrue(result.isModified()); assertEquals(Set.of(path("displayName")),result.getModifiedAttributePaths());
        assertEquals(original,old.getDocument().toJson());
    }

    @Test void finalNoOpRetainsIdentityTimestampAndVersionButKeepsAuthorizationTargets() {
        ScimResource old=user("\"displayName\":\"old\",\"meta\":{\"version\":\"W/\\\"1\\\"\",\"lastModified\":\"2026-01-01T00:00:00Z\"}");
        ScimPatchRequest request=request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"displayName","\"new\""),
                op(1,ScimPatchOperationType.REPLACE,"displayName","\"old\""));
        ScimPatchResult result=success(apply(old,request));
        assertFalse(result.isModified()); assertSame(old,result.getResource());
        assertEquals("W/\"1\"",result.getResource().getVersion().orElseThrow());
        assertEquals(Set.of(path("displayName")),result.getRequestedAttributePaths());
        assertEquals(Set.of(path("displayName")),result.getSuppliedAttributePaths());
        assertTrue(result.getModifiedAttributePaths().isEmpty());
        assertSame(CONTEXT,result.getSemanticContext());
        assertThrows(UnsupportedOperationException.class,() -> result.getModifiedAttributePaths().add(path("active")));
    }

    @Test void addAndReplaceSingleComplexMergeOnlySuppliedChildren() {
        ScimResource old=user("\"name\":{\"givenName\":\"Ada\",\"familyName\":\"Lovelace\"}");
        for (ScimPatchOperationType kind : List.of(ScimPatchOperationType.ADD,ScimPatchOperationType.REPLACE)) {
            ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,kind,"name","{\"givenName\":\"Augusta\"}"))));
            assertEquals(json("{\"givenName\":\"Augusta\",\"familyName\":\"Lovelace\"}"),result.getResource().getDocument().find("name").orElseThrow());
            assertEquals(Set.of(path("name"),path("name.givenName")),result.getModifiedAttributePaths());
        }
    }

    @Test void noPathWritesApplyNestedChildrenAndExplicitNullWithoutClearingOmittedFields() {
        ScimResource old=user("\"displayName\":\"old\",\"name\":{\"givenName\":\"Ada\",\"familyName\":\"Lovelace\"}");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,null,
                "{\"displayName\":null,\"name\":{\"givenName\":\"Augusta\"},\"active\":false}"))));
        assertFalse(result.getResource().getDocument().getMembers().containsKey("displayName"));
        assertEquals(json("{\"givenName\":\"Augusta\",\"familyName\":\"Lovelace\"}"),result.getResource().getDocument().find("name").orElseThrow());
        assertEquals("Ada",ScimUser.fromResource(result.getResource()).getUserName());
        assertFalse(ScimUser.fromResource(result.getResource()).isActive().orElseThrow());
    }

    @Test void missingSimpleReplaceCreatesAndMissingRemoveIsNoOp() {
        ScimResource old=user("");
        assertEquals("created",success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"displayName","\"created\""))))
                .getResource().getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        for (String target : List.of("displayName","name.givenName","emails.value")) {
            ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REMOVE,target,null))));
            assertSame(old,result.getResource()); assertFalse(result.isModified());
        }
    }

    @Test void requiredRemovalRejectsImmediatelyAndCannotBeRescuedByALaterOperation() {
        ScimResource old=user("");
        ScimServiceProvider provider=publicProvider(old.getResourceType());
        ScimPatchOperation remove=op(0,ScimPatchOperationType.REMOVE,"userName",null);
        rejected(publicApply(provider,old,remove),ScimErrorType.MUTABILITY);
        rejected(publicApply(provider,old,op(0,ScimPatchOperationType.ADD,"displayName","\"candidate\""),remove,
                op(2,ScimPatchOperationType.ADD,"userName","\"new\"")),ScimErrorType.MUTABILITY);
        assertEquals("Ada",ScimUser.fromResource(old).getUserName());
        assertTrue(old.getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).isEmpty());
        for (ScimPatchOperationType kind : List.of(ScimPatchOperationType.ADD,ScimPatchOperationType.REPLACE)) {
            rejected(publicApply(provider,old,op(0,kind,"userName","null")),ScimErrorType.MUTABILITY);
            rejected(publicApply(provider,old,op(0,kind,"userName","\"\"")),ScimErrorType.MUTABILITY);
        }
    }

    @Test void requiredArraysCannotBeRemovedEmptiedOrLoseTheirLastFilteredElement() {
        ScimResourceType type=requiredType();
        ScimServiceProvider provider=publicProvider(type);
        ScimResource old=requiredResource(type);
        for (String target : List.of("codes","rows")) {
            rejected(publicApply(provider,old,op(0,ScimPatchOperationType.REMOVE,target,null)),ScimErrorType.MUTABILITY);
            rejected(publicApply(provider,old,op(0,ScimPatchOperationType.REPLACE,target,"[]")),ScimErrorType.MUTABILITY);
            for (ScimPatchOperationType kind : List.of(ScimPatchOperationType.ADD,ScimPatchOperationType.REPLACE))
                rejected(publicApply(provider,old,op(0,kind,target,"null")),ScimErrorType.MUTABILITY);
            assertFalse(success(publicApply(provider,old,op(0,ScimPatchOperationType.ADD,target,"[]"))).isModified());
        }
        ScimPatchOperation remove=filtered(0,ScimPatchOperationType.REMOVE,"rows","code eq \"one\"",null,null);
        rejected(publicApply(provider,old,remove),ScimErrorType.MUTABILITY);
        rejected(publicApply(provider,old,remove,op(1,ScimPatchOperationType.ADD,"rows","[{\"code\":\"restored\"}]")),ScimErrorType.MUTABILITY);
        rejected(publicApply(provider,old,filtered(0,ScimPatchOperationType.REPLACE,"rows","code eq \"one\"",null,"null")),ScimErrorType.MUTABILITY);
        assertFalse(success(publicApply(provider,old,filtered(0,ScimPatchOperationType.REMOVE,"rows","code eq \"absent\"",null,null))).isModified());
        ScimResource two=resource(type,"\"codes\":[\"one\"],\"rows\":[{\"code\":\"one\"},{\"code\":\"two\"}]");
        assertEquals(json("[{\"code\":\"two\"}]"),success(publicApply(provider,two,remove)).getResource().getDocument().find("rows").orElseThrow());
    }

    @Test void requiredChildrenRejectTheirOwnRemovalButOptionalContainersMayDisappear() {
        ScimResourceType type=requiredType();
        ScimServiceProvider provider=publicProvider(type);
        ScimResource old=requiredResource(type);
        for (ScimPatchOperation operation : List.of(op(0,ScimPatchOperationType.REMOVE,"details.code",null),
                op(0,ScimPatchOperationType.REPLACE,"details","{\"code\":null}"),
                op(0,ScimPatchOperationType.REPLACE,"details.code","\"\""),
                op(0,ScimPatchOperationType.REMOVE,"optionalRows.code",null),
                filtered(0,ScimPatchOperationType.REMOVE,"optionalRows","code eq \"one\"","code",null),
                filtered(0,ScimPatchOperationType.REPLACE,"optionalRows","code eq \"one\"","code","null")))
            rejected(publicApply(provider,old,operation),ScimErrorType.MUTABILITY);
        ScimPatchResult removed=success(publicApply(provider,old,op(0,ScimPatchOperationType.REMOVE,"details",null),
                filtered(1,ScimPatchOperationType.REMOVE,"optionalRows","code eq \"one\"",null,null)));
        assertTrue(removed.getResource().getDocument().find("details").isEmpty());
        assertEquals(json("[]"),removed.getResource().getDocument().find("optionalRows").orElseThrow());
        ScimResource absent=resource(type,"\"codes\":[\"one\"],\"rows\":[{\"code\":\"one\"}]");
        assertFalse(success(publicApply(provider,absent,op(0,ScimPatchOperationType.REMOVE,"details.code",null),
                filtered(1,ScimPatchOperationType.REMOVE,"optionalRows","code eq \"absent\"","code",null))).isModified());
        // A newly introduced optional complex still needs its required child at final validation.
        rejected(publicApply(provider,absent,op(0,ScimPatchOperationType.ADD,"details","{\"note\":\"new\"}")),ScimErrorType.INVALID_VALUE);
    }

    @Test void filteredNoTargetFailsAddReplaceAndRemoveIsAnAtomicNoOp() {
        ScimResource old=user("\"emails\":[{\"value\":\"work@example.invalid\",\"type\":\"work\"}]");
        for (ScimPatchOperationType kind : List.of(ScimPatchOperationType.ADD,ScimPatchOperationType.REPLACE))
            rejected(apply(old,request(old.getResourceType(),filtered(0,kind,"emails","type eq \"home\"","value","\"home@example.invalid\""))),ScimErrorType.NO_TARGET);
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","type eq \"home\"",null,null))));
        assertFalse(result.isModified()); assertSame(old,result.getResource());
        ScimResource absent=user("");
        assertFalse(success(apply(absent,request(absent.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","type eq \"home\"",null,null)))).isModified());
    }

    @Test void selectorsUseSameElementBooleanLogicAndAttributeAwareStrategy() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\",\"type\":\"work\"},{\"value\":\"b\",\"type\":\"home\"},{\"value\":\"c\",\"type\":\"work\"}]");
        AtomicInteger calls=new AtomicInteger();
        ScimStringMatching strategy=(target,definition,operator,value,literal) -> {
            assertTrue(target.toScimString().startsWith("emails.")); calls.incrementAndGet();
            return EXACT.match(target,definition,operator,value,literal);
        };
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails",
                "type eq \"WORK\" and not (value eq \"c\" or value eq \"b\")",null,null)),ScimCompatibility.strictInstance(),strategy,new ScimWork(1_000_000)));
        assertEquals(json("[{\"value\":\"b\",\"type\":\"home\"},{\"value\":\"c\",\"type\":\"work\"}]"),result.getResource().getDocument().find("emails").orElseThrow());
        assertEquals(9,calls.get());
    }

    @Test void unsupportedMatchingRejectsTheWholeTransformationEvenInAnUnselectedBooleanBranch() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\",\"type\":\"work\"}]");
        ScimStringMatching strategy=(target,definition,operator,value,literal) -> target.getSubAttributeName().orElseThrow().equals("value")
                ? ScimStringMatchResult.unsupportedInstance() : ScimStringMatchResult.fromMatched(false);
        rejected(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"displayName","\"new\""),
                filtered(1,ScimPatchOperationType.REMOVE,"emails","type eq \"x\" and value eq \"a\"",null,null)),
                ScimCompatibility.strictInstance(),strategy,new ScimWork(1_000_000)),ScimErrorType.INVALID_FILTER);
        assertTrue(old.getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).isEmpty());
        ScimPatchRequest duplicate=request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"emails","[{\"value\":\"a\",\"type\":\"work\"}]"));
        rejected(apply(old,duplicate,ScimCompatibility.strictInstance(),strategy,new ScimWork(1_000_000)),ScimErrorType.INVALID_FILTER);
    }

    @SuppressWarnings("NullAway") // Deliberately violate the callback contract to calibrate the fault boundary.
    @Test void callbackFaultsBubbleOnlyToTheFacadeBoundary() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\"}]");
        ScimPatchRequest request=request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","value eq \"a\"",null,null));
        assertThrows(IllegalStateException.class,() -> apply(old,request,ScimCompatibility.strictInstance(),
                (target,definition,operator,value,literal) -> { throw new IllegalStateException("private backend data"); },new ScimWork(1_000_000)));
        assertThrows(NullPointerException.class,() -> apply(old,request,ScimCompatibility.strictInstance(),
                (target,definition,operator,value,literal) -> null,new ScimWork(1_000_000)));
    }

    @Test void multivalueAddDeduplicatesUnderTheBoundDefinitionAndPreservesOrderAndMetadata() {
        ScimResource old=user("\"emails\":[{\"value\":\"Ada@EXAMPLE.invalid\",\"type\":\"work\",\"display\":\"saved\"}]");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"emails",
                "[{\"value\":\"ada@example.invalid\",\"type\":\"WORK\",\"display\":\"saved\"},{\"value\":\"b\",\"type\":\"home\"},{\"value\":\"B\",\"type\":\"HOME\"}]"))));
        assertEquals(json("[{\"value\":\"Ada@EXAMPLE.invalid\",\"type\":\"work\",\"display\":\"saved\"},{\"value\":\"b\",\"type\":\"home\"}]"),result.getResource().getDocument().find("emails").orElseThrow());
    }

    @Test void groupAddExistingRetainsMetadataAndUsesExactIdsWithoutCallingTheStrategy() {
        ScimResource old=group("[{\"value\":\"a\",\"display\":\"saved\",\"type\":\"User\"}]");
        ScimStringMatching unusable=(target,definition,operator,value,literal) -> fail("Group identity must use exact IDs.");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"members","[{\"value\":\"a\"},{\"value\":\"A\"}]")),
                ScimCompatibility.strictInstance(),unusable,new ScimWork(1_000_000)));
        assertEquals(json("[{\"value\":\"a\",\"display\":\"saved\",\"type\":\"User\"},{\"value\":\"A\"}]"),result.getResource().getDocument().find("members").orElseThrow());
        ScimPatchResult removed=success(apply(result.getResource(),request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"members","value eq \"A\"",null,null)),
                ScimCompatibility.strictInstance(),unusable,new ScimWork(1_000_000)));
        assertEquals(json("[{\"value\":\"a\",\"display\":\"saved\",\"type\":\"User\"}]"),removed.getResource().getDocument().find("members").orElseThrow());
    }

    @Test void standardGroupSchemaAndUnassignedReferencesPreserveMembershipSemantics() {
        ScimResourceType type=ScimResourceType.withName("Team").endpoint("/Teams").schema(ScimSchema.groupInstance()).build();
        ScimResource old=resource(type,"\"displayName\":\"Team\",\"members\":[{\"value\":\"a\",\"$ref\":\"Users/a\",\"display\":\"saved\"}]");
        ScimPatchResult result=success(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"members","[{\"value\":\"a\",\"$ref\":null},{\"value\":\"A\",\"$ref\":null}]"))));
        assertEquals(json("[{\"value\":\"a\",\"$ref\":\"Users/a\",\"display\":\"saved\"},{\"value\":\"A\"}]"),result.getResource().getDocument().find("members").orElseThrow());
    }

    @Test void addingAnEmptyArrayIsANoOpForAbsentEmptyAndAssignedValues() {
        for (ScimResource old : List.of(user(""),user("\"emails\":[]"),user("\"emails\":[{\"value\":\"a\"}]"))) {
            ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"emails","[]"))));
            assertSame(old,result.getResource()); assertFalse(result.isModified());
        }
    }

    @Test void membersWithoutAssignedIdsDoNotCollapseDifferentReferencesIntoOneValue() {
        ScimResource old=group("[{\"$ref\":\"Users/a\"}]");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"members","[{\"$ref\":\"Users/b\"}]"))));
        assertEquals(json("[{\"$ref\":\"Users/a\"},{\"$ref\":\"Users/b\"}]"),result.getResource().getDocument().find("members").orElseThrow());
        assertFalse(success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"members","[{\"$ref\":\"Users/a\"}]")))).isModified());
    }

    @Test void groupRemoveThenAddRecreatesAndReplacementPreservesOnlySurvivingExactMetadata() {
        ScimResource old=group("[{\"value\":\"a\",\"display\":\"A\"},{\"value\":\"b\",\"display\":\"B\"}]");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"members","value eq \"a\"",null,null),
                op(1,ScimPatchOperationType.ADD,"members","[{\"value\":\"a\"}]"))));
        assertEquals(json("[{\"value\":\"b\",\"display\":\"B\"},{\"value\":\"a\"}]"),result.getResource().getDocument().find("members").orElseThrow());
        ScimPatchResult replaced=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"members","[{\"value\":\"b\"},{\"value\":\"c\"}]"))));
        assertEquals(json("[{\"value\":\"b\",\"display\":\"B\"},{\"value\":\"c\"}]"),replaced.getResource().getDocument().find("members").orElseThrow());
        assertFalse(success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"members","[{\"value\":\"a\"}]")))).isModified());
    }

    @Test void groupProtectedMetadataCannotBeWrittenEvenOnADuplicateAdd() {
        ScimResource old=group("[{\"value\":\"a\",\"display\":\"saved\",\"type\":\"User\"}]");
        for (String value : List.of("[{\"value\":\"a\",\"display\":\"forged\"}]","[{\"value\":\"a\",\"type\":\"Group\"}]"))
            rejected(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"members",value))),ScimErrorType.MUTABILITY);
        rejected(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"members","value eq \"a\"","value","\"b\""))),ScimErrorType.MUTABILITY);
        rejected(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"members","value eq \"a\"","display","\"forged\""))),ScimErrorType.MUTABILITY);
    }

    @Test void primaryTrueInducesChangesToOtherElements() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\",\"type\":\"work\",\"primary\":true},{\"value\":\"b\",\"type\":\"home\"}]");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"emails","type eq \"home\"","primary","true"))));
        assertEquals(json("[{\"value\":\"a\",\"type\":\"work\",\"primary\":false},{\"value\":\"b\",\"type\":\"home\",\"primary\":true}]"),result.getResource().getDocument().find("emails").orElseThrow());
        assertTrue(result.getModifiedAttributePaths().containsAll(Set.of(path("emails"),path("emails.primary"))));
        ScimPatchResult added=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,"emails","[{\"value\":\"c\",\"primary\":true}]"))));
        JsonArray array=(JsonArray)added.getResource().getDocument().find("emails").orElseThrow();
        assertFalse(((JsonObject)array.getElements().get(0)).find("primary").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElseThrow());
        assertTrue(((JsonObject)array.getElements().get(2)).find("primary").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElseThrow());
    }

    @Test void extensionIntroductionAndFinalRemovalUpdateSchemasAndEffectivePaths() {
        ScimResource old=user("");
        ScimPatchResult introduced=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.ADD,ENTERPRISE+":department","\"Research\""))));
        assertEquals(List.of(USER,ENTERPRISE),introduced.getResource().getDocument().find("schemas").map(JsonArray.class::cast).map(array -> array.getElements().stream().map(JsonString.class::cast).map(JsonString::getValue).toList()).orElseThrow());
        assertTrue(introduced.getModifiedAttributePaths().containsAll(Set.of(path("schemas"),path(ENTERPRISE+":department"))));
        ScimPatchResult cleared=success(apply(introduced.getResource(),request(old.getResourceType(),op(0,ScimPatchOperationType.REMOVE,ENTERPRISE+":department",null))));
        assertEquals(List.of(USER),cleared.getResource().getDocument().find("schemas").map(JsonArray.class::cast).map(array -> array.getElements().stream().map(JsonString.class::cast).map(JsonString::getValue).toList()).orElseThrow());
        assertFalse(cleared.getResource().getDocument().getMembers().containsKey(ENTERPRISE));
    }

    @Test void immutableAndReadOnlyFacetsApplyAtEveryNestedPosition() {
        ScimResourceType type=custom();
        ScimResource old=resource(type,"\"label\":\"old\",\"locked\":\"fixed\",\"profile\":{\"code\":\"assigned\",\"server\":\"saved\",\"note\":\"old\"}");
        ScimPatchResult result=success(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"profile","{\"note\":\"new\"}"))));
        assertEquals(json("{\"code\":\"assigned\",\"server\":\"saved\",\"note\":\"new\"}"),result.getResource().getDocument().find("profile").orElseThrow());
        assertFalse(success(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"locked","\"fixed\"")))).isModified());
        for (ScimPatchOperation operation : List.of(op(0,ScimPatchOperationType.REPLACE,"locked","\"changed\""),
                op(0,ScimPatchOperationType.REMOVE,"locked",null),op(0,ScimPatchOperationType.REMOVE,"profile",null),
                op(0,ScimPatchOperationType.REPLACE,"profile.code","null"),op(0,ScimPatchOperationType.REPLACE,"profile.server","\"saved\"")))
            rejected(apply(old,request(type,operation)),ScimErrorType.MUTABILITY);
    }

    @Test void noPositionalTransferOfProtectedCustomArrayDescendants() {
        ScimResourceType type=custom();
        ScimResource old=resource(type,"\"rows\":[{\"code\":\"a\",\"note\":\"old\"}]");
        rejected(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"rows","[{\"note\":\"new\"}]"))),ScimErrorType.MUTABILITY);
        rejected(apply(old,request(type,op(0,ScimPatchOperationType.REMOVE,"rows",null))),ScimErrorType.MUTABILITY);
        rejected(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"rows","note eq \"old\"",null,null))),ScimErrorType.MUTABILITY);
        assertEquals(2,((JsonArray)success(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"rows","[{\"code\":\"b\",\"note\":\"new\"}]"))))
                .getResource().getDocument().find("rows").orElseThrow()).getElements().size());
    }

    @Test void compatibilityUpsertIsLimitedToEmailTypeValueShape() {
        ScimResource old=user("");
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT)).build();
        Set<ScimCompatibilityFeature> features=new LinkedHashSet<>();
        ScimPatchRequest request=request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"emails","type eq \"home\"","value","\"a\""));
        ScimPatchResult result=success(ScimPatchEngine.apply(old,request,compatibility,EXACT,new ScimWork(1_000_000),CONTEXT,features));
        assertEquals(json("[{\"value\":\"a\",\"type\":\"home\"}]"),result.getResource().getDocument().find("emails").orElseThrow());
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT),features);
        for (ScimPatchOperation operation : List.of(filtered(0,ScimPatchOperationType.ADD,"emails","value eq \"a\"","value","\"b\""),
                filtered(0,ScimPatchOperationType.ADD,"emails","type eq \"home\"",null,"{\"value\":\"a\"}"),
                filtered(0,ScimPatchOperationType.ADD,"phoneNumbers","type eq \"home\"","value","\"a\"")))
            rejected(apply(old,request(old.getResourceType(),operation),compatibility,EXACT,new ScimWork(1_000_000)),ScimErrorType.NO_TARGET);
    }

    @Test void identicalIdEchoCompatibilityDoesNotAuthorizeAnyOtherReadOnlyWrite() {
        ScimResource old=user("\"id\":\"one\"");
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_READ_ONLY_ID_ECHO)).build();
        ScimPatchRequest echo=request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,null,"{\"id\":\"one\",\"displayName\":\"new\"}"));
        rejected(apply(old,echo),ScimErrorType.MUTABILITY);
        assertEquals("new",success(apply(old,echo,compatibility,EXACT,new ScimWork(1_000_000))).getResource().getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        for (ScimPatchOperation operation : List.of(op(0,ScimPatchOperationType.REPLACE,null,"{\"id\":\"two\"}"),op(0,ScimPatchOperationType.REPLACE,null,"{\"id\":null}"),
                op(0,ScimPatchOperationType.REPLACE,"id","\"one\""),op(0,ScimPatchOperationType.REPLACE,null,"{\"meta\":{}}"),
                op(0,ScimPatchOperationType.REPLACE,"schemas","[\""+USER+"\"]")))
            rejected(apply(old,request(old.getResourceType(),operation),compatibility,EXACT,new ScimWork(1_000_000)),ScimErrorType.MUTABILITY);
    }

    @Test void compatibleRemoveWithValueSelectsIdsAndNeverClearsUnlistedMembers() {
        ScimResource old=group("[{\"value\":\"a\"},{\"value\":\"b\"},{\"value\":\"A\"}]");
        ScimPatchResult result=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REMOVE,"members","[{\"value\":\"a\"}]"))));
        assertEquals(json("[{\"value\":\"b\"},{\"value\":\"A\"}]"),result.getResource().getDocument().find("members").orElseThrow());
    }

    @Test void typedPredicatesAndDeduplicationHandleNumbersBooleansDatetimeAndBinary() {
        ScimResourceType type=custom();
        ScimResource old=resource(type,"\"flags\":[{\"number\":2,\"flag\":true,\"moment\":\"2000-01-01T00:00:00Z\",\"bytes\":\"Zg==\"},{\"number\":1,\"flag\":false,\"bytes\":\"Zw==\"}],\"numbers\":[1,2],\"moments\":[\"2000-01-01T00:00:00Z\"],\"blobs\":[\"Zg==\"]");
        ScimPatchResult selected=success(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"flags",
                "number ge 2 and flag eq true and moment eq \"1999-12-31T19:00:00-05:00\" and bytes eq \"Zg\"",null,null))));
        assertEquals(json("[{\"number\":1,\"flag\":false,\"bytes\":\"Zw==\"}]"),selected.getResource().getDocument().find("flags").orElseThrow());
        ScimPatchResult dedup=success(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"numbers","[2,3]"),
                op(1,ScimPatchOperationType.ADD,"moments","[\"1999-12-31T19:00:00-05:00\"]"),op(2,ScimPatchOperationType.ADD,"blobs","[\"Zg\",\"Zw\"]"))));
        assertEquals(json("[1,2,3]"),dedup.getResource().getDocument().find("numbers").orElseThrow());
        assertEquals(json("[\"2000-01-01T00:00:00Z\"]"),dedup.getResource().getDocument().find("moments").orElseThrow());
        assertEquals(json("[\"Zg==\",\"Zw\"]"),dedup.getResource().getDocument().find("blobs").orElseThrow());
    }

    @Test void dateSelectorsNormalizeCalendarBoundariesAndKeepVeryLongYearsAndFractionsLinear() {
        ScimResourceType type=custom();
        String hugeYear="1"+"0".repeat(10_000);
        String fineFraction="0".repeat(10_000)+"1";
        for (String[] pair : List.of(new String[]{"2000-02-29T24:00:00Z","2000-03-01T00:00:00Z"},
                new String[]{"2000-01-01T00:00:00+01:00","1999-12-31T23:00:00Z"},
                new String[]{"-0001-12-31T23:00:00-01:00","0001-01-01T00:00:00Z"},
                new String[]{"0001-01-01T00:00:00+01:00","-0001-12-31T23:00:00Z"},
                new String[]{hugeYear+"-01-01T00:00:00Z",hugeYear+"-01-01T01:00:00+01:00"},
                new String[]{"2000-01-01T00:00:00."+fineFraction+"Z","2000-01-01T00:00:00."+fineFraction+"0Z"})) {
            ScimResource old=resource(type,"\"moments\":[\""+pair[0]+"\"]");
            assertFalse(success(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"moments","[\""+pair[1]+"\"]")))).isModified());
        }
        ScimResource old=resource(type,"\"moments\":[\"2000-01-01T00:00:00Z\"]");
        rejected(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"moments","[\"2000-01-01T00:00:00\"]"))),ScimErrorType.INVALID_FILTER);
    }

    @Test void referencesAndGroupIdsSupportExactSubstringSelectorsWithoutCollation() {
        ScimResourceType type=custom();
        ScimResource old=resource(type,"\"flags\":[{\"reference\":\"Users/a\"},{\"reference\":\"Groups/b\"}]");
        ScimPatchResult result=success(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"flags","reference sw \"Users/\" and reference co \"s/a\" and reference ew \"/a\"",null,null))));
        assertEquals(json("[{\"reference\":\"Groups/b\"}]"),result.getResource().getDocument().find("flags").orElseThrow());
        ScimResource group=group("[{\"value\":\"ab\"},{\"value\":\"AB\"}]");
        ScimPatchResult exact=success(apply(group,request(group.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"members","value co \"a\"",null,null))));
        assertEquals(json("[{\"value\":\"AB\"}]"),exact.getResource().getDocument().find("members").orElseThrow());
    }

    @Test void presenceAndNullSelectorsKeepAssignedEmptyStringsDistinctFromMissingValues() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\"},{\"type\":\"work\"},{\"value\":\"\"}]");
        ScimPatchResult present=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","value pr",null,null))));
        assertEquals(json("[{\"type\":\"work\"},{\"value\":\"\"}]"),present.getResource().getDocument().find("emails").orElseThrow());
        ScimPatchResult missing=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","value eq null",null,null))));
        assertEquals(json("[{\"value\":\"a\"},{\"value\":\"\"}]"),missing.getResource().getDocument().find("emails").orElseThrow());
    }

    @Test void oneBudgetCoversAllOperationsScansStrategiesAndFinalDiff() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\"}]");
        ScimPatchRequest one=request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"displayName","\"new\""));
        long minimum=1;
        while (apply(old,one,ScimCompatibility.strictInstance(),EXACT,new ScimWork(minimum)) instanceof ScimPatchApplicationResult.Rejected) minimum++;
        assertTrue(minimum < 10_000);
        List<ScimPatchOperation> operations=new ArrayList<>();
        for (int index=0; index<8; index++) operations.add(op(index,ScimPatchOperationType.REPLACE,"displayName","\"new\""));
        rejected(apply(old,request(old.getResourceType(),operations.toArray(ScimPatchOperation[]::new)),ScimCompatibility.strictInstance(),EXACT,new ScimWork(minimum)),ScimError.requestTooLargeInstance());
        AtomicInteger callbacks=new AtomicInteger();
        rejected(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"emails","value eq \"a\"",null,null)),
                ScimCompatibility.strictInstance(),(target,definition,operator,value,literal) -> { callbacks.incrementAndGet(); return ScimStringMatchResult.fromMatched(true); },new ScimWork(0)),ScimError.requestTooLargeInstance());
        assertEquals(0,callbacks.get());
    }

    @Test void everyInsufficientBudgetPrefixRejectsWithoutChangingTheOriginal() {
        ScimResourceType custom=custom();
        List<BudgetCase> cases=List.of(
                new BudgetCase(user(""),op(0,ScimPatchOperationType.REPLACE,null,"{\""+ENTERPRISE+"\":{\"department\":\"Research\"}}")),
                new BudgetCase(user("\"emails\":[{\"value\":\"a\"},{\"value\":\"b\"}]"),op(0,ScimPatchOperationType.REPLACE,"emails.value","\"new\"")),
                new BudgetCase(user("\"emails\":[{\"value\":\"a\",\"primary\":true},{\"value\":\"b\"}]"),filtered(0,ScimPatchOperationType.REPLACE,"emails","value eq \"b\"",null,"{\"primary\":true}")),
                new BudgetCase(user("\"name\":{\"givenName\":\"Ada\"}"),op(0,ScimPatchOperationType.REMOVE,"name.givenName",null)),
                new BudgetCase(resource(custom,"\"rows\":[{\"code\":\"fixed\",\"note\":\"saved\"}]"),op(0,ScimPatchOperationType.REPLACE,"rows","[{\"code\":\"fixed\",\"note\":\"saved\"}]")),
                new BudgetCase(group("[{\"value\":\"a\"},{\"value\":\"b\",\"display\":\"saved\"}]"),op(0,ScimPatchOperationType.REMOVE,"members","[{\"value\":\"a\"}]")),
                new BudgetCase(group("[{\"value\":\"a\",\"display\":\"saved\"}]"),op(0,ScimPatchOperationType.REPLACE,"members","[{\"value\":\"a\"},{\"value\":\"b\"}]")),
                new BudgetCase(resource(custom,"\"flags\":[{\"number\":1,\"bytes\":\"Zg\"}]"),filtered(0,ScimPatchOperationType.REMOVE,"flags","number eq 1 and bytes eq \"Zg==\"",null,null)));
        for (BudgetCase fixture : cases) {
            ScimPatchRequest request=request(fixture.resource.getResourceType(),fixture.operation);
            String original=fixture.resource.getDocument().toJson();
            boolean completed=false;
            for (int budget=0;budget<5000;budget++) {
                ScimPatchApplicationResult outcome=apply(fixture.resource,request,ScimCompatibility.strictInstance(),EXACT,new ScimWork(budget));
                if (outcome instanceof ScimPatchApplicationResult.Succeeded) { completed=true; break; }
                rejected(outcome,ScimError.requestTooLargeInstance());
                assertEquals(original,fixture.resource.getDocument().toJson());
            }
            assertTrue(completed);
        }
    }

    @Test void selectorsAddressAllExistingSubattributesAndFilteredWholeComplexMergesRetainOmitted() {
        ScimResource old=user("\"emails\":[{\"value\":\"a\",\"type\":\"work\"},{\"value\":\"b\",\"type\":\"home\"}]");
        ScimPatchResult all=success(apply(old,request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"emails.value","\"new\""))));
        assertEquals(json("[{\"value\":\"new\",\"type\":\"work\"},{\"value\":\"new\",\"type\":\"home\"}]"),all.getResource().getDocument().find("emails").orElseThrow());
        ScimPatchResult selected=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"emails","type eq \"work\"",null,"{\"value\":\"new\"}"))));
        assertEquals(json("[{\"value\":\"new\",\"type\":\"work\"},{\"value\":\"b\",\"type\":\"home\"}]"),selected.getResource().getDocument().find("emails").orElseThrow());
        ScimPatchResult cleared=success(apply(old,request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"emails","type eq \"work\"",null,"null"))));
        assertEquals(json("[{\"value\":\"b\",\"type\":\"home\"}]"),cleared.getResource().getDocument().find("emails").orElseThrow());
        rejected(apply(user(""),request(old.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"emails.value","\"new\""))),ScimErrorType.NO_TARGET);
        ScimResource ro=user("\"groups\":[{\"value\":\"one\"}]");
        rejected(apply(ro,request(ro.getResourceType(),op(0,ScimPatchOperationType.REPLACE,"groups.value","\"one\""))),ScimErrorType.MUTABILITY);
        rejected(apply(ro,request(ro.getResourceType(),filtered(0,ScimPatchOperationType.REMOVE,"groups","value eq \"one\"",null,null))),ScimErrorType.MUTABILITY);
    }

    @Test void typedComparisonTruthTableIncludesOrderingAndAnyElementNotEqual() {
        ScimResourceType type=custom();
        for (String expression : List.of("number eq 2","number ne 1","number gt 1","number ge 2","number lt 3","number le 2","flag ne false","reference eq \"Users/a\"","tags ne \"a\"","tags eq \"b\"")) {
            ScimResource old=resource(type,"\"flags\":[{\"number\":2,\"flag\":true,\"reference\":\"Users/a\",\"tags\":[\"a\",\"b\"]}]");
            assertEquals(json("[]"),success(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"flags",expression,null,null)))).getResource().getDocument().find("flags").orElseThrow());
        }
        for (String expression : List.of("number eq 1","number ne 2","number gt 2","number ge 3","number lt 2","number le 1","flag ne true","reference eq \"Users/b\"","tags eq \"c\"","tags ne null")) {
            ScimResource old=resource(type,"\"flags\":[{\"number\":2,\"flag\":true,\"reference\":\"Users/a\"}]");
            assertFalse(success(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"flags",expression,null,null)))).isModified());
        }
    }

    @Test void immutableComplexParentsCannotBeBypassedThroughChildOrFilteredPaths() {
        ScimResourceType type=ScimResourceType.withName("Fixed").endpoint("/Fixed").schema(ScimSchema.withId("urn:example:Fixed").name("Fixed")
                .attributes(List.of(ScimAttributeDefinition.withName("profile").type(ScimAttributeType.COMPLEX).mutability(ScimMutability.IMMUTABLE)
                        .subAttributes(List.of(ScimAttributeDefinition.withName("note").build())).build(),
                        ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true).mutability(ScimMutability.IMMUTABLE)
                                .subAttributes(List.of(ScimAttributeDefinition.withName("note").build())).build())).build()).build();
        ScimResource old=resource(type,"\"profile\":{\"note\":\"old\"},\"rows\":[{\"note\":\"old\"}]");
        for (ScimPatchOperation operation : List.of(op(0,ScimPatchOperationType.REPLACE,"profile.note","\"new\""),
                op(0,ScimPatchOperationType.REPLACE,"rows.note","\"new\""),
                filtered(0,ScimPatchOperationType.REPLACE,"rows","note eq \"old\"","note","\"new\""),
                filtered(0,ScimPatchOperationType.REMOVE,"rows","note eq \"old\"",null,null)))
            rejected(apply(old,request(type,operation)),ScimErrorType.MUTABILITY);
        assertFalse(success(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"profile.note","\"old\"")))).isModified());
    }

    @Test void datatypeAwareArrayDedupPreservesReadOnlyChildrenAndSimpleReferenceValues() {
        ScimResourceType type=custom();
        ScimResource old=resource(type,"\"rows\":[{\"code\":\"a\",\"note\":\"old\",\"server\":\"saved\"}],\"links\":[\"Users/a\"]");
        assertFalse(success(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"rows","[{\"code\":\"a\",\"note\":\"old\"}]")))).isModified());
        ScimPatchResult replaced=success(apply(old,request(type,op(0,ScimPatchOperationType.REPLACE,"rows","[{\"code\":\"a\",\"note\":\"old\"}]"),
                op(1,ScimPatchOperationType.ADD,"links","[\"Users/a\",\"Users/b\"]"))));
        assertEquals(json("[{\"code\":\"a\",\"note\":\"old\",\"server\":\"saved\"}]"),replaced.getResource().getDocument().find("rows").orElseThrow());
        assertEquals(json("[\"Users/a\",\"Users/b\"]"),replaced.getResource().getDocument().find("links").orElseThrow());
    }

    @Test void dateOrderingUsesTheFullCalendarAndFractionRatherThanLexicalWireText() {
        ScimResourceType type=custom();
        for (String[] pair : List.of(new String[]{"9999-12-31T23:00:00-01:00","10000-01-01T00:00:00Z"},
                new String[]{"10000-01-01T00:00:00+01:00","9999-12-31T23:00:00Z"},
                new String[]{"-0002-12-31T23:00:00-01:00","-0001-01-01T00:00:00Z"},
                new String[]{"-0001-01-01T00:00:00+01:00","-0002-12-31T23:00:00Z"},
                new String[]{"-10000-12-31T23:00:00-01:00","-9999-01-01T00:00:00Z"},
                new String[]{"2000-03-01T00:00:00+01:00","2000-02-29T23:00:00Z"})) {
            ScimResource old=resource(type,"\"moments\":[\""+pair[0]+"\"]");
            assertFalse(success(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"moments","[\""+pair[1]+"\"]")))).isModified());
        }
        for (String[] pair : List.of(new String[]{"2001-01-01T00:00:00Z","2000-01-01T00:00:00Z"},
                new String[]{"2000-02-01T00:00:00Z","2000-01-01T00:00:00Z"},
                new String[]{"2000-01-02T00:00:00Z","2000-01-01T00:00:00Z"},
                new String[]{"2000-01-01T00:00:01Z","2000-01-01T00:00:00Z"},
                new String[]{"2000-01-01T00:00:00.1Z","2000-01-01T00:00:00.01Z"},
                new String[]{"-9999-01-01T00:00:00Z","-10000-01-01T00:00:00Z"})) {
            ScimResource old=resource(type,"\"flags\":[{\"moment\":\""+pair[0]+"\"}]");
            assertEquals(json("[]"),success(apply(old,request(type,filtered(0,ScimPatchOperationType.REMOVE,"flags","moment gt \""+pair[1]+"\"",null,null)))).getResource().getDocument().find("flags").orElseThrow());
        }
    }

    @Test void automaticPrimaryClearingCannotChangeAnAssignedImmutablePrimary() {
        ScimResourceType type=ScimResourceType.withName("Preferred").endpoint("/Preferred").schema(ScimSchema.withId("urn:example:Preferred").name("Preferred")
                .attributes(List.of(ScimAttributeDefinition.withName("entries").type(ScimAttributeType.COMPLEX).multiValued(true)
                        .subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),
                                ScimAttributeDefinition.withName("primary").type(ScimAttributeType.BOOLEAN).mutability(ScimMutability.IMMUTABLE).build())).build())).build()).build();
        ScimResource old=resource(type,"\"entries\":[{\"value\":\"a\",\"primary\":true}]");
        rejected(apply(old,request(type,op(0,ScimPatchOperationType.ADD,"entries","[{\"value\":\"b\",\"primary\":true}]"))),ScimErrorType.MUTABILITY);
        assertEquals(json("[{\"value\":\"a\",\"primary\":true}]"),old.getDocument().find("entries").orElseThrow());
    }

    @Test void vendorUpsertIsAtomicAtEveryInsufficientWorkBoundary() {
        ScimResource old=user("");
        ScimPatchRequest request=request(old.getResourceType(),filtered(0,ScimPatchOperationType.REPLACE,"emails","type eq \"home\"","value","\"new\""));
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT)).build();
        boolean completed=false;
        for (int budget=0;budget<5000;budget++) {
            ScimPatchApplicationResult outcome=apply(old,request,compatibility,EXACT,new ScimWork(budget));
            if (outcome instanceof ScimPatchApplicationResult.Succeeded success) {
                assertEquals(json("[{\"value\":\"new\",\"type\":\"home\"}]"),success.getPatchResult().getResource().getDocument().find("emails").orElseThrow());
                completed=true; break;
            }
            rejected(outcome,ScimError.requestTooLargeInstance());
            assertTrue(old.getDocument().find("emails").isEmpty());
        }
        assertTrue(completed);
    }

    private record BudgetCase(@NonNull ScimResource resource,@NonNull ScimPatchOperation operation) { }

    private static @NonNull ScimResourceType requiredType() {
        ScimAttributeDefinition code=ScimAttributeDefinition.withName("code").required(true).build();
        ScimAttributeDefinition note=ScimAttributeDefinition.withName("note").build();
        return ScimResourceType.withName("Required").endpoint("/Required").schema(ScimSchema.withId("urn:example:Required").name("Required")
                .attributes(List.of(ScimAttributeDefinition.withName("codes").multiValued(true).required(true).build(),
                        ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true).required(true).subAttributes(List.of(code,note)).build(),
                        ScimAttributeDefinition.withName("details").type(ScimAttributeType.COMPLEX).subAttributes(List.of(code,note)).build(),
                        ScimAttributeDefinition.withName("optionalRows").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(code,note)).build())).build()).build();
    }
    private static @NonNull ScimResource requiredResource(@NonNull ScimResourceType type) {
        return resource(type,"\"codes\":[\"one\"],\"rows\":[{\"code\":\"one\"}],\"details\":{\"code\":\"one\",\"note\":\"saved\"},\"optionalRows\":[{\"code\":\"one\"}]");
    }
    private static @NonNull ScimServiceProvider publicProvider(@NonNull ScimResourceType type) {
        return ScimServiceProvider.builder().baseUri(java.net.URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).stringMatching(EXACT)
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static @NonNull ScimPatchApplicationResult publicApply(@NonNull ScimServiceProvider provider,@NonNull ScimResource resource,
            @NonNull ScimPatchOperation @NonNull ... operations) {
        List<JsonValue> values=new ArrayList<>();
        for (ScimPatchOperation operation : operations) {
            JsonObject.Builder value=JsonObject.builder().put("op",operation.getOperationType().name().toLowerCase(java.util.Locale.ROOT));
            operation.getAttributePath().ifPresent(target -> {
                String expression=target.toScimString();
                if (operation.getValueFilter().isPresent()) expression+="["+operation.getValueFilter().orElseThrow().toScimString()+"]";
                if (operation.getSubAttributeName().isPresent()) expression+="."+operation.getSubAttributeName().orElseThrow();
                value.put("path",expression);
            });
            operation.getValue().ifPresent(incoming -> value.put("value",incoming));
            values.add(value.build());
        }
        JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue("urn:ietf:params:scim:api:messages:2.0:PatchOp"))))
                .put("Operations",JsonArray.fromElements(values)).build();
        ScimPatchRequest parsed=assertInstanceOf(ScimPatchParseResult.Succeeded.class,provider.parsePatchRequestResult(resource.getResourceType(),body.toJson().getBytes(StandardCharsets.UTF_8))).getPatchRequest();
        return provider.applyPatchResult(resource,parsed);
    }

    private static @NonNull ScimResourceType custom() {
        ScimAttributeDefinition code=ScimAttributeDefinition.withName("code").mutability(ScimMutability.IMMUTABLE).build();
        ScimAttributeDefinition note=ScimAttributeDefinition.withName("note").build();
        return ScimResourceType.withName("Widget").endpoint("/Widgets").schema(ScimSchema.withId("urn:example:Widget")
                .name("Widget").attributes(List.of(ScimAttributeDefinition.withName("label").build(),
                        ScimAttributeDefinition.withName("locked").mutability(ScimMutability.IMMUTABLE).build(),
                        ScimAttributeDefinition.withName("profile").type(ScimAttributeType.COMPLEX).subAttributes(List.of(code,note,
                                ScimAttributeDefinition.withName("server").mutability(ScimMutability.READ_ONLY).build())).build(),
                        ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(code,note,
                                ScimAttributeDefinition.withName("server").mutability(ScimMutability.READ_ONLY).build())).build(),
                        ScimAttributeDefinition.withName("flags").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(
                                ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),
                                ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),
                                ScimAttributeDefinition.withName("moment").type(ScimAttributeType.DATE_TIME).build(),
                                ScimAttributeDefinition.withName("reference").type(ScimAttributeType.REFERENCE).build(),
                                ScimAttributeDefinition.withName("tags").multiValued(true).build(),
                                ScimAttributeDefinition.withName("bytes").type(ScimAttributeType.BINARY).build())).build(),
                        ScimAttributeDefinition.withName("numbers").type(ScimAttributeType.INTEGER).multiValued(true).build(),
                        ScimAttributeDefinition.withName("moments").type(ScimAttributeType.DATE_TIME).multiValued(true).build(),
                        ScimAttributeDefinition.withName("links").type(ScimAttributeType.REFERENCE).multiValued(true).build(),
                        ScimAttributeDefinition.withName("blobs").type(ScimAttributeType.BINARY).multiValued(true).build())).build()).build();
    }
    private static @NonNull ScimResource user(@NonNull String fields) { return resource(ScimResourceType.userInstance(),"\"userName\":\"Ada\""+(fields.isEmpty() ? "" : ","+fields)); }
    private static @NonNull ScimResource group(@NonNull String members) { return resource(ScimResourceType.groupInstance(),"\"displayName\":\"Team\",\"members\":"+members); }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type,@NonNull String fields) {
        return ScimResource.withResourceType(type).document((JsonObject)json("{\"schemas\":[\""+type.getSchema().getId()+"\"]"+(fields.isEmpty() ? "" : ","+fields)+"}")).build();
    }
    private static @NonNull JsonValue json(@NonNull String value) { return ((com.revetsec.internal.json.JsonParseResult.Succeeded)JsonCodec.parseResult(value.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(1_000_000,100_000))).getDocument().getValue(); }
    private static @NonNull ScimAttributePath path(@NonNull String value) { return ((ScimAttributePathParseResult.Succeeded)ScimAttributePath.fromExpressionResult(value)).getAttributePath(); }
    private static @NonNull ScimPatchOperation op(int index,@NonNull ScimPatchOperationType kind,@Nullable String path,@Nullable String value) {
        return new ScimPatchOperation(index,kind,path == null ? null : path(path),null,null,value == null ? null : json(value));
    }
    private static @NonNull ScimPatchOperation filtered(int index,@NonNull ScimPatchOperationType kind,@NonNull String path,
            @NonNull String filter,@Nullable String suffix,@Nullable String value) {
        return new ScimPatchOperation(index,kind,path(path),((ScimFilterParseResult.Succeeded)ScimFilter.fromExpressionResult(filter)).getFilter(),suffix,value == null ? null : json(value));
    }
    private static @NonNull ScimPatchRequest request(@NonNull ScimResourceType type,@NonNull ScimPatchOperation @NonNull ... operations) {
        Set<ScimAttributePath> requested=new LinkedHashSet<>(),supplied=new LinkedHashSet<>();
        for (ScimPatchOperation operation : operations) operation.getAttributePath().ifPresent(target -> {
            requested.add(target); if (operation.getValue().isPresent()) supplied.add(target);
        });
        return new ScimPatchRequest(type,List.of(operations),requested,supplied,CONTEXT);
    }
    private static @NonNull ScimPatchApplicationResult apply(@NonNull ScimResource old,@NonNull ScimPatchRequest request) {
        return apply(old,request,ScimCompatibility.strictInstance(),EXACT,new ScimWork(1_000_000));
    }
    private static @NonNull ScimPatchApplicationResult apply(@NonNull ScimResource old,@NonNull ScimPatchRequest request,
            @NonNull ScimCompatibility compatibility,@NonNull ScimStringMatching matching,@NonNull ScimWork work) {
        return ScimPatchEngine.apply(old,request,compatibility,matching,work,CONTEXT,new LinkedHashSet<>());
    }
    private static @NonNull ScimPatchResult success(@NonNull ScimPatchApplicationResult result) {
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,result); return ((ScimPatchApplicationResult.Succeeded)result).getPatchResult();
    }
    private static void rejected(@NonNull ScimPatchApplicationResult result,@NonNull ScimError error) {
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,result); assertSame(error,((ScimPatchApplicationResult.Rejected)result).getError());
    }
    private static void rejected(@NonNull ScimPatchApplicationResult result,@NonNull ScimErrorType type) {
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,result); assertEquals(type,((ScimPatchApplicationResult.Rejected)result).getError().getErrorType().orElseThrow());
    }
}
