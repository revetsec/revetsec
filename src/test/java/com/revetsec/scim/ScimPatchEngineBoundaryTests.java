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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Direct calibration of pure private decision helpers whose hostile shapes cannot survive public normalization. */
final class ScimPatchEngineBoundaryTests {
    @Test void presenceTraversalCoversNullScalarArrayObjectHiddenAndBudgetShapes() throws Exception {
        ScimAttributeDefinition hidden=ScimAttributeDefinition.withName("hidden").returned(ScimReturned.NEVER).build();
        ScimAttributeDefinition visible=ScimAttributeDefinition.withName("visible").build();
        ScimAttributeDefinition nested=ScimAttributeDefinition.withName("nested").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(ScimAttributeDefinition.withName("leaf").build())).build();
        ScimAttributeDefinition complex=ScimAttributeDefinition.withName("complex").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(hidden,visible,nested)).build();
        Method present=method("filterPresent",com.revetsec.json.JsonValue.class,ScimAttributeDefinition.class);
        ScimPatchEngine engine=engine(10_000);

        assertFalse((Boolean)present.invoke(engine,null,visible));
        assertFalse((Boolean)present.invoke(engine,JsonNull.defaultInstance(),visible));
        assertFalse((Boolean)present.invoke(engine,JsonString.fromValue(""),visible));
        assertTrue((Boolean)present.invoke(engine,JsonString.fromValue("value"),visible));
        assertTrue((Boolean)present.invoke(engine,JsonBoolean.fromValue(true),visible));
        assertFalse((Boolean)present.invoke(engine,JsonArray.fromElements(List.of()),complex));
        assertTrue((Boolean)present.invoke(engine,JsonArray.fromElements(List.of(
                JsonNull.defaultInstance(),JsonBoolean.fromValue(false))),complex));
        assertTrue((Boolean)present.invoke(engine,JsonArray.fromElements(List.of(
                JsonBoolean.fromValue(true),JsonNull.defaultInstance())),complex));
        assertFalse((Boolean)present.invoke(engine,JsonObject.builder().put("hidden","secret").build(),complex));
        assertTrue((Boolean)present.invoke(engine,JsonObject.builder().put("visible","shown").build(),complex));
        assertTrue((Boolean)present.invoke(engine,JsonObject.builder()
                .put("nested",JsonObject.builder().put("leaf","shown").build()).build(),complex));

        assertFalse((Boolean)present.invoke(engine(0),JsonBoolean.fromValue(true),visible));
        assertFalse((Boolean)present.invoke(engine(1),JsonArray.fromElements(List.of(JsonBoolean.fromValue(true))),complex));
        assertFalse((Boolean)present.invoke(engine(1),JsonObject.builder().put("visible","shown").build(),complex));
        assertFalse((Boolean)present.invoke(engine(2),JsonObject.builder().put("visible","shown").build(),complex));
    }

    @Test void equivalenceAndScalarComparisonCoverUnnormalizableTypeBoundaries() throws Exception {
        ScimAttributeDefinition visible=ScimAttributeDefinition.withName("visible").build();
        ScimAttributeDefinition object=ScimAttributeDefinition.withName("row").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(
                        ScimAttributeDefinition.withName("readonly").mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("hidden").returned(ScimReturned.NEVER).build(),visible)).build();
        Method equivalent=method("equivalent",ScimAttributeDefinition.class,com.revetsec.json.JsonValue.class,
                com.revetsec.json.JsonValue.class,ScimAttributePath.class,boolean.class);
        ScimAttributePath target=path("rows");
        ScimPatchEngine engine=engine(10_000);

        assertTrue((Boolean)equivalent.invoke(engine,visible,null,null,target,false));
        assertTrue((Boolean)equivalent.invoke(engine,visible,JsonNull.defaultInstance(),null,target,false));
        assertFalse((Boolean)equivalent.invoke(engine,visible,null,JsonString.fromValue("x"),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,visible,JsonString.fromValue("x"),null,target,false));
        assertFalse((Boolean)equivalent.invoke(engine,visible,JsonNull.defaultInstance(),JsonString.fromValue("x"),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,visible,JsonString.fromValue("x"),JsonNull.defaultInstance(),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,visible,JsonString.fromValue("x"),JsonNumber.fromValue(1L),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,object,JsonObject.builder().build(),JsonString.fromValue("x"),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,object,JsonString.fromValue("x"),JsonObject.builder().build(),target,true));
        assertTrue((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("readonly","one").put("hidden","one").put("visible","same").build(),
                JsonObject.builder().put("readonly","two").put("hidden","two").put("visible","same").build(),target,false));
        assertFalse((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("visible","one").build(),
                JsonObject.builder().put("visible","two").build(),target,false));
        assertTrue((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("value","id").build(),
                JsonObject.builder().put("value","id").build(),target,true));
        assertFalse((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("value","id-a").build(),
                JsonObject.builder().put("value","id-b").build(),target,true));
        assertTrue((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("visible","same").build(),
                JsonObject.builder().put("visible","same").build(),target,true));
        assertFalse((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().build(),JsonString.fromValue("x"),target,true));
        assertTrue((Boolean)equivalent.invoke(engine,object,
                JsonObject.builder().put("value","id").put("visible","same").build(),
                JsonObject.builder().put("visible","same").build(),target,true));

        Method scalar=method("scalarCompare",ScimAttributePath.class,ScimAttributeDefinition.class,
                com.revetsec.json.JsonValue.class,ScimFilterValue.class,ScimComparisonOperator.class,boolean.class);
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,visible,JsonBoolean.fromValue(true),
                new ScimFilterValue.StringValue("true"),ScimComparisonOperator.EQ,false));
        ScimAttributeDefinition values=ScimAttributeDefinition.withName("values").multiValued(true).build();
        assertTrue((Boolean)scalar.invoke(engine(10_000),target,values,JsonArray.fromElements(List.of()),
                new ScimFilterValue.NullValue(),ScimComparisonOperator.EQ,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,values,JsonArray.fromElements(List.of()),
                new ScimFilterValue.NullValue(),ScimComparisonOperator.NE,false));
        assertTrue((Boolean)scalar.invoke(engine(10_000),target,visible,null,
                new ScimFilterValue.StringValue("x"),ScimComparisonOperator.NE,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,values,JsonString.fromValue("x"),
                new ScimFilterValue.NullValue(),ScimComparisonOperator.EQ,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,values,
                JsonArray.fromElements(List.of(JsonString.fromValue("x"))),
                new ScimFilterValue.NullValue(),ScimComparisonOperator.EQ,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,visible,JsonArray.fromElements(List.of()),
                new ScimFilterValue.NullValue(),ScimComparisonOperator.EQ,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,visible,JsonString.fromValue("x"),
                new ScimFilterValue.BooleanValue(true),ScimComparisonOperator.EQ,false));
        assertFalse((Boolean)scalar.invoke(engine(10_000),target,visible,JsonNumber.fromValue(1L),
                new ScimFilterValue.StringValue("1"),ScimComparisonOperator.EQ,false));
        ScimAttributeDefinition reference=ScimAttributeDefinition.withName("reference")
                .type(ScimAttributeType.REFERENCE).build();
        assertFalse((Boolean)scalar.invoke(engine(1),target,reference,JsonString.fromValue("x"),
                new ScimFilterValue.StringValue("x"),ScimComparisonOperator.EQ,true));

        Method exact=method("exact",com.revetsec.json.JsonValue.class,com.revetsec.json.JsonValue.class);
        assertTrue((Boolean)exact.invoke(engine(10_000),JsonNull.defaultInstance(),JsonNull.defaultInstance()));
        assertTrue((Boolean)exact.invoke(engine(10_000),JsonBoolean.fromValue(true),JsonBoolean.fromValue(true)));
        assertFalse((Boolean)exact.invoke(engine(0),JsonString.fromValue("x"),JsonString.fromValue("x")));
        assertFalse((Boolean)exact.invoke(engine(0),JsonNumber.fromValue(1L),JsonNumber.fromValue(1L)));
        assertFalse((Boolean)exact.invoke(engine(10_000),JsonNumber.fromValue(1L),JsonNumber.fromValue(2L)));
        assertTrue((Boolean)exact.invoke(engine(10_000),JsonNumber.fromValue(1L),JsonNumber.fromValue(1L)));

        Method verdict=method("verdict",int.class,ScimComparisonOperator.class);
        assertFalse((Boolean)verdict.invoke(null,0,ScimComparisonOperator.CO));
        Method binary=method("binaryEqual",String.class,String.class);
        assertFalse((Boolean)binary.invoke(engine(0),"Zg==","Zg=="));
        Method date=method("dateCompare",String.class,String.class,ScimComparisonOperator.class);
        assertFalse((Boolean)date.invoke(engine(0),"2000-01-01T00:00:00Z",
                "2000-01-01T00:00:00Z",ScimComparisonOperator.EQ));
    }

    @Test void membershipPrimaryProtectionAndGroupShapeHelpersCoverIndependentBoundaries() throws Exception {
        ScimAttributeDefinition primary=ScimAttributeDefinition.withName("primary")
                .type(ScimAttributeType.BOOLEAN).build();
        ScimAttributeDefinition entries=ScimAttributeDefinition.withName("entries")
                .type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(primary)).build();
        Method supplied=method("suppliedPrimary",ScimAttributeDefinition.class,
                com.revetsec.json.JsonValue.class,String.class);
        assertTrue((Boolean)supplied.invoke(engine(10_000),entries,JsonBoolean.fromValue(true),"primary"));
        assertFalse((Boolean)supplied.invoke(engine(10_000),entries,JsonBoolean.fromValue(false),"primary"));
        assertFalse((Boolean)supplied.invoke(engine(10_000),entries,JsonObject.builder().build(),"primary"));
        assertTrue((Boolean)supplied.invoke(engine(10_000),entries,
                JsonObject.builder().put("primary",true).build(),null));
        assertFalse((Boolean)supplied.invoke(engine(10_000),entries,
                JsonObject.builder().put("primary",false).build(),null));
        assertFalse((Boolean)supplied.invoke(engine(10_000),entries,JsonBoolean.fromValue(true),"other"));
        assertFalse((Boolean)supplied.invoke(engine(10_000),entries,JsonBoolean.fromValue(true),null));

        Method remove=method("removeIds",com.revetsec.json.JsonValue.class,JsonArray.class);
        JsonArray candidates=JsonArray.fromElements(List.of(JsonObject.builder().put("$ref","Users/x").build()));
        assertEquals(null,remove.invoke(engine(10_000),null,candidates));
        JsonArray old=JsonArray.fromElements(List.of(JsonObject.builder().put("$ref","Users/a").build()));
        assertEquals(null,remove.invoke(engine(1),old,candidates));
        assertEquals(null,remove.invoke(engine(2),old,candidates));

        ScimAttributeDefinition readOnly=ScimAttributeDefinition.withName("saved")
                .mutability(ScimMutability.READ_ONLY).build();
        ScimAttributeDefinition writable=ScimAttributeDefinition.withName("note").build();
        ScimAttributeDefinition protectedRow=ScimAttributeDefinition.withName("row").type(ScimAttributeType.COMPLEX)
                .subAttributes(List.of(readOnly,writable)).build();
        Method protectedChildren=method("protectedChildren",ScimAttributeDefinition.class,
                com.revetsec.json.JsonValue.class);
        assertTrue((Boolean)protectedChildren.invoke(engine(10_000),protectedRow,
                JsonObject.builder().put("saved","server").build()));
        assertFalse((Boolean)protectedChildren.invoke(engine(10_000),protectedRow,
                JsonObject.builder().put("note","client").build()));
        ScimAttributeDefinition writeOnly=ScimAttributeDefinition.withName("secret")
                .mutability(ScimMutability.WRITE_ONLY).returned(ScimReturned.NEVER).build();
        ScimAttributeDefinition writeOnlyRow=ScimAttributeDefinition.withName("row")
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(writeOnly)).build();
        assertFalse((Boolean)protectedChildren.invoke(engine(10_000),writeOnlyRow,
                JsonObject.builder().put("secret","client").build()));
        ScimAttributeDefinition nestedReadOnly=ScimAttributeDefinition.withName("nested")
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(readOnly)).build();
        ScimAttributeDefinition nestedRow=ScimAttributeDefinition.withName("row")
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(nestedReadOnly)).build();
        assertTrue((Boolean)protectedChildren.invoke(engine(10_000),nestedRow,
                JsonObject.builder().put("nested",JsonObject.builder().put("saved","server").build()).build()));
        assertTrue((Boolean)protectedChildren.invoke(engine(0),protectedRow,
                JsonArray.fromElements(List.of(JsonObject.builder().build()))));

        Method group=method("groupMembers",ScimAttributePath.class);
        ScimPatchEngine groupEngine=engine(10_000);
        assertTrue((Boolean)group.invoke(groupEngine,path("members")));
        assertFalse((Boolean)group.invoke(groupEngine,path("members.value")));
        assertFalse((Boolean)group.invoke(groupEngine,path("displayName")));
        assertFalse((Boolean)group.invoke(engine(ScimTestResourceTypes.userWithEnterpriseInstance(),10_000),
                path("members")));

        ScimAttributeDefinition singleVisible=ScimAttributeDefinition.withName("single")
                .type(ScimAttributeType.COMPLEX).subAttributes(List.of(writable)).build();
        Method present=method("filterPresent",com.revetsec.json.JsonValue.class,ScimAttributeDefinition.class);
        assertFalse((Boolean)present.invoke(engine(2),
                JsonObject.builder().put("note","shown").build(),singleVisible));

        Method difference=method("difference",ScimAttributeDefinition.class,
                com.revetsec.json.JsonValue.class,com.revetsec.json.JsonValue.class,String.class,java.util.Set.class);
        difference.invoke(engine(10_000),singleVisible,JsonString.fromValue("invalid-shape"),
                JsonObject.builder().put("note","shown").build(),"single",new LinkedHashSet<ScimAttributePath>());

        Method extension=method("extensionTarget",JsonObject.class,String.class,
                ScimPatchOperationType.class,com.revetsec.json.JsonValue.class);
        assertEquals(null,extension.invoke(engine(10_000),JsonObject.emptyInstance(),"urn:missing",
                ScimPatchOperationType.REMOVE,null));
        ScimPatchEngine failed=engine(0);
        assertFalse((Boolean)present.invoke(failed,JsonBoolean.fromValue(true),writable));
        assertEquals(null,extension.invoke(failed,JsonObject.emptyInstance(),"urn:missing",
                ScimPatchOperationType.REMOVE,null));
    }

    private static @NonNull ScimPatchEngine engine(long work) throws Exception {
        return engine(ScimResourceType.groupInstance(),work);
    }

    private static @NonNull ScimPatchEngine engine(@NonNull ScimResourceType type,long work) throws Exception {
        Constructor<ScimPatchEngine> constructor=ScimPatchEngine.class.getDeclaredConstructor(ScimResourceType.class,
                ScimCompatibility.class,ScimStringMatching.class,ScimWork.class,java.util.Set.class);
        constructor.setAccessible(true);
        ScimStringMatching matching=(target,definition,operator,value,literal) ->
                ScimStringMatchResult.fromMatched(value.equals(literal));
        return constructor.newInstance(type,ScimCompatibility.strictInstance(),matching,
                new ScimWork(work),new LinkedHashSet<>());
    }

    private static @NonNull Method method(@NonNull String name,
            @NonNull Class<?> @NonNull ... arguments) throws Exception {
        Method method=ScimPatchEngine.class.getDeclaredMethod(name,arguments);
        method.setAccessible(true);
        return method;
    }

    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return ((ScimAttributePathParseResult.Succeeded)ScimAttributePath.fromExpressionResult(expression))
                .getAttributePath();
    }
}
