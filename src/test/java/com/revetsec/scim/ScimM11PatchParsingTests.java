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
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Independent grammar, typed-wire-value and canonical provenance assertions. */
final class ScimM11PatchParsingTests {
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP=ScimResourceType.groupInstance();
    private static final @NonNull Object CONTEXT=new Object();
    private static final @NonNull String SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static @NonNull JsonDocument json(@NonNull String text) {
        return assertInstanceOf(JsonParseResult.Succeeded.class,JsonCodec.parseResult(text.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(1024*1024,100000))).getDocument();
    }
    private static @NonNull ScimPatchParseResult parse(@NonNull ScimResourceType type,@NonNull String operations) {
        return parse(type,operations,ScimCompatibility.strictInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>());
    }
    private static @NonNull ScimPatchParseResult parse(@NonNull ScimResourceType type,@NonNull String operations,
            @NonNull ScimCompatibility compatibility,@NonNull ScimLimits limits,@NonNull Set<@NonNull ScimCompatibilityFeature> used) {
        return ScimPatchParsing.parse(type,json("{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":["+operations+"]}"),compatibility,limits,new ScimWork(limits.getMaximumWorkUnits()),CONTEXT,used);
    }
    private static @NonNull ScimPatchRequest request(@NonNull ScimPatchParseResult result) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,result).getPatchRequest();
    }
    private static @NonNull ScimError rejected(@NonNull ScimPatchParseResult result) { return assertInstanceOf(ScimPatchParseResult.Rejected.class,result).getError(); }
    private static @NonNull Set<@NonNull String> paths(@NonNull Set<@NonNull ScimAttributePath> values) {
        Set<String> result=new LinkedHashSet<>(); for(ScimAttributePath path:values) result.add(path.toScimString()); return result;
    }
    @Test void patchEnvelopeRequiresItsExactSchemaAndNonemptyArray() {
        for(String text:List.of("null","[]","{}","{\"schemas\":[],\"Operations\":[]}",
                "{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":{}}",
                "{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":[]}",
                "{\"schemas\":[\""+SCHEMA+"\",\"urn:other\"],\"Operations\":[{}]}",
                "{\"schemas\":[\""+SCHEMA.toLowerCase(java.util.Locale.ROOT)+"\"],\"Operations\":[{}]}",
                "{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":[{}],\"other\":true}"))
            assertSame(ScimError.invalidSyntaxInstance(),rejected(ScimPatchParsing.parse(USER,json(text),ScimCompatibility.strictInstance(),ScimLimits.fromDefaults(),new ScimWork(1000000),CONTEXT,new LinkedHashSet<>())));
        assertSame(USER,request(parse(USER,"{\"op\":\"replace\",\"path\":\"active\",\"value\":true}")).getResourceType());
    }
    @Test void operationMembersFoldAsciiButOperationValuesNeedNamedFeature() {
        String operation="{\"OP\":\"Replace\",\"PATH\":\"ACTIVE\",\"VALUE\":true}";
        assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(USER,operation)));
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        ScimPatchRequest value=request(parse(USER,operation,ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used));
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE),used);
        assertEquals(ScimPatchOperationType.REPLACE,value.getOperations().get(0).getOperationType());
        assertEquals("active",value.getOperations().get(0).getAttributePath().orElseThrow().toScimString());
        assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(USER,"{\"op\":\"rEplAceX\",\"path\":\"active\",\"value\":true}",ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>())));
        assertEquals("displayName",request(parse(USER,"{\"OP\":\"replace\",\"PATH\":\"DISPLAYNAME\",\"VALUE\":\"hello\"}")).getOperations().get(0).getAttributePath().orElseThrow().toScimString());
    }
    @Test void operationShapeRejectsUnknownMembersKindsAndMissingValues() {
        for(String operation:List.of("null","{}","{\"op\":false}","{\"op\":\"move\",\"path\":\"active\",\"value\":true}",
                "{\"op\":\"replace\",\"path\":\"active\"}","{\"op\":\"add\",\"value\":false}","{\"op\":\"replace\",\"value\":{}}",
                "{\"op\":\"remove\",\"path\":\"displayName\",\"value\":null}","{\"op\":\"replace\",\"path\":\"active\",\"value\":true,\"from\":\"x\"}"))
            assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(USER,operation)));
        assertSame(ScimError.noTargetInstance(),rejected(parse(USER,"{\"op\":\"remove\"}")));
        assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,"{\"op\":\"remove\",\"path\":null}")));
    }
    @Test void valuesRetainExplicitNullAndActualNestedLeafPaths() {
        ScimPatchRequest value=request(parse(USER,"{\"op\":\"replace\",\"path\":\"name\",\"value\":{\"familyName\":null,\"givenName\":\"one\"}},"
                +"{\"op\":\"remove\",\"path\":\"displayName\"},{\"op\":\"replace\",\"path\":\"emails\",\"value\":[]}"));
        JsonObject object=assertInstanceOf(JsonObject.class,value.getOperations().get(0).getValue().orElseThrow());
        assertInstanceOf(JsonNull.class,object.getMembers().get("familyName"));
        assertTrue(value.getOperations().get(1).getValue().isEmpty());
        assertEquals(Set.of("name.familyName","name.givenName","emails"),paths(value.getSuppliedAttributePaths()));
        assertEquals(Set.of("name","name.familyName","name.givenName","displayName","emails"),paths(value.getRequestedAttributePaths()));
        assertEquals(List.of(0,1,2),value.getOperations().stream().map(ScimPatchOperation::getOperationIndex).toList());
        assertSame(CONTEXT,value.getSemanticContext());
        ScimPatchRequest nullValue=request(parse(USER,"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":null}"));
        assertInstanceOf(JsonNull.class,nullValue.getOperations().get(0).getValue().orElseThrow());
        assertEquals(Set.of("displayName"),paths(nullValue.getSuppliedAttributePaths()));
    }
    @Test void filteredPathsCanonicalizeOneElementPredicateAndSuffixIndependentlyOfQueryPolicy() {
        ScimPatchOperation operation=request(parse(USER,"{\"op\":\"replace\",\"path\":\"EMAILS[TYPE eq \\\"work\\\" and not(PRIMARY eq false)].VALUE\",\"value\":\"new@example.test\"}")).getOperations().get(0);
        assertEquals("emails",operation.getAttributePath().orElseThrow().toScimString());
        assertEquals("value",operation.getSubAttributeName().orElseThrow());
        assertEquals("type eq \"work\" and not(primary eq false)",operation.getValueFilter().orElseThrow().toScimString());
        ScimPatchRequest value=request(parse(USER,"{\"op\":\"remove\",\"path\":\"emails[type pr or value eq \\\"a]b\\\"]\"}"));
        assertEquals(Set.of("emails","emails.type","emails.value"),paths(value.getRequestedAttributePaths()));
    }
    @Test void invalidUnknownAndSimpleArraySelectorPathsAreFixedInvalidPath() {
        for(String path:List.of("","unknown","emails[0]","emails[value eq \"x\"","emails[value eq \"x\"]..value",
                "emails[value eq \"x\"].missing","emails[value eq \"x\"][value eq \"y\"]","active[value eq true]",
                "emails[unknown eq \"x\"]","emails[primary co \"x\"]","emails[type eq 1]","emails[type[type eq \"x\"]]",
                "emails[urn:example:value eq \"x\"]","emails[type.value eq \"x\"]")) {
            String encoded=JsonString.fromValue(path).toJson();
            assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,"{\"op\":\"remove\",\"path\":"+encoded+"}")),path);
        }
        ScimResourceType type=ScimResourceType.withName("Custom").endpoint("/Customs").schema(ScimSchema.withId("urn:test:custom").name("Custom").attributes(List.of(
                ScimAttributeDefinition.withName("tags").multiValued(true).build(),
                ScimAttributeDefinition.withName("entries").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("secret").returned(ScimReturned.NEVER).build(),ScimAttributeDefinition.withName("value").build())).build())).build()).build();
        for(String path:List.of("tags[value eq \"x\"]","entries[secret eq \"x\"]"))
            assertSame(ScimError.invalidPathInstance(),rejected(parse(type,"{\"op\":\"remove\",\"path\":"+JsonString.fromValue(path).toJson()+"}")));
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,parse(type,"{\"op\":\"replace\",\"path\":\"entries[value eq \\\"x\\\"].secret\",\"value\":\"new\"}"));
    }
    @Test void uriAuthorityBracketsAreNotSelectorBrackets() {
        String id="https://[::1]/schema";
        ScimAttributeDefinition emails=ScimSchemas.attribute(ScimSchema.userInstance(),"emails").orElseThrow();
        ScimResourceType type=ScimResourceType.withName("Custom").endpoint("/Customs").schema(ScimSchema.withId("urn:test:base").name("Base").build())
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.withId(id).name("Bracket").attributes(List.of(emails)).build(),false))).build();
        ScimPatchOperation plain=request(parse(type,"{\"op\":\"remove\",\"path\":\""+id+":emails\"}")).getOperations().get(0);
        assertEquals(id+":emails",plain.getAttributePath().orElseThrow().toScimString());
        ScimPatchOperation selected=request(parse(type,"{\"op\":\"remove\",\"path\":\""+id+":emails[type eq \\\"work\\\"]\"}")).getOperations().get(0);
        assertEquals(id+":emails",selected.getAttributePath().orElseThrow().toScimString());
        assertEquals("type eq \"work\"",selected.getValueFilter().orElseThrow().toScimString());
    }
    @Test void integerWireSyntaxIsCheckedBeforeAcceptedCarriersAtAllPositions() {
        ScimResourceType type=integerType();
        for(String bad:List.of("1.0","1e0","1e2","1.0e1","0e0","-0.0"))
            for(String operation:List.of("{\"op\":\"replace\",\"path\":\"number\",\"value\":"+bad+"}",
                    "{\"op\":\"add\",\"path\":\"numbers\",\"value\":["+bad+"]}",
                    "{\"op\":\"replace\",\"value\":{\"object\":{\"number\":"+bad+"}}}",
                    "{\"op\":\"replace\",\"path\":\"objects[type eq \\\"x\\\"].number\",\"value\":"+bad+"}"))
                assertSame(ScimError.invalidValueInstance(),rejected(parse(type,operation)),operation);
        ScimPatchRequest accepted=request(parse(type,"{\"op\":\"replace\",\"path\":\"number\",\"value\":123},{\"op\":\"replace\",\"path\":\"objects[number eq 1.0].number\",\"value\":2}"));
        assertEquals(new BigDecimal("123"),assertInstanceOf(JsonNumber.class,accepted.getOperations().get(0).getValue().orElseThrow()).getValue());
    }
    private static @NonNull ScimResourceType integerType() {
        ScimAttributeDefinition n=ScimAttributeDefinition.withName("number").type(ScimAttributeType.INTEGER).build();
        return ScimResourceType.withName("Custom").endpoint("/Customs").schema(ScimSchema.withId("urn:test:integer").name("Integer").attributes(List.of(n,
                ScimAttributeDefinition.withName("numbers").type(ScimAttributeType.INTEGER).multiValued(true).build(),
                ScimAttributeDefinition.withName("object").type(ScimAttributeType.COMPLEX).subAttributes(List.of(n)).build(),
                ScimAttributeDefinition.withName("objects").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(n,ScimAttributeDefinition.withName("type").build())).build())).build()).build();
    }
    @Test void scalarTypesArraysAndComplexValuesRemainSchemaCheckedForPartialRequests() {
        for(String operation:List.of("{\"op\":\"replace\",\"path\":\"active\",\"value\":\"true\"}",
                "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":[]}","{\"op\":\"replace\",\"path\":\"name\",\"value\":\"text\"}",
                "{\"op\":\"replace\",\"path\":\"emails\",\"value\":{\"value\":\"x\"}}",
                "{\"op\":\"replace\",\"path\":\"emails[type eq \\\"x\\\"]\",\"value\":[{\"value\":\"x\"}]}",
                "{\"op\":\"replace\",\"path\":\"emails\",\"value\":[null]}"))
            assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,operation)));
        JsonArray append=assertInstanceOf(JsonArray.class,request(parse(USER,"{\"op\":\"add\",\"path\":\"emails\",\"value\":{\"value\":\"x\"}}")).getOperations().get(0).getValue().orElseThrow());
        assertEquals(1,append.getElements().size());
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,parse(USER,"{\"op\":\"replace\",\"path\":\"userName\",\"value\":null}"));
    }
    @Test void enabledBooleanStringsAreExactAtTypedValuesAndSelectors() {
        String operation="{\"op\":\"replace\",\"path\":\"active\",\"value\":\"false\"}";
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        assertInstanceOf(JsonBoolean.class,request(parse(USER,operation,ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used)).getOperations().get(0).getValue().orElseThrow());
        assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),used);
        assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,operation.replace("false","FALSE"),ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>())));
        used.clear();
        ScimPatchOperation selector=request(parse(USER,"{\"op\":\"remove\",\"path\":\"emails[primary eq \\\"true\\\"]\"}",ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used)).getOperations().get(0);
        assertEquals("primary eq true",selector.getValueFilter().orElseThrow().toScimString());
        assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),used);
    }
    @Test void entraRemoveValueNeverBecomesAnUnfilteredClear() {
        String good="{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"one\",\"$ref\":null},{\"value\":\"two\"}]}";
        assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(GROUP,good)));
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        ScimPatchOperation operation=request(parse(GROUP,good,ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used)).getOperations().get(0);
        assertEquals(ScimPatchOperationType.REMOVE,operation.getOperationType());
        assertTrue(operation.getValue().isPresent()); assertTrue(operation.getValueFilter().isEmpty());
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE),used);
        for(String value:List.of("[]","null","{}","[{}]","[{\"value\":null}]","[{\"value\":\"one\",\"display\":\"data\"}]","[{\"value\":\"one\",\"$ref\":\"x\"}]"))
            assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(GROUP,"{\"op\":\"remove\",\"path\":\"members\",\"value\":"+value+"}",ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>()));
        ScimResourceType fabricated=ScimResourceType.withName("Group").endpoint("/Groups")
                .schema(ScimSchema.withId(ScimSchema.groupInstance().getId()).name("Group")
                        .attributes(ScimSchema.groupInstance().getAttributes()).build()).build();
        assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(fabricated,good,ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>())));
        for(String path:List.of("displayName","members[value eq \"one\"]","members.value"))
            assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(GROUP,"{\"op\":\"remove\",\"path\":"+JsonString.fromValue(path).toJson()+",\"value\":[{\"value\":\"one\"}]}",ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>())));
    }
    @Test void extensionObjectStrictAndDottedQualifiedFeatureCanonicalizeWithoutAmbiguousOverlaps() {
        String id=ScimSchema.enterpriseUserInstance().getId();
        String block="{\"op\":\"replace\",\"value\":{\""+id+"\":{\"manager\":{\"value\":\"manager-id\"},\"department\":\"one\"}}}";
        ScimPatchRequest strict=request(parse(USER,block));
        assertEquals(Set.of(id+":manager.value",id+":department"),paths(strict.getSuppliedAttributePaths()));
        String dotted="{\"op\":\"replace\",\"value\":{\"name.givenName\":\"one\",\""+id+":department\":\"two\"}}";
        assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,dotted)));
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        ScimPatchRequest enabled=request(parse(USER,dotted,ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used));
        assertEquals(Set.of("name.givenName",id+":department"),paths(enabled.getSuppliedAttributePaths()));
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS),used);
        JsonObject normalized=assertInstanceOf(JsonObject.class,enabled.getOperations().get(0).getValue().orElseThrow());
        assertEquals("one",assertInstanceOf(JsonObject.class,normalized.getMembers().get("name")).findString("givenName").orElseThrow());
        for(String value:List.of("{\"name\":{\"givenName\":\"a\"},\"name.familyName\":\"b\"}","{\"emails.value\":\"x\"}","{\""+id+":manager.value\":\"a\",\""+id+":manager\":{\"value\":\"b\"}}"))
            assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(USER,"{\"op\":\"replace\",\"value\":"+value+"}",ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>()));
    }
    @Test void unknownAttributeRelaxationDoesNotEraseMalformedPathsOrKnownTypedRules() {
        ScimCompatibility relaxed=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)).build();
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        ScimPatchRequest ignored=request(parse(USER,"{\"op\":\"replace\",\"value\":{\"unknown\":{\"nested\":[1,2]},\"displayName\":\"one\"}}",relaxed,ScimLimits.fromDefaults(),used));
        assertEquals(Set.of("displayName"),paths(ignored.getSuppliedAttributePaths()));
        assertEquals(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES),used);
        assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":{\"emails[0]\":\"x\"}}",relaxed,ScimLimits.fromDefaults(),new LinkedHashSet<>())));
        assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":{\"active\":1}}",relaxed,ScimLimits.fromDefaults(),new LinkedHashSet<>())));
    }
    @Test void operationAndWholeRequestWorkBoundsApplyBeforeSuccess() {
        String one="{\"op\":\"replace\",\"path\":\"active\",\"value\":true}";
        ScimLimits limits=ScimLimits.builder().maximumPatchOperations(1).build();
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,parse(USER,one,ScimCompatibility.strictInstance(),limits,new LinkedHashSet<>()));
        assertSame(ScimError.requestTooLargeInstance(),rejected(parse(USER,one+","+one,ScimCompatibility.strictInstance(),limits,new LinkedHashSet<>())));
        assertSame(ScimError.requestTooLargeInstance(),rejected(ScimPatchParsing.parse(USER,json("{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":["+one+"]}"),ScimCompatibility.strictInstance(),limits,new ScimWork(1),CONTEXT,new LinkedHashSet<>())));
        ScimLimits pathLimits=ScimLimits.builder().filterLimits(ScimFilterLimits.builder().maximumExpressionCharacters(256).maximumLiteralCharacters(256).build()).build();
        String prefix="emails[type eq \"", suffix="\"].value";
        String exact=prefix+"x".repeat(256-prefix.length()-suffix.length())+suffix;
        String operation="{\"op\":\"replace\",\"path\":"+JsonString.fromValue(exact).toJson()+",\"value\":\"new\"}";
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,parse(USER,operation,ScimCompatibility.strictInstance(),pathLimits,new LinkedHashSet<>()));
        operation="{\"op\":\"replace\",\"path\":"+JsonString.fromValue(exact+"x").toJson()+",\"value\":\"new\"}";
        assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,operation,ScimCompatibility.strictInstance(),pathLimits,new LinkedHashSet<>())));
    }
    @Test void carriersSnapshotCollectionsAndAllDiagnosticsRedactPersonalData() {
        ScimPatchRequest parsed=request(parse(USER,"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"secret-fixture\"}"));
        ArrayList<ScimPatchOperation> operations=new ArrayList<>(parsed.getOperations());
        Set<ScimAttributePath> paths=new LinkedHashSet<>(parsed.getSuppliedAttributePaths());
        ScimPatchRequest copy=new ScimPatchRequest(USER,operations,paths,paths,CONTEXT);
        operations.clear(); paths.clear(); assertEquals(1,copy.getOperations().size()); assertEquals(1,copy.getSuppliedAttributePaths().size());
        assertThrows(UnsupportedOperationException.class,()->copy.getOperations().clear());
        assertThrows(UnsupportedOperationException.class,()->copy.getSuppliedAttributePaths().clear());
        for(Object value:List.of(parsed,parsed.getOperations().get(0),new ScimPatchParseResult.Succeeded(parsed),new ScimPatchParseResult.Rejected(ScimError.invalidValueInstance())))
            assertFalse(value.toString().contains("secret-fixture"));
    }    private static @NonNull ScimResourceType selectorType() {
        List<ScimAttributeDefinition> children=new ArrayList<>();
        for(ScimAttributeType type:List.of(ScimAttributeType.STRING,ScimAttributeType.BOOLEAN,ScimAttributeType.INTEGER,
                ScimAttributeType.DECIMAL,ScimAttributeType.DATE_TIME,ScimAttributeType.BINARY,ScimAttributeType.REFERENCE))
            children.add(ScimAttributeDefinition.withName(switch(type) {
                case STRING -> "text"; case BOOLEAN -> "flag"; case INTEGER -> "count"; case DECIMAL -> "amount";
                case DATE_TIME -> "date"; case BINARY -> "binary"; case REFERENCE -> "link"; case COMPLEX -> "unused";
            }).type(type).build());
        return ScimResourceType.withName("Selector").endpoint("/Selectors").schema(ScimSchema.withId("urn:test:selector").name("Selector")
                .attributes(List.of(ScimAttributeDefinition.withName("items").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(children).build(),
                        ScimAttributeDefinition.withName("single").type(ScimAttributeType.COMPLEX).subAttributes(children).build(),
                        ScimAttributeDefinition.withName("hidden").type(ScimAttributeType.COMPLEX).multiValued(true).returned(ScimReturned.NEVER).subAttributes(children).build(),
                        ScimAttributeDefinition.withName("texts").multiValued(true).build())).build()).build();
    }
    private static @NonNull String selectorOperation(@NonNull String predicate) {
        return "{\"op\":\"remove\",\"path\":"+JsonString.fromValue("items["+predicate+"]").toJson()+"}";
    }
    @Test void allSelectorLiteralFamiliesAndOperatorsUseSchemaTypes() {
        ScimResourceType type=selectorType();
        for(String predicate:List.of("text eq \"x\"","text ne \"x\"","text co \"x\"","text sw \"x\"","text ew \"x\"","text gt \"x\"",
                "flag eq true","flag ne false","count eq 1.0","count gt 2","amount eq 1.5","amount le 2e0",
                "date eq \"2026-10-13T12:00:00Z\"","date ge \"-0001-02-28T24:00:00+14:00\"",
                "binary eq \"YQ==\"","binary ne \"YQ\"","link eq \"../Users/one\"","link co \"Users\"","link sw \"https://\"","link ew \"one\"",
                "text eq null","text ne null","flag eq null","amount pr","date pr")) {
            ScimPatchOperation operation=request(parse(type,selectorOperation(predicate))).getOperations().get(0);
            assertTrue(operation.getValueFilter().isPresent(),predicate);
            assertEquals("items",operation.getAttributePath().orElseThrow().toScimString());
        }
        for(String predicate:List.of("flag eq 1","flag gt true","flag eq \"false\"","count eq 1.5","count eq \"1\"",
                "amount eq true","amount co 1","date eq 1","date eq \"2026-02-30T00:00:00Z\"","date sw \"2026\"",
                "binary eq false","binary eq \"!\"","binary gt \"YQ==\"","link eq true","link eq \"\\n\"","text eq false","text co null",
                "text eq \"x\" and missing pr","text pr or missing eq \"x\"","not(missing pr)"))
            assertSame(ScimError.invalidPathInstance(),rejected(parse(type,selectorOperation(predicate))),predicate);
    }
    @Test void selectorBooleanCompatibilityDoesNotBroadenOtherLiteralFamilies() {
        ScimResourceType type=selectorType();
        for(String literal:List.of("true","false")) {
            Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
            ScimPatchOperation operation=request(parse(type,selectorOperation("flag eq \""+literal+"\""),ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),used)).getOperations().get(0);
            assertEquals("flag eq "+literal,operation.getValueFilter().orElseThrow().toScimString());
            assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),used);
        }
        for(String predicate:List.of("flag eq \"TRUE\"","flag eq \"yes\"","count eq \"true\"","binary eq \"true\"")) {
            ScimPatchParseResult result=parse(type,selectorOperation(predicate),ScimCompatibility.microsoftEntraIdInstance(),ScimLimits.fromDefaults(),new LinkedHashSet<>());
            if(predicate.equals("binary eq \"true\"")) assertInstanceOf(ScimPatchParseResult.Succeeded.class,result); // Four valid Base64 alphabet units.
            else assertSame(ScimError.invalidPathInstance(),rejected(result),predicate);
        }
    }
    @Test void selectorsCannotSelectSingularHiddenOrSimpleArrayTargetsAndRetainEscapes() {
        ScimResourceType type=selectorType();
        for(String path:List.of("single[text pr]","hidden[text pr]","texts[text pr]","items.text[text pr]",
                "items[text pr].","items[text pr]suffix","unknown[text pr]","[text pr]","items[text eq \"unterminated]"))
            assertSame(ScimError.invalidPathInstance(),rejected(parse(type,"{\"op\":\"remove\",\"path\":"+JsonString.fromValue(path).toJson()+"}")),path);
        String literal="quote\" slash\\ bracket]";
        ScimFilter filter=request(parse(type,selectorOperation("text eq "+JsonString.fromValue(literal).toJson()))).getOperations().get(0).getValueFilter().orElseThrow();
        assertEquals(literal,assertInstanceOf(ScimFilterValue.StringValue.class,assertInstanceOf(ScimFilter.Comparison.class,filter).getValue()).getValue());
    }
    @Test void envelopeAndOperationCaseModesRemainPreciselyBounded() {
        for(String text:List.of("{\"schemas\":true,\"Operations\":[{}]}","{\"schemas\":[1],\"Operations\":[{}]}",
                "{\"schemas\":[\""+SCHEMA+"\"],\"unknown\":[{}]}","{\"unknown\":true,\"Operations\":[{}]}"))
            assertSame(ScimError.invalidSyntaxInstance(),rejected(ScimPatchParsing.parse(USER,json(text),ScimCompatibility.strictInstance(),ScimLimits.fromDefaults(),new ScimWork(1000000),CONTEXT,new LinkedHashSet<>())));
        for(String op:List.of("Add","REMOVE")) {
            Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
            String operation=op.equals("Add") ? "{\"op\":\"Add\",\"path\":\"displayName\",\"value\":\"one\"}" : "{\"op\":\"REMOVE\",\"path\":\"displayName\"}";
            request(parse(USER,operation,ScimCompatibility.oktaInstance(),ScimLimits.fromDefaults(),used));
            assertEquals(Set.of(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE),used);
        }
        request(parse(USER,"{\"op\":\"add\",\"path\":\"emails\",\"value\":null}"));
        request(parse(USER,"{\"op\":\"add\",\"path\":\"emails[type eq \\\"work\\\"]\",\"value\":{\"value\":\"one\"}}"));
    }
    @Test void noPathExtensionAndDottedCanonicalizationRejectAmbiguityAndBadTypes() {
        String id=ScimSchema.enterpriseUserInstance().getId();
        request(parse(USER,"{\"op\":\"replace\",\"value\":{\""+id+"\":{}}}"));
        for(String value:List.of("null","1","\"text\"","[]"))
            assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":{\""+id+"\":"+value+"}}")));
        assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":{\""+id+"\":{\"department\":1}}}")));
        String dottedExtension = "{\"op\":\"replace\",\"value\":{\"" + id
                + "\":{\"manager.value\":\"alice\"}}}";
        assertSame(ScimError.invalidPathInstance(), rejected(parse(USER, dottedExtension)));
        ScimCompatibility compatible=ScimCompatibility.microsoftEntraIdInstance();
        request(parse(USER, dottedExtension, compatible, ScimLimits.fromDefaults(), new LinkedHashSet<>()));
        ScimPatchRequest dotted=request(parse(USER,"{\"op\":\"replace\",\"value\":{\"name.givenName\":\"one\",\"name.familyName\":\"two\"}}",compatible,ScimLimits.fromDefaults(),new LinkedHashSet<>()));
        JsonObject object=assertInstanceOf(JsonObject.class,dotted.getOperations().get(0).getValue().orElseThrow());
        assertEquals(Set.of("givenName","familyName"),assertInstanceOf(JsonObject.class,object.getMembers().get("name")).getMembers().keySet());
        assertEquals(Set.of("name.givenName","name.familyName"),paths(dotted.getSuppliedAttributePaths()));
        for(String value:List.of("{\"name.givenName\":\"one\",\"name\":{\"familyName\":\"two\"}}")) {
            assertSame(ScimError.invalidSyntaxInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":"+value+"}",compatible,ScimLimits.fromDefaults(),new LinkedHashSet<>())));
        }
    }
    @Test void unknownAttributeFeatureDropsOnlyUnknownTypedPositionsAndScansValues() {
        ScimCompatibility compatible=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES,ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS)).build();
        String id=ScimSchema.enterpriseUserInstance().getId();
        for(String unknown:List.of("null","true","1","\"text\"","[]","[null,true,1,\"text\",{}]","{\"nested\":[1,2,\"text\"]}")) {
            ScimPatchRequest patch=request(parse(USER,"{\"op\":\"replace\",\"value\":{\"unknown\":"+unknown+",\"name\":{\"givenName\":\"one\"}}}",compatible,ScimLimits.fromDefaults(),new LinkedHashSet<>()));
            assertEquals(Set.of("name.givenName"),paths(patch.getSuppliedAttributePaths()));
        }
        request(parse(USER,"{\"op\":\"replace\",\"value\":{\""+id+":unknown\":{\"nested\":true},\"displayName\":\"one\"}}",compatible,ScimLimits.fromDefaults(),new LinkedHashSet<>()));
        assertSame(ScimError.invalidPathInstance(),rejected(parse(USER,"{\"op\":\"replace\",\"value\":{\"unknown\":true}}")));
        request(parse(USER,"{\"op\":\"replace\",\"path\":\"name\",\"value\":{\"unknown\":true,\"givenName\":\"one\"}}",compatible,ScimLimits.fromDefaults(),new LinkedHashSet<>()));
    }
    @Test void partialWireValuesUseXmlSchemaDateBinaryReferenceAndBooleanDefinitions() {
        ScimResourceType type=selectorType();
        for(String value:List.of("{\"date\":\"-0001-02-28T24:00:00+14:00\"}","{\"date\":\"12026-10-13T00:00:00\"}",
                "{\"binary\":\"YQ==\"}","{\"binary\":\"YQ\"}","{\"link\":\"../Users/one\"}","{\"amount\":1.25}","{\"flag\":true}"))
            request(parse(type,"{\"op\":\"replace\",\"path\":\"single\",\"value\":"+value+"}"));
        for(String value:List.of("{\"date\":\"0000-01-01T00:00:00Z\"}","{\"date\":\"2026-02-30T00:00:00Z\"}",
                "{\"binary\":\"YQ=\"}","{\"link\":\"\\n\"}","{\"flag\":1}"))
            assertSame(ScimError.invalidValueInstance(),rejected(parse(type,"{\"op\":\"replace\",\"path\":\"single\",\"value\":"+value+"}")),value);
        ScimCompatibility scalar=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR)).build();
        String manager=ScimSchema.enterpriseUserInstance().getId()+":manager";
        String operation="{\"op\":\"replace\",\"path\":\""+manager+"\",\"value\":\"manager-id\"}";
        assertSame(ScimError.invalidValueInstance(),rejected(parse(USER,operation)));
        Set<ScimCompatibilityFeature> used=new LinkedHashSet<>();
        ScimPatchRequest patch=request(parse(USER,operation,scalar,ScimLimits.fromDefaults(),used));
        assertEquals(Set.of(manager+".value"),paths(patch.getSuppliedAttributePaths()));
        assertEquals(Set.of(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR),used);
    }
    @Test void workExhaustionInEveryPartialParsingStageReturnsNoPartialRequest() {
        String id=ScimSchema.enterpriseUserInstance().getId();
        ScimCompatibility compatibility=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE,
                ScimCompatibilityFeature.BOOLEAN_STRINGS,ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE,
                ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS,ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)).build();
        List<String> cases=List.of(
                "{\"op\":\"Add\",\"path\":\"active\",\"value\":\"true\"}",
                "{\"op\":\"replace\",\"path\":\"emails[type eq \\\"work\\\" and not(primary eq false)].value\",\"value\":\"new\"}",
                "{\"op\":\"replace\",\"path\":\"emails[type pr or value eq \\\"a\\\"].value\",\"value\":\"new\"}",
                "{\"op\":\"replace\",\"value\":{\"name.givenName\":\"one\",\"name.familyName\":\"two\",\""+id+"\":{\"department\":\"one\"}}}",
                "{\"op\":\"replace\",\"value\":{\"unknown\":{\"nested\":[1,2,\"text\",null,true]},\"displayName\":\"one\"}}",
                "{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"one\",\"$ref\":null},{\"value\":\"two\"}]}"
        );
        for(String operation:cases) {
            ScimResourceType type=operation.contains("members") ? GROUP : USER;
            JsonDocument document=json("{\"schemas\":[\""+SCHEMA+"\"],\"Operations\":["+operation+"]}");
            boolean completed=false;
            for(int budget=0;budget<=10000;budget++) {
                ScimPatchParseResult result=ScimPatchParsing.parse(type,document,compatibility,ScimLimits.fromDefaults(),new ScimWork(budget),CONTEXT,new LinkedHashSet<>());
                if(result instanceof ScimPatchParseResult.Succeeded) { completed=true; break; }
                assertSame(ScimError.requestTooLargeInstance(),rejected(result),"Valid request must fail only its work budget: "+operation);
            }
            assertTrue(completed,"A valid request completes under the existing minimum public work budget");
        }
    }

}
