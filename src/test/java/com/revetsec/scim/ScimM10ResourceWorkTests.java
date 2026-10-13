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
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScimM10ResourceWorkTests {
    private static final @NonNull Object CONTEXT=new Object();
    private static final @NonNull String GROUP="urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final @NonNull String USER="urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String ENTERPRISE="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    @Test void everyPartialWorkBudgetRejectsAtomicallyAndSufficientBudgetsProduceTheSameCandidate() {
        ScimResourceType type=ScimResourceType.userInstance();
        String createBody="{\"schemas\":[\""+USER+"\",\""+ENTERPRISE+"\"],\"userName\":\"new\",\"active\":true,\"name\":{\"givenName\":\"Ada\",\"familyName\":\"Lovelace\"},\"emails\":[{\"value\":\"a@example.invalid\",\"primary\":true},{\"value\":\"b@example.invalid\",\"primary\":false}],\"meta\":{\"ignored\":[\"one\",{\"two\":3}]},\""+ENTERPRISE+"\":{\"department\":\"research\",\"manager\":{\"value\":\"manager\",\"$ref\":\"../Users/manager\"}}}";
        JsonDocument creation=parsed(createBody);
        ScimResource current=trusted(type,"{\"schemas\":[\""+USER+"\",\""+ENTERPRISE+"\"],\"id\":\"server\",\"externalId\":\"old-client\",\"userName\":\"old\",\"name\":{\"givenName\":\"Old\"},\"emails\":[{\"value\":\"old@example.invalid\"}],\""+ENTERPRISE+"\":{\"department\":\"old\"}}");
        String unchanged=current.getDocument().toJson();
        boolean creationSucceeded=false,replacementSucceeded=false;
        for (int available=0; available<=1500; available++) {
            ScimWork work=new ScimWork(available+7L); assertTrue(work.take(7));
            ScimResourceParseResult create=ScimResources.create(type,creation,ScimCompatibility.strictInstance(),work,CONTEXT);
            if (create instanceof ScimResourceParseResult.Succeeded success) {
                creationSucceeded=true;
                assertEquals("new",ScimUser.fromResource(success.getResource()).getUserName());
                assertEquals("Lovelace",((JsonObject)success.getResource().getDocument().find("name").orElseThrow()).findString("familyName").orElseThrow());
                assertTrue(success.getResource().getId().isEmpty());
                assertFalse(success.getResource().getDocument().getMembers().containsKey("meta"));
                assertEquals(Set.of(path("userName"),path("active"),path("name.givenName"),path("name.familyName"),path("emails.value"),path("emails.primary"),path(ENTERPRISE+":department"),path(ENTERPRISE+":manager.value"),path(ENTERPRISE+":manager.$ref")),success.getSuppliedAttributePaths());
            } else { assertFalse(creationSucceeded); assertEquals(413,((ScimResourceParseResult.Rejected)create).getError().getStatusCode()); }
            ScimResourceParseResult replace=ScimResources.replace(type,current,creation,ScimCompatibility.strictInstance(),new ScimWork(available),CONTEXT);
            if (replace instanceof ScimResourceParseResult.Succeeded success) {
                replacementSucceeded=true;
                assertEquals("server",success.getResource().getId().orElseThrow());
                assertTrue(success.getResource().getExternalId().isEmpty());
                assertEquals("new",ScimUser.fromResource(success.getResource()).getUserName());
                assertEquals("research",ScimEnterpriseUser.fromResource(success.getResource()).getDepartment().orElseThrow());
            } else { assertFalse(replacementSucceeded); assertEquals(413,((ScimResourceParseResult.Rejected)replace).getError().getStatusCode()); }
            assertEquals(unchanged,current.getDocument().toJson());
        }
        assertTrue(creationSucceeded); assertTrue(replacementSucceeded);
    }

    @Test void projectionWorkNeverReturnsAFragmentAndNeverExposesRequestOnlySiblings() {
        ScimResourceType type=ScimResourceType.withName("Projected").endpoint("/Projected").schema(ScimSchema.withId("urn:example:Projected").name("Projected").attributes(List.of(
                ScimAttributeDefinition.withName("items").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(
                        ScimAttributeDefinition.withName("value").build(),ScimAttributeDefinition.withName("label").returned(ScimReturned.REQUEST).build())).build(),
                ScimAttributeDefinition.withName("tags").multiValued(true).build(),ScimAttributeDefinition.withName("integer").type(ScimAttributeType.INTEGER).build())).build()).build();
        ScimResource resource=trusted(type,"{\"schemas\":[\"urn:example:Projected\"],\"id\":\"id\",\"items\":[{\"value\":\"a\",\"label\":\"private\"},{\"value\":\"b\",\"label\":\"private\"}],\"tags\":[\"first\",\"second\"],\"integer\":1234}");
        ScimAttributeSelection selection=new ScimAttributeSelection(type,Set.of(),Set.of(),false,CONTEXT);
        boolean succeeded=false;
        for (int available=0; available<=1000; available++) {
            JsonObject projected=ScimResources.project(resource,selection,Set.of(),false,new ScimWork(available));
            if (projected==null) { assertFalse(succeeded); continue; }
            succeeded=true;
            assertEquals(Set.of("schemas","id","items","tags","integer"),projected.getMembers().keySet());
            JsonArray items=(JsonArray)projected.find("items").orElseThrow();
            assertEquals(2,items.getElements().size());
            assertEquals(Set.of("value"),((JsonObject)items.getElements().get(0)).getMembers().keySet());
            assertEquals("a",((JsonObject)items.getElements().get(0)).findString("value").orElseThrow());
            assertEquals("b",((JsonObject)items.getElements().get(1)).findString("value").orElseThrow());
        }
        assertTrue(succeeded);
        ScimAttributeSelection includeParent=new ScimAttributeSelection(type,Set.of(path("items")),Set.of(),true,CONTEXT);
        JsonObject explicit=java.util.Objects.requireNonNull(ScimResources.project(resource,includeParent,Set.of(),false,new ScimWork(1000)));
        assertEquals(Set.of("value","label"),((JsonObject)((JsonArray)explicit.find("items").orElseThrow()).getElements().get(0)).getMembers().keySet());
        ScimAttributeSelection includeChild=new ScimAttributeSelection(type,Set.of(path("items.label")),Set.of(),true,CONTEXT);
        JsonObject child=java.util.Objects.requireNonNull(ScimResources.project(resource,includeChild,Set.of(),false,new ScimWork(1000)));
        assertEquals(Set.of("label"),((JsonObject)((JsonArray)child.find("items").orElseThrow()).getElements().get(0)).getMembers().keySet());
    }

    @Test void groupIdentityRetainsPerElementImmutableOmissionsAndRejectsExplicitClears() {
        ScimResourceType type=ScimResourceType.groupInstance();
        ScimResource current=trusted(type,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"group\",\"members\":[{\"value\":\"one\",\"type\":\"User\",\"$ref\":\"Users/one\"},{\"value\":\"two\",\"type\":\"User\",\"$ref\":\"Users/two\"}]}");
        String body="{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"group\",\"members\":[{\"value\":\"one\"},{\"value\":\"two\",\"type\":\"User\"}]}";
        ScimResource result=success(ScimResources.replace(type,current,parsed(body),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getResource();
        assertEquals("User",ScimGroup.fromResource(result).getMembers().get(0).findString("type").orElseThrow());
        assertEquals("Users/one",ScimGroup.fromResource(result).getMembers().get(0).findString("$ref").orElseThrow());
        for (String member : new String[]{"{\"value\":\"one\",\"type\":null}","{\"value\":\"one\",\"type\":\"Group\"}","{\"value\":\"one\",\"$ref\":null}"})
            assertEquals(ScimErrorType.MUTABILITY,assertInstanceOf(ScimResourceParseResult.Rejected.class,ScimResources.replace(type,current,parsed("{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"group\",\"members\":["+member+"]}"),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getError().getErrorType().orElseThrow());
        boolean succeeded=false;
        for (int available=0; available<=1500; available++) {
            ScimResourceParseResult replaced=ScimResources.replace(type,current,parsed(body),ScimCompatibility.strictInstance(),new ScimWork(available),CONTEXT);
            if (replaced instanceof ScimResourceParseResult.Succeeded success) { succeeded=true; assertEquals(2,ScimGroup.fromResource(success.getResource()).getMembers().size()); }
            else { assertFalse(succeeded); assertEquals(413,((ScimResourceParseResult.Rejected)replaced).getError().getStatusCode()); }
        }
        assertTrue(succeeded);
        ScimResource duplicate=trusted(type,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"group\",\"members\":[{\"value\":\"one\"},{\"value\":\"one\"}]}");
        assertInstanceOf(ScimResourceParseResult.Rejected.class,ScimResources.replace(type,duplicate,parsed(body),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT));
    }

    @Test void normalizedEmptyObjectsDoNotMixExplicitClearProofAcrossComplexAttributes() {
        ScimResourceType type=ScimResourceType.withName("Two").endpoint("/Two").schema(ScimSchema.withId("urn:example:Two").name("Two").attributes(List.of(
                ScimAttributeDefinition.withName("first").type(ScimAttributeType.COMPLEX).subAttributes(List.of(ScimAttributeDefinition.withName("longName").mutability(ScimMutability.IMMUTABLE).build())).build(),
                ScimAttributeDefinition.withName("second").type(ScimAttributeType.COMPLEX).subAttributes(List.of(ScimAttributeDefinition.withName("other").build())).build())).build()).build();
        ScimResource old=trusted(type,"{\"schemas\":[\"urn:example:Two\"],\"first\":{\"longName\":\"immutable\"},\"second\":{\"other\":\"x\"}}");
        JsonDocument clear=parsed("{\"schemas\":[\"urn:example:Two\"],\"first\":{\"LONGNAME\":null},\"second\":{\"other\":null}}");
        assertEquals(ScimErrorType.MUTABILITY,assertInstanceOf(ScimResourceParseResult.Rejected.class,ScimResources.replace(type,old,clear,ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getError().getErrorType().orElseThrow());
        JsonDocument keep=parsed("{\"schemas\":[\"urn:example:Two\"],\"first\":{},\"second\":{\"other\":null}}");
        ScimResource kept=success(ScimResources.replace(type,old,keep,ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getResource();
        assertEquals("immutable",((JsonObject)kept.getDocument().find("first").orElseThrow()).findString("longName").orElseThrow());
    }

    @Test void assignedImmutableValuesCompareEveryValueTypeAndPreserveServerChildrenBeforeComparison() {
        ScimResourceType type=ScimResourceType.withName("Immutable").endpoint("/Immutable").schema(ScimSchema.withId("urn:example:Immutable").name("Immutable").attributes(List.of(
                ScimAttributeDefinition.withName("text").mutability(ScimMutability.IMMUTABLE).build(),
                ScimAttributeDefinition.withName("truth").type(ScimAttributeType.BOOLEAN).mutability(ScimMutability.IMMUTABLE).build(),
                ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).mutability(ScimMutability.IMMUTABLE).build(),
                ScimAttributeDefinition.withName("tags").multiValued(true).mutability(ScimMutability.IMMUTABLE).build(),
                ScimAttributeDefinition.withName("object").type(ScimAttributeType.COMPLEX).mutability(ScimMutability.IMMUTABLE).subAttributes(List.of(
                        ScimAttributeDefinition.withName("one").build(),ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),ScimAttributeDefinition.withName("server").mutability(ScimMutability.READ_ONLY).build())).build())).build()).build();
        String original="{\"schemas\":[\"urn:example:Immutable\"],\"text\":\"a\",\"truth\":true,\"number\":1.00,\"tags\":[\"one\",\"two\"],\"object\":{\"one\":\"one\",\"flag\":true,\"server\":\"protected\"}}";
        ScimResource current=trusted(type,original);
        String same="{\"schemas\":[\"urn:example:Immutable\"],\"text\":\"a\",\"truth\":true,\"number\":1e0,\"tags\":[\"one\",\"two\"],\"object\":{\"one\":\"one\",\"flag\":true,\"server\":false}}";
        ScimResource result=success(ScimResources.replace(type,current,parsed(same),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getResource();
        assertEquals("protected",((JsonObject)result.getDocument().find("object").orElseThrow()).findString("server").orElseThrow());
        for (String changed : new String[]{same.replace("\"text\":\"a\"","\"text\":null"),same.replace("\"truth\":true","\"truth\":false"),same.replace("\"number\":1e0","\"number\":2"),same.replace("\"one\",\"two\"","\"two\",\"one\""),same.replace("\"one\",\"two\"","\"one\""),same.replace("\"flag\":true","\"flag\":false"),same.replace("\"one\":\"one\",","")})
            assertEquals(ScimErrorType.MUTABILITY,assertInstanceOf(ScimResourceParseResult.Rejected.class,ScimResources.replace(type,current,parsed(changed),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getError().getErrorType().orElseThrow());
        boolean succeeded=false;
        JsonDocument replacement=parsed(same);
        for (int available=0;available<=1500;available++) {
            ScimResourceParseResult candidate=ScimResources.replace(type,current,replacement,ScimCompatibility.strictInstance(),new ScimWork(available),CONTEXT);
            if (candidate instanceof ScimResourceParseResult.Succeeded success) { succeeded=true; assertEquals(current.getDocument(),success.getResource().getDocument()); }
            else { assertFalse(succeeded); assertEquals(413,((ScimResourceParseResult.Rejected)candidate).getError().getStatusCode()); }
        }
        assertTrue(succeeded);
    }

    @Test void immutableParentArrayPreservesReadOnlyChildrenOnlyAfterProvingWholeSequenceUnchanged() {
        ScimResourceType type=ScimResourceType.withName("Frozen").endpoint("/Frozen").schema(ScimSchema.withId("urn:example:Frozen").name("Frozen").attributes(List.of(
                ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true).mutability(ScimMutability.IMMUTABLE).subAttributes(List.of(
                        ScimAttributeDefinition.withName("value").build(),ScimAttributeDefinition.withName("server").mutability(ScimMutability.READ_ONLY).build())).build())).build()).build();
        ScimResource old=trusted(type,"{\"schemas\":[\"urn:example:Frozen\"],\"rows\":[{\"value\":\"a\",\"server\":\"one\"},{\"value\":\"b\",\"server\":\"two\"}]}");
        String same="{\"schemas\":[\"urn:example:Frozen\"],\"rows\":[{\"value\":\"a\",\"server\":false},{\"value\":\"b\"}]}";
        assertEquals(old.getDocument(),success(ScimResources.replace(type,old,parsed(same),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getResource().getDocument());
        for (String rows : new String[]{"[]","[{\"value\":\"a\"}]","[{\"value\":\"b\"},{\"value\":\"a\"}]","[{\"value\":\"a\"},{\"value\":\"changed\"}]"})
            assertEquals(ScimErrorType.MUTABILITY,assertInstanceOf(ScimResourceParseResult.Rejected.class,ScimResources.replace(type,old,parsed("{\"schemas\":[\"urn:example:Frozen\"],\"rows\":"+rows+"}"),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT)).getError().getErrorType().orElseThrow());
        boolean succeeded=false;
        JsonDocument document=parsed(same);
        for (int available=0;available<=1500;available++) {
            ScimResourceParseResult candidate=ScimResources.replace(type,old,document,ScimCompatibility.strictInstance(),new ScimWork(available),CONTEXT);
            if (candidate instanceof ScimResourceParseResult.Succeeded success) { succeeded=true; assertEquals(old.getDocument(),success.getResource().getDocument()); }
            else { assertFalse(succeeded); assertEquals(413,((ScimResourceParseResult.Rejected)candidate).getError().getStatusCode()); }
        }
        assertTrue(succeeded);
    }

    private static @NonNull JsonDocument parsed(@NonNull String body) { return assertInstanceOf(JsonParseResult.Succeeded.class,JsonCodec.parseResult(body.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(1048576,100000))).getDocument(); }
    private static @NonNull ScimResource trusted(@NonNull ScimResourceType type,@NonNull String body) { return ScimResource.withResourceType(type).document((JsonObject)parsed(body).getValue()).build(); }
    private static ScimResourceParseResult.@NonNull Succeeded success(@NonNull ScimResourceParseResult result) { return assertInstanceOf(ScimResourceParseResult.Succeeded.class,result); }
    private static @NonNull ScimAttributePath path(@NonNull String expression) { return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult(expression)).getAttributePath(); }
}
