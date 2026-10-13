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
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScimM10ResourceBoundariesTests {
    private static final @NonNull Object CONTEXT=new Object();
    private static final @NonNull String USER="urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String ENTERPRISE="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    @Test void intentionalViewsFindValuesAndRetainImmutableCopiesWithoutDiagnosticDisclosure() {
        ScimResource user=trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\",\""+ENTERPRISE+"\"],\"id\":\"server\",\"externalId\":\"external\",\"userName\":\"private-user\",\"displayName\":\"private-display\",\"active\":true,\"name\":{\"givenName\":\"Ada\"},\"emails\":[{\"value\":\"a@example.invalid\"},{\"value\":\"b@example.invalid\"}],\"meta\":{\"resourceType\":\"User\",\"created\":\"2000-02-29T12:00:00.123456789123+05:00\",\"lastModified\":\"2000-03-01T00:00:00-14:00\"},\""+ENTERPRISE+"\":{\"employeeNumber\":\"1\",\"department\":\"d\",\"organization\":\"o\",\"division\":\"v\",\"manager\":{\"value\":\"manager-1\",\"$ref\":\"../Users/manager-1\"}}}");
        ScimUser view=ScimUser.fromResource(user);
        assertSame(user,view.getResource()); assertEquals("private-display",view.getDisplayName().orElseThrow());
        assertTrue(view.isActive().orElseThrow()); assertEquals(2,view.getEmails().size());
        assertThrows(UnsupportedOperationException.class,() -> view.getEmails().clear());
        assertEquals("ScimUser{resource=<redacted>}",view.toString());
        ScimEnterpriseUser enterprise=ScimEnterpriseUser.fromResource(user);
        assertSame(user,enterprise.getResource()); assertEquals("1",enterprise.getEmployeeNumber().orElseThrow());
        assertEquals("d",enterprise.getDepartment().orElseThrow()); assertEquals("o",enterprise.getOrganization().orElseThrow()); assertEquals("v",enterprise.getDivision().orElseThrow());
        assertEquals("ScimEnterpriseUser{resource=<redacted>}",enterprise.toString());
        assertEquals("Ada",((JsonString)user.find(path("name.givenName")).orElseThrow()).getValue());
        assertEquals("private-user",((JsonString)user.find(path(USER+":USERNAME")).orElseThrow()).getValue());
        assertEquals(List.of(JsonString.fromValue("a@example.invalid"),JsonString.fromValue("b@example.invalid")),((JsonArray)user.find(path("emails.value")).orElseThrow()).getElements());
        assertEquals("d",((JsonString)user.find(path(ENTERPRISE+":DEPARTMENT")).orElseThrow()).getValue());
        assertTrue(user.find(path("unknown")).isEmpty()); assertTrue(user.find(path("userName.value")).isEmpty());
        assertTrue(user.find(path("name.familyName")).isEmpty()); assertTrue(user.find(path("emails.type")).isEmpty());
        assertTrue(user.find(path("phoneNumbers.value")).isEmpty()); assertTrue(user.find(path("name")).isPresent());
        assertTrue(user.getExtension("urn:unknown").isEmpty()); assertTrue(user.getExtension(USER).isEmpty());
        assertEquals("server",user.getId().orElseThrow()); assertEquals("external",user.getExternalId().orElseThrow());
        assertEquals(Instant.parse("2000-02-29T07:00:00.123456789Z"),user.getCreated().orElseThrow());
        assertEquals(Instant.parse("2000-03-01T14:00:00Z"),user.getLastModified().orElseThrow());
        ScimResource.Builder builder=ScimResource.withResourceType(ScimResourceType.userInstance()).document(user.getDocument());
        assertEquals("ScimResource.Builder{document=<redacted>}",builder.toString());
        ScimResource.Copier copier=user.copy().document(JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER)))).put("userName","other").build());
        assertEquals("ScimResource.Copier{document=<redacted>}",copier.toString());
        assertEquals("other",ScimUser.fromResource(copier.finish()).getUserName());
        assertEquals("private-user",view.getUserName());
        ScimResource empty=trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\",\""+ENTERPRISE+"\"],\"userName\":\"a\",\""+ENTERPRISE+"\":{}}");
        assertTrue(empty.getId().isEmpty()); assertTrue(empty.getExternalId().isEmpty()); assertTrue(empty.getVersion().isEmpty()); assertTrue(empty.getLocation().isEmpty()); assertTrue(empty.getCreated().isEmpty()); assertTrue(empty.getLastModified().isEmpty());
        assertTrue(ScimUser.fromResource(empty).getEmails().isEmpty()); assertTrue(ScimUser.fromResource(empty).getDisplayName().isEmpty()); assertTrue(ScimUser.fromResource(empty).isActive().isEmpty());
        assertTrue(ScimEnterpriseUser.fromResource(empty).getManager().isEmpty());
        ScimResource without=trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\"}");
        assertTrue(without.find(path(ENTERPRISE+":department")).isEmpty());
        assertThrows(IllegalArgumentException.class,() -> ScimUser.fromResource(trusted(ScimResourceType.groupInstance(),"{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"g\"}")));
        ScimGroup group=ScimGroup.fromResource(trusted(ScimResourceType.groupInstance(),"{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"g\"}"));
        assertEquals("g",group.getDisplayName()); assertTrue(group.getMembers().isEmpty()); assertEquals("ScimGroup{resource=<redacted>}",group.toString());
        assertThrows(IllegalArgumentException.class,() -> ScimEnterpriseUser.fromResource(group.getResource()));
        assertEquals("ScimWork{remaining=<redacted>}",new ScimWork(1).toString());
        assertFalse(new ScimWork(1).spend(-1));
    }

    @Test void realResourceTypeMatrixRejectsWrongJsonKindsAndAcceptsEveryDeclaredKind() {
        ScimResourceType type=types();
        for (String member : new String[]{"\"flag\":true","\"decimal\":1.25","\"integer\":-3","\"integers\":[1,2]","\"date\":\"2000-02-29T24:00:00\"","\"binary\":\"Zg\"","\"link\":\"Users/1\"","\"object\":{\"label\":\"x\",\"flag\":false}","\"items\":[{\"label\":\"a\",\"primary\":false},{\"label\":\"b\",\"primary\":true}]"})
            success(create(type,envelope(member)));
        for (String member : new String[]{"\"flag\":1","\"decimal\":\"1\"","\"integer\":1.5","\"integers\":1","\"integers\":[null]","\"date\":\"2001-02-29T00:00:00\"","\"binary\":\"Zh\"","\"link\":\"bad link\"","\"object\":[]","\"object\":\"x\"","\"object\":{\"flag\":\"false\"}","\"object\":{\"unknown\":true}","\"items\":{}","\"items\":[null]","\"items\":[1]","\"items\":[{\"primary\":true},{\"primary\":true}]"})
            assertInstanceOf(ScimResourceParseResult.Rejected.class,create(type,envelope(member)),member);
        assertInstanceOf(ScimResourceParseResult.Rejected.class,create(type,"[]"));
        assertInstanceOf(ScimResourceParseResult.Rejected.class,replace(type,trusted(type,envelope("\"integer\":1")),"true"));
        JsonObject untyped=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue("urn:example:Types")))).put("integer",JsonNumber.fromValue(new BigDecimal("1.1"))).build();
        assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(untyped).build());
        JsonObject tooLarge=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue("urn:example:Types")))).put("integer",JsonNumber.fromValue(new BigDecimal("1e5000"))).build();
        assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(type).document(tooLarge).build());
        JsonObject zero=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue("urn:example:Types")))).put("integer",JsonNumber.fromValue(new BigDecimal("0.0000"))).build();
        assertEquals("0",ScimResource.withResourceType(type).document(zero).build().getDocument().find("integer").orElseThrow().toJson());
        ScimResourceParseResult.Succeeded paths=success(create(type,envelope("\"object\":{},\"flag\":null,\"integers\":[]")));
        assertEquals(Set.of(path("object"),path("flag"),path("integers")),paths.getSuppliedAttributePaths());
        assertEquals("ScimResourceParseResult.Succeeded{resource=<redacted>, paths=<redacted>}",paths.toString());
    }

    @Test void uriDateAndBase64PrimaryBoundaryMatrix() {
        for (String value : new String[]{"", "./Users/1", "../../Users/1", "/Users/1", "https://user@example.invalid:443/a%20b?x=a/b?#f/", "http://[2001:db8::1]:80/x", "http://[v1.alpha:beta]/", "urn:example:a", "urn:", "https://example.invalid:65536/", "a:opaque", "a:/root", "a:///", "https://example.invalid/%AB", "https://example.invalid/?x=%00", "https://example.invalid/#%2F"})
            assertTrue(ScimResourceValidation.reference(value),value);
        for (String value : new String[]{"1a:bad", "+a:bad", "a^:bad", "https://u@@example.invalid/", "https://[::1", "https://[]/", "https://[v.alpha]/", "https://[v1.]/", "https://[v1.alpha]x/", "https://example.invalid:p/", "https://exa[mple.invalid/", "https://example.invalid/%", "https://example.invalid/%0", "https://example.invalid/%0g", "https://example.invalid/?x=%gg", "https://example.invalid/#%g0", "https://example.invalid/#a#b", "https://example.invalid/\\\\", "https://example.invalid/\u0001", "https://example.invalid/\u212A"})
            assertFalse(ScimResourceValidation.reference(value),value);
        for (String value : new String[]{"2000-01-01T00:00:00Z","2000-01-01T00:00:00+00:00","2000-01-01T00:00:00-00:00","2000-01-01T23:59:59-13:59","2000-04-30T24:00:00.000Z","2000-02-29T00:00:00.0","1900-02-28T00:00:00Z","2004-02-29T00:00:00Z","-0002-02-28T00:00:00Z","999999999999999999999999-12-31T23:59:59Z"})
            assertTrue(ScimResourceValidation.dateTime(value),value);
        for (String value : new String[]{"", "x", "2000", "2000-01-01", "2000-01-01T00:00", "2000/01-01T00:00:00Z", "2000-01/01T00:00:00Z", "2000-01-01 00:00:00Z", "2000-01-01T00-00:00Z", "2000-01-01T00:00-00Z", "2000-00-01T00:00:00Z", "2000-13-01T00:00:00Z", "2000-01-00T00:00:00Z", "2000-01-32T00:00:00Z", "2000-04-31T00:00:00Z", "1900-02-29T00:00:00Z", "2000-01-01T25:00:00Z", "2000-01-01T24:01:00Z", "2000-01-01T24:00:01Z", "2000-01-01T00:60:00Z", "2000-01-01T00:00:60Z", "2000-01-01T0x:00:00Z", "2000-01-01T00:0x:00Z", "2000-01-01T00:00:0xZ", "2000-01-01T00:00:00.Z", "2000-01-01T00:00:00.Q", "2000-01-01T00:00:00Zx", "2000-01-01T00:00:00+15:00", "2000-01-01T00:00:00+14:01", "2000-01-01T00:00:00+01:60", "2000-01-01T00:00:00+0x:00", "2000-01-01T00:00:00+00:0x", "2000-01-01T00:00:00+0100", "-0000-01-01T00:00:00Z", "001-01-01T00:00:00Z"})
            assertFalse(ScimResourceValidation.dateTime(value),value);
        for (String value : new String[]{"AA==","AA","AAA=","AAA","AAAA","++//","/w==","/w","YWJjZA","YWJjZA=="}) assertTrue(ScimResourceValidation.binary(value),value);
        for (String value : new String[]{"A","A=","AA=","AA===","AAA==","AAAA=","AAAA==","A===","AB","AB==","AAB","AAB=","AA A","__==","--=="}) assertFalse(ScimResourceValidation.binary(value),value);
    }

    @Test void metadataIdentifiersAndProgrammerDataRejectMalformedServerValues() {
        for (String member : new String[]{"\"id\":\"\"","\"id\":\"reservedBulkIDinside\"","\"id\":\"x\\u0000y\"","\"id\":\"x\\u007fy\"","\"meta\":{\"version\":\"1\"}","\"meta\":{\"version\":\"\\\"x\\u0000\\\"\"}","\"meta\":{\"version\":\"\\\"x\\u007f\\\"\"}","\"meta\":{\"version\":\"\\\"x\\u0100\\\"\"}","\"meta\":{\"location\":\"urn:example:location\"}","\"meta\":{\"location\":\"https:///\"}","\"meta\":{\"location\":\"https://user@example.invalid/\"}","\"meta\":{\"location\":\"http://[v1.alpha]/\"}","\"meta\":{\"created\":\"2000-01-01T00:00:00\"}","\"meta\":{\"created\":\"1000000000-01-01T00:00:00Z\"}","\"meta\":{\"resourceType\":\"Other\"}"})
            assertThrows(IllegalArgumentException.class,() -> trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\","+member+"}"),member);
        ScimResource maximum=trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"id\":\""+"a".repeat(1024)+"\",\"meta\":{\"version\":\"\\\"\\\"\",\"location\":\"HTTP://[::1]:80/Users/1\"}}");
        assertEquals(1024,maximum.getId().orElseThrow().length()); assertEquals("\"\"",maximum.getVersion().orElseThrow()); assertTrue(maximum.getLocation().isPresent());
        assertThrows(IllegalArgumentException.class,() -> trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"id\":\""+"a".repeat(1025)+"\"}"));
        assertThrows(IllegalArgumentException.class,() -> trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"meta\":{\"version\":\"\\\""+"a".repeat(1023)+"\\\"\"}}"));
        JsonObject duplicate=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER)))).put("userName","a").put("USERNAME","b").build();
        assertThrows(IllegalArgumentException.class,() -> ScimResource.withResourceType(ScimResourceType.userInstance()).document(duplicate).build());
    }

    private static @NonNull ScimResourceType types() {
        return ScimResourceType.withName("Types").endpoint("/Types").schema(ScimSchema.withId("urn:example:Types").name("Types").attributes(List.of(
                ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),ScimAttributeDefinition.withName("decimal").type(ScimAttributeType.DECIMAL).build(),ScimAttributeDefinition.withName("integer").type(ScimAttributeType.INTEGER).build(),ScimAttributeDefinition.withName("integers").type(ScimAttributeType.INTEGER).multiValued(true).build(),ScimAttributeDefinition.withName("date").type(ScimAttributeType.DATE_TIME).build(),ScimAttributeDefinition.withName("binary").type(ScimAttributeType.BINARY).caseExact(true).build(),ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).caseExact(true).build(),ScimAttributeDefinition.withName("object").type(ScimAttributeType.COMPLEX).subAttributes(List.of(ScimAttributeDefinition.withName("label").build(),ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build())).build(),ScimAttributeDefinition.withName("items").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("label").build(),ScimAttributeDefinition.withName("primary").type(ScimAttributeType.BOOLEAN).build())).build())).build()).build();
    }
    private static @NonNull String envelope(@NonNull String members) { return "{\"schemas\":[\"urn:example:Types\"],"+members+"}"; }
    private static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type,@NonNull String body) { return ScimResources.create(type,parsed(body),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT); }
    private static @NonNull ScimResourceParseResult replace(@NonNull ScimResourceType type,@NonNull ScimResource current,@NonNull String body) { return ScimResources.replace(type,current,parsed(body),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT); }
    private static com.revetsec.internal.json.@NonNull JsonDocument parsed(@NonNull String body) { return assertInstanceOf(JsonParseResult.Succeeded.class,JsonCodec.parseResult(body.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(1048576,100000))).getDocument(); }
    private static @NonNull ScimResource trusted(@NonNull ScimResourceType type,@NonNull String body) { return ScimResource.withResourceType(type).document((JsonObject)parsed(body).getValue()).build(); }
    private static ScimResourceParseResult.@NonNull Succeeded success(@NonNull ScimResourceParseResult result) { return assertInstanceOf(ScimResourceParseResult.Succeeded.class,result); }
    private static @NonNull ScimAttributePath path(@NonNull String expression) { return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult(expression)).getAttributePath(); }
}
