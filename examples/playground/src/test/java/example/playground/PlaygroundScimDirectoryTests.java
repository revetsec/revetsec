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
package example.playground;

import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class PlaygroundScimDirectoryTests {
    private static final URI ORIGIN=URI.create("https://app.example");
    private static final String ADMIN="synthetic-alpha-admin-private-credential-0000", LIMITED="synthetic-alpha-limited-private-credential-0000", READER="synthetic-alpha-reader-private-credential-0000", BETA="synthetic-beta-admin-private-credential-0000", BETA_READER="synthetic-beta-reader-private-credential-0000";
    private static @NonNull PlaygroundScimDirectory directory(){return Objects.requireNonNull(PlaygroundScimDirectory.fromEnvironment(ORIGIN,Map.of("SCIM_BEARER_TOKEN",ADMIN,"SCIM_ALPHA_LIMITED_TOKEN",LIMITED,"SCIM_ALPHA_READER_TOKEN",READER,"SCIM_BETA_BEARER_TOKEN",BETA,"SCIM_BETA_READER_TOKEN",BETA_READER)));}
    private static @NonNull Request request(@NonNull HttpMethod method,@NonNull String path,@NonNull String token,@NonNull String body){
        var builder=Request.withRawUrl(method,path).headers(Map.of("Host",List.of("app.example"),"Authorization",List.of("Bearer "+token),"Content-Type",List.of("application/scim+json")));
        if(!body.isEmpty())builder.body(body.getBytes(StandardCharsets.UTF_8));return builder.build();
    }
    private static @NonNull String user(@NonNull String name,@NonNull String fields){return "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"externalId\":\""+name+"\",\"userName\":\""+name+"\",\"active\":true"+fields+"}";}
    private static @NonNull String text(@NonNull MarshaledResponse response){return response.getBody().map(body->new String(((MarshaledResponseBody.Bytes)body).getBytes(),StandardCharsets.UTF_8)).orElse("");}

    @Test void privateServiceRolesAndCanonicalTenantAliasesDoNotShareAuthority(){
        var app=directory();var alpha=app.handle(request(HttpMethod.POST,"/scim/v2/Users",ADMIN,user("alice","")));assertEquals(201,alpha.getStatusCode());
        assertEquals(List.of("https://app.example/scim/alpha/v2/Users/u1"),alpha.getHeaders().get("Location"));
        assertEquals(200,app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users/u1",READER,"")).getStatusCode());
        assertEquals(200,app.handle(request(HttpMethod.GET,"/scim/v2/Users/u1",READER,"")).getStatusCode());
        assertEquals(403,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",READER,"not-json")).getStatusCode());
        assertEquals(403,app.handle(request(HttpMethod.GET,"/scim/beta/v2/Users/u1",READER,"")).getStatusCode());
        assertEquals(404,app.handle(request(HttpMethod.GET,"/scim/beta/v2/Users/u1",BETA_READER,"")).getStatusCode());
        assertEquals(201,app.handle(request(HttpMethod.POST,"/scim/beta/v2/Users",BETA,user("bob",""))).getStatusCode());
        assertTrue(text(app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users/u1",READER,""))).contains("alice"));
        assertFalse(text(app.handle(request(HttpMethod.GET,"/scim/beta/v2/Users/u1",BETA_READER,""))).contains("alice"));
        var filtered=app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users?filter=userName%20eq%20%22bob%22",READER,""));assertEquals(200,filtered.getStatusCode());assertTrue(text(filtered).contains("\"totalResults\":0"));
    }
    @Test void privilegedFieldsAndCredentialRightsAreAuthorizedBeforeWork(){
        var app=directory();for(String field:List.of("roles","entitlements")){
            var denied=app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice",",\""+field+"\":[{\"value\":\"administrator\"}]")));assertEquals(403,denied.getStatusCode(),field);
        }
        assertEquals(403,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice",",\"userType\":\"administrator\""))).getStatusCode());
        assertEquals(403,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",LIMITED,user("alice",",\"password\":\"synthetic-private-password\""))).getStatusCode());
        var created=app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice",",\"password\":\"synthetic-private-password\"")));assertEquals(201,created.getStatusCode());assertFalse(text(created).contains("synthetic-private-password"));assertFalse(text(created).contains("argon2"));
        var privilegedQuery=app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users?filter=roles.value%20eq%20%22administrator%22",READER,""));assertEquals(400,privilegedQuery.getStatusCode());
    }
    @Test void exactWritePreconditionsAndGroupMembershipStayWithinTenant(){
        var app=directory();assertEquals(201,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice",""))).getStatusCode());
        String group="{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"externalId\":\"team\",\"displayName\":\"team\",\"members\":[{\"value\":\"u1\"}]}";
        assertEquals(201,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Groups",ADMIN,group)).getStatusCode());assertEquals(400,app.handle(request(HttpMethod.POST,"/scim/beta/v2/Groups",BETA,group)).getStatusCode());
        String patch="{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"New\"}]}";
        assertEquals(412,app.handle(request(HttpMethod.PATCH,"/scim/alpha/v2/Users/u1",ADMIN,patch)).getStatusCode());
        var valid=request(HttpMethod.PATCH,"/scim/alpha/v2/Users/u1",ADMIN,patch).copy().headers(headers->headers.put("If-Match",List.of("W/\"u1:1\""))).finish();assertEquals(200,app.handle(valid).getStatusCode());assertEquals(412,app.handle(valid).getStatusCode());
        assertEquals(409,app.handle(request(HttpMethod.DELETE,"/scim/alpha/v2/Users/u1",ADMIN,"").copy().headers(headers->headers.put("If-Match",List.of("W/\"u1:2\""))).finish()).getStatusCode());
    }
    @Test void strictCredentialAndHeaderChannelsDoNotTrustRoleOrTenantHints(){
        var app=directory();assertEquals(401,app.handle(request(HttpMethod.GET,"/scim/alpha/v2/Users","unregistered-private-credential-00000000","")).getStatusCode());
        var lower=request(HttpMethod.GET,"/scim/alpha/v2/Users",READER,"").copy().headers(headers->headers.put("Authorization",List.of("bearer   "+READER))).finish();assertEquals(200,app.handle(lower).getStatusCode());
        assertEquals(403,app.handle(lower.copy().headers(headers->headers.put("Origin",List.of("https://foreign.example"))).finish()).getStatusCode());
        assertEquals(400,app.handle(lower.copy().headers(headers->headers.put("Cookie",List.of("role=administrator"))).finish()).getStatusCode());
        assertEquals(403,app.handle(request(HttpMethod.POST,"/scim/alpha/v2/Users",READER,user("alice","")).copy().headers(headers->{headers.put("X-Role",List.of("PROVISIONER"));headers.put("X-Tenant",List.of("alpha"));}).finish()).getStatusCode());
        assertThrows(IllegalArgumentException.class,()->PlaygroundScimDirectory.fromEnvironment(ORIGIN,Map.of("SCIM_BEARER_TOKEN",ADMIN,"SCIM_ALPHA_READER_TOKEN",ADMIN)));
        assertNull(PlaygroundScimDirectory.fromEnvironment(ORIGIN,Map.of()));
        assertThrows(IllegalArgumentException.class,()->PlaygroundScimDirectory.fromEnvironment(ORIGIN,Map.of("SCIM_BEARER_TOKEN",ADMIN,"SCIM_BASE_URI","https://foreign.example/scim/v2/")));
        assertNotNull(PlaygroundScimDirectory.fromEnvironment(ORIGIN,Map.of("SCIM_BEARER_TOKEN",ADMIN,"SCIM_BASE_URI","https://app.example/scim/v2/")));
    }
    @Test void sharedRouteConfigurationKeepsLegacyFixtureOutOfTenantAliases(){
        var app=directory();SokletSimulator.run(ScimPlayground.config(app,"127.0.0.1",0),simulator->{
            assertEquals(201,simulator.performHttpRequest(request(HttpMethod.POST,"/scim/alpha/v2/Users",ADMIN,user("alice",""))).getMarshaledResponse().getStatusCode());
            for(String prefix:List.of("/scim/v2/","/scim/alpha/v2/")){
                for(String path:List.of("Users","Groups","ServiceProviderConfig","Schemas","ResourceTypes")){
                    var head=simulator.performHttpRequest(request(HttpMethod.HEAD,prefix+path,READER,"")).getMarshaledResponse();assertEquals(200,head.getStatusCode(),path);assertTrue(head.getBody().isEmpty());
                    assertEquals(204,simulator.performHttpRequest(request(HttpMethod.OPTIONS,prefix+path,READER,"")).getMarshaledResponse().getStatusCode());
                }
                var wrongMethod=simulator.performHttpRequest(request(HttpMethod.PATCH,prefix+"Users",ADMIN,"{}")).getMarshaledResponse();assertEquals(405,wrongMethod.getStatusCode());assertTrue(Objects.requireNonNull(wrongMethod.getHeaders().get("Allow")).get(0).contains("HEAD"));
            }
        });
        var legacy=PlaygroundScim.create(URI.create("https://app.example/scim/v2/"),ADMIN);
        SokletSimulator.run(ScimPlayground.config(legacy,"127.0.0.1",0),simulator->assertEquals(404,simulator.performHttpRequest(request(HttpMethod.GET,"/scim/beta/v2/Users",ADMIN,"")).getMarshaledResponse().getStatusCode()));
    }
}
