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

import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScimM10FacadeResourceTests {
    private static final @NonNull String USER="urn:ietf:params:scim:schemas:core:2.0:User";

    @Test void parsingWithRelaxedProviderCannotLaunderThroughCopyIntoStrictRenderingOrReplacement() {
        ScimResourceType type=ScimResourceType.userInstance();
        ScimServiceProvider strict=provider(ScimCompatibility.strictInstance());
        ScimServiceProvider relaxed=provider(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS)).build());
        ScimResourceParseResult.Succeeded parsed=assertInstanceOf(ScimResourceParseResult.Succeeded.class,relaxed.parseResourceResult(type,bytes("{\"schemas\":[\""+USER+"\"],\"userName\":\"private-name\",\"active\":\"true\",\"password\":\"private-secret\"}")));
        JsonObject assigned=documentWithId(parsed.getResource(),"assigned");
        ScimResource persisted=parsed.getResource().copy().document(assigned).finish();
        ScimAttributeSelection selection=selection(strict,type);
        assertEquals(ScimErrorType.INVALID_VALUE,assertInstanceOf(ScimResponseResult.Rejected.class,strict.createdResponseResult(persisted,parsed.getSuppliedAttributePaths(),selection)).getError().getErrorType().orElseThrow());
        assertInstanceOf(ScimResponseResult.Rejected.class,strict.resourceResponseResult(persisted.copy().document(null).finish(),selection));
        assertInstanceOf(ScimResourceParseResult.Rejected.class,strict.parseReplacementResult(type,persisted,bytes("{\"schemas\":[\""+USER+"\"],\"userName\":\"another\"}")));
        ScimAttributeSelection relaxedSelection=selection(relaxed,type);
        ScimResponse response=assertInstanceOf(ScimResponseResult.Prepared.class,relaxed.createdResponseResult(persisted,parsed.getSuppliedAttributePaths(),relaxedSelection)).getResponse();
        String body=new String(response.toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(body.contains("private-name")); assertFalse(body.contains("private-secret")); assertFalse(body.contains("password"));
        assertFalse(response.toString().contains("private-name")); assertFalse(response.toString().contains("assigned"));
        assertFalse(parsed.toString().contains("private-name")); assertFalse(parsed.getResource().toString().contains("private-secret"));
        byte[] edited=response.toHttpBodyWithPersonalData(); edited[0]=0;
        assertEquals('{',response.toHttpBodyWithPersonalData()[0]);
        assertThrows(UnsupportedOperationException.class,() -> response.getHeaders().clear());
        ScimResource deliberate=ScimResource.withResourceType(type).document(assigned).build();
        assertNull(deliberate.getSemanticContext());
        assertInstanceOf(ScimResponseResult.Prepared.class,strict.resourceResponseResult(deliberate,selection));
    }

    @Test void baseUriCopyKeepsSemanticBindingsWhileCompatibilityCopyRequiresRebinding() {
        ScimResourceType type=ScimResourceType.userInstance();
        ScimServiceProvider original=provider(ScimCompatibility.strictInstance());
        ScimAttributeSelection originalSelection=selection(original,type);
        ScimResourceParseResult.Succeeded parsed=assertInstanceOf(ScimResourceParseResult.Succeeded.class,original.parseResourceResult(type,bytes("{\"schemas\":[\""+USER+"\"],\"userName\":\"a\"}")));
        ScimResource assigned=parsed.getResource().copy().document(documentWithId(parsed.getResource(),"1")).finish();
        ScimServiceProvider rebased=original.copy().baseUri(URI.create("https://other.example.invalid/provisioning/")).finish();
        ScimResponse response=assertInstanceOf(ScimResponseResult.Prepared.class,rebased.createdResponseResult(assigned,parsed.getSuppliedAttributePaths(),originalSelection)).getResponse();
        assertEquals(List.of("https://other.example.invalid/provisioning/Users/1"),response.getHeaders().get("Location"));
        ScimServiceProvider changed=original.copy().compatibility(ScimCompatibility.microsoftEntraIdInstance()).finish();
        assertInstanceOf(ScimResponseResult.Rejected.class,changed.resourceResponseResult(assigned,originalSelection));
        assertInstanceOf(ScimResponseResult.Rejected.class,original.resourceResponseResult(assigned,selection(changed,type)));
        assertInstanceOf(ScimResponseResult.Prepared.class,original.copy().baseUri(null).compatibility(null).finish().resourceResponseResult(assigned,originalSelection));
    }

    @Test void framingAndObserverEventsAreFixedAndDoNotContainProvisioningData() {
        Recording observer=new Recording();
        ScimResourceType type=ScimResourceType.userInstance();
        ScimServiceProvider provider=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/v2/")).resourceTypes(List.of(type))
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS)).build()).observer(observer).build();
        byte[] secret=bytes("{\"schemas\":[\""+USER+"\"],\"userName\":\"private-data\",\"active\":\"true\"}");
        assertEquals(415,assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(type,List.of(),secret)).getError().getStatusCode());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseResourceResult(type,List.of("application/scim+json; charset=UTF-8"),secret));
        assertEquals(List.of(ScimObserver.Operation.RESOURCE_CREATE,ScimObserver.Operation.RESOURCE_CREATE),observer.started);
        assertEquals(List.of(ScimObserver.Outcome.REJECTED,ScimObserver.Outcome.SUCCEEDED),observer.outcomes);
        assertEquals(List.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),observer.features);
        assertTrue(observer.failed.isEmpty());
        assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(type,new byte[0]));
        assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(type,new byte[]{(byte)0xc0,(byte)0x80}));
        assertFalse(observer.started.toString().contains("private-data")); assertFalse(observer.features.toString().contains("private-data"));
        assertThrows(IllegalArgumentException.class,() -> provider.parseResourceResult(ScimResourceType.groupInstance(),secret));
        ScimServiceProvider fault=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/v2/")).resourceTypes(List.of(type)).observer(new ScimObserver() {
            @Override public void willProcess(@NonNull Operation operation) { throw new IllegalStateException("private-callback-detail"); }
        }).build();
        ScimResourceParseResult.Succeeded unaffected=assertInstanceOf(ScimResourceParseResult.Succeeded.class,fault.parseResourceResult(type,bytes("{\"schemas\":[\""+USER+"\"],\"userName\":\"private-data\",\"active\":true}")));
        assertEquals("private-data",ScimUser.fromResource(unaffected.getResource()).getUserName());
        assertFalse(unaffected.toString().contains("private-callback-detail"));
    }

    @Test void schemaDiscoveryIncludesDeepDescriptorMetadataAndDoesNotTreatUriIdsAsOpaqueApplicationIds() {
        ScimServiceProvider provider=provider(ScimCompatibility.strictInstance());
        ScimResponse response=assertInstanceOf(ScimResponseResult.Prepared.class,provider.schemasResponseResult("")).getResponse();
        String body=new String(response.toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(body.contains("\"subAttributes\"")); assertTrue(body.contains("\"required\"")); assertTrue(body.contains("\"attributes\""));
        assertTrue(body.contains("urn:ietf:params:scim:schemas:core:2.0:User"));
        assertFalse(response.toString().contains("urn:ietf"));
        assertInstanceOf(ScimResponseResult.Prepared.class,provider.schemaResponseResult(USER,"attributes=id,name,attributes.subAttributes"));
        assertInstanceOf(ScimResponseResult.Prepared.class,provider.resourceTypesResponseResult(""));
        assertInstanceOf(ScimResponseResult.Prepared.class,provider.resourceTypeResponseResult("User",""));
        assertInstanceOf(ScimResponseResult.Prepared.class,provider.serviceProviderConfigResponseResult(""));
    }

    private static @NonNull ScimServiceProvider provider(@NonNull ScimCompatibility compatibility) { return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/v2/")).resourceTypes(List.of(ScimResourceType.userInstance())).compatibility(compatibility).build(); }
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type) { return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,provider.parseAttributeSelectionResult(type,"")).getAttributeSelection(); }
    private static @NonNull JsonObject documentWithId(@NonNull ScimResource resource,@NonNull String id) { java.util.Map<String,JsonValue> members=new java.util.LinkedHashMap<>(resource.getDocument().getMembers());members.put("id",JsonString.fromValue(id));return JsonObject.fromMembers(members); }
    private static byte @NonNull [] bytes(@NonNull String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static final class Recording implements ScimObserver {
        final @NonNull List<@NonNull Operation> started=new ArrayList<>();
        final @NonNull List<@NonNull Outcome> outcomes=new ArrayList<>();
        final @NonNull List<@NonNull Operation> failed=new ArrayList<>();
        final @NonNull List<@NonNull ScimCompatibilityFeature> features=new ArrayList<>();
        @Override public void willProcess(@NonNull Operation operation) { started.add(operation); }
        @Override public void didProcess(@NonNull Operation operation,@NonNull Outcome outcome) { outcomes.add(outcome); }
        @Override public void didFailToProcess(@NonNull Operation operation) { failed.add(operation); }
        @Override public void didUseCompatibilityFeature(@NonNull ScimCompatibilityFeature feature) { features.add(feature); }
    }
}
