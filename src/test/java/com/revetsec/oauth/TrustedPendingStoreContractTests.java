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

package com.revetsec.oauth;

import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.json.*;
import com.revetsec.internal.json.*;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Characterizes the selected trusted-store boundary; structural resolution is not authentication or identity. */
final class TrustedPendingStoreContractTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-11-05T12:00:00Z");
 private static final @NonNull Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final @NonNull String BINDING="TEST-ONLY-browser-binding";
 private static @NonNull PendingAuthorization pending(){
  var metadata=OidcProviderMetadata.withIssuer("https://issuer.example").authorizationEndpoint(URI.create("https://issuer.example/auth")).tokenEndpoint(URI.create("https://issuer.example/token")).jwksUri(URI.create("https://issuer.example/keys")).build();
  return OidcClient.withProviderMetadata(metadata).clientId("client").redirectUri(URI.create("https://app.example/callback")).clock(CLOCK).build().beginAuthentication(OidcAuthenticationOptions.builder().applicationData(Map.of("returnTo","/account")).build()).getPendingAuthorization();
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> aBindingDigestDoesNotAuthenticateStoreControlledFields(){
  return Stream.of("verifier","nonce","expires_at","authorization_endpoint","application_data").map(field->DynamicTest.dynamicTest("trusted-store-"+field,()->{
   var original=pending();var store=new Capture();assertEquals(PendingAuthorizationSaveResult.SAVED,original.saveToResult(store,BINDING));
   byte[] bytes=StrictUtf8.encode(Objects.requireNonNull(store.record.get()));JsonObject envelope;
   try{envelope=(JsonObject)JsonCodec.parse(bytes,JsonLimits.protocolDocument(65536));}finally{Arrays.fill(bytes,(byte)0);}
   Map<String,JsonValue> fields=new HashMap<>(envelope.getMembers());
   switch(field){
    case "verifier"->fields.put(field,JsonString.fromValue("v".repeat(43)));
    case "nonce"->fields.put(field,JsonString.fromValue("n".repeat(43)));
    case "expires_at"->fields.put(field,JsonString.fromValue(NOW.plusSeconds(1800).toString()));
    case "authorization_endpoint"->fields.put(field,JsonString.fromValue("https://changed.example/auth"));
    case "application_data"->fields.put(field,JsonObject.builder().put("returnTo","https://attacker.invalid/").build());
    default->throw new AssertionError("Unselected fixture");
   }
   fields.put("binding_digest",JsonString.fromValue(PendingAuthorizationCodec.bindingDigest(BINDING)));
   store.record.set(JsonObject.fromMembers(fields).toJson());
   var resolved=PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(store,BINDING),original.state(),CLOCK);
   assertEquals(1,store.consumes.get());assertEquals(original.state(),resolved.state());
   switch(field){case "verifier"->assertEquals("v".repeat(43),resolved.verifier());case "nonce"->assertEquals("n".repeat(43),resolved.nonce());case "expires_at"->assertEquals(NOW.plusSeconds(1800),resolved.getExpiresAt());case "authorization_endpoint"->assertEquals("https://changed.example/auth",resolved.authorizationEndpoint().toString());case "application_data"->assertEquals("https://attacker.invalid/",resolved.getApplicationData().get("returnTo"));default->throw new AssertionError("Unselected fixture");}
   // No token endpoint, ID-token validation, return redirect or authentication proof is invoked/released here.
  }));
 }
 @Test void theDigestStillRejectsAnUnchangedRecordFromAnotherBrowser(){var pending=pending();var store=new Capture();assertEquals(PendingAuthorizationSaveResult.SAVED,pending.saveToResult(store,BINDING));assertEquals(OAuthException.Reason.BROWSER_BINDING_MISMATCH,assertThrows(OAuthValidationException.class,()->PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(store,"different-browser"),pending.state(),CLOCK)).getReason());assertEquals(1,store.consumes.get());}
 @Test void atomicSingleUseStillComesFromTheStore(){var pending=pending();var store=new Capture();assertEquals(PendingAuthorizationSaveResult.SAVED,pending.saveToResult(store,BINDING));assertNotNull(PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(store,BINDING),pending.state(),CLOCK));assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND,assertThrows(OAuthValidationException.class,()->PendingAuthorizationResolver.resolve(PendingAuthorizationSource.fromStore(store,BINDING),pending.state(),CLOCK)).getReason());assertEquals(2,store.consumes.get());}
 private static final class Capture implements PendingAuthorizationStore{
  private final @NonNull AtomicReference<@Nullable String> record=new AtomicReference<>();private final @NonNull AtomicInteger consumes=new AtomicInteger();
  @Override public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding,@NonNull String state,@NonNull String encoded,@NonNull Instant expiresAt,@NonNull Duration remaining){record.set(encoded);return PendingAuthorizationSaveResult.SAVED;}
  @Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding,@NonNull String state,@NonNull Duration remaining){consumes.incrementAndGet();return Optional.ofNullable(record.getAndSet(null));}
 }
}
