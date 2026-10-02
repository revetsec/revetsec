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

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.testing.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.Nullable;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** Resource verdict events contain no credentials; inherited endpoint observers are identity-deduplicated. */
final class AccessTokenObserverTests {
    @Test void compatibilityEnableUseAndVerdictsFireOnceAndThrowingHooksAreContained() {
        AtomicInteger enabled=new AtomicInteger(),used=new AtomicInteger(),good=new AtomicInteger(),bad=new AtomicInteger();
        AccessTokenObserver observer=new AccessTokenObserver(){
            @Override public void didEnableCompatibilityMode(@NonNull AccessTokenCompatibilityMode m){enabled.incrementAndGet();throw new IllegalStateException("TEST-ONLY-hook");}
            @Override public void didUseCompatibilityMode(@NonNull AccessTokenCompatibilityMode m){used.incrementAndGet();throw new IllegalStateException("TEST-ONLY-hook");}
            @Override public void didValidateAccessToken(){good.incrementAndGet();throw new IllegalStateException("TEST-ONLY-hook");}
            @Override public void didRejectAccessToken(@NonNull AccessTokenValidationException e){bad.incrementAndGet();redacted(e,"TEST-ONLY-subject");throw new IllegalStateException("TEST-ONLY-hook");}
        };
        JwtAccessTokenValidator validator=jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("app")).observer(observer).build();assertEquals(1,enabled.get());assertEquals(0,used.get());
        Map<String,String> c=claims(ISSUER);c.put("app","true");assertNotNull(validator.validate(bearer(token(c,"JWT"))));assertEquals(1,used.get());assertEquals(1,good.get());
        c.put("nonce","null");assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(bearer(token(c,null))));assertEquals(2,used.get());assertEquals(1,bad.get());
        assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(bearer("broken")));assertEquals(2,used.get());assertEquals(2,bad.get());
    }
    @Test void sameObserverReceivesOneEndpointEventAndResourceVerdictsOnlyOnce() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger before=new AtomicInteger(),after=new AtomicInteger(),good=new AtomicInteger(),bad=new AtomicInteger(),failure=new AtomicInteger();
            AccessTokenObserver observer=new AccessTokenObserver(){
                @Override public void willRequestEndpoint(@NonNull OAuthEndpoint k,@NonNull URI uri){assertEquals(OAuthEndpoint.INTROSPECTION,k);assertNull(uri.getRawQuery());before.incrementAndGet();throw new IllegalStateException();}
                @Override public void didRequestEndpoint(@NonNull OAuthEndpoint k,@NonNull URI uri,@NonNull Integer status,@NonNull Duration elapsed){after.incrementAndGet();}
                @Override public void didFailEndpoint(@NonNull OAuthEndpoint k,@NonNull URI uri,@NonNull OAuthException e,@NonNull Duration elapsed){failure.incrementAndGet();redacted(e,SECRET,"opaque");}
                @Override public void didValidateAccessToken(){good.incrementAndGet();}
                @Override public void didRejectAccessToken(@NonNull AccessTokenValidationException e){bad.incrementAndGet();}
            };
            OAuthClient oauth=oauth(server).observer(observer).build();TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).observer(observer).build();
            response(server,"/inspect",200,"application/json",active());assertNotNull(client.validate(bearer("opaque")));assertEquals(1,before.get());assertEquals(1,after.get());assertEquals(1,good.get());
            response(server,"/inspect",200,"application/json","{\"active\":false}");assertInstanceOf(AccessTokenValidationResult.Rejected.class,client.validateResult(bearer("opaque")));assertEquals(1,bad.get());assertEquals(2,before.get());
            response(server,"/inspect",503,"application/json","{}");assertThrows(OAuthErrorResponseException.class,()->client.validateResult(bearer("opaque")));assertEquals(1,failure.get());assertEquals(1,bad.get());assertEquals(3,before.get());
        }
    }
    @Test void distinctEndpointObserversBothReceiveRequestsButOnlyResourceGetsVerdicts() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger app=new AtomicInteger(),resource=new AtomicInteger();OAuthObserver one=new OAuthObserver(){@Override public void didRequestEndpoint(@NonNull OAuthEndpoint k,@NonNull URI uri,@NonNull Integer status,@NonNull Duration elapsed){app.incrementAndGet();}};
            AccessTokenObserver two=new AccessTokenObserver(){@Override public void didRequestEndpoint(@NonNull OAuthEndpoint k,@NonNull URI uri,@NonNull Integer status,@NonNull Duration elapsed){resource.incrementAndGet();}};
            response(server,"/inspect",200,"application/json",active());TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth(server).observer(one).build()).expectedAudiences(Set.of(AUD)).observer(two).build();assertNotNull(client.validate(bearer("opaque")));assertEquals(1,app.get());assertEquals(1,resource.get());
        }
    }
    @Test void transportResponseFailuresAndUnencodedBasicAreReportedExactlyOnce() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            for(boolean identical:List.of(true,false)) {
                RecordingObserver<AccessTokenObserver> app=RecordingObserver.fromInterface(AccessTokenObserver.class);RecordingObserver<AccessTokenObserver> resource=identical?app:RecordingObserver.fromInterface(AccessTokenObserver.class);
                ClientAuthentication authentication=ClientAuthentication.fromClientSecretBasic(SECRET,ClientSecretBasicEncoding.UNENCODED);
                OAuthClient oauth=oauth(server).observer(app.getObserver()).clientAuthentication(authentication).build();TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).observer(resource.getObserver()).build();
                assertEquals(1,app.getCalls().stream().filter(c->c.getMethodName().equals("didUseUnencodedBasic")).count());
                response(server,"/inspect",200,"application/token-introspection+jwt","TEST-ONLY-prose");assertThrows(OAuthResponseException.class,()->client.validateResult(bearer("opaque")));
                assertEquals(2,app.getCalls().stream().filter(c->c.getMethodName().equals("didUseUnencodedBasic")).count());
                assertEquals(identical?2:1,resource.getCalls().stream().filter(c->c.getMethodName().equals("didUseUnencodedBasic")).count());
                for(var recorder:List.of(app,resource)) {
                    assertEquals(1,recorder.getCalls().stream().filter(c->c.getMethodName().equals("didFailEndpoint")).count());assertEquals(0,recorder.getCalls().stream().filter(c->c.getMethodName().equals("didRejectAccessToken")).count());
                }
            }
        }
    }

}
