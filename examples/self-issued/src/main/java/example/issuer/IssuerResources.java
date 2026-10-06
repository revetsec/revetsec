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
package example.issuer;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.server.*;
import com.revetsec.oauth.ProtectedResourceMetadata;
import com.revetsec.soklet.SokletOAuthAuthorizationServer;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.HEAD;
import com.soklet.annotation.POST;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** App-owned routes, fixed demo account and consent. Library results are emitted without re-serialization. */
public final class IssuerResources {
    final IssuerConfig config;
    final OAuthAuthorizationServer server;
    final BrowserSessions sessions;
    IssuerResources(@NonNull IssuerConfig config,@NonNull Clock clock) throws java.security.GeneralSecurityException {
        this(config,clock,new VolatileStore(clock,2048,4_194_304));
    }
    IssuerResources(@NonNull IssuerConfig config,@NonNull Clock clock,@NonNull OAuthAuthorizationServerStore store) throws java.security.GeneralSecurityException {
        this.config=config;this.sessions=new BrowserSessions(clock,64,config.origin.getScheme().equals("https"));
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
        OAuthIssuerKeyProvider keys=OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(
                OAuthIssuerSigningKey.fromKeyPair(LocalInputs.randomId(),pair.getPrivate(),pair.getPublic())).generation(LocalInputs.randomId()).publishedAt(clock.instant()).build());
        Map<String,Set<String>> resources=Map.of(config.resource.toString(),IssuerConfig.SCOPES);
        OAuthServerClientAuthentication confidential=OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget) -> {
            if(budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted()) return false;
            String expected=id.equals("demo-confidential")?config.clientKey:id.equals("resource-client")?config.resourceKey:"";
            return !expected.isEmpty() && java.security.MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),secret);
        });
        OAuthServerClientRegistration publicClient=OAuthServerClientRegistration.withClientId("demo-public")
                .clientName("Local public client").redirectUris(List.of(config.redirect)).allowedScopesByResource(resources).refreshTokenPermitted(true)
                .configurationVersion("demo-v1").build();
        OAuthServerClientRegistration privateClient=OAuthServerClientRegistration.withClientId("demo-confidential")
                .clientName("Local confidential client").redirectUris(List.of(config.redirect)).allowedScopesByResource(resources).refreshTokenPermitted(true)
                .authentication(confidential).configurationVersion("demo-v1").build();
        OAuthServerClientRegistration resourceClient=OAuthServerClientRegistration.withClientId("resource-client")
                .authorizationCodePermitted(false).authentication(confidential).introspectionResources(Set.of(config.resource.toString()))
                .configurationVersion("demo-v1").build();
        Map<String,OAuthServerClientRegistration> clients=Map.of("demo-public",publicClient,"demo-confidential",privateClient,"resource-client",resourceClient);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("demo-seal",Base64.getEncoder().encodeToString(LocalInputs.randomBytes()))).build();
        this.server=OAuthAuthorizationServer.withIssuer(config.origin.toString())
                .authorizationEndpoint(config.origin.resolve("/authorize")).tokenEndpoint(config.origin.resolve("/token"))
                .jsonWebKeySetEndpoint(config.origin.resolve("/jwks")).revocationEndpoint(config.origin.resolve("/revoke"))
                .introspectionEndpoint(config.origin.resolve("/introspect"))
                .clientRepository((id,budget) -> Optional.ofNullable(clients.get(id)))
                .store(store).stateSealer(sealer).signingKeys(keys).resources(resources)
                .grantPolicy((context,budget) -> IssuerConfig.SUBJECT.equals(context.getSubject())
                        ? OAuthAuthorizationDecision.withSubject(context.getSubject()).authorizedScopesByResource(context.getAuthorizedScopesByResource())
                                .refreshTokenPermitted(context.isRefreshTokenPermitted()).build()
                        : OAuthAuthorizationDecision.deniedInstance())
                .clock(clock).clockSkew(Duration.ZERO).publicMetadataFreshness(Duration.ZERO).accessTokenLifetime(Duration.ofMinutes(2)).refreshTokensEnabled(true)
                .allowInsecureLoopback(config.loopback).allowNativeLoopbackRedirects(true).build();
        // This app deliberately creates a fresh volatile store and keys; never use this as a recovery recipe.
        if(server.initializeFreshIssuer()!=OAuthStoreCommitStatus.COMMITTED) throw new IllegalStateException("Fresh demo store initialization failed.");
        server.establishNewSubject(IssuerConfig.SUBJECT);server.warmUp();
    }
    @GET("/") public @NonNull MarshaledResponse index(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        return page("Self-issued MCP Playground","<p>Use a preregistered OAuth client with <code>demo-public</code> or <code>demo-confidential</code>. "
                +"This local application has one demo account and a volatile store. Restart discards every session, key and grant.</p>");
    }
    @GET("/.well-known/oauth-authorization-server") @HEAD("/.well-known/oauth-authorization-server")
    public @NonNull MarshaledResponse metadata(@NonNull Request request) {
        return issuerHost(request)?SokletOAuthAuthorizationServer.responseFor(server.metadataResponse(request.getHttpMethod().name())):fixed(403,"Request denied.");
    }
    @GET("/jwks") @HEAD("/jwks") public @NonNull MarshaledResponse jwks(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        try {return SokletOAuthAuthorizationServer.responseFor(server.jsonWebKeySetResponse(request.getHttpMethod().name()));}
        catch(OAuthServerException failure) {return failure(failure);}
    }
    @GET("/.well-known/oauth-protected-resource/mcp")
    public @NonNull MarshaledResponse resourceMetadata(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        return json(ProtectedResourceMetadata.withResource(config.resource).authorizationServers(List.of(config.origin.toString()))
                .scopesSupported(IssuerConfig.SCOPES.stream().sorted().toList()).allowInsecureLoopback(config.loopback).build().toJson());
    }
    @GET("/authorize") public @NonNull MarshaledResponse authorize(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        try {
            BrowserSessions.Session session=sessions.find(request).orElseGet(sessions::begin);
            OAuthAuthorizationResult result=SokletOAuthAuthorizationServer.beginAuthorizationResultFor(server,request,session.binding);
            if(result instanceof OAuthAuthorizationResult.InteractionRequired required) {
                session.pending.set(new BrowserSessions.Pending(required.getInteraction().getInteractionValue()));
                return view(session).copy().cookies(Set.of(sessions.cookie(session))).finish();
            }
            return authorizationResponse(result);
        } catch(OAuthServerException failure) {return failure(failure);}
        catch(IllegalStateException full) {return fixed(503,"Local application unavailable.");}
    }
    @GET("/consent") public @NonNull MarshaledResponse consent(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        BrowserSessions.Session session=sessions.find(request).orElse(null);if(session==null) return fixed(403,"Request denied.");
        try {return view(session);} catch(OAuthServerException failure) {return failure(failure);}
    }
    @POST("/login") public @NonNull MarshaledResponse login(@NonNull Request request) {
        if(!sameOrigin(request)) return fixed(403,"Request denied.");
        BrowserSessions.Session session=sessions.find(request).orElse(null);if(session==null) return fixed(403,"Request denied.");
        try {
            BrowserSessions.Pending selected=session.pending.get();
            Map<String,String> form=LocalInputs.form(request,Set.of("csrf","flow","key"));
            if(selected==null || !LocalInputs.matches(selected.nonce,form.get("flow")) || !LocalInputs.matches(session.csrf,form.get("csrf")) || !LocalInputs.matches(config.loginKey,form.get("key"))) return fixed(403,"Request denied.");
            BrowserSessions.Session rotated=sessions.login(session,selected);
            return localRedirect("/consent").copy().cookies(Set.of(sessions.cookie(rotated))).finish();
        } catch(IllegalArgumentException bad) {return fixed(403,"Request denied.");}
        catch(IllegalStateException expired) {return fixed(403,"Request denied.");}
    }
    @POST("/consent") public @NonNull MarshaledResponse complete(@NonNull Request request) {
        if(!sameOrigin(request)) return fixed(403,"Request denied.");
        BrowserSessions.Session session=sessions.find(request).orElse(null);
        if(session==null || !session.authenticated) return fixed(403,"Request denied.");
        try {
            BrowserSessions.Pending selected=session.pending.get();
            Map<String,String> form=LocalInputs.form(request,Set.of("csrf","flow","decision"));
            if(selected==null || !LocalInputs.matches(selected.nonce,form.get("flow")) || !LocalInputs.matches(session.csrf,form.get("csrf")) || !Set.of("approve","deny").contains(form.getOrDefault("decision",""))) return fixed(403,"Request denied.");
            OAuthAuthorizationResult checked=server.resumeAuthorizationResult(selected.handle,session.binding);
            if(!(checked instanceof OAuthAuthorizationResult.InteractionRequired required)) return authorizationResponse(checked);
            OAuthAuthorizationDecision decision=form.get("decision").equals("deny")?OAuthAuthorizationDecision.deniedInstance()
                    :OAuthAuthorizationDecision.withSubject(IssuerConfig.SUBJECT).authorizedScopesByResource(required.getInteraction().getRequestedScopesByResource())
                            .refreshTokenPermitted(true).build();
            OAuthAuthorizationResult result=server.completeAuthorizationResult(selected.handle,session.binding,decision);
            session.pending.compareAndSet(selected,null);return authorizationResponse(result);
        } catch(IllegalArgumentException bad) {return fixed(403,"Request denied.");}
        catch(OAuthServerException failure) {return failure(failure);}
    }
    @POST("/logout") public @NonNull MarshaledResponse logout(@NonNull Request request) {
        if(!sameOrigin(request)) return fixed(403,"Request denied.");
        BrowserSessions.Session session=sessions.find(request).orElse(null);if(session==null) return fixed(403,"Request denied.");
        try {
            if(!LocalInputs.matches(session.csrf,LocalInputs.form(request,Set.of("csrf")).get("csrf"))) return fixed(403,"Request denied.");
            sessions.remove(session);return fixed(200,"Browser session ended; issued grants require OAuth revocation.");
        } catch(IllegalArgumentException bad) {return fixed(403,"Request denied.");}
    }
    @POST("/token") public @NonNull MarshaledResponse token(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        try {OAuthTokenResult result=SokletOAuthAuthorizationServer.tokenResultFor(server,request);
            return SokletOAuthAuthorizationServer.responseFor(result instanceof OAuthTokenResult.Succeeded s?s.getResponse():((OAuthTokenResult.Rejected)result).getResponse());}
        catch(OAuthServerException failure) {return failure(failure);}
    }
    @POST("/revoke") public @NonNull MarshaledResponse revoke(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        try {OAuthRevocationResult result=SokletOAuthAuthorizationServer.revocationResultFor(server,request);
            return SokletOAuthAuthorizationServer.responseFor(result instanceof OAuthRevocationResult.Succeeded s?s.getResponse():((OAuthRevocationResult.Rejected)result).getResponse());}
        catch(OAuthServerException failure) {return failure(failure);}
    }
    @POST("/introspect") public @NonNull MarshaledResponse introspect(@NonNull Request request) {
        if(!issuerHost(request)) return fixed(403,"Request denied.");
        try {OAuthIntrospectionResult result=SokletOAuthAuthorizationServer.introspectionResultFor(server,request);
            return SokletOAuthAuthorizationServer.responseFor(result instanceof OAuthIntrospectionResult.Succeeded s?s.getResponse():((OAuthIntrospectionResult.Rejected)result).getResponse());}
        catch(OAuthServerException failure) {return failure(failure);}
    }
    private @NonNull MarshaledResponse view(BrowserSessions.@NonNull Session session) {
        BrowserSessions.Pending selected=session.pending.get();
        if(selected==null) return fixed(403,"Request denied.");
        OAuthAuthorizationResult result=server.resumeAuthorizationResult(selected.handle,session.binding);
        if(!(result instanceof OAuthAuthorizationResult.InteractionRequired required)) return authorizationResponse(result);
        OAuthServerInteraction interaction=required.getInteraction();
        String details="<p>Client: "+LocalInputs.html(interaction.getClientName().orElse(interaction.getClientId()))+"</p><p>Return destination: "
                +LocalInputs.html(interaction.getRedirectUri().toString())+"</p><p>Requested scopes: "+LocalInputs.html(interaction.getRequestedScopesByResource().toString())+"</p>";
        String csrf="<input type='hidden' name='csrf' value='"+LocalInputs.html(session.csrf)+"'><input type='hidden' name='flow' value='"+LocalInputs.html(selected.nonce)+"'>";
        if(!session.authenticated) return page("Demo login",details+"<form method='post' action='/login'>"+csrf
                +"<label>Local demo access key <input type='password' name='key' autocomplete='off' maxlength='43' required></label><button>Sign in</button></form>");
        return page("Consent",details+"<form method='post' action='/consent'>"+csrf
                +"<button name='decision' value='approve'>Approve</button><button name='decision' value='deny'>Deny</button></form>");
    }
    private @NonNull MarshaledResponse authorizationResponse(@NonNull OAuthAuthorizationResult result) {
        OAuthServerResponse response;
        if(result instanceof OAuthAuthorizationResult.Completed r) response=r.getResponse();
        else if(result instanceof OAuthAuthorizationResult.Denied r) response=r.getResponse();
        else if(result instanceof OAuthAuthorizationResult.Rejected r) response=r.getResponse();
        else throw new IllegalStateException("Interaction requires application rendering.");
        return SokletOAuthAuthorizationServer.responseFor(response);
    }
    private @NonNull MarshaledResponse failure(@NonNull OAuthServerException failure) {return SokletOAuthAuthorizationServer.responseFor(server.responseForFailure(failure));}
    private boolean issuerHost(@NonNull Request request) {return LocalInputs.headers(request,"Host").equals(List.of(config.origin.getRawAuthority()));}
    private boolean sameOrigin(@NonNull Request request) {return issuerHost(request) && LocalInputs.headers(request,"Origin").equals(List.of(config.origin.toString()));}
    private static @NonNull MarshaledResponse localRedirect(@NonNull String path) {
        return MarshaledResponse.withStatusCode(303).headers(Map.of("Location",Set.of(path),"Cache-Control",Set.of("no-store"),"Referrer-Policy",Set.of("no-referrer"))).build();
    }
    static @NonNull MarshaledResponse fixed(int status,@NonNull String text) {return response(status,text,"text/plain; charset=UTF-8");}
    private static @NonNull MarshaledResponse json(@NonNull String text) {return response(200,text,"application/json");}
    private static @NonNull MarshaledResponse page(@NonNull String title,@NonNull String content) {
        return response(200,"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>"+LocalInputs.html(title)
                +"</title></head><body><h1>"+LocalInputs.html(title)+"</h1>"+content+"</body></html>","text/html; charset=UTF-8");
    }
    private static @NonNull MarshaledResponse response(int status,@NonNull String text,@NonNull String type) {
        return MarshaledResponse.withStatusCode(status).headers(Map.of("Content-Type",Set.of(type),"Cache-Control",Set.of("no-store"),
                "Pragma",Set.of("no-cache"),"Referrer-Policy",Set.of("no-referrer"),"X-Content-Type-Options",Set.of("nosniff"),
                "Content-Security-Policy",Set.of("default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")))
                .body(text.getBytes(StandardCharsets.UTF_8)).build();
    }
}
