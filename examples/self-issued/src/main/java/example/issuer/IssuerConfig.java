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

import java.io.IOException;
import java.net.URI;
import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import com.revetsec.oauth.server.OAuthClientMetadataPolicy;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Fixed local app identities; request headers never configure the issuer or resource. */
final class IssuerConfig {
    static final String SUBJECT="demo-user";
    static final Set<String> SCOPES=Set.of("mcp:discover","mcp:whoami");
    final URI origin,resource,redirect,browserOrigin;
    final int httpPort,mcpPort;
    final String loginKey,clientKey,resourceKey;
    final boolean loopback,secondResourceEnabled;
    final @NonNull OAuthClientMetadataPolicy metadataPolicy;
    IssuerConfig(@NonNull URI origin,@NonNull URI resource,@NonNull URI redirect,int httpPort,int mcpPort,
            @NonNull String loginKey,@NonNull String clientKey,@NonNull String resourceKey,boolean loopback) {
        this(origin,resource,redirect,URI.create(redirect.getScheme()+"://"+redirect.getRawAuthority()),httpPort,mcpPort,loginKey,clientKey,resourceKey,loopback);
    }
    IssuerConfig(@NonNull URI origin,@NonNull URI resource,@NonNull URI redirect,@NonNull URI browserOrigin,int httpPort,int mcpPort,
            @NonNull String loginKey,@NonNull String clientKey,@NonNull String resourceKey,boolean loopback) {
        this(origin,resource,redirect,browserOrigin,httpPort,mcpPort,loginKey,clientKey,resourceKey,loopback,false);
    }
    IssuerConfig(@NonNull URI origin,@NonNull URI resource,@NonNull URI redirect,@NonNull URI browserOrigin,int httpPort,int mcpPort,
            @NonNull String loginKey,@NonNull String clientKey,@NonNull String resourceKey,boolean loopback,boolean secondResourceEnabled) {
        this(origin,resource,redirect,browserOrigin,httpPort,mcpPort,loginKey,clientKey,resourceKey,loopback,secondResourceEnabled,OAuthClientMetadataPolicy.disabledInstance());
    }
    IssuerConfig(@NonNull URI origin,@NonNull URI resource,@NonNull URI redirect,@NonNull URI browserOrigin,int httpPort,int mcpPort,
            @NonNull String loginKey,@NonNull String clientKey,@NonNull String resourceKey,boolean loopback,boolean secondResourceEnabled,
            @NonNull OAuthClientMetadataPolicy metadataPolicy) {
        this.metadataPolicy=java.util.Objects.requireNonNull(metadataPolicy);
        checkOrigin(browserOrigin,true);
        if(httpPort<1 || httpPort>65535 || mcpPort<1 || mcpPort>65535 || httpPort==mcpPort) throw invalid();
        checkOrigin(origin,loopback);
        if(!resource.getPath().equals("/mcp") || resource.getRawQuery()!=null || resource.getRawFragment()!=null) throw invalid();
        checkOrigin(URI.create(resource.getScheme()+"://"+resource.getRawAuthority()),loopback);
        for(String key:Set.of(loginKey,clientKey,resourceKey)) if(!key.matches("[A-Za-z0-9_-]{43}")) throw invalid();
        if(loginKey.equals(clientKey) || loginKey.equals(resourceKey) || clientKey.equals(resourceKey)) throw invalid();
        this.origin=origin;this.resource=resource;this.redirect=redirect;this.browserOrigin=browserOrigin;this.httpPort=httpPort;this.mcpPort=mcpPort;
        this.loginKey=loginKey;this.clientKey=clientKey;this.resourceKey=resourceKey;this.loopback=loopback;this.secondResourceEnabled=secondResourceEnabled;
    }
    static @NonNull IssuerConfig fromEnvironment(@NonNull Map<@NonNull String,@NonNull String> env) throws IOException {
        if(!"true".equals(env.get("REVETSEC_ISSUER_FRESH_NAMESPACE"))) throw invalid();
        boolean local="true".equals(env.get("REVETSEC_ISSUER_ALLOW_HTTP_LOOPBACK"));
        int hp=Integer.parseInt(env.getOrDefault("REVETSEC_ISSUER_HTTP_PORT","8089"));
        int mp=Integer.parseInt(env.getOrDefault("REVETSEC_ISSUER_MCP_PORT","8090"));
        URI origin=URI.create(env.getOrDefault("REVETSEC_ISSUER_ORIGIN",local?"http://127.0.0.1:"+hp:"https://localhost:8443"));
        URI resource=URI.create(env.getOrDefault("REVETSEC_ISSUER_RESOURCE",local?"http://127.0.0.1:"+mp+"/mcp":origin+"/mcp"));
        URI redirect=URI.create(env.getOrDefault("REVETSEC_ISSUER_REDIRECT","https://client.example/callback"));
        URI browserOrigin=URI.create(env.getOrDefault("REVETSEC_ISSUER_BROWSER_ORIGIN",redirect.getScheme()+"://"+redirect.getRawAuthority()));
        return new IssuerConfig(origin,resource,redirect,browserOrigin,hp,mp,
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_LOGIN_KEY_FILE")),
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_CLIENT_KEY_FILE")),
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_RESOURCE_KEY_FILE")),local,"true".equals(env.get("REVETSEC_ISSUER_SECOND_RESOURCE")),metadataPolicy(env));
    }
    // Trusted app configuration only. Never derive this mapping from request input or perform DNS.
    static @NonNull OAuthClientMetadataPolicy metadataPolicy(@NonNull Map<@NonNull String,@NonNull String> env) throws IOException {
        String value=env.get("REVETSEC_ISSUER_CIMD_ORIGIN"),numeric=env.get("REVETSEC_ISSUER_CIMD_ADDRESS");
        if(value==null && numeric==null) return OAuthClientMetadataPolicy.disabledInstance();
        if(value==null || numeric==null || !numeric.matches("(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}")) throw invalid();
        URI origin=URI.create(value);String[] components=numeric.split("\\.");byte[] bytes=new byte[4];
        for(int i=0;i<4;i++) {int n=Integer.parseInt(components[i]);if(n>255) throw invalid();bytes[i]=(byte)n;}
        InetAddress address=InetAddress.getByAddress(bytes);
        return OAuthClientMetadataPolicy.withAddressResolver((@NonNull String hostname,@NonNull Duration budget)-> {
            if(!hostname.equalsIgnoreCase(origin.getHost()) || budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted())
                throw invalid();
            return List.of(address);
        }).allowedOrigins(Set.of(origin)).build();
    }
    @NonNull Map<@NonNull String,@NonNull Set<@NonNull String>> resources() {
        return secondResourceEnabled?Map.of(resource.toString(),SCOPES,resource.resolve("/mcp-second").toString(),SCOPES):Map.of(resource.toString(),SCOPES);
    }
    java.util.@NonNull Optional<@NonNull URI> resourceForEndpoint(@NonNull String path) {
        return resources().keySet().stream().map(URI::create).filter(uri->uri.getRawPath().equals(path)).findFirst();
    }
    private static @NonNull String required(@NonNull Map<@NonNull String,@NonNull String> env,@NonNull String name) {
        String value=env.get(name);if(value==null) throw invalid();return value;
    }
    private static void checkOrigin(@NonNull URI uri,boolean local) {
        if(uri.getHost()==null || uri.getRawUserInfo()!=null || uri.getRawQuery()!=null || uri.getRawFragment()!=null
                || !uri.getPath().isEmpty() || uri.getPort()==0 || uri.getPort()>65535
                || !(uri.getScheme().equals("https") || local && uri.getScheme().equals("http") && uri.getHost().equals("127.0.0.1"))) throw invalid();
    }
    private static @NonNull IllegalArgumentException invalid() {return new IllegalArgumentException("Local issuer configuration rejected.");}
    @Override public @NonNull String toString() {return "IssuerConfig{<redacted>}";}
}
