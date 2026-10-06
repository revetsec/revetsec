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
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Fixed local app identities; request headers never configure the issuer or resource. */
final class IssuerConfig {
    static final String SUBJECT="demo-user";
    static final Set<String> SCOPES=Set.of("mcp:discover","mcp:whoami");
    final URI origin,resource,redirect;
    final int httpPort,mcpPort;
    final String loginKey,clientKey,resourceKey;
    final boolean loopback;
    IssuerConfig(@NonNull URI origin,@NonNull URI resource,@NonNull URI redirect,int httpPort,int mcpPort,
            @NonNull String loginKey,@NonNull String clientKey,@NonNull String resourceKey,boolean loopback) {
        if(httpPort<1 || httpPort>65535 || mcpPort<1 || mcpPort>65535 || httpPort==mcpPort) throw invalid();
        checkOrigin(origin,loopback);
        if(!resource.getPath().equals("/mcp") || resource.getRawQuery()!=null || resource.getRawFragment()!=null) throw invalid();
        checkOrigin(URI.create(resource.getScheme()+"://"+resource.getRawAuthority()),loopback);
        for(String key:Set.of(loginKey,clientKey,resourceKey)) if(!key.matches("[A-Za-z0-9_-]{43}")) throw invalid();
        if(loginKey.equals(clientKey) || loginKey.equals(resourceKey) || clientKey.equals(resourceKey)) throw invalid();
        this.origin=origin;this.resource=resource;this.redirect=redirect;this.httpPort=httpPort;this.mcpPort=mcpPort;
        this.loginKey=loginKey;this.clientKey=clientKey;this.resourceKey=resourceKey;this.loopback=loopback;
    }
    static @NonNull IssuerConfig fromEnvironment(@NonNull Map<@NonNull String,@NonNull String> env) throws IOException {
        if(!"true".equals(env.get("REVETSEC_ISSUER_FRESH_NAMESPACE"))) throw invalid();
        boolean local="true".equals(env.get("REVETSEC_ISSUER_ALLOW_HTTP_LOOPBACK"));
        int hp=Integer.parseInt(env.getOrDefault("REVETSEC_ISSUER_HTTP_PORT","8089"));
        int mp=Integer.parseInt(env.getOrDefault("REVETSEC_ISSUER_MCP_PORT","8090"));
        URI origin=URI.create(env.getOrDefault("REVETSEC_ISSUER_ORIGIN",local?"http://127.0.0.1:"+hp:"https://localhost:8443"));
        URI resource=URI.create(env.getOrDefault("REVETSEC_ISSUER_RESOURCE",local?"http://127.0.0.1:"+mp+"/mcp":origin+"/mcp"));
        return new IssuerConfig(origin,resource,URI.create(env.getOrDefault("REVETSEC_ISSUER_REDIRECT","https://client.example/callback")),hp,mp,
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_LOGIN_KEY_FILE")),
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_CLIENT_KEY_FILE")),
                LocalInputs.keyFile(required(env,"REVETSEC_ISSUER_RESOURCE_KEY_FILE")),local);
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
