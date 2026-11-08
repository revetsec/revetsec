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

import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.oauth.*;
import com.revetsec.password.*;
import com.revetsec.scim.*;
import com.revetsec.soklet.*;
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

/** Restrictive bounded single-process service-client directory; trusted HTTPS edge is required. */
@ThreadSafe
final class PlaygroundScimDirectory {
    public static final @NonNull String EXTENSION="urn:example:scim:schemas:extension:Directory:2.0:User";
    public static final @NonNull ScimResourceType USER_TYPE=ScimResourceType.withName("User").id("User").endpoint("/Users").schema(ScimSchema.userInstance())
            .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.withId(EXTENSION).name("DirectoryLabels").attributes(List.of(
                    ScimAttributeDefinition.withName("password").description("Ordinary directory label; not a credential. Never supply a secret here.").build())).build(),false))).build();
    public enum Role{PROVISIONER,READER,SELF}
    /** Only a trusted application lookup/registration supplies role, tenant, owner and generation. */
    public record Principal(@NonNull String id,@NonNull String tenant,@NonNull Role role,@Nullable String ownedUserId,long generation,boolean credentialChangesAllowed){
        public Principal{identifier(id);identifier(tenant);Objects.requireNonNull(role);if(ownedUserId!=null)identifier(ownedUserId);if(generation<1||role==Role.SELF&&ownedUserId==null||credentialChangesAllowed&&role!=Role.PROVISIONER)throw new IllegalArgumentException("Trusted bounded principal required");}
        @Override public @NonNull String toString(){return "Principal{<redacted>}";}
    }
    public record Identity(@NonNull String issuer,@NonNull String subject,@NonNull String clientId){
        public Identity{bounded(issuer,256);bounded(subject,256);bounded(clientId,128);}
        @Override public @NonNull String toString(){return "Identity{<redacted>}";}
    }
    record Configuration(@NonNull URI origin,@NonNull Set<@NonNull String> tenants){
        Configuration{https(origin);if(!origin.getRawPath().isEmpty())throw new IllegalArgumentException("Fixed root HTTPS origin required");tenants=Set.copyOf(tenants);if(tenants.isEmpty()||tenants.size()>2||!Set.of("alpha","beta").containsAll(tenants))throw new IllegalArgumentException("Fixed bounded tenants required");}
        @Override public @NonNull String toString(){return "Configuration{<redacted>}";}
    }
    record Registration(@NonNull String credential,@NonNull Identity identity,@NonNull Principal principal){
        Registration{if(credential.length()<32||credential.length()>256||!(BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+credential),8192) instanceof BearerTokenResult.Present))throw new IllegalArgumentException("Private bounded credential required");Objects.requireNonNull(identity);Objects.requireNonNull(principal);}
        @Override public @NonNull String toString(){return "Registration{<redacted>}";}
    }
    private record Access(@NonNull Identity identity,@NonNull Principal principal){ }
    /** Pure/read-only current credential policy. Do not retain or modify the borrowed array. */
    @FunctionalInterface public interface CredentialPolicy{boolean accepts(@NonNull Principal principal,char @NonNull [] password,@NonNull Duration remaining)throws Exception;}
    @FunctionalInterface public interface Admission{boolean allow(@NonNull String trustedPeer,@NonNull Duration remaining)throws Exception;}
    enum Stage{VALIDATED,BEFORE_KDF,BEFORE_PREPARE,BEFORE_PUBLISH}
    @FunctionalInterface interface Probe{void visit(@NonNull Stage stage,@NonNull Duration remaining)throws Exception;}
    private record Row(@NonNull ScimResource resource,@Nullable String credential,long version){
        @Override public @NonNull String toString(){return "Row{<redacted>}";}
    }
    private record State(@NonNull Map<@NonNull String,@NonNull Row> rows,long sequence,long revision,long bytes){ }
    private record Snapshot(@NonNull Identity identity,@NonNull Principal principal,@NonNull State state){ }
    private enum Commit{CONFIRMED,UNAVAILABLE,UNKNOWN}
    /**
     * Trusted volatile directory, not a shared/durable provider. All protected resource/hash state and
     * principal policy are compared and published under one short lock. Never allocate it per request.
     */
    @ThreadSafe
    public static final class Directory{
        private final @NonNull Object lock=new Object();
        private final @NonNull Map<@NonNull Identity,@NonNull Principal> principals;
        private final @NonNull Map<@NonNull String,@NonNull State> states=new LinkedHashMap<>();
        private @NonNull Commit nextCommit=Commit.CONFIRMED;
        private long reads,writes,conflicts;
        public Directory(@NonNull Set<@NonNull String> tenants,@NonNull Map<@NonNull Identity,@NonNull Principal> principals){
            if(tenants.isEmpty()||tenants.size()>8||principals.isEmpty()||principals.size()>128)throw new IllegalArgumentException("Bounded trusted directory required");
            for(String tenant:tenants){identifier(tenant);this.states.put(tenant,new State(Map.of(),0,0,0));}
            this.principals=new LinkedHashMap<>(principals);if(this.principals.values().stream().anyMatch(p->!tenants.contains(p.tenant())))throw new IllegalArgumentException("Principal tenant not registered");
        }
        private @NonNull Principal principal(@NonNull Identity identity){synchronized(this.lock){Principal found=this.principals.get(identity);if(found==null)throw new Refused(ScimError.unauthenticatedInstance());return found;}}
        private @NonNull Snapshot snapshot(@NonNull Identity identity,@NonNull Principal principal){synchronized(this.lock){if(!principal.equals(this.principals.get(identity)))throw new Refused(ScimError.forbiddenInstance());State state=Objects.requireNonNull(this.states.get(principal.tenant()));active(principal,state);this.reads++;return new Snapshot(identity,principal,state);}}
        @SuppressWarnings("ReferenceEquality") // State object identity is the immutable snapshot CAS token.
        private void current(@NonNull Snapshot original,boolean mutation){
            Principal current=this.principals.get(original.identity());if(current==null||!original.principal().equals(current))throw new Refused(ScimError.forbiddenInstance());
            State state=Objects.requireNonNull(this.states.get(current.tenant()));active(current,state);
            if(state!=original.state()){this.conflicts++;throw new Refused(mutation?ScimError.preconditionFailedInstance():ScimError.unavailableInstance());}
        }
        private static void active(@NonNull Principal principal,@NonNull State state){if(principal.role()==Role.SELF){Row owner=state.rows().get("Users/"+principal.ownedUserId());if(owner==null||owner.resource().getDocument().find("active").filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).filter(value->!value).isPresent())throw new Refused(ScimError.forbiddenInstance());}}
        void replacePrincipal(@NonNull Identity identity,@NonNull Principal replacement){synchronized(this.lock){Principal current=this.principals.get(identity);if(current==null||!this.states.containsKey(replacement.tenant())||replacement.generation()<=current.generation())throw new IllegalArgumentException("Trusted current principal with advancing generation required");this.principals.put(identity,replacement);}}
        void failNext(boolean unknown){synchronized(this.lock){this.nextCommit=unknown?Commit.UNKNOWN:Commit.UNAVAILABLE;}}
        @NonNull JsonObject snapshotCounts(){synchronized(this.lock){return JsonObject.builder().put("rows",this.states.values().stream().mapToLong(s->s.rows().size()).sum()).put("credentials",this.states.values().stream().flatMap(s->s.rows().values().stream()).filter(row->row.credential()!=null).count()).put("charged_bytes",this.states.values().stream().mapToLong(State::bytes).sum()).put("plaintext_credentials",this.states.values().stream().flatMap(state->state.rows().values().stream()).filter(row->USER_TYPE.equals(row.resource().getResourceType())&&row.resource().getDocument().getMembers().containsKey("password")).count()).put("sequences",this.states.values().stream().mapToLong(State::sequence).sum()).put("revisions",this.states.values().stream().mapToLong(State::revision).sum()).put("reads",this.reads).put("writes",this.writes).put("conflicts",this.conflicts).build();}}
        @Nullable String credential(@NonNull String tenant,@NonNull String id){synchronized(this.lock){Row row=Objects.requireNonNull(this.states.get(tenant)).rows().get("Users/"+id);return row==null?null:row.credential();}}
        @Override public @NonNull String toString(){return "Directory{<redacted>}";}
    }
    private final @NonNull Configuration config;
    private final @NonNull Map<@NonNull String,@NonNull ScimServiceProvider> providers;
    private final @NonNull List<@NonNull Registration> registrations;
    private final @NonNull Directory directory;
    private final @NonNull PasswordHasher hasher;
    private final @NonNull CredentialPolicy credentialPolicy;
    private final @NonNull Admission admission;
    private final @NonNull Clock clock;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull Probe probe;
    private final @NonNull Semaphore work=new Semaphore(8);

    static @Nullable PlaygroundScimDirectory fromEnvironment(@NonNull URI origin,@NonNull Map<@NonNull String,@NonNull String> environment){
        List<Registration> values=new ArrayList<>();
        register(values,environment,"SCIM_BEARER_TOKEN","alpha-admin","alpha",Role.PROVISIONER,true);
        register(values,environment,"SCIM_ALPHA_LIMITED_TOKEN","alpha-limited","alpha",Role.PROVISIONER,false);
        register(values,environment,"SCIM_ALPHA_READER_TOKEN","alpha-reader","alpha",Role.READER,false);
        register(values,environment,"SCIM_BETA_BEARER_TOKEN","beta-admin","beta",Role.PROVISIONER,true);
        register(values,environment,"SCIM_BETA_READER_TOKEN","beta-reader","beta",Role.READER,false);
        if(values.isEmpty())return null;String oldBase=environment.get("SCIM_BASE_URI");if(oldBase!=null&&!Set.of(origin.resolve("/scim/v2/").toString(),origin.resolve("/scim/alpha/v2/").toString()).contains(oldBase))throw new IllegalArgumentException("Restrictive SCIM profile requires its canonical alpha base or legacy alpha alias");Set<String> tenants=new LinkedHashSet<>();values.forEach(value->tenants.add(value.principal().tenant()));return create(new Configuration(origin,tenants),values);
    }
    private static void register(@NonNull List<@NonNull Registration> values,@NonNull Map<@NonNull String,@NonNull String> environment,@NonNull String setting,@NonNull String id,@NonNull String tenant,@NonNull Role role,boolean credentialChanges){
        String value=environment.get(setting);if(value!=null)values.add(new Registration(value,new Identity("private-scim",id,"service-client"),new Principal(id,tenant,role,null,1,credentialChanges)));
    }
    static @NonNull PlaygroundScimDirectory create(@NonNull Configuration config,@NonNull List<@NonNull Registration> registrations){
        Map<Identity,Principal> principals=new LinkedHashMap<>();for(Registration registration:registrations){if(principals.putIfAbsent(registration.identity(),registration.principal())!=null)throw new IllegalArgumentException("Distinct trusted clients required");}
        var parameters=Argon2idParameters.fromCosts(19_456,2,1);
        var hasher=PasswordHasher.withArgon2id(parameters).workGate(PasswordWorkGate.fromInMemoryLimits(2,38_912)).build();
        return new PlaygroundScimDirectory(config,registrations,new Directory(config.tenants(),principals),hasher,(principal,password,remaining)->password.length>=8,(peer,remaining)->true,Clock.systemUTC(),System::nanoTime,(stage,remaining)->{},65_536);
    }
    PlaygroundScimDirectory(@NonNull Configuration config,@NonNull List<@NonNull Registration> registrations,@NonNull Directory directory,@NonNull PasswordHasher hasher,
            @NonNull CredentialPolicy credentialPolicy,@NonNull Admission admission,@NonNull Clock clock,@NonNull LongSupplier nanoTime,@NonNull Probe probe,int responseLimit){
        this.config=Objects.requireNonNull(config);this.registrations=List.copyOf(registrations);if(registrations.isEmpty()||registrations.size()>16)throw new IllegalArgumentException("Bounded explicit registrations required");
        Set<String> credentials=new HashSet<>();for(Registration registration:registrations)if(!credentials.add(registration.credential()))throw new IllegalArgumentException("Distinct private credentials required");
        this.directory=Objects.requireNonNull(directory);this.hasher=Objects.requireNonNull(hasher);this.credentialPolicy=Objects.requireNonNull(credentialPolicy);this.admission=Objects.requireNonNull(admission);this.clock=Objects.requireNonNull(clock);this.nanoTime=Objects.requireNonNull(nanoTime);this.probe=Objects.requireNonNull(probe);
        synchronized(directory.lock){if(!directory.states.keySet().equals(config.tenants()))throw new IllegalArgumentException("Exact directory tenant registration required");for(Registration registration:registrations)if(!registration.principal().equals(directory.principals.get(registration.identity())))throw new IllegalArgumentException("Exact trusted credential principal registration required");}
        Map<String,ScimServiceProvider> providers=new LinkedHashMap<>();for(String tenant:config.tenants())providers.put(tenant,provider(config.origin().resolve("/scim/"+tenant+"/v2/"),responseLimit));this.providers=Map.copyOf(providers);
    }
    private @NonNull Access authenticate(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers){
        List<String> values=headers.getOrDefault("authorization",List.of());BearerTokenResult parsed=BearerToken.fromAuthorizationHeaderValuesResult(values,8192);if(parsed instanceof BearerTokenResult.Absent)throw new Refused(ScimError.unauthenticatedInstance());if(!(parsed instanceof BearerTokenResult.Present))throw new Refused(ScimError.invalidSyntaxInstance());String field=values.get(0);int start=6;while(field.charAt(start)==' ')start++;String value=field.substring(start);if(value.length()>256)throw new Refused(ScimError.invalidSyntaxInstance());Registration found=null;
        for(Registration registration:this.registrations){String expected=registration.credential();int difference=expected.length()^value.length();for(int i=0;i<expected.length();i++)difference|=expected.charAt(i)^(i<value.length()?value.charAt(i):0);if(difference==0)found=registration;}
        if(found==null)throw new Refused(ScimError.unauthenticatedInstance());return new Access(found.identity(),this.directory.principal(found.identity()));
    }
    static @NonNull ScimServiceProvider provider(@NonNull URI base,int responseLimit){
        var comparisons=Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE);var policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("id",comparisons,"externalId",comparisons,"userName",comparisons,"displayName",comparisons,"active",comparisons)).allowedPresence(Set.of("id","externalId","userName","displayName","active")).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND,ScimLogicalOperator.OR,ScimLogicalOperator.NOT)).maximumComparisons(8).build();
        var groupPolicy=ScimFilterPolicy.builder().allowedComparisons(Map.of("id",comparisons,"externalId",comparisons,"displayName",comparisons)).allowedPresence(Set.of("id","externalId","displayName")).allowedLogicalOperators(Set.of(ScimLogicalOperator.AND,ScimLogicalOperator.OR,ScimLogicalOperator.NOT)).maximumComparisons(8).build();
        return ScimServiceProvider.builder().baseUri(base).resourceTypes(List.of(USER_TYPE,ScimResourceType.groupInstance())).serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).filterMaximumResults(20).pagination(ScimPaginationConfig.builder().indexSupported(true).cursorSupported(false).defaultMethod(ScimPaginationMethod.INDEX).defaultPageSize(20).maximumPageSize(20).build()).sortSupported(true).patchSupported(true).etagSupported(true).changePasswordSupported(true).build())
                .filterPolicies(Map.of(USER_TYPE,policy,ScimResourceType.groupInstance(),groupPolicy)).stringMatching((path,definition,operator,value,literal)->{if(!ascii(value)||!ascii(literal))return ScimStringMatchResult.unsupportedInstance();boolean exact=definition.isCaseExact()||path.getAttributeName().equals("id")||path.getAttributeName().equals("members")&&path.getSubAttributeName().orElse("").equals("value");String left=exact?value:fold(value),right=exact?literal:fold(literal);return ScimStringMatchResult.fromMatched(operator==ScimComparisonOperator.EQ?left.equals(right):operator==ScimComparisonOperator.NE&&!left.equals(right));})
                .limits(ScimLimits.builder().maximumBodyBytes(16_384).maximumPatchOperations(16).maximumJsonNodes(4096).maximumRawQueryBytes(2048).maximumQueryParameters(8).maximumParameterCharacters(1024).maximumProjectionPaths(16).maximumPageSize(20).maximumResponseBytes(responseLimit).maximumWorkUnits(131_072)
                        .filterLimits(ScimFilterLimits.builder().maximumExpressionCharacters(512).maximumDepth(8).maximumNodes(32).maximumLiteralCharacters(128).build()).build()).build();
    }
    @NonNull MarshaledResponse handle(@NonNull Request request){
        ScimServiceProvider provider=this.providers.values().iterator().next();Budget budget=new Budget(this.nanoTime);ScimResponse ready;String allowed="GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";
        try{
            budget.check();String rawPath=request.getRawPath();String path=rawPath.startsWith("/scim/v2/")?"/alpha/v2/"+rawPath.substring("/scim/v2/".length()):rawPath.startsWith("/scim/")?rawPath.substring("/scim".length()):null;Map<String,List<String>> headers=headers(request);
            if(path==null||!request.getRawPath().equals(request.getPath())||!one(headers,"host").equalsIgnoreCase(this.config.origin().getRawAuthority())||headers.containsKey("cookie"))throw new Refused(ScimError.invalidSyntaxInstance());
            List<String> origins=headers.getOrDefault("origin",List.of());if(!origins.isEmpty()&&!origins.equals(List.of(this.config.origin().toString())))throw new Refused(ScimError.forbiddenInstance());
            String[] parts=path.split("/",-1);if(parts.length<4||parts.length>5||!parts[2].equals("v2")||!this.providers.containsKey(parts[1]))throw new Refused(ScimError.notFoundInstance());provider=this.providers.get(parts[1]);
            rejectQueryCredential(request.getRawQuery().orElse(null));
            String method=request.getHttpMethod()==HttpMethod.HEAD?"GET":request.getHttpMethod().name();boolean collection=parts.length==4,search=!collection&&parts[4].equals(".search");String id=collection||search?null:parts[4];
            boolean discovery=Set.of("ServiceProviderConfig","Schemas","ResourceTypes").contains(parts[3]);ScimResourceType type=parts[3].equals("Users")?USER_TYPE:parts[3].equals("Groups")?ScimResourceType.groupInstance():null;
            if(!discovery&&type==null)throw new Refused(ScimError.notFoundInstance());Set<String> methods=discovery?Set.of("GET"):search?Set.of("POST"):collection?Set.of("GET","POST"):Set.of("GET","PUT","PATCH","DELETE");allowed=discovery?"GET, HEAD, OPTIONS":search?"POST, OPTIONS":collection?"GET, HEAD, POST, OPTIONS":"GET, HEAD, PUT, PATCH, DELETE, OPTIONS";if(!methods.contains(method))throw new Refused(ScimError.methodNotAllowedInstance());if(id!=null&&(!discovery&&!id.matches("[A-Za-z0-9_-]{1,64}")||discovery&&id.length()>256))throw new Refused(ScimError.invalidSyntaxInstance());
            if(search&&request.getRawQuery().orElse(null)!=null)throw new Refused(ScimError.invalidSyntaxInstance());
            boolean writing=Set.of("POST","PUT","PATCH","DELETE").contains(method)&&!search&&!discovery;
            if(Set.of("GET","DELETE").contains(method)&&(request.getEncodedBodySizeInBytes()>0||headers.containsKey("transfer-encoding")))throw new Refused(ScimError.invalidSyntaxInstance());
            if(request.getEncodedBodySizeInBytes()>16_384)throw new Refused(ScimError.requestTooLargeInstance());
            if(Set.of("POST","PUT","PATCH").contains(method)){ScimContentTypeResult media=provider.validateContentTypeResult(headers.getOrDefault("content-type",List.of()));if(media instanceof ScimContentTypeResult.Rejected rejected)throw new Refused(rejected.getError());}
            if(!this.work.tryAcquire())throw new Refused(ScimError.unavailableInstance());
            try{
                if(!this.admission.allow(request.getRemoteAddress().map(address->address.getAddress().getHostAddress()).orElse("unknown"),budget.remaining()))throw new Refused(ScimError.forbiddenInstance());budget.beforeCore();Instant began=this.clock.instant();
                Access token=authenticate(headers);Identity identity=token.identity();Principal principal=token.principal();
                if(!principal.tenant().equals(parts[1]))throw new Refused(ScimError.forbiddenInstance());
                if(writing&&principal.role()!=Role.PROVISIONER&&!(principal.role()==Role.SELF&&method.equals("PATCH")&&USER_TYPE.equals(type)&&Objects.equals(id,principal.ownedUserId())))throw new Refused(ScimError.forbiddenInstance());
                if(principal.role()==Role.SELF&&!discovery&&(!USER_TYPE.equals(type)||id!=null&&!id.equals(principal.ownedUserId())))throw new Refused(ScimError.notFoundInstance());
                this.probe.visit(Stage.VALIDATED,budget.remaining());fresh(token,began,budget);
                byte[] body=new byte[0];if(Set.of("POST","PUT","PATCH").contains(method)){if(request.isContentTooLarge())throw new Refused(ScimError.requestTooLargeInstance());body=request.getBody().orElseGet(()->new byte[0]);if(body.length>16_384)throw new Refused(ScimError.requestTooLargeInstance());}
                Snapshot snapshot=this.directory.snapshot(identity,principal);fresh(token,began,budget);
                if(discovery){if(!method.equals("GET")||parts[3].equals("ServiceProviderConfig")&&!collection)throw new Refused(ScimError.methodNotAllowedInstance());this.probe.visit(Stage.BEFORE_PREPARE,budget.remaining());fresh(token,began,budget);ready=prepared(parts[3].equals("Schemas")?(collection?provider.schemasResponseResult(query(request)):provider.schemaResponseResult(Objects.requireNonNull(id),query(request))):parts[3].equals("ResourceTypes")?(collection?provider.resourceTypesResponseResult(query(request)):provider.resourceTypeResponseResult(Objects.requireNonNull(id),query(request))):provider.serviceProviderConfigResponseResult(query(request)));this.probe.visit(Stage.BEFORE_PUBLISH,budget.remaining());confirm(snapshot,token,began,budget,false,null);}
                else if((collection&&method.equals("GET"))||(search&&method.equals("POST"))){
                    ScimQueryParseResult parsed=search?provider.parseSearchRequestResult(Objects.requireNonNull(type),headers.getOrDefault("content-type",List.of()),body):SokletScim.queryResultFor(provider,Objects.requireNonNull(type),request);
                    if(parsed instanceof ScimQueryParseResult.Rejected rejected)throw new Refused(rejected.getError());ScimQuery plan=((ScimQueryParseResult.Succeeded)parsed).getQuery();this.probe.visit(Stage.BEFORE_PREPARE,budget.remaining());fresh(token,began,budget);ready=list(provider,plan,snapshot,budget);this.probe.visit(Stage.BEFORE_PUBLISH,budget.remaining());confirm(snapshot,token,began,budget,false,null);
                }else if(!collection&&!search&&method.equals("GET")){
                    Row current=required(snapshot,Objects.requireNonNull(type),Objects.requireNonNull(id));ScimAttributeSelection selection=selection(provider,Objects.requireNonNull(type),request);ScimIfNoneMatchResult conditional=SokletScim.ifNoneMatchResultFor(provider,current.resource(),request);if(conditional instanceof ScimIfNoneMatchResult.Rejected rejected)throw new Refused(rejected.getError());
                    this.probe.visit(Stage.BEFORE_PREPARE,budget.remaining());fresh(token,began,budget);ready=prepared(conditional instanceof ScimIfNoneMatchResult.NotModified?provider.notModifiedResponseResult(current.resource()):provider.resourceResponseResult(current.resource(),selection));this.probe.visit(Stage.BEFORE_PUBLISH,budget.remaining());confirm(snapshot,token,began,budget,false,null);
                }else if(writing&&!search&&((collection&&method.equals("POST"))||(!collection&&Set.of("PUT","PATCH","DELETE").contains(method)))){
                    ready=mutate(provider,Objects.requireNonNull(type),id,method,headers,body,request,snapshot,token,began,budget);
                }else throw new Refused(ScimError.methodNotAllowedInstance());
            }finally{this.work.release();}
        }catch(Refused refused){ready=provider.errorResponse(refused.error);}
        catch(InterruptedException cancelled){Thread.currentThread().interrupt();ready=provider.errorResponse(ScimError.unavailableInstance());}
        catch(InterruptedIOException cancelled){if(!(cancelled instanceof java.net.SocketTimeoutException))Thread.currentThread().interrupt();ready=provider.errorResponse(ScimError.unavailableInstance());}
        catch(Exception unavailable){ready=provider.errorResponse(ScimError.unavailableInstance());}
        String permitted=allowed;ScimResponse output=ready;
        return SokletScim.responseFor(output).copy().headers(values->{if(readyStatus(output)==401)values.put("WWW-Authenticate",List.of("Bearer realm=\"scim\""));if(readyStatus(output)==405)values.put("Allow",List.of(permitted));values.put("Cache-Control",List.of("no-store"));}).finish();
    }
    private static int readyStatus(@NonNull ScimResponse value){return value.getStatusCode();}
    private @NonNull ScimResponse mutate(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,@Nullable String id,@NonNull String method,
            @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,byte @NonNull [] body,@NonNull Request request,@NonNull Snapshot snapshot,
            @NonNull Access token,@NonNull Instant began,@NonNull Budget budget)throws Exception{
        Row old=id==null?null:required(snapshot,Objects.requireNonNull(type),id);ScimAttributeSelection selected=selection(provider,Objects.requireNonNull(type),request);String key=id==null?null:key(type,id);
        if(old!=null){ScimIfMatchResult result=SokletScim.ifMatchResultFor(provider,old.resource(),request);if(result instanceof ScimIfMatchResult.Rejected rejected)throw new Refused(rejected.getError());if(!headers.getOrDefault("if-match",List.of()).equals(List.of(old.resource().getVersion().orElseThrow())))throw new Refused(ScimError.preconditionFailedInstance());}
        if(snapshot.state().revision()==Long.MAX_VALUE||snapshot.state().sequence()==Long.MAX_VALUE||old!=null&&old.version()==Long.MAX_VALUE)throw new Refused(ScimError.unavailableInstance());
        if(old==null&&snapshot.state().rows().size()>=64)throw new Refused(ScimError.unavailableInstance());
        Map<String,Row> replacement=new LinkedHashMap<>(snapshot.state().rows());ScimResponse response;long sequence=snapshot.state().sequence();boolean modified;
        if(method.equals("DELETE")){
            if(USER_TYPE.equals(type)&&snapshot.state().rows().values().stream().anyMatch(row->ScimResourceType.groupInstance().equals(row.resource().getResourceType())&&memberIds(row.resource()).contains(id)))throw new Refused(ScimError.uniquenessInstance());
            replacement.remove(key);modified=true;this.probe.visit(Stage.BEFORE_PREPARE,budget.remaining());response=provider.noContentResponse();
        }else{
            ScimResource candidate;Set<ScimAttributePath> requested,supplied;
            if(method.equals("PATCH")){
                ScimPatchParseResult parsed=provider.parsePatchRequestResult(type,headers.getOrDefault("content-type",List.of()),body);if(parsed instanceof ScimPatchParseResult.Rejected rejected)throw new Refused(rejected.getError());ScimPatchRequest patch=((ScimPatchParseResult.Succeeded)parsed).getPatchRequest();requested=patch.getRequestedAttributePaths();supplied=patch.getSuppliedAttributePaths();authorizeFields(snapshot.principal(),type,requested);
                for(ScimPatchOperation operation:patch.getOperations())if(operation.getOperationType()==ScimPatchOperationType.REMOVE&&operation.getAttributePath().filter(path->credentialPath(type,path)).isPresent())throw new Refused(ScimError.invalidValueInstance());
                ScimPatchApplicationResult applied=provider.applyPatchResult(Objects.requireNonNull(old).resource(),patch);if(applied instanceof ScimPatchApplicationResult.Rejected rejected)throw new Refused(rejected.getError());ScimPatchResult change=((ScimPatchApplicationResult.Succeeded)applied).getPatchResult();candidate=change.getResource();authorizeEffective(snapshot.principal(),type,change.getModifiedAttributePaths());
            }else{
                ScimResourceParseResult parsed=old==null?provider.parseResourceResult(type,headers.getOrDefault("content-type",List.of()),body):provider.parseReplacementResult(type,old.resource(),headers.getOrDefault("content-type",List.of()),body);
                if(parsed instanceof ScimResourceParseResult.Rejected rejected)throw new Refused(rejected.getError());ScimResourceParseResult.Succeeded accepted=(ScimResourceParseResult.Succeeded)parsed;candidate=accepted.getResource();requested=accepted.getSuppliedAttributePaths();supplied=requested;authorizeFields(snapshot.principal(),type,requested);
            }
            profile(candidate,snapshot,id);String credential=old==null?null:old.credential();boolean passwordChange=false;
            if(requested.stream().anyMatch(path->credentialPath(type,path))){
                if(snapshot.principal().role()!=Role.PROVISIONER||!snapshot.principal().credentialChangesAllowed())throw new Refused(ScimError.forbiddenInstance());
                JsonValue raw=candidate.getDocument().getMembers().get("password");if(!(raw instanceof JsonString text)||text.getValue().length()>256)throw new Refused(ScimError.invalidValueInstance());char[] password=text.getValue().toCharArray();
                try{
                    if(!this.credentialPolicy.accepts(snapshot.principal(),password,budget.remaining()))throw new Refused(ScimError.invalidValueInstance());fresh(token,began,budget);this.probe.visit(Stage.BEFORE_KDF,budget.remaining());fresh(token,began,budget);
                    boolean same=false;if(credential!=null){PasswordVerificationResult verified=this.hasher.verifyResult(password,credential);fresh(token,began,budget);if(verified instanceof PasswordVerificationResult.Unavailable)throw new Refused(ScimError.unavailableInstance());if(verified instanceof PasswordVerificationResult.Rejected)throw new Refused(ScimError.invalidValueInstance());same=verified instanceof PasswordVerificationResult.Matched;}
                    if(!same){PasswordHashResult hashed=this.hasher.hashResult(password);fresh(token,began,budget);if(!(hashed instanceof PasswordHashResult.Succeeded success))throw new Refused(hashed instanceof PasswordHashResult.Rejected?ScimError.invalidValueInstance():ScimError.unavailableInstance());credential=success.getPasswordHash().getStoredForm();if(credential.length()>2048)throw new Refused(ScimError.unavailableInstance());passwordChange=true;}
                }finally{Arrays.fill(password,'\0');}
            }
            candidate=withoutCredential(candidate);modified=old==null||passwordChange||!business(candidate).equals(business(old.resource()));
            String assigned=id;if(assigned==null){assigned=(USER_TYPE.equals(type)?"u":"g")+(++sequence);key=key(type,assigned);if(replacement.containsKey(key))throw new Refused(ScimError.unavailableInstance());}
            long version=old==null?1:modified?old.version()+1:old.version();Instant now=this.clock.instant();if(old!=null&&now.isBefore(old.resource().getLastModified().orElseThrow()))throw new Refused(ScimError.unavailableInstance());
            ScimResource finalResource=modified?metadata(provider,candidate,assigned,version,old==null?now:old.resource().getCreated().orElseThrow(),now):Objects.requireNonNull(old).resource();
            if(modified)replacement.put(Objects.requireNonNull(key),new Row(finalResource,credential,version));
            if(replacement.size()>64)throw new Refused(ScimError.unavailableInstance());integrity(type,finalResource,replacement,Objects.requireNonNull(key));
            this.probe.visit(Stage.BEFORE_PREPARE,budget.remaining());fresh(token,began,budget);
            response=prepared(old==null?provider.createdResponseResult(finalResource,supplied,selected):method.equals("PATCH")?provider.patchResponseResult(finalResource,supplied,selected):provider.replacementResponseResult(finalResource,supplied,selected));
        }
        fresh(token,began,budget);long bytes=charge(replacement);if(bytes>262_144)throw new Refused(ScimError.unavailableInstance());State next=modified?new State(Map.copyOf(replacement),sequence,snapshot.state().revision()+1,bytes):snapshot.state();
        this.probe.visit(Stage.BEFORE_PUBLISH,budget.remaining());fresh(token,began,budget);Commit committed=confirm(snapshot,token,began,budget,true,next);
        if(committed!=Commit.CONFIRMED)throw new Refused(ScimError.unavailableInstance());return response;
    }
    @SuppressWarnings("ReferenceEquality") // No-op/changed immutable snapshot identity, not value comparison.
    private @NonNull Commit confirm(@NonNull Snapshot snapshot,@NonNull Access token,@NonNull Instant began,@NonNull Budget budget,boolean mutation,@Nullable State next){
        synchronized(this.directory.lock){fresh(token,began,budget);this.directory.current(snapshot,mutation);Commit disposition=this.directory.nextCommit;
            if(mutation)this.directory.nextCommit=Commit.CONFIRMED;if(mutation&&disposition==Commit.UNAVAILABLE)return Commit.UNAVAILABLE;
            if(next!=null&&next!=snapshot.state()){this.directory.states.put(snapshot.principal().tenant(),next);this.directory.writes++;}
            return mutation?disposition:Commit.CONFIRMED;
        }
    }
    private @NonNull ScimResponse list(@NonNull ScimServiceProvider provider,@NonNull ScimQuery plan,@NonNull Snapshot snapshot,@NonNull Budget budget){
        if(plan.getPaginationMethod()!=ScimPaginationMethod.INDEX)throw new Refused(ScimError.invalidValueInstance());String sort=plan.getSortBy().map(ScimAttributePath::getAttributeName).orElse("id");
        if(plan.getSortBy().isPresent()&&(plan.getSortBy().orElseThrow().getSchemaId().isPresent()||plan.getSortBy().orElseThrow().getSubAttributeName().isPresent())||!Set.of("id","externalId","userName","displayName","active").contains(sort))throw new Refused(ScimError.invalidPathInstance());
        List<ScimResource> values=new ArrayList<>();ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider);int visited=0;
        for(Row row:snapshot.state().rows().values()){
            if(++visited>64)throw new Refused(ScimError.requestTooLargeInstance());ScimResource value=row.resource();if(!value.getResourceType().equals(plan.getResourceType()))continue;
            if(snapshot.principal().role()==Role.SELF&&!value.getId().orElseThrow().equals(snapshot.principal().ownedUserId()))continue;
            budget.check();if(plan.getFilter().isPresent()){ScimFilterEvaluationResult evaluated=evaluator.evaluateResult(value,plan.getFilter().orElseThrow());if(evaluated instanceof ScimFilterEvaluationResult.Rejected rejected)throw new Refused(rejected.getError());if(!((ScimFilterEvaluationResult.Succeeded)evaluated).isMatched())continue;}values.add(value);
        }
        int[] comparisons={0};Comparator<ScimResource> comparator=(left,right)->{if(++comparisons[0]>4096)throw new Refused(ScimError.requestTooLargeInstance());String a=scalar(left,sort),b=scalar(right,sort);int compared=a.compareTo(b);return compared==0?left.getId().orElseThrow().compareTo(right.getId().orElseThrow()):compared;};
        if(plan.getSortOrder().orElse(ScimSortOrder.ASCENDING)==ScimSortOrder.DESCENDING)comparator=comparator.reversed();values.sort(comparator);
        int start=(int)Math.min(values.size(),plan.getStartIndex().orElse(1L)-1),end=Math.min(values.size(),start+plan.getCount());return prepared(provider.listResponseResult(ScimListPage.withQuery(plan).resources(values.subList(start,end)).totalResults((long)values.size()).build()));
    }
    private static void authorizeFields(@NonNull Principal principal,@NonNull ScimResourceType type,@NonNull Set<@NonNull ScimAttributePath> paths){
        for(ScimAttributePath path:paths){String schema=path.getSchemaId().orElse(type.getSchema().getId()),name=path.getAttributeName(),sub=path.getSubAttributeName().orElse("");
            if(schema.equalsIgnoreCase(EXTENSION)){if(!USER_TYPE.equals(type)||principal.role()!=Role.PROVISIONER||!name.equals("password")||!sub.isEmpty())throw new Refused(ScimError.forbiddenInstance());continue;}
            if(!schema.equalsIgnoreCase(type.getSchema().getId()))throw new Refused(ScimError.forbiddenInstance());
            if(principal.role()==Role.SELF){if(!USER_TYPE.equals(type)||!Set.of("displayName","name").contains(name))throw new Refused(ScimError.forbiddenInstance());}
            else if(principal.role()!=Role.PROVISIONER)throw new Refused(ScimError.forbiddenInstance());
            if(USER_TYPE.equals(type)){if(!Set.of("schemas","externalId","userName","displayName","name","active","password").contains(name)||name.equals("name")&&!Set.of("","formatted","givenName","familyName").contains(sub)||name.equals("password")&&!principal.credentialChangesAllowed())throw new Refused(ScimError.forbiddenInstance());}
            else if(!Set.of("schemas","externalId","displayName","members").contains(name)||name.equals("members")&&!Set.of("","value").contains(sub))throw new Refused(ScimError.forbiddenInstance());
        }
    }
    private static void authorizeEffective(@NonNull Principal principal,@NonNull ScimResourceType type,@NonNull Set<@NonNull ScimAttributePath> paths){
        Set<ScimAttributePath> direct=new LinkedHashSet<>();
        for(ScimAttributePath path:paths){
            boolean groupMetadata=ScimResourceType.groupInstance().equals(type)&&path.getSchemaId().map(schema->schema.equalsIgnoreCase(type.getSchema().getId())).orElse(true)&&path.getAttributeName().equals("members")&&Set.of("display","type","$ref").contains(path.getSubAttributeName().orElse(""));
            // Core reports all member metadata invalidated by an ID change. The caller cannot
            // request these fields: requested-path authorization remains strict. This host stores
            // only validated same-tenant User IDs, so these effects remove metadata, never inject it.
            if(groupMetadata){if(principal.role()!=Role.PROVISIONER)throw new Refused(ScimError.forbiddenInstance());}else direct.add(path);
        }
        authorizeFields(principal,type,direct);
    }
    private static boolean credentialPath(@NonNull ScimResourceType type,@NonNull ScimAttributePath path){return USER_TYPE.equals(type)&&path.getSchemaId().map(schema->schema.equalsIgnoreCase(USER_TYPE.getSchema().getId())).orElse(true)&&path.getAttributeName().equals("password")&&path.getSubAttributeName().isEmpty()
            &&USER_TYPE.getSchema().getAttributes().stream().anyMatch(attribute->attribute.getName().equals("password")&&attribute.getMutability()==ScimMutability.WRITE_ONLY&&attribute.getReturned()==ScimReturned.NEVER);}
    private static void profile(@NonNull ScimResource resource,@NonNull Snapshot snapshot,@Nullable String originalId){
        Set<String> allowed=USER_TYPE.equals(resource.getResourceType())?Set.of("schemas","id","meta","externalId","userName","displayName","name","active","password",EXTENSION):Set.of("schemas","id","meta","externalId","displayName","members");
        if(!allowed.containsAll(resource.getDocument().getMembers().keySet()))throw new Refused(ScimError.invalidValueInstance());
        for(String field:List.of("externalId","userName","displayName")){JsonValue raw=resource.getDocument().getMembers().get(field);if(raw instanceof JsonString text&&(text.getValue().length()>256||!ascii(text.getValue())))throw new Refused(ScimError.invalidValueInstance());}
        JsonValue name=resource.getDocument().getMembers().get("name");if(name instanceof JsonObject object){if(!Set.of("formatted","givenName","familyName").containsAll(object.getMembers().keySet()))throw new Refused(ScimError.invalidValueInstance());for(JsonValue value:object.getMembers().values())if(!(value instanceof JsonString text)||text.getValue().length()>256||!ascii(text.getValue()))throw new Refused(ScimError.invalidValueInstance());}
        JsonValue extension=resource.getDocument().getMembers().get(EXTENSION);if(extension instanceof JsonObject object){if(!Set.of("password").containsAll(object.getMembers().keySet()))throw new Refused(ScimError.invalidValueInstance());JsonValue value=object.getMembers().get("password");if(value!=null&&(!(value instanceof JsonString text)||text.getValue().length()>256||!ascii(text.getValue())))throw new Refused(ScimError.invalidValueInstance());}
        if(originalId==null&&resource.getExternalId().filter(value->!value.isEmpty()).isEmpty())throw new Refused(ScimError.invalidValueInstance());
        JsonValue raw=resource.getDocument().getMembers().get("members");if(raw instanceof JsonArray array){if(array.getElements().size()>32)throw new Refused(ScimError.requestTooLargeInstance());Set<String> ids=new HashSet<>();for(JsonValue value:array.getElements()){if(!(value instanceof JsonObject member)||!member.getMembers().keySet().equals(Set.of("value")))throw new Refused(ScimError.invalidValueInstance());String id=member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow(()->new Refused(ScimError.invalidValueInstance()));if(!id.matches("[A-Za-z0-9_-]{1,64}")||!ids.add(id)||!snapshot.state().rows().containsKey("Users/"+id))throw new Refused(ScimError.invalidValueInstance());}}
    }
    private static void integrity(@NonNull ScimResourceType type,@NonNull ScimResource candidate,@NonNull Map<@NonNull String,@NonNull Row> rows,@NonNull String target){
        for(var entry:rows.entrySet())if(!entry.getKey().equals(target)&&entry.getValue().resource().getResourceType().equals(type)){ScimResource other=entry.getValue().resource();if(candidate.getExternalId().isPresent()&&candidate.getExternalId().equals(other.getExternalId()))throw new Refused(ScimError.uniquenessInstance());
            if(USER_TYPE.equals(type)&&fold(string(candidate,"userName")).equals(fold(string(other,"userName"))))throw new Refused(ScimError.uniquenessInstance());}
    }
    private static @NonNull Row required(@NonNull Snapshot snapshot,@NonNull ScimResourceType type,@NonNull String id){Row value=snapshot.state().rows().get(key(type,id));if(value==null)throw new Refused(ScimError.notFoundInstance());return value;}
    private static @NonNull String key(@NonNull ScimResourceType type,@NonNull String id){return type.getEndpoint().substring(1)+'/'+id;}
    private static @NonNull Set<@NonNull String> memberIds(@NonNull ScimResource group){Set<String> ids=new LinkedHashSet<>();JsonValue raw=group.getDocument().getMembers().get("members");if(raw instanceof JsonArray array)for(JsonValue value:array.getElements())if(value instanceof JsonObject member)member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).ifPresent(ids::add);return ids;}
    private static @NonNull JsonObject business(@NonNull ScimResource resource){Map<String,JsonValue> values=new LinkedHashMap<>(resource.getDocument().getMembers());values.remove("id");values.remove("meta");return JsonObject.fromMembers(values);}
    private static @NonNull ScimResource withoutCredential(@NonNull ScimResource candidate){if(!candidate.getDocument().getMembers().containsKey("password"))return candidate;Map<String,JsonValue> values=new LinkedHashMap<>(candidate.getDocument().getMembers());values.remove("password");return candidate.copy().document(JsonObject.fromMembers(values)).finish();}
    private static @NonNull ScimResource metadata(@NonNull ScimServiceProvider provider,@NonNull ScimResource candidate,@NonNull String id,long version,@NonNull Instant created,@NonNull Instant modified){Map<String,JsonValue> values=new LinkedHashMap<>(candidate.getDocument().getMembers());values.put("id",JsonString.fromValue(id));values.put("meta",JsonObject.builder().put("resourceType",candidate.getResourceType().getName()).put("version","W/\""+id+':'+version+"\"").put("created",created.toString()).put("lastModified",modified.toString()).put("location",provider.resourceLocationFor(candidate.getResourceType(),id).toString()).build());return candidate.copy().document(JsonObject.fromMembers(values)).finish();}
    private static long charge(@NonNull Map<@NonNull String,@NonNull Row> rows){long total=0;for(var entry:rows.entrySet()){String credential=entry.getValue().credential();total+=entry.getKey().getBytes(StandardCharsets.UTF_8).length+entry.getValue().resource().getDocument().toJson().getBytes(StandardCharsets.UTF_8).length+(credential==null?0:credential.getBytes(StandardCharsets.UTF_8).length)+8;}return total;}
    private static @NonNull String scalar(@NonNull ScimResource resource,@NonNull String path){if(path.equals("active"))return resource.getDocument().find(path).filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(value->value.getValue()?"1":"0").orElse("");return path.equals("id")?resource.getId().orElseThrow():path.equals("externalId")?string(resource,path):fold(string(resource,path));}
    private static @NonNull String string(@NonNull ScimResource resource,@NonNull String name){return resource.getDocument().find(name).filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse("");}
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,@NonNull Request request){ScimAttributeSelectionResult result=SokletScim.attributeSelectionResultFor(provider,type,request);if(result instanceof ScimAttributeSelectionResult.Rejected rejected)throw new Refused(rejected.getError());return ((ScimAttributeSelectionResult.Succeeded)result).getAttributeSelection();}
    private static @NonNull ScimResponse prepared(@NonNull ScimResponseResult result){if(result instanceof ScimResponseResult.Prepared prepared)return prepared.getResponse();throw new Refused(((ScimResponseResult.Rejected)result).getError());}
    private void fresh(@NonNull Access token,@NonNull Instant began,@NonNull Budget budget){budget.check();if(this.clock.instant().isBefore(began))throw new Refused(ScimError.unavailableInstance());if(!token.principal().equals(this.directory.principal(token.identity())))throw new Refused(ScimError.forbiddenInstance());}
    private static void rejectQueryCredential(@Nullable String query){
        if(query==null)return;if(query.length()>2048)throw new Refused(ScimError.requestTooLargeInstance());String[] fields=query.split("&",-1);if(fields.length>8)throw new Refused(ScimError.invalidSyntaxInstance());
        for(String field:fields){int equal=field.indexOf('=');String name=equal<0?field:field.substring(0,equal);if(name.length()>128)throw new Refused(ScimError.invalidSyntaxInstance());
            try{if(java.net.URLDecoder.decode(name,StandardCharsets.UTF_8).equalsIgnoreCase("access_token"))throw new Refused(ScimError.invalidSyntaxInstance());}catch(IllegalArgumentException malformed){throw new Refused(ScimError.invalidSyntaxInstance());}}
    }
    private static @NonNull String query(@NonNull Request request){String raw=request.getRawQuery().orElse(null);return raw==null?"":raw;}
    private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull Request request){Map<String,List<String>> values=new LinkedHashMap<>();int occurrences=0;long bytes=0;if(request.getHeaders().size()>32)throw new Refused(ScimError.invalidSyntaxInstance());for(var entry:request.getHeaders().entrySet()){String name=entry.getKey();if(!name.matches("[A-Za-z0-9-]{1,64}"))throw new Refused(ScimError.invalidSyntaxInstance());List<String> copy=new ArrayList<>();for(String value:entry.getValue()){if(++occurrences>32||value.length()>8192||!ascii(value))throw new Refused(ScimError.invalidSyntaxInstance());bytes+=name.length()+value.length();if(bytes>16384)throw new Refused(ScimError.invalidSyntaxInstance());copy.add(value);}if(copy.isEmpty()||values.putIfAbsent(fold(name),List.copyOf(copy))!=null)throw new Refused(ScimError.invalidSyntaxInstance());}return Map.copyOf(values);}
    private static @NonNull String one(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers,@NonNull String name){List<String> values=headers.getOrDefault(name,List.of());if(values.size()!=1)throw new Refused(ScimError.invalidSyntaxInstance());return values.get(0);}
    private static void identifier(@NonNull String value){if(!value.matches("[A-Za-z0-9_-]{1,64}"))throw new IllegalArgumentException("Bounded local identifier required");}
    private static void bounded(@NonNull String value,int maximum){if(value.isEmpty()||value.length()>maximum||!ascii(value))throw new IllegalArgumentException("Bounded trusted value required");}
    private static boolean ascii(@NonNull String value){return value.chars().allMatch(c->c>=0x20&&c<=0x7e);}
    private static @NonNull String fold(@NonNull String value){return value.toLowerCase(Locale.ROOT);}
    private static void https(@NonNull URI uri){if(!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null||uri.getPort()==0||uri.getPort()>65535)throw new IllegalArgumentException("Fixed trusted HTTPS configuration required");}
    @SuppressWarnings("serial") // Private control-flow signal; no serialization format.
    private static final class Refused extends RuntimeException{private static final long serialVersionUID=1L;final @NonNull ScimError error;Refused(@NonNull ScimError error){super("SCIM request refused");this.error=error;}}
    private static final class Budget{final @NonNull LongSupplier time;final long end;Budget(@NonNull LongSupplier time){this.time=time;this.end=time.getAsLong()+Duration.ofSeconds(8).toNanos();}void check(){if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)throw new Refused(ScimError.unavailableInstance());}void beforeCore(){check();if(this.end-this.time.getAsLong()<Duration.ofSeconds(3).toNanos())throw new Refused(ScimError.unavailableInstance());}@NonNull Duration remaining(){check();return Duration.ofNanos(Math.max(1,this.end-this.time.getAsLong()));}}
    @Override public @NonNull String toString(){return "PlaygroundScimDirectory{<redacted>}";}
}
