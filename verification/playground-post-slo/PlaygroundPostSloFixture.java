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

import com.revetsec.json.*;
import com.revetsec.saml.*;
import com.revetsec.soklet.SokletSaml;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import java.io.*;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/** Test-only IdP/control host. Fixtures, keys and control routes never belong in the application JAR. */
@ThreadSafe
public final class PlaygroundPostSloFixture implements AutoCloseable {
    private static final @NonNull Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
    private final @NonNull URI origin, idpOrigin;
    private final @NonNull String entity, idpEntity;
    private final @NonNull PrivateKey idpKey;
    private final @NonNull PublicKey spKey;
    private final @NonNull AtomicInteger sequence = new AtomicInteger(), marks = new AtomicInteger();
    private final @NonNull AtomicBoolean blockNext = new AtomicBoolean();
    private final @NonNull AtomicReference<@Nullable CountDownLatch> blocked = new AtomicReference<>();
    private final @NonNull AtomicReference<@NonNull String> lastMark = new AtomicReference<>("NONE");
    private final @NonNull AtomicLong blockedDeadline = new AtomicLong();
    private final @NonNull Set<@NonNull String> issued = ConcurrentHashMap.newKeySet();
    private final @NonNull CountDownLatch entered = new CountDownLatch(1);
    private final @NonNull BrowserSessions sessions;
    private final @NonNull PlaygroundResources resources;
    private final @NonNull PlaygroundConfig config;
    private final @NonNull SafeViews views;

    private PlaygroundPostSloFixture(int port, @NonNull String binding, @NonNull URI origin, @NonNull URI idpOrigin) throws Exception {
        this.origin = origin; this.idpOrigin = idpOrigin; this.entity = origin.resolve("/saml/metadata").toString(); this.idpEntity = idpOrigin.resolve("/entity").toString();
        Path keys = Path.of(required("REVETSEC_SLO_FIXTURE_KEYS")), work = Path.of(required("REVETSEC_SLO_FIXTURE_WORK"));
        this.idpKey = key(keys.resolve("idp-signing-rsa-2048-key.pem"));
        this.spKey = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(keys.resolve("sp-signing-rsa-2048-cert.pem")))).getPublicKey();
        String certificate = Files.readString(keys.resolve("idp-signing-rsa-2048-cert.pem")).replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        String metadata = "<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='" + this.idpEntity + "'><md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='" + idpOrigin.resolve("/sso") + "'/><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='" + idpOrigin.resolve("/slo") + "'/><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='" + idpOrigin.resolve("/slo-post") + "'/></md:IDPSSODescriptor></md:EntityDescriptor>";
        Path metadataFile = work.resolve("idp.xml"); Files.writeString(metadataFile, metadata);
        this.config = PlaygroundConfig.fromEnvironment(Map.of("PLAYGROUND_ORIGIN", origin.toString(), "PLAYGROUND_HTTP_PORT", Integer.toString(port), "PLAYGROUND_MCP_PORT", "0", "PLAYGROUND_ISSUER", "https://oidc.example.test", "PLAYGROUND_SECRET_REFERENCE", "none", "PLAYGROUND_PROBE_SECRET_REFERENCE", "none"));
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC); this.sessions = new BrowserSessions(clock, 64); this.views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundSaml saml = Objects.requireNonNull(PlaygroundSaml.fromEnvironment(Map.of("PLAYGROUND_SAML_METADATA_FILE", metadataFile.toString(), "PLAYGROUND_SAML_IDP_ENTITY_ID", this.idpEntity, "PLAYGROUND_SAML_CONNECTION_ID", "fixture-idp", "PLAYGROUND_SAML_SIGNING_KEY_FILE", keys.resolve("sp-signing-rsa-2048-key.pem").toString(), "PLAYGROUND_SAML_SIGNING_CERT_FILE", keys.resolve("sp-signing-rsa-2048-cert.pem").toString(), "PLAYGROUND_SAML_LOGOUT_BINDING", binding), this.config, this.sessions, this.views, clock));
        this.resources = new PlaygroundResources(this.config, this.sessions, this.views, new PlaygroundOidc(this.sessions, this.views, clock), HttpClient.newHttpClient(), token -> { throw new IllegalStateException("No fixture resource-token path"); }, saml);
        // Spy only: the actual backend mark happens before a bounded test wait. No proof/result is fabricated.
        Field spField = PlaygroundSaml.class.getDeclaredField("sp"); spField.setAccessible(true); SamlServiceProvider sp = (SamlServiceProvider) spField.get(saml);
        Field replay = SamlServiceProvider.class.getDeclaredField("replayCache"); replay.setAccessible(true); SamlReplayCache actual = (SamlReplayCache) replay.get(sp);
        replay.set(sp, new SamlReplayCache() {
            @Override public @NonNull MarkResult markIfAbsent(@NonNull String key, @NonNull Instant expiry, @NonNull Duration remaining) { return after(actual.markIfAbsent(key, expiry, remaining), remaining); }
            @Override public @NonNull MarkResult markIfAbsent(@NonNull String connection, @NonNull String key, @NonNull Instant expiry, @NonNull Duration remaining) { return after(actual.markIfAbsent(connection, key, expiry, remaining), remaining); }
            private @NonNull MarkResult after(@NonNull MarkResult result, @NonNull Duration remaining) {
                marks.incrementAndGet(); lastMark.set(result.name()); if (blockNext.compareAndSet(true, false)) { CountDownLatch gate = new CountDownLatch(1); blockedDeadline.set(System.nanoTime() + Math.min(Duration.ofSeconds(2).toNanos(), remaining.toNanos())); blocked.set(gate); entered.countDown(); try { if (!gate.await(2, TimeUnit.SECONDS)) return MarkResult.UNAVAILABLE; } catch (InterruptedException cancelled) { Thread.currentThread().interrupt(); return MarkResult.UNAVAILABLE; } finally { blocked.compareAndSet(gate, null); } } return result;
            }
        });
    }

    public static void main(@NonNull String @NonNull [] args) throws Exception {
        verifyOrigin(SamlServiceProvider.class, "CORE"); verifyOrigin(SokletSaml.class, "ADAPTER"); verifyOrigin(Soklet.class, "FRAMEWORK"); verifyOrigin(PlaygroundResources.class, "APPLICATION");
        int port = Integer.parseInt(args[0]); var fixture = new PlaygroundPostSloFixture(port, args[1], URI.create(args[2]), URI.create(args[3]));
        SokletConfig base = Playground.sokletConfig(fixture.config, fixture.resources, fixture.views);
        SokletConfig configured = SokletConfig.withHttpServer(base.getHttpServer().orElseThrow()).lifecycleObservers(base.getLifecycleObservers()).corsAuthorizer(base.getCorsAuthorizer())
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(PlaygroundResources.class, PlaygroundPostSloFixture.class)))
                .instanceProvider(new InstanceProvider() { @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) { if (type == PlaygroundResources.class) return type.cast(fixture.resources); if (type == PlaygroundPostSloFixture.class) return type.cast(fixture); throw new IllegalArgumentException("Unknown fixture type"); } })
                .requestInterceptor(new RequestInterceptor() { @Override public void interceptRequest(@NonNull ServerType type, @NonNull Request request, @Nullable ResourceMethod method, @NonNull Function<@NonNull Request,@NonNull MarshaledResponse> handler, @NonNull Consumer<@NonNull MarshaledResponse> writer) {
                    String expected = required("REVETSEC_SLO_FIXTURE_CREDENTIAL"), actual = one(request, "X-Fixture-Credential");
                    if (actual == null || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), actual.getBytes(StandardCharsets.US_ASCII))) writer.accept(MarshaledResponse.fromResponse(json(401, JsonObject.builder().put("error", "Fixture denied").build()))); else writer.accept(handler.apply(request));
                } }).build();
        Soklet server = Soklet.fromConfig(configured); Runtime.getRuntime().addShutdownHook(new Thread(() -> { fixture.close(); server.close(); })); server.start(); System.out.println("READY"); new CountDownLatch(1).await();
    }

    @GET("/fixture/state") public @NonNull Response state(@NonNull Request request) { return json(200, JsonObject.builder().put("marks", this.marks.longValue()).put("blocked", this.blocked.get() != null).put("sessions", (long) this.sessions.size()).put("charged_bytes", this.sessions.chargedBytes()).put("selected_origins", true).put("java_version", Runtime.version().toString()).put("last_mark", this.lastMark.get()).put("blocked_remaining_ms", Math.max(0L, (this.blockedDeadline.get() - System.nanoTime()) / 1_000_000L)).build()); }
    @GET("/fixture/current") public @NonNull Response current(@NonNull Request request) {
        BrowserSessions.Session session = this.sessions.findForSamlLogout(request).orElse(null);
        return json(200, JsonObject.builder().put("logout_pending", session != null && session.samlLogout != null).put("authentication_closed", session != null && session.authenticationClosed).put("normal_lookup", this.sessions.find(request).isPresent()).build());
    }
    @POST("/fixture/check-logout-response") public @NonNull Response checkLogoutResponse(@NonNull Request request) {
        try { Map<String,String> values = object(request); boolean post = values.containsKey("form"); Map<String,String> fields = post ? formFields(values.get("form")) : redirect(values.get("redirect"), "/slo", "SAMLResponse");
            String xml = post ? new String(Base64.getDecoder().decode(fields.get("SAMLResponse")), StandardCharsets.UTF_8) : inflate(fields.get("SAMLResponse")); Document document = parse(xml); if (post) verifyXml(document); Element root = document.getDocumentElement(); NodeList status = root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
            if (!root.getLocalName().equals("LogoutResponse") || !root.getAttribute("Destination").equals(this.idpOrigin.resolve(post ? "/slo-post" : "/slo").toString()) || status.getLength() != 1 || !((Element)status.item(0)).getAttribute("Value").equals("urn:oasis:names:tc:SAML:2.0:status:Success") || !this.issued.remove(root.getAttribute("InResponseTo"))) throw denied();
            return json(200, JsonObject.builder().put("verified", true).build());
        } catch (Exception rejected) { return json(400, JsonObject.builder().put("error", "Fixture denied").build()); }
    }
    @GET("/fixture/control/{command}") public @NonNull Response control(@NonNull Request request) {
        String command = request.getPath().substring("/fixture/control/".length());
        if (command.equals("block-next-mark")) this.blockNext.set(true); else if (command.equals("release")) { CountDownLatch gate = this.blocked.get(); if (gate != null) gate.countDown(); } else return json(400, JsonObject.builder().put("error", "Fixture denied").build());
        return state(request);
    }
    @POST("/fixture/authn") public @NonNull Response authn(@NonNull Request request) {
        try { Map<String,String> values = object(request); Map<String,String> fields = redirect(values.get("redirect"), "/sso", "SAMLRequest"); String xml = inflate(fields.get("SAMLRequest")); Document parsed = parse(xml); Element root = parsed.getDocumentElement(); if (!root.getLocalName().equals("AuthnRequest") || !root.getAttribute("Destination").equals(this.idpOrigin.resolve("/sso").toString())) throw denied();
            String id = root.getAttribute("ID"), suffix = Integer.toString(this.sequence.incrementAndGet());
            String assertion = "<a:Assertion ID='_assert" + suffix + "' Version='2.0' IssueInstant='" + NOW + "'><a:Issuer>" + this.idpEntity + "</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' NameQualifier='" + this.idpEntity + "'>alice</a:NameID><a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData Recipient='" + this.origin.resolve("/saml/acs") + "' InResponseTo='" + id + "' NotOnOrAfter='" + NOW.plusSeconds(120) + "'/></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore='" + NOW.minusSeconds(1) + "' NotOnOrAfter='" + NOW.plusSeconds(120) + "'><a:AudienceRestriction><a:Audience>" + this.entity + "</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant='" + NOW + "' SessionIndex='fixture-session'><a:AuthnContext><a:AuthnContextClassRef>urn:example:password</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion>";
            String response = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_response" + suffix + "' Version='2.0' IssueInstant='" + NOW + "' Destination='" + this.origin.resolve("/saml/acs") + "' InResponseTo='" + id + "'><a:Issuer>" + this.idpEntity + "</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>" + assertion + "</p:Response>";
            return form("SAMLResponse", sign(response), fields.get("RelayState"));
        } catch (Exception malformed) { return json(400, JsonObject.builder().put("error", "Fixture denied").build()); }
    }
    @POST("/fixture/logout-response") public @NonNull Response logoutResponse(@NonNull Request request) {
        try { Map<String,String> values = object(request); boolean post = values.containsKey("form"); Map<String,String> fields = post ? formFields(values.get("form")) : redirect(values.get("redirect"), "/slo", "SAMLRequest"); String xml = post ? new String(Base64.getDecoder().decode(fields.get("SAMLRequest")), StandardCharsets.UTF_8) : inflate(fields.get("SAMLRequest")); Document parsed = parse(xml); if (post) verifyXml(parsed); Element root = parsed.getDocumentElement(); if (!root.getLocalName().equals("LogoutRequest") || !root.getAttribute("Destination").equals(this.idpOrigin.resolve(post ? "/slo-post" : "/slo").toString())) throw denied();
            String response = "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_logout-response" + this.sequence.incrementAndGet() + "' Version='2.0' IssueInstant='" + NOW + "' Destination='" + this.origin.resolve("/saml/slo") + "' InResponseTo='" + root.getAttribute("ID") + "'><a:Issuer>" + this.idpEntity + "</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:LogoutResponse>";
            return post ? form("SAMLResponse", sign(response), fields.get("RelayState")) : json(200, JsonObject.builder().put("query", signedRedirect("SAMLResponse", response, fields.get("RelayState"))).build());
        } catch (Exception malformed) { return json(400, JsonObject.builder().put("error", "Fixture denied").build()); }
    }
    @GET("/fixture/idp-request/{binding}/{mode}") public @NonNull Response idpRequest(@NonNull Request request) {
        try { String[] parts = request.getPath().split("/"); if (parts.length != 5 || !Set.of("post","redirect").contains(parts[3]) || !Set.of("normal","wrong-index","wrong-signature").contains(parts[4])) throw denied();
            String id = "_idp-logout" + this.sequence.incrementAndGet(); synchronized (this.issued) { if (this.issued.size() >= 64) throw denied(); this.issued.add(id); }
            String xml = "<p:LogoutRequest xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='" + id + "' Version='2.0' IssueInstant='" + NOW + "' Destination='" + this.origin.resolve("/saml/slo") + "'><a:Issuer>" + this.idpEntity + "</a:Issuer><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' NameQualifier='" + this.idpEntity + "'>alice</a:NameID><p:SessionIndex>" + (parts[4].equals("wrong-index") ? "wrong" : "fixture-session") + "</p:SessionIndex></p:LogoutRequest>";
            if (parts[3].equals("post")) { String signed = sign(xml); if (parts[4].equals("wrong-signature")) signed = corruptSignature(signed); return form("SAMLRequest", signed, "fixture-idp-relay"); }
            return json(200, JsonObject.builder().put("query", signedRedirect("SAMLRequest", xml, "fixture-idp-relay")).build());
        } catch (Exception malformed) { return json(400, JsonObject.builder().put("error", "Fixture denied").build()); }
    }

    private static @NonNull String corruptSignature(@NonNull String signed) {
        String marker = "<ds:SignatureValue>"; int start = signed.indexOf(marker);
        if (start < 0) throw denied(); start += marker.length();
        char changed = signed.charAt(start) == 'A' ? 'B' : 'A';
        return signed.substring(0, start) + changed + signed.substring(start + 1);
    }
    private @NonNull Map<@NonNull String,@NonNull String> redirect(@NonNull String uri, @NonNull String path, @NonNull String field) throws Exception { URI target = URI.create(uri); if (!target.getScheme().equals("https") || !target.getRawAuthority().equals(this.idpOrigin.getRawAuthority()) || !target.getRawPath().equals(path)) throw denied(); String raw = Objects.requireNonNull(target.getRawQuery()); Map<String,String> fields = formFields(raw); if (!fields.keySet().equals(Set.of(field,"RelayState","SigAlg","Signature")) || !fields.get("SigAlg").equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) throw denied(); int index = raw.lastIndexOf("&Signature="); if (index < 0) throw denied(); Signature verify = Signature.getInstance("SHA256withRSA"); verify.initVerify(this.spKey); verify.update(raw.substring(0,index).getBytes(StandardCharsets.US_ASCII)); if (!verify.verify(Base64.getDecoder().decode(fields.get("Signature")))) throw denied(); return fields; }
    private void verifyXml(@NonNull Document document) throws Exception { Element root = document.getDocumentElement(); root.setIdAttribute("ID", true); NodeList signatures = root.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature"); if (signatures.getLength() != 1) throw denied(); DOMValidateContext context = new DOMValidateContext(this.spKey, signatures.item(0)); context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE); XMLSignature signature = XMLSignatureFactory.getInstance("DOM", "XMLDSig").unmarshalXMLSignature(context); if (signature.getSignedInfo().getReferences().size() != 1 || !signature.getSignedInfo().getReferences().get(0).getURI().equals("#" + root.getAttribute("ID")) || !signature.validate(context)) throw denied(); }
    private @NonNull String sign(@NonNull String xml) throws Exception { Document document = parse(xml); Element root = document.getDocumentElement(); root.setIdAttribute("ID",true); XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM","XMLDSig"); Reference reference = factory.newReference("#" + root.getAttribute("ID"),factory.newDigestMethod(DigestMethod.SHA256,null),List.of(factory.newTransform(Transform.ENVELOPED,(javax.xml.crypto.dsig.spec.TransformParameterSpec)null),factory.newTransform(CanonicalizationMethod.EXCLUSIVE,(javax.xml.crypto.dsig.spec.TransformParameterSpec)null)),null,null); SignedInfo info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(javax.xml.crypto.dsig.spec.C14NMethodParameterSpec)null),factory.newSignatureMethod(SignatureMethod.RSA_SHA256,null),List.of(reference)); DOMSignContext context = new DOMSignContext(this.idpKey,root); context.setDefaultNamespacePrefix("ds"); if(root.getFirstChild().getNextSibling()!=null)context.setNextSibling(root.getFirstChild().getNextSibling()); factory.newXMLSignature(info,null).sign(context); ByteArrayOutputStream bytes = new ByteArrayOutputStream(); var writer = TransformerFactory.newDefaultInstance().newTransformer();writer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,"yes");writer.transform(new DOMSource(document),new StreamResult(bytes));return bytes.toString(StandardCharsets.UTF_8); }
    private @NonNull String signedRedirect(@NonNull String field,@NonNull String xml,@Nullable String relay) throws Exception { Deflater compressor = new Deflater(Deflater.DEFAULT_COMPRESSION,true); byte[] compressed = new byte[32768]; int length;try{compressor.setInput(xml.getBytes(StandardCharsets.UTF_8));compressor.finish();length=compressor.deflate(compressed);if(!compressor.finished())throw denied();}finally{compressor.end();}String unsigned = field+'='+encode(Base64.getEncoder().encodeToString(Arrays.copyOf(compressed,length)))+(relay==null?"":"&RelayState="+encode(relay))+"&SigAlg="+encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(this.idpKey);signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));return unsigned+"&Signature="+encode(Base64.getEncoder().encodeToString(signature.sign())); }
    private static @NonNull String inflate(@NonNull String encoded) throws Exception { Inflater inflater=new Inflater(true);byte[] output=new byte[65536];try{inflater.setInput(Base64.getDecoder().decode(encoded));int length=inflater.inflate(output);if(!inflater.finished())throw denied();return new String(output,0,length,StandardCharsets.UTF_8);}finally{inflater.end();} }
    private static @NonNull Document parse(@NonNull String xml) throws Exception { if(xml.length()>65536)throw denied();var parser=DocumentBuilderFactory.newDefaultInstance();parser.setNamespaceAware(true);parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);parser.setFeature("http://xml.org/sax/features/external-general-entities",false);parser.setFeature("http://xml.org/sax/features/external-parameter-entities",false);return parser.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))); }
    private static @NonNull PrivateKey key(@NonNull Path path) throws Exception { String encoded=Files.readString(path).replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replaceAll("\\s","");return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded))); }
    private static @NonNull Map<@NonNull String,@NonNull String> object(@NonNull Request request) { byte[] body=request.getBody().orElseThrow();if(body.length>65536||request.isContentTooLarge())throw denied();for(byte value:body)if(value<32||value>126)throw denied();return formFields(new String(body,StandardCharsets.US_ASCII)); }

    private static @NonNull Map<@NonNull String,@NonNull String> formFields(@NonNull String raw) { if(raw.length()>65536)throw denied();Map<String,String> values=new LinkedHashMap<>();for(String field:raw.split("&",-1)){int equal=field.indexOf('=');if(equal<1)throw denied();String name=URLDecoder.decode(field.substring(0,equal),StandardCharsets.UTF_8),value=URLDecoder.decode(field.substring(equal+1),StandardCharsets.UTF_8);if(values.putIfAbsent(name,value)!=null||values.size()>4)throw denied();}return values; }
    private static @NonNull Response form(@NonNull String name,@NonNull String xml,@Nullable String relay) { Map<String,JsonValue> fields=new LinkedHashMap<>();fields.put(name,JsonString.fromValue(Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))));if(relay!=null)fields.put("RelayState",JsonString.fromValue(relay));return json(200,JsonObject.builder().put("fields",JsonObject.fromMembers(fields)).build()); }
    private static @NonNull String encode(@NonNull String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }
    private static @NonNull Response json(int status,@NonNull JsonObject value) { return Response.withStatusCode(status).headers(Map.of("Content-Type",List.of("application/json; charset=UTF-8"),"Cache-Control",List.of("no-store"))).body(value.toJson().getBytes(StandardCharsets.UTF_8)).build(); }
    private static @Nullable String one(@NonNull Request request,@NonNull String name) { List<String> found=new ArrayList<>();request.getHeaders().forEach((key,values)->{if(key.equalsIgnoreCase(name))found.addAll(values);});return found.size()==1?found.get(0):null; }
    private static @NonNull String required(@NonNull String name) { String value=System.getenv(name);if(value==null||value.isEmpty())throw new IllegalStateException("Fixture configuration unavailable");return value; }
    private static @NonNull IllegalArgumentException denied() { return new IllegalArgumentException("Fixture denied"); }
    private static void verifyOrigin(@NonNull Class<?> type,@NonNull String kind) throws Exception { Path expected=Path.of(required("REVETSEC_SLO_"+kind+"_JAR")).toRealPath(),actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();if(!expected.equals(actual)||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual))).equals(required("REVETSEC_SLO_"+kind+"_SHA256")))throw new IllegalStateException("Selected artifact mismatch"); }
    @Override public void close() { CountDownLatch gate=this.blocked.get();if(gate!=null)gate.countDown(); }
}
