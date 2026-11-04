/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package example.issuer;

import com.soklet.*;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

/** Calibrate the selected adapter's headerless rejection against supported explicit legacy versions. */
final class IssuerMcpCompatibilityTests {
 @TestFactory @NonNull Stream<@NonNull DynamicTest> explicitSupportedLegacyNotificationsAreAccepted() {
  return Stream.of("2025-06-18","2025-11-25").map(version->DynamicTest.dynamicTest(version,()->{
   var app=new IssuerResources(IssuerApplicationTests.config(8089,8090),Clock.systemUTC());String access=IssuerApplicationTests.scalar(IssuerApplicationTests.issued(app,"mcp:discover"),"access_token");assertEquals(202,notification(app,access,version));
  }));
 }
 @Test void headerlessAndUnknownVersionRejectionsDoNotHideSuccessfulAdmissionOrBypassAuthentication() throws Exception {
  var app=new IssuerResources(IssuerApplicationTests.config(8089,8090),Clock.systemUTC());String access=IssuerApplicationTests.scalar(IssuerApplicationTests.issued(app,"mcp:discover"),"access_token");
  assertEquals(400,notification(app,access,null));assertEquals(400,notification(app,access,"2099-01-01"));assertEquals(401,notification(app,null,"2025-11-25"));assertEquals(202,notification(app,access,"2025-11-25"));
 }
 @Test void declaredMarchRevisionIsExplicitlyUnimplementedByThePinnedAdapter() {
  assertThrows(IllegalStateException.class,()->McpEndpoint.withPath("/mcp",McpImplementation.withNameAndVersion("Compatibility control","1.0").build(),Set.of(McpProtocolVersion.V2025_03_26)).build());
 }
 private int notification(@NonNull IssuerResources app,@Nullable String access,@Nullable String protocol) {
  var headers=new LinkedHashMap<String,List<String>>(Map.of("Host",List.of(app.config.resource.getRawAuthority()),"Content-Type",List.of("application/json"),"Accept",List.of("application/json, text/event-stream")));
  if(access!=null)headers.put("Authorization",List.of("Bearer "+access));if(protocol!=null)headers.put("MCP-Protocol-Version",List.of(protocol));
  var request=Request.withRawUrl(HttpMethod.POST,"/mcp").headers(headers).body("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8)).build();
  var status=new java.util.concurrent.atomic.AtomicInteger();SokletSimulator.run(IssuerPlayground.sokletConfig(app),sim->{try(var pending=sim.startMcpRequest(request)){status.set(pending.awaitResponse(Duration.ofSeconds(5)).orElseThrow().getStatusCode());}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}});return status.get();
 }
}
