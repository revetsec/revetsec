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

package com.revetsec.oidc;

import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.TestHttpsServer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;

/** Bounded deterministic codec mutation replay; no coverage-guided campaign or authenticated-identity claim. */
final class OidcLogoutCodecMutationTests {
	@Test void seededHintEnvelopeAndTokenMutationsNeverReleaseIdentityOrInputDiagnostics() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,client,clock);var hint=client.logoutHintFrom(login.authentication());String form=hint.toSerializedForm();Random random=new Random(20261105L);
			for(int i=0;i<2048;i++){String changed=mutate(form,random);OidcLogoutHintParseResult result=OidcLogoutHint.fromSerializedFormResult(changed);if(result instanceof OidcLogoutHintParseResult.Parsed parsed){assertTrue(parsed.getHint().toSerializedForm().length()<=OidcLogoutSupport.HINT_LIMIT,"parsing storage creates no identity proof");assertInstanceOf(OidcLogoutHintParseResult.Parsed.class,OidcLogoutHint.fromSerializedFormResult(parsed.getHint().toSerializedForm()));}else assertInstanceOf(OidcLogoutHintParseResult.Rejected.class,result);assertFalse(result.toString().contains(login.compact()));}
		}
	}
	@Test void seededPendingMutationsStayWithinTheClosedSchemaAndStateOnlyGrammar() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,client,clock);var request=client.beginLogout(login.authentication().getSessionReference(),client.logoutHintFrom(login.authentication()));String form=OidcLogoutPendingCodec.encode(request.getPending(),null);Random random=new Random(20261106L);
			for(int i=0;i<2048;i++){String changed=mutate(form,random);try{var parsed=OidcLogoutPendingCodec.decode(changed);String canonical=OidcLogoutPendingCodec.encode(parsed.pending(),parsed.bindingDigest());assertTrue(canonical.length()<=OidcLogoutSupport.PENDING_LIMIT);assertFalse(parsed.toString().contains(parsed.pending().state()));}catch(IllegalArgumentException rejected){assertEquals("Invalid OIDC logout value.",rejected.getMessage());assertNull(rejected.getCause());assertEquals(0,rejected.getSuppressed().length);}}
			for(String query:List.of("state=%F4%90%80%80","state=%E0%80%80","state=%F0%80%80%80","state=%00","state=","state=+","state=%","state=%A","state=%GG"))assertThrows(IllegalArgumentException.class,()->OidcLogoutSupport.returnedState(query));
			assertEquals(request.getFormParameters().get("state"),OidcLogoutSupport.returnedState("state="+request.getFormParameters().get("state")));assertNotNull(QueryParameters.parse(request.toFormBody()));
		}
	}
	private static @NonNull String mutate(@NonNull String input,@NonNull Random random){StringBuilder result=new StringBuilder(input);int index=random.nextInt(result.length());switch(random.nextInt(4)){case 0->result.setCharAt(index,(char)random.nextInt(128));case 1->result.deleteCharAt(index);case 2->result.insert(index,(char)random.nextInt(128));default->result.setCharAt(index,(char)(0xD800+random.nextInt(0x800)));}return result.toString();}
}
