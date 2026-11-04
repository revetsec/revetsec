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

import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import static com.revetsec.testing.OAuthFailureAssertions.assertIndependentFailure;
import static org.junit.jupiter.api.Assertions.*;

final class OAuthFailureCopyTests {
    @Test void everySealedFailureLeafCopiesItsFixedDataWithoutMutableDiagnostics() {
        List<OAuthException> failures = List.of(
                OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, new IOException("private-cause")),
                OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED),
                OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID),
                OAuthConfigurationException.fromReason(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE),
                PendingAuthorizationStoreException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE),
                AuthorizationErrorException.fromErrorCode("temporarily_unavailable"),
                OAuthErrorResponseException.fromResponse(429, "invalid_request", Optional.of(Duration.ofSeconds(7))));
        assertEquals(Set.of(OAuthException.class.getPermittedSubclasses()),
                failures.stream().map(Object::getClass).collect(Collectors.toSet()));
        for (OAuthException original : failures) {
            original.addSuppressed(new IllegalStateException("caller-diagnostic"));
            original.setStackTrace(new StackTraceElement[0]);
            OAuthException first = OAuthHttpErrors.copyForCaller(original);
            assertIndependentFailure(original, first);
            assertTrue(first.getStackTrace().length > 0);
            first.addSuppressed(new IllegalStateException("private-copy-diagnostic"));
            assertIndependentFailure(first, OAuthHttpErrors.copyForCaller(original));
        }
    }
    @Test void metadataAndOperationErrorsKeepTheirProvenance() {
        for (int code : new int[]{200,401,429,503}) {
            OAuthErrorResponseException metadata = OAuthErrorResponseException.fromMetadataResponse(code, Optional.of(Duration.ofSeconds(7)));
            OAuthErrorResponseException operation = OAuthErrorResponseException.fromResponse(code, "invalid_client", Optional.of(Duration.ofSeconds(7)));
            OAuthErrorResponseException copiedMetadata = assertInstanceOf(OAuthErrorResponseException.class, OAuthHttpErrors.copyForCaller(metadata));
            OAuthErrorResponseException copiedOperation = assertInstanceOf(OAuthErrorResponseException.class, OAuthHttpErrors.copyForCaller(operation));
            assertIndependentFailure(metadata, copiedMetadata); assertIndependentFailure(operation, copiedOperation);
            assertFalse(copiedMetadata.isEndpointRejection());
            assertEquals(operation.isEndpointRejection(), copiedOperation.isEndpointRejection());
        }
    }
    @Test void theLeaderTransportCauseStaysLocalToThatInvocation() {
        IOException cause = new IOException("private-transport-diagnostic");
        OAuthException leader = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, cause);
        OAuthException follower = OAuthHttpErrors.copyForCaller(leader);
        assertSame(cause, leader.getCause()); assertNull(follower.getCause());
        assertFalse(follower.toString().contains("private-transport-diagnostic"));
    }
}
