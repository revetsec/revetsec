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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.oauth.VerifiedAccessToken;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;

/** Explicit application redaction, independent of a credential's textual representation. */
final class SafeViews {
    private final byte[] partitionKey;
    SafeViews(byte @NonNull [] partitionKey) { this.partitionKey = partitionKey.clone(); }

    @NonNull String partition(@NonNull String issuer, @NonNull String subject, @NonNull String tenant) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(partitionKey, "HmacSHA256"));
            for (String field : List.of(issuer, tenant, subject)) {
                byte[] value = field.getBytes(StandardCharsets.UTF_8);
                mac.update(new byte[] { (byte) (value.length >>> 24), (byte) (value.length >>> 16),
                        (byte) (value.length >>> 8), (byte) value.length });
                mac.update(value);
            }
            return "p1_" + Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal());
        } catch (GeneralSecurityException failure) { throw new IllegalStateException("Partition key unavailable."); }
    }

    @NonNull JsonObject checked(@NonNull VerifiedAccessToken token) {
        String subject = token.getSubject().orElseGet(() -> token.getClientId().orElse("anonymous-client"));
        return JsonObject.builder().put("issuer", token.getIssuer())
                .put("subject", partition(token.getIssuer(), subject, "local"))
                .put("scopes", scopes(token.getScopes().stream().filter(PlaygroundConfig.SCOPES::contains).sorted().toList()))
                .put("validation", "Completed configured issuer, audience and credential profile checks").build();
    }

    static @NonNull JsonArray scopes(@NonNull List<@NonNull String> values) {
        return JsonArray.fromElements(values.stream().map(JsonString::fromValue).toList());
    }

    static @NonNull String html(@NonNull String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
