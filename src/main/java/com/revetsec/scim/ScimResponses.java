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

package com.revetsec.scim;

import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.Limits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/** Response preparation after schema projection and operation association checks. */
@ThreadSafe
final class ScimResponses {
    private static final int FRAMING_BYTES = 128;
    private static final @NonNull String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
    private ScimResponses() { }

    static @NonNull ScimResponseResult prepare(@NonNull ScimLimits limits, int status,
            @Nullable JsonObject body, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> extraHeaders,
            @NonNull ScimWork work) {
        requireNonNull(limits); requireNonNull(extraHeaders); requireNonNull(work);
        if (status < 100 || status > 599 || ((status == 204 || status == 304) && body != null))
            return new ScimResponseResult.Rejected(ScimError.internalErrorInstance());
        LinkedHashMap<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Cache-Control", List.of("private, no-store"));
        if (body != null) headers.put("Content-Type", List.of("application/scim+json"));
        Set<String> names = new HashSet<>();
        for (String name : headers.keySet()) names.add(AsciiCase.fold(name));
        long headerBytes = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            long amount = headerBytes(entry.getKey(), entry.getValue(), limits.getMaximumResponseHeaderBytes(), work);
            if (amount < 0) return tooLarge();
            headerBytes += amount;
        }
        if (headerBytes < 0 || headerBytes > limits.getMaximumResponseHeaderBytes()) return tooLarge();
        for (Map.Entry<String, List<String>> entry : extraHeaders.entrySet()) {
            String name = requireNonNull(entry.getKey());
            List<String> values = requireNonNull(entry.getValue());
            long amount = headerBytes(name, values, limits.getMaximumResponseHeaderBytes(), work);
            if (amount < 0 || headerBytes + amount > limits.getMaximumResponseHeaderBytes()) return tooLarge();
            if (!names.add(AsciiCase.fold(name))) return new ScimResponseResult.Rejected(ScimError.internalErrorInstance());
            headerBytes += amount;
            headers.put(name, List.copyOf(values));
        }
        long available = (long) limits.getMaximumResponseBytes() - headerBytes - FRAMING_BYTES;
        if (available < 0 || !work.take(FRAMING_BYTES)) return tooLarge();
        byte[] bytes = body == null ? new byte[0] : ScimJsonOutput.write(body, (int) available, work);
        if (bytes == null) return tooLarge();
        return new ScimResponseResult.Prepared(new ScimResponse(status, headers, bytes));
    }

    static @NonNull ScimResponse error(@NonNull ScimError error) {
        requireNonNull(error);
        JsonObject.Builder body = JsonObject.builder()
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(ERROR_SCHEMA))))
                .put("status", error.getStatusCode().toString())
                .put("detail", error.getDetail());
        error.getErrorType().ifPresent(type -> body.put("scimType", type.getValue()));
        ScimLimits floor = ScimLimits.builder().maximumResponseBytes(Math.toIntExact(Limits.SCIM_RESPONSE_BYTES.getFloor()))
                .maximumResponseHeaderBytes(Math.toIntExact(Limits.SCIM_RESPONSE_HEADER_BYTES.getFloor())).build();
        ScimResponseResult result = prepare(floor, error.getStatusCode(), body.build(), Map.of(), new ScimWork(Limits.SCIM_WORK_UNITS.getFloor()));
        return ((ScimResponseResult.Prepared) result).getResponse();
    }

    static @NonNull ScimResponse noContent() {
        return new ScimResponse(204, Map.of("Cache-Control", List.of("private, no-store")), new byte[0]);
    }

    private static ScimResponseResult.@NonNull Rejected tooLarge() {
        return new ScimResponseResult.Rejected(ScimError.responseTooLargeInstance());
    }

    private static long headerBytes(@NonNull String name, @NonNull List<@NonNull String> values,
            int maximum, @NonNull ScimWork work) {
        if (name.isEmpty() || name.length() > maximum || values.isEmpty() || values.size() > maximum) return -1;
        for (int index = 0; index < name.length(); ++index) {
            char ch = name.charAt(index);
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                    || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0)) return -1;
        }
        long size = 0;
        for (String value : values) {
            int length = utf8HeaderLength(requireNonNull(value), maximum);
            if (length < 0) return -1;
            long amount = name.length() + 4L + length;
            if (amount > maximum - size || !work.spend(amount)) return -1;
            size += amount;
        }
        return size;
    }

    private static int utf8HeaderLength(@NonNull String value, int maximum) {
        if (value.length() > maximum) return -1;
        int length = 0;
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) return -1;
            if (ch < 0x80) ++length;
            else if (ch < 0x800) length += 2;
            else if (Character.isHighSurrogate(ch)) {
                if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) return -1;
                length += 4;
            } else {
                if (Character.isLowSurrogate(ch)) return -1;
                length += 3;
            }
            if (length > maximum) return -1;
        }
        return length;
    }
}
