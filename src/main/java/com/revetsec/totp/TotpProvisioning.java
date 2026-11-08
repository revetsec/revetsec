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
package com.revetsec.totp;

import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/** One bounded display/URI profile; encoding never establishes account identity. */
@ThreadSafe
final class TotpProvisioning {
    private TotpProvisioning() {}

    static void validateLabel(@NonNull String value) {
        if(value.isEmpty() || !StrictUtf8.isWellFormed(value))throw invalidLabel();
        if(space(value.codePointAt(0)) || space(value.codePointBefore(value.length())))throw invalidLabel();
        for(int offset=0;offset<value.length();) {
            int point=value.codePointAt(offset),type=Character.getType(point);
            if(point==':' || Character.isISOControl(point) || type==Character.FORMAT
                    || type==Character.LINE_SEPARATOR || type==Character.PARAGRAPH_SEPARATOR)throw invalidLabel();
            offset+=Character.charCount(point);
        }
    }

    static void validateEncodedBudget(@NonNull String issuer,@NonNull String accountName) {
        // Same wire shape as the 20-byte secret, without generating or retaining a secret.
        validateLength(compose(issuer,accountName,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    static @NonNull String uri(@NonNull String issuer,@NonNull String accountName,@NonNull String manualKey) {
        String result=compose(issuer,accountName,manualKey);
        validateLength(result);
        return result;
    }

    private static @NonNull String compose(@NonNull String issuer,@NonNull String accountName,@NonNull String manualKey) {
        String encodedIssuer=encode(issuer);
        return "otpauth://totp/"+encodedIssuer+':'+encode(accountName)
                +"?secret="+manualKey+"&issuer="+encodedIssuer+"&algorithm=SHA1&digits=6&period=30";
    }

    private static void validateLength(@NonNull String result) {
        // Every character is ASCII, including UTF-8 percent escapes; length is the final byte count.
        if(result.length()>512)throw new IllegalArgumentException("TOTP provisioning URI exceeds encoded byte limit");
    }

    private static boolean space(int point) {return Character.isWhitespace(point) || Character.isSpaceChar(point);}
    private static @NonNull IllegalArgumentException invalidLabel() {return new IllegalArgumentException("Invalid TOTP display label");}
    private static @NonNull String encode(@NonNull String text) {return URLEncoder.encode(text,StandardCharsets.UTF_8).replace("+","%20");}
}
