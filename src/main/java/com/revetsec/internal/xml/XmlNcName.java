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
package com.revetsec.internal.xml;

import org.jspecify.annotations.NonNull;

/** XML NCName check for SAML {@code xs:ID} values.
 *
 * @since 1.0.0
 */
public final class XmlNcName {
    private XmlNcName() { }

    /**
     * Checks the XML 1.0 NCName code-point ranges without normalizing the identifier.
     *
     * @param value ID value to inspect
     * @return whether it is an NCName
     * @since 1.0.0
     */
    public static boolean valid(@NonNull String value) {
        if (value.isEmpty()) return false;
        int codePoint = value.codePointAt(0);
        if (!nameStart(codePoint)) return false;
        for (int position = Character.charCount(codePoint); position < value.length();
                position += Character.charCount(codePoint)) {
            codePoint = value.codePointAt(position);
            if (!nameStart(codePoint) && codePoint != '-' && codePoint != '.'
                    && !(codePoint >= '0' && codePoint <= '9') && codePoint != 0xB7
                    && !(codePoint >= 0x300 && codePoint <= 0x36F)
                    && !(codePoint >= 0x203F && codePoint <= 0x2040)) return false;
        }
        return true;
    }

    private static boolean nameStart(int codePoint) {
        return codePoint == '_' || (codePoint >= 'A' && codePoint <= 'Z')
                || (codePoint >= 'a' && codePoint <= 'z')
                || (codePoint >= 0xC0 && codePoint <= 0xD6)
                || (codePoint >= 0xD8 && codePoint <= 0xF6)
                || (codePoint >= 0xF8 && codePoint <= 0x2FF)
                || (codePoint >= 0x370 && codePoint <= 0x37D)
                || (codePoint >= 0x37F && codePoint <= 0x1FFF)
                || (codePoint >= 0x200C && codePoint <= 0x200D)
                || (codePoint >= 0x2070 && codePoint <= 0x218F)
                || (codePoint >= 0x2C00 && codePoint <= 0x2FEF)
                || (codePoint >= 0x3001 && codePoint <= 0xD7FF)
                || (codePoint >= 0xF900 && codePoint <= 0xFDCF)
                || (codePoint >= 0xFDF0 && codePoint <= 0xFFFD)
                || (codePoint >= 0x10000 && codePoint <= 0xEFFFF);
    }
}
