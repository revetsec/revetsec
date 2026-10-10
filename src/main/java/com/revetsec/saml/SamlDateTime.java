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

package com.revetsec.saml;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/** A bounded SAML xs:dateTime reader. It accepts timezone-free values as UTC and rejects leap seconds. */
final class SamlDateTime {
    private static final Pattern LEXICAL = Pattern.compile(
            "([0-9]{4,9})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
                    + "(?:\\.([0-9]{1,100}))?(Z|[+-][0-9]{2}:[0-9]{2})?");

    private SamlDateTime() { }

    static @Nullable Instant parse(@NonNull String value) {
        requireNonNull(value);
        if (value.length() < 19 || value.length() > 128) return null;
        Matcher match = LEXICAL.matcher(value);
        if (!match.matches()) return null;
        try {
            int year = Integer.parseInt(match.group(1));
            int month = Integer.parseInt(match.group(2));
            int day = Integer.parseInt(match.group(3));
            int hour = Integer.parseInt(match.group(4));
            int minute = Integer.parseInt(match.group(5));
            int second = Integer.parseInt(match.group(6));
            if (year == 0 || second == 60) return null;
            int nanos = 0;
            String fraction = match.group(7);
            if (fraction != null) {
                String firstNine = fraction.length() <= 9 ? fraction : fraction.substring(0, 9);
                nanos = Integer.parseInt((firstNine + "000000000").substring(0, 9));
            }
            String zone = match.group(8);
            ZoneOffset offset = ZoneOffset.UTC;
            if (zone != null && !"Z".equals(zone)) {
                int hours = Integer.parseInt(zone.substring(1, 3));
                int minutes = Integer.parseInt(zone.substring(4, 6));
                if (hours > 14 || minutes > 59 || (hours == 14 && minutes != 0)) return null;
                int totalSeconds = (hours * 60 + minutes) * 60;
                offset = ZoneOffset.ofTotalSeconds(zone.charAt(0) == '-' ? -totalSeconds : totalSeconds);
            }
            return LocalDateTime.of(year, month, day, hour, minute, second, nanos).toInstant(offset);
        } catch (DateTimeException | NumberFormatException exception) {
            return null;
        }
    }
}
