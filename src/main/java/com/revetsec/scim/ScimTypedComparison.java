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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Core-owned linear comparisons of already schema-validated data. Callers precharge their shared budget. */
final class ScimTypedComparison {
    private ScimTypedComparison() {}

    /** Compares validated XML Schema date-times; mixed offset availability is a partial order. */
    static @Nullable Integer dateComparison(@NonNull String left, @NonNull String right) {
        DateValue a=date(left), b=date(right);
        if (a.offset != b.offset) return null;
        int comparison=yearCompare(a.year,b.year);
        if (comparison == 0) comparison=Integer.compare(a.month,b.month);
        if (comparison == 0) comparison=Integer.compare(a.day,b.day);
        if (comparison == 0) comparison=Integer.compare(a.seconds,b.seconds);
        if (comparison == 0) {
            int maximum=Math.max(a.fraction.length(),b.fraction.length());
            for (int index=0; index<maximum; index++) {
                char first=index < a.fraction.length() ? a.fraction.charAt(index) : '0';
                char second=index < b.fraction.length() ? b.fraction.charAt(index) : '0';
                comparison=Character.compare(first,second);
                if (comparison != 0) break;
            }
        }
        return comparison;
    }
    /** Linear calendar normalization avoids constructing unbounded numeric year/fraction values. */
    private static @NonNull DateValue date(@NonNull String value) {
        int start=value.startsWith("-") ? 1 : 0;
        int end=value.indexOf('-',start);
        String year=value.substring(0,end);
        int month=two(value,end+1), day=two(value,end+4);
        int seconds=two(value,end+7)*3600+two(value,end+10)*60+two(value,end+13);
        int fractionStart=end+15, fractionEnd=fractionStart;
        if (fractionStart < value.length() && value.charAt(fractionStart) == '.') {
            fractionEnd=++fractionStart;
            while (fractionEnd < value.length() && value.charAt(fractionEnd) >= '0' && value.charAt(fractionEnd) <= '9') fractionEnd++;
        }
        String fraction=value.substring(fractionStart,fractionEnd);
        boolean offset=fractionEnd < value.length();
        if (offset && value.charAt(fractionEnd) != 'Z') {
            int zone=two(value,fractionEnd+1)*3600+two(value,fractionEnd+4)*60;
            seconds-=value.charAt(fractionEnd) == '-' ? -zone : zone;
        }
        if (seconds < 0) {
            seconds+=86400;
            day--;
            if (day == 0) {
                month--;
                if (month == 0) { year=shiftYear(year,-1); month=12; }
                day=monthDays(year,month);
            }
        } else if (seconds >= 86400) {
            seconds-=86400;
            day++;
            if (day > monthDays(year,month)) {
                day=1; month++;
                if (month == 13) { year=shiftYear(year,1); month=1; }
            }
        }
        return new DateValue(year,month,day,seconds,fraction,offset);
    }
    private static int two(@NonNull String value,int start) { return (value.charAt(start)-'0')*10+value.charAt(start+1)-'0'; }
    private static int monthDays(@NonNull String year,int month) {
        if (month != 2) return month == 4 || month == 6 || month == 9 || month == 11 ? 30 : 31;
        int mod=0;
        for (int index=year.startsWith("-") ? 1 : 0; index<year.length(); index++) mod=(mod*10+year.charAt(index)-'0')%400;
        if (year.startsWith("-")) mod=(401-mod)%400;
        return mod%4 == 0 && (mod%100 != 0 || mod == 0) ? 29 : 28;
    }
    private static int yearCompare(@NonNull String left,@NonNull String right) {
        boolean a=left.startsWith("-"), b=right.startsWith("-");
        if (a != b) return a ? -1 : 1;
        int comparison=Integer.compare(left.length(),right.length());
        if (comparison == 0) comparison=left.compareTo(right);
        return a ? -comparison : comparison;
    }
    private static @NonNull String shiftYear(@NonNull String year,int delta) {
        boolean negative=year.startsWith("-");
        String magnitude=negative ? year.substring(1) : year;
        int direction=negative ? -delta : delta;
        if (direction < 0 && magnitude.equals("0001")) return negative ? "0001" : "-0001";
        StringBuilder digits=new StringBuilder(magnitude);
        for (int index=digits.length()-1; index>=0; index--) {
            int digit=digits.charAt(index)-'0'+direction;
            digits.setCharAt(index,(char)('0'+(digit+10)%10));
            if (digit >= 0 && digit <= 9) break;
            if (index == 0 && direction > 0) digits.insert(0,'1');
        }
        if (digits.length() > 4 && digits.charAt(0) == '0') digits.deleteCharAt(0);
        return negative ? "-"+digits : digits.toString();
    }
    private record DateValue(@NonNull String year,int month,int day,int seconds,@NonNull String fraction,boolean offset) { }

}
