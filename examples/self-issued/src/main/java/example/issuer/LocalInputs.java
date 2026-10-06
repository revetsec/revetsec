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
package example.issuer;

import com.soklet.Request;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Bounded application form/cookie inputs. No browser-supplied subject, resource, scope or return target. */
final class LocalInputs {
    private static final SecureRandom RANDOM = new SecureRandom();
    private LocalInputs() {}
    static byte @NonNull [] randomBytes() { byte[] bytes=new byte[32]; RANDOM.nextBytes(bytes); return bytes; }
    static @NonNull String randomId() { return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes()); }
    static boolean matches(@NonNull String expected, @Nullable String candidate) {
        return candidate != null && candidate.length()==expected.length()
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),candidate.getBytes(StandardCharsets.UTF_8));
    }
    static @NonNull String keyFile(@NonNull String file) throws IOException {
        Path path=Path.of(file);
        Set<PosixFilePermission> permissions=Files.getPosixFilePermissions(path);
        if (permissions.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))
                || !Files.isRegularFile(path,java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.size(path)>44)
            throw new IOException("Private demo key file rejected.");
        ByteBuffer buffer=ByteBuffer.allocate(45);
        try(var channel=Files.newByteChannel(path,Set.of(java.nio.file.StandardOpenOption.READ,java.nio.file.LinkOption.NOFOLLOW_LINKS))) {
            while(buffer.hasRemaining() && channel.read(buffer)!=-1) { /* fixed maximum allocation */ }
        }
        if(buffer.position()>44) throw new IOException("Private demo key file rejected.");
        buffer.flip();String value=StandardCharsets.US_ASCII.decode(buffer).toString();
        if(value.endsWith("\n")) value=value.substring(0,value.length()-1);
        if(!value.matches("[A-Za-z0-9_-]{43}")) throw new IOException("Private demo key file rejected.");
        return value;
    }
    static @NonNull List<@NonNull String> headers(@NonNull Request request,@NonNull String name) {
        return request.getHeaders().entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                .flatMap(e -> e.getValue().stream()).toList();
    }
    static @Nullable String cookie(@NonNull Request request,@NonNull String selected) {
        List<String> fields=headers(request,"Cookie"); if(fields.size()!=1 || fields.get(0).length()>4096) return null;
        String raw=fields.get(0); if(raw.endsWith(";") || raw.chars().anyMatch(c -> c<32 || c>126)) return null;
        Set<String> names=new HashSet<>(); String found=null;
        for(String pair:raw.split(";",-1)) {
            if(names.size()==16) return null;
            String item=pair.strip(); int eq=item.indexOf('='); if(eq<1) return null;
            String name=item.substring(0,eq),value=item.substring(eq+1);
            if(!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}") || !names.add(name)
                    || value.length()>512 || value.chars().anyMatch(c -> c<33 || c>126 || c=='"' || c==',' || c=='\\')) return null;
            if(name.equals(selected)) found=value;
        }
        return found;
    }
    static @NonNull Map<@NonNull String,@NonNull String> form(@NonNull Request request,@NonNull Set<@NonNull String> allowed) {
        byte[] body=request.getBody().orElseGet(() -> new byte[0]);
        if(request.isContentTooLarge() || body.length>4096 || request.getRawQuery().isPresent()
                || !headers(request,"Content-Encoding").isEmpty()) throw invalid();
        List<String> types=headers(request,"Content-Type");
        if(types.size()!=1 || !(types.get(0).equalsIgnoreCase("application/x-www-form-urlencoded")
                || types.get(0).equalsIgnoreCase("application/x-www-form-urlencoded; charset=UTF-8"))) throw invalid();
        Map<String,String> out=new LinkedHashMap<>(); int start=0;
        while(start<body.length) {
            if(out.size()==8) throw invalid(); int end=start; while(end<body.length && body[end]!='&') end++;
            int eq=start; while(eq<end && body[eq]!='=') eq++;
            if(eq==start || eq==end) throw invalid();
            String name=decode(body,start,eq),value=decode(body,eq+1,end);
            if(!allowed.contains(name) || out.putIfAbsent(name,value)!=null) throw invalid();
            if(end==body.length-1) throw invalid(); start=end+1;
        }
        return Map.copyOf(out);
    }
    private static @NonNull String decode(byte @NonNull [] input,int start,int end) {
        byte[] decoded=new byte[end-start]; int count=0;
        for(int i=start;i<end;i++) {
            int b=input[i]&255;
            if(b=='+') b=' ';
            else if(b=='%') {
                if(i+2>=end) throw invalid(); int high=hex(input[++i]),low=hex(input[++i]);
                if(high<0 || low<0) throw invalid(); b=high*16+low;
            }
            decoded[count++]=(byte)b;
        }
        try {
            String value=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(decoded,0,count)).toString();
            if(value.length()>512 || value.chars().anyMatch(c -> c<32 || c==127)) throw invalid(); return value;
        } catch(java.nio.charset.CharacterCodingException failure) { throw invalid(); }
    }
    private static int hex(byte b) { int c=b&255;return c>='0' && c<='9'?c-'0':c>='A' && c<='F'?c-'A'+10:c>='a' && c<='f'?c-'a'+10:-1; }
    private static @NonNull IllegalArgumentException invalid() { return new IllegalArgumentException("Control input rejected."); }
    static @NonNull String html(@NonNull String value) {
        return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");
    }
}
