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
package example.passkeys;

import com.soklet.Soklet;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;

/** Verifies the packaged app routes on an actual loopback Soklet listener; no TLS or authenticator. */
public final class PasskeySocketChecks {
    private PasskeySocketChecks() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        int port;
        try (ServerSocket available = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = available.getLocalPort();
        }
        PasskeyApp app = new PasskeyApp("https://passkeys.example.test:9443",
                "passkeys.example.test", "A".repeat(43), Clock.systemUTC());
        try (Soklet soklet = Soklet.fromConfig(PasskeyPlayground.config(app, port))) {
            soklet.start();
            String page = request(port, "GET / HTTP/1.1\r\nHost: passkeys.example.test:9443\r\nConnection: close\r\n\r\n");
            if (!page.startsWith("HTTP/1.1 200 ") || !page.contains("__Host-RevetsecPasskeyDemo=")
                    || !page.contains("Secure") || !page.contains("HttpOnly"))
                throw new AssertionError("Passkey page or protected cookie missing");
            String cookie = capture(page, "(?im)^set-cookie: (__Host-RevetsecPasskeyDemo=[A-Za-z0-9_-]{43});");
            String csrf = capture(page, "data-csrf='([A-Za-z0-9_-]{43})'");
            String login = request(port, post("/access-login", cookie, csrf,
                    "X-Demo-Access-Key: " + "A".repeat(43) + "\r\n"));
            if (!login.startsWith("HTTP/1.1 200 "))
                throw new AssertionError("Soklet access approval did not reach the app");
            String authenticatedCookie = capture(login,
                    "(?im)^set-cookie: (__Host-RevetsecPasskeyDemo=[A-Za-z0-9_-]{43});");
            if (authenticatedCookie.equals(cookie)) throw new AssertionError("Session was not rotated");
            String account = request(port, "GET / HTTP/1.1\r\nHost: passkeys.example.test:9443\r\n"
                    + "Cookie: " + authenticatedCookie + "\r\nConnection: close\r\n\r\n");
            if (!account.startsWith("HTTP/1.1 200 ") || !account.contains("data-authenticated='true'"))
                throw new AssertionError("Soklet account session was not accepted");
            String accountCsrf = capture(account, "data-csrf='([A-Za-z0-9_-]{43})'");
            String registration = request(port, post("/register/start", authenticatedCookie,
                    accountCsrf, ""));
            if (!registration.startsWith("HTTP/1.1 200 ") || !registration.contains("\"publicKey\""))
                throw new AssertionError("Soklet registration preparation did not reach Revetsec");
            String wrongHost = request(port, "GET / HTTP/1.1\r\nHost: other.example.test\r\nConnection: close\r\n\r\n");
            if (!wrongHost.startsWith("HTTP/1.1 403 "))
                throw new AssertionError("Unexpected Host accepted");
        }
        System.out.println("Passkey Soklet socket checks passed.");
    }

    private static @NonNull String post(@NonNull String path, @NonNull String cookie,
            @NonNull String csrf, @NonNull String extraHeader) {
        return "POST " + path + " HTTP/1.1\r\nHost: passkeys.example.test:9443\r\n"
                + "Origin: https://passkeys.example.test:9443\r\nCookie: " + cookie
                + "\r\nX-CSRF-Token: " + csrf + "\r\n" + extraHeader
                + "Content-Length: 0\r\nConnection: close\r\n\r\n";
    }

    private static @NonNull String capture(@NonNull String value, @NonNull String pattern) {
        Matcher match = Pattern.compile(pattern).matcher(value);
        if (!match.find()) throw new AssertionError("Expected Soklet response field missing");
        return match.group(1);
    }

    private static @NonNull String request(int port, @NonNull String raw) throws Exception {
        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(raw.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
