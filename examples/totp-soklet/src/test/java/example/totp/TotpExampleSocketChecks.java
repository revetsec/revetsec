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
package example.totp;

import com.soklet.Soklet;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.NotThreadSafe;
import org.jspecify.annotations.NonNull;

/** Exercises default marshaling and HEAD suppression on an actual loopback Soklet listener. */
@NotThreadSafe
public final class TotpExampleSocketChecks {
    private TotpExampleSocketChecks() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        int port;
        try (ServerSocket available = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = available.getLocalPort();
        }
        TotpApplication app = TotpExampleChecks.application(new TotpExampleChecks.Boundary());
        try (Soklet soklet = Soklet.fromConfig(TotpApplication.config(app, port))) {
            soklet.start();
            String get = request(port, "GET", "/account/totp");
            String head = request(port, "HEAD", "/account/totp");
            if (!get.startsWith("HTTP/1.1 403 ") || !get.contains("Request rejected")
                    || !get.toLowerCase(java.util.Locale.ROOT).contains("cache-control: no-store"))
                throw new AssertionError("Default marshaler failed to deliver the JSON response");
            if (!head.startsWith("HTTP/1.1 403 ") || !head.endsWith("\r\n\r\n"))
                throw new AssertionError("Default HEAD response included body bytes");
            for (String path : java.util.List.of("/account/totp/enrollment", "/account/totp/replacement",
                    "/account/totp/confirm", "/login/totp", "/login/recovery",
                    "/account/recovery-codes/rotate", "/account/totp/remove",
                    "/account/totp/enrollment/cancel")) {
                if (!request(port, "POST", path).startsWith("HTTP/1.1 403 "))
                    throw new AssertionError("Expected protected Soklet route missing");
            }
        }
        System.out.println("TOTP Soklet socket checks passed.");
    }

    private static @NonNull String request(int port, @NonNull String method, @NonNull String path)
            throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(15_000);
            String wire = method + " " + path + " HTTP/1.1\r\nHost: localhost:" + port
                    + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(wire.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
