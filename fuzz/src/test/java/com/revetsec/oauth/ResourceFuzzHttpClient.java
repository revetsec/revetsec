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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.NotThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Synthetic synchronous body delivery only. No socket, executor, thread, DNS or live credential.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
final class ResourceFuzzHttpClient extends HttpClient {
    private final byte[] first;
    private final byte[] second;
    private int requests;
    ResourceFuzzHttpClient(byte @NonNull [] first, byte @NonNull [] second) {
        this.first = first.clone(); this.second = second.clone();
    }
    int getRequests() { return this.requests; }
    @Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(
            @NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> handler) {
        if (!request.method().equals("POST") || !request.uri().equals(URI.create("http://localhost:1/issuer/introspection"))
                || request.headers().firstValue("Authorization").isEmpty()) throw new AssertionError("Expected one authenticated fixture POST");
        byte[] bytes = (++this.requests == 1 ? this.first : this.second).clone();
        HttpResponse.BodySubscriber<T> subscriber = handler.apply(new Info());
        subscriber.onSubscribe(new Flow.Subscription() {
            @Override public void request(long count) { }
            @Override public void cancel() { }
        });
        if (bytes.length != 0) subscriber.onNext(List.of(ByteBuffer.wrap(bytes)));
        subscriber.onComplete();
        // HttpExchange completes from its own subscriber, then cancels this intentionally detached future.
        return new CompletableFuture<>();
    }
    @Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(
            @NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> handler,
            HttpResponse.@NonNull PushPromiseHandler<@NonNull T> push) { return sendAsync(request, handler); }
    @Override public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request,
            HttpResponse.@NonNull BodyHandler<@NonNull T> handler) throws IOException { throw new IOException("Asynchronous fixture only"); }
    @Override public @NonNull Optional<@NonNull CookieHandler> cookieHandler() { return Optional.empty(); }
    @Override public @NonNull Optional<@NonNull Duration> connectTimeout() { return Optional.empty(); }
    @Override public HttpClient.@NonNull Redirect followRedirects() { return Redirect.NEVER; }
    @Override public @NonNull Optional<@NonNull ProxySelector> proxy() { return Optional.empty(); }
    @Override public @NonNull SSLContext sslContext() {
        try { return SSLContext.getDefault(); } catch (NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }
    @Override public @NonNull SSLParameters sslParameters() { return new SSLParameters(); }
    @Override public @NonNull Optional<@NonNull Authenticator> authenticator() { return Optional.empty(); }
    @Override public HttpClient.@NonNull Version version() { return Version.HTTP_1_1; }
    @Override public @NonNull Optional<@NonNull Executor> executor() { return Optional.empty(); }
    private static final class Info implements HttpResponse.ResponseInfo {
        @Override public int statusCode() { return 200; }
        @Override public @NonNull HttpHeaders headers() { return HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (name, value) -> true); }
        @Override public HttpClient.@NonNull Version version() { return Version.HTTP_1_1; }
    }
}
