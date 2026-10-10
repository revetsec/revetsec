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
import com.soklet.ResponseCookie;
import java.util.Optional;
import org.jspecify.annotations.NonNull;

/** Application-owned browser state. Writes must be atomic; an uncertain write releases no success. */
interface BrowserSessionStore {
    BrowserSessions.@NonNull Session begin();
    @NonNull Optional<BrowserSessions.@NonNull Session> find(@NonNull Request request);
    void replacePending(BrowserSessions.@NonNull Session session,BrowserSessions.@NonNull Pending pending);
    BrowserSessions.@NonNull Session login(BrowserSessions.@NonNull Session previous,
            BrowserSessions.@NonNull Pending selected);
    boolean claimPending(BrowserSessions.@NonNull Session session,BrowserSessions.@NonNull Pending selected);
    void remove(BrowserSessions.@NonNull Session session);
    @NonNull ResponseCookie cookie(BrowserSessions.@NonNull Session session);
}
