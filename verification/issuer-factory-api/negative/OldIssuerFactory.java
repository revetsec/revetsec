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

package verification.issuerfactory;
import org.jspecify.annotations.NonNull;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import java.security.KeyPair;
final class OldIssuerFactory { static @NonNull OAuthIssuerSigningKey old(@NonNull KeyPair pair){return OAuthIssuerSigningKey.fromKeyPair("old",pair.getPrivate(),pair.getPublic());} }
