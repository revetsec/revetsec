# Google and Apple backend tokens with Soklet

This unpublished Java 21 integration wires the [common Java 17 application recipe](../provider-backend-tokens/README.md) to real Soklet request, route and cookie types. It preserves header/cookie multiplicity, complete raw form bytes, body-discard flags, exact raw path, actual socket peer and separate response cookies. The common implementation owns provider/nonce/CSRF checks, one-use attempts, bounded sessions, rotation and current account/tenant/owner authorization; the application supplies its real account and admission callbacks.

Build after installing a matching core and the checksum-pinned framework described in [the examples guide](../README.md):

```sh
mvn -B -ntp -f examples/pom.xml -pl provider-backend-tokens-soklet -am verify
```

## Trusted edge is required

The provided listener binds IPv4 loopback. Enable `trustedHttpsAndQueryFreeEdge` only after the deployment provides all these controls:

- An authenticated/private path from the HTTPS edge to this listener, with connection, queue and request/read/response deadlines.
- Rejection of **every raw request target containing a query delimiter**, including a bare trailing `?`, on these provider recipe routes, before Soklet parses the target.
- A fixed trusted external origin/Host and preservation or fail-closed rejection of ambiguous security-relevant request fields. Never derive transport trust from arbitrary forwarding headers.

The selected Soklet JAR collapses `/google/begin?` to `/google/begin` with an absent raw query. Its public request value cannot distinguish those two originals. The handler rejects observable nonempty queries and encoded path aliases, but cannot recover the lost empty delimiter. Without the declared edge rule, a request with otherwise valid nonce/CSRF/provider credentials can complete on a trailing-question-mark route. This is an explicit carrier/profile gap, not a successfully tested rejection. Do not enable this recipe on an unqualified edge or expose its backend listener publicly.

```java
import example.provider.BackendApplication;
import example.provider.soklet.SokletProviderTokensRecipe;
import com.soklet.Soklet;
import java.net.URI;

final class ProviderSokletWiring {
    static void run(BackendApplication.Accounts accounts,
            BackendApplication.Admission admission, boolean qualifiedHttpsAndQueryFreeEdge)
            throws InterruptedException {
        var configuration = new BackendApplication.Configuration(
                URI.create("https://app.example"), "configured-google-client-id",
                "configured-apple-bundle-id", null, 128, 65_536);
        var application = BackendApplication.create(configuration, accounts, admission);
        var recipe = new SokletProviderTokensRecipe(application, qualifiedHttpsAndQueryFreeEdge);
        try (Soklet server = Soklet.fromConfig(recipe.configuration(18080))) {
            server.start();
            server.awaitShutdown();
        }
    }
}
```

The fixed routes are `/google/begin`, `/google/complete`, `/apple/begin`, `/apple/complete`, `/session`, `/native/session`, `/account/{tenant}/{account}`, `/native/account/{tenant}/{account}`, `/logout` and `/native/logout`. Use the common recipe's exact Google browser/Apple native contracts. Native provider tokens are not application API bearer credentials. No account is created or linked by email, and a valid provider token grants no application permission by itself.

The backend caps complete bodies at 32 KiB, headers at 32/8 KiB, connections at 64 and handlers at eight with a queue of 16. Header/body reads have three-second limits, handlers six seconds and response idle writes three seconds; the common operation retains its own original four-second budget. Denied or discarded requests allocate no attempt/session. GET status allocates nothing. Responses carry no-store policy; do not log bodies, cookies, tokens, source exceptions or explicit credential-bearing getters. Framework HEAD handling suppresses response bytes.

## Local checks and remaining qualification

Maven runs six meaningful carrier tests plus the common module's 85 cases. Test-only fixtures generate synthetic provider keys and own a loopback JWKS listener; they are excluded from application JARs. The optional [socket runner](../../verification/provider-token-soklet/README.md) runs the signed Google/Apple flows and adversarial matrix through a real Soklet listener on JDK 21/27, without annotation/JUnit runtime dependencies. It records the trailing-question-mark information loss and actual EOF/connection-close rejection for truncated framing rather than inventing an HTTP error response.

These local component checks do not qualify an actual HTTPS/query-rejection edge, browser, hosted Google account, Apple device, distributed session/recovery deployment or full M12 profile. The source and explicit collaborator contracts are reviewable; those profile gates remain open.
