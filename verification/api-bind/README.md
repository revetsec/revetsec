# Typed binding public-API verification

This fixture checks the API-BIND boundary using an exact current core JAR and an exact pre-change
baseline JAR. The positive consumer compiles every affected high-level family with
`BrowserBinding` or `OperationBinding` and executes the carrier boundaries. A legacy external
consumer using raw `String` bindings must compile against the baseline and fail against the
current JAR. Cross-role consumers must also fail against the current JAR.

The fixture deliberately does not parse a request value with `fromTrustedPersistence`. Its
restoration values are fixed test representations of application-controlled persisted state.
Low-level store SPIs remain raw `String` compatibility boundaries and are tested separately in
`BindingPublicApiTests`.

Run with a new private output directory:

```sh
python3 run.py \
  --current-jar /absolute/revetsec-current.jar \
  --baseline-jar /absolute/revetsec-before-api-bind.jar \
  --java-home /absolute/jdk21 \
  --output /private/tmp/new-api-bind-check
```

The selected compatibility loss is exact: well-formed OAuth/OIDC pending bindings over 65,536
Java UTF-16 code units that were accepted by a sufficiently provisioned in-memory or custom store
are no longer accepted by the high-level API. Only deployments retaining such a live pending
attempt or its server-session correlation need to expire, clear or rotate that state before
starting a newly authorized flow. No account, credential, reference PostgreSQL schema, key or
codec migration follows from this change.
