# Restricted WebAuthn reauthentication consumer

This standalone fixture compiles and runs using only the selected public core JAR. Nine genuine engine outcomes cover success, known consumed context rejection, unavailability, both UNKNOWN effect controls, known output withholding, cancellation, and both expected-account buffer mutation controls. It audits restricted construction and the five permitted result leaves. Java 21 no-default switches route the actual results; removing each leaf must fail compilation. Ordinary sign-in facts and generic success cannot be passed to a restricted-proof consumer.

Run with Python 3 and owned private output. Repeat `--java-home` for JDK17, 21 and 27:

```sh
python3 run.py --core-jar /absolute/core.jar --core-sha256 EXPECTED_SHA256 --java-home /absolute/jdk21 --work /private/tmp/new-proof-check
```

No internal test classes, annotations, private constructors, network service or framework classes enter the runtime. The real app's session, pending ceremony, purpose, exact target, one-use and output refusal policy is tested separately in `PasskeyActionPolicyTests`. These finite checks do not qualify a physical authenticator, hosted provider, deployed transport or final release artifact. The original ceremony handle is a correlation value and must not be logged.
