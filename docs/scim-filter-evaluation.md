# Optional SCIM filter evaluation

`ScimFilterEvaluator.fromServiceProvider(provider)` evaluates a filter against an immutable `ScimResource`. The provider must have an application `ScimStringMatching` strategy. The evaluator uses that same strategy as PATCH, the provider's registered schemas and filter policies, and one aggregate work budget per evaluation.

```java
ScimFilterEvaluator evaluator = ScimFilterEvaluator.fromServiceProvider(provider);
ScimFilterEvaluationResult result = evaluator.evaluateResult(resource, filter);
if (result instanceof ScimFilterEvaluationResult.Succeeded success) {
    boolean matched = success.isMatched();
} else {
    ScimError error = ((ScimFilterEvaluationResult.Rejected) result).getError();
}
```

Every evaluation rebinds and approves the complete tree under its receiving provider. A syntax-only filter, or one approved by another provider, cannot grant filtering permission. A resource with request provenance from a different semantic context rejects. Trusted application resources must use a resource type registered with this provider. The application remains responsible for caller authorization, tenant isolation, storage queries and authoritative identity uniqueness.

For strings, the application strategy receives the canonical attribute path, its definition, the operator, the stored value and the literal. It must be thread-safe, deterministic, bounded and free of I/O. Matching for `userName` must agree with the authoritative database's chosen [internationalized username preparation profile](https://www.rfc-editor.org/rfc/rfc8265.html). The synthetic ASCII strategies in tests and the example prove their fixture behavior; they do not provide a production Unicode matching default.

Numbers, booleans, binary values, date-times and references use core rules. Numeric equality compares values rather than lexical spellings. Binary equality compares decoded bytes. References and standard Group membership IDs compare exact text. An accepted rebuilt Group schema with equal definitions and facets keeps this exact ID behavior; a custom schema uses its application matching strategy. Date-times with offsets compare normalized instants, including extended XML Schema years and fractional precision. Comparing a date-time with an offset to one without an offset rejects with `invalidFilter`, because that mixed comparison has no selected total order.

The evaluator explicitly selects these interpretations of [SCIM filtering](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.2) and [unassigned attributes](https://www.rfc-editor.org/rfc/rfc7643.html#section-2.5):

| Stored attribute | `eq null` | `ne null` | `eq "a"` | `ne "a"` | `pr` | `not(eq "a")` |
| --- | --- | --- | --- | --- | --- | --- |
| Missing or explicit null | true | false | false | true | false | true |
| Empty multivalue array | true | false | false | true | false | true |
| Empty string | false | true | false | true | false | true |
| `"a"` | false | true | true | false | true | false |
| `["a", "b"]` | false | true | true | true | true | false |
| `[""]` | false | true | false | true | false | true |

Every comparison on an assigned multivalue uses any-element semantics, including `ne`. Negation applies to the complete predicate. Missing subattributes retain their unassigned meaning when a flat path scans complex elements, so `rows.value eq null` can match an element without `value` even when another element has a value. ValuePath predicates evaluate all their child clauses against the same element. Complex presence considers visible assigned child values; an empty object or an object with only `returned:never` data does not satisfy presence.

All logical clauses and array elements are visited until a rejection occurs. An unsupported strategy result rejects the complete operation with `invalidFilter`, including when another clause already determines a truth value. Work exhaustion returns `requestTooLarge`. Unexpected ordinary strategy faults, including a null return or assertion failure, produce the fixed `internalError` result and a redacted `FILTER_EVALUATE` failure event. A thrown interruption restores the thread flag; fatal VM errors escape. Rejected results contain no partial verdict or arbitrary exception data.

The independent authored truth matrix is in `ScimM12EvaluatorTests`; the evaluator fuzz target checks arbitrary foreign trees and a separate generated default-null model. These tests qualify local semantics and bounds. They do not stand in for external provisioning interoperability.
