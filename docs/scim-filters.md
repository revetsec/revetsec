# SCIM filter syntax

SCIM support includes bounded filter and attribute-path parsing, immutable
syntax trees, a Java 17 visitor, explicit serialization, schema binding,
policy enforcement, resource models, query framing, an optional evaluator,
and provisioning primitives.

**A successful syntax parse grants no query permission.** Before executing a
filter, an application needs registered-schema binding, type validation,
approval of the complete normalized tree, and tenant and caller authorization.
`ScimFilter.fromExpressionResult` performs syntax validation only.
`ScimServiceProvider.parseFilterResult` also binds the tree to registered
schemas and checks the configured filter policy. The application still
authenticates the caller, authorizes its tenant and scope, and executes the
approved tree against its own data.

## Parse a filter

```java
ScimFilterParseResult result = ScimFilter.fromExpressionResult(
        "userName eq \"alice@example.com\"");
if (result instanceof ScimFilterParseResult.Succeeded succeeded) {
    ScimFilter syntax = succeeded.getFilter();
    // Retain or inspect syntax; schema binding and permission checks come next.
} else if (result instanceof ScimFilterParseResult.Rejected rejected) {
    ScimError error = rejected.getError();
    // Fixed status/type/detail; optional zero-based UTF-16 expression offset.
}
```

Malformed input and exceeded parsing bounds return `Rejected` without a partial
tree. Errors retain no input or cause, and their fixed detail does not include
the expression offset. Null API arguments and invalid trusted configuration
remain programming errors.

The six node types are `And`, `Or`, `Not`, `Comparison`, `Present` and
`ValuePath`. AND and OR use ordered operand lists and flatten adjacent nodes
with the same operator. NOT requires a parenthesized expression. A ValuePath
predicate describes one array element; nested ValuePaths and schema-qualified
paths inside its predicate are rejected. This syntax representation does not
evaluate those predicates.

Operators and path names compare using ASCII case folding. Boolean and null
literals require their lowercase JSON spellings. Strings use strict JSON
escapes and valid Unicode scalar sequences; numbers use strict JSON syntax
and exact `BigDecimal` values. Numeric literal equality compares numeric value.
Ordinary whitespace is space, tab, carriage return, line feed or form feed;
path/operator/value boundaries require whitespace.

`ScimAttributePath.fromExpressionResult(...)` parses a standalone path into
`ScimAttributePathParseResult`. Paths contain an optional absolute schema URI,
one attribute and an optional subattribute. Schema IDs support URNs and HTTPS
URIs, including IPv6 authorities. They are identifiers and are never fetched.
Names start with an ASCII letter and continue with letters, digits, `_` or `-`;
The narrow `$ref` exception is also accepted, including relative predicates
such as `members[$ref pr]`. No other leading-dollar name is accepted. Later
schema binding determines whether a name exists in its context. Surrounding
whitespace is rejected for standalone paths. Original component spellings are
preserved.

## Bounds

`ScimFilterLimits.defaultInstance()` supplies the following limits. The overloaded
`ScimFilter.fromExpressionResult(expression, limits)` uses an immutable custom
configuration built with `ScimFilterLimits.builder()`.

| Builder setting | Default | Inclusive range |
| --- | ---: | ---: |
| `maximumExpressionCharacters` | 4,096 | 256–65,536 |
| `maximumDepth` | 16 | 4–64 |
| `maximumNodes` | 128 | 8–4,096 |
| `maximumLiteralCharacters` | 2,048 | 1–16,384 |
| `maximumNumberCharacters` | 64 | 1–256 |
| `maximumNumberExponentMagnitude` | 1,000 | 0–10,000 |

Character counts use UTF-16 code units. The literal limit applies to decoded
strings, and number length applies to the complete source token. The literal
limit cannot exceed the expression limit. A null builder value restores that
setting's default. Attribute and subattribute names have a fixed 128-character
cap, and schema IDs have a fixed 2,048-character cap.

Depth bounds both retained AST levels and temporary grouping, negation and
ValuePath nesting. Nodes count the retained flattened tree. Parsing checks
bounds before recursive growth and expensive literal or numeric allocation.
Applications must also bound transport allocation before constructing a Java
String; parsing cannot undo an already allocated request body.

## Inspect and emit syntax

`ScimFilterVisitor<R>` exposes one method per node type. The visitor controls
traversal and must return a nonnull result. Immutable getters expose operands,
paths, comparison operators and literal values without public node factories.

The six `ScimFilter` node kinds and four `ScimFilterValue` literal kinds remain
stable within a major version and may be matched exhaustively. Adding a node
kind or an abstract visitor method requires a major release. Operation result
switches and enum switches retain a rejecting default.

`toScimString()` explicitly emits filter data with lowercase operators, minimal
grouping, JSON string escapes and compact exponent notation. It preserves
path spelling and is intended for round trips, not identity matching or
authorization. Equivalent numeric values can retain different decimal
spellings. Filters, values, paths, parse results and policy diagnostics redact
their data in `toString()`. Explicit getters and serialization can disclose
personal data and need application-controlled logging.

## Declare filter permission

`ScimFilterPolicy.rejectAllInstance()` and a fresh policy builder deny every
filter shape. The builder replaces complete snapshots of comparison paths,
presence paths, ValuePath child policies and allowed logical operators. Its
comparison-count default is 32, with an inclusive range of 1–128. Null values
restore empty collections or the comparison-count default.

Construction validates path syntax, rejects equivalent duplicate paths, and
bounds the policy graph. Service-provider registration binds these declarations to registered schemas.
A flat comparison declaration does not imply ValuePath permission. The provider
enforces the policy against the complete normalized tree before returning an
approved filter or query. Syntax-only parsing grants no permission; applications
still authenticate callers, authorize scope and execute the approved tree.
See [schema-bound server primitives](scim-server-primitives.md) and
[the optional evaluator](scim-filter-evaluation.md).
