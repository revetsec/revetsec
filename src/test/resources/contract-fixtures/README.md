# Contract-test fixtures

Deliberate violations of RevetSec's contract tests. `ContractMetaTests` points each checker at one of these
trees and asserts that every seeded violation is detected, and that the compliant controls are not flagged.

| Directory | Checker | Seeded violations |
|---|---|---|
| `public-api/` | `PublicApiContractTests` | a public record, missing and duplicate thread-safety markers, missing Javadoc and `@since`, missing nullness, `of*`/`create*`/`new*` factory names, a non-final concrete class, a sealed concrete class reopened by a non-sealed subclass (and a sealed one with a final subclass as a control), implicit and explicit public or protected constructors (including on a class listed in `R1_EXCEPTIONS`), members inherited from a package-private base class, and verified (R17) types: one with a public constructor and a builder, one neither final nor sealed, a public subtype, one sealed with a public permitted subclass, and factories, a top-level builder and a field that return or hold one (directly, as a type argument, through a type-variable bound, or as a subtype), plus a listed verified-type source whose static factory and static field are still reported. `ContractMetaTests` supplies its own `VERIFIED_TYPE_SOURCES` and `R1_EXCEPTIONS` lists for this tree, with stale and misspelled (canonical-name) entries |
| `package-dependencies/` | `PackageDependencyTests` | forbidden imports (plain, static and fully qualified), `internal.xml` used outside `saml`, internal types in public signatures (declared, inherited from a package-private class, and as a supertype reached through one), published internal annotations, a package outside the graph, a missing `package-info.java`, and one without `@NullMarked` |
| `source-policy/` | `SourcePolicyTests` | one line per detection alternative, each reported by that alternative alone: calls, method references, constructors and subclasses; static setters called through an instance or an expression; constructs split across lines or spelled with Unicode escapes; Markdown (`///`) doc comments; a file outside its package's directory; plus exempt controls, among them a `\uFFFF` literal followed by a string that names `System.out` |
| `claims/` | `ClaimsLintTests` | banned claim terms in Markdown, Javadoc (`/** */` and `///`), `package.html`, `doc-files/`, the Javadoc overview and the POM description, including terms wrapped across lines, joined by no-break spaces or dashes, or spelled with HTML entities; plus stale, malformed and too-broad allowlist entries |

The real contract tests never scan this directory: the Java files here are not on any source path, and
`ClaimsLintTests` excludes `src/test/resources/contract-fixtures/` when it lints the repository.
