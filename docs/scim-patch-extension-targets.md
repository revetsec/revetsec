# Whole-extension PATCH targets

The explicit `PATCH_EXTENSION_SCHEMA_ROOT` compatibility feature allows a PATCH `path` to name a registered extension schema URI itself. It is disabled in the strict, Microsoft Entra ID and Okta presets. When selected, the parser exposes the canonical URI through `ScimPatchOperation.getExtensionSchemaId()`. `getAttributePath()` is empty for this operation. Applications inspecting operations must check the extension identifier before interpreting an absent attribute path as a resource-object operation.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "add",
    "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    "value": {"department": "Research"}
  }]
}
```

`add` and `replace` accept a partial extension object. They apply the same typed attribute rules as ordinary PATCH targets, retain omitted siblings, and preserve explicit null child instructions. An empty explicit object retains an empty extension container and its `schemas` declaration. Scalar, array and whole-root null values reject. `remove` has no value, removes the whole optional extension, and removes its declaration; an absent optional extension is a no-op. Remove-with-value compatibility remains restricted to its reviewed Group membership shape.

Requested paths for object writes include `schemas` and the canonical supplied child targets. Removal includes `schemas` and every registered child/subattribute target, even when no value is assigned. Supplied paths retain only fields actually supplied in the object; the library does not invent supplied child values for removal or empty objects. The operation's extension identifier also remains available for application authorization of the whole-container attempt. Modified paths reflect the resulting resource and declaration changes; never-assigned siblings of a scalar complex value are not reported as changed when that value is created or removed.

The engine enforces required extensions and required child values at the operation where they would be cleared. Removing an optional extension container can remove its required children together. Assigned immutable/read-only fields and protected descendants prevent whole-container removal. An ordinary mutable field does not become protected because a different unassigned field has immutable/read-only mutability.

The original shared work budget covers URI matching, declaration/child path accounting, normalization and application. Every operation remains atomic with the rest of its PATCH request; a late failure exposes no candidate or partial modification. The engine maintains declarations, keeps server versions and timestamps unchanged, and leaves authorization and persistence to the application.

The bare extension URI target is an explicit interoperability profile for registered extension objects. The RFC's PATH grammar does not explicitly show this whole-container form; the profile applies [RFC 7644's ordered operation, typed value, mutability and atomicity rules](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2). `ScimM12ExtensionPatchTests` qualifies the object/merge/removal profile, requiredness, mutability, path accounting and work boundaries. The required top-level PatchOp `schemas` envelope remains strict.

Successful parsing and application each emit the fixed feature event once per public call when they use this profile, regardless of the number of root operations. Unknown roots and rejected ordinary grammar do not implicitly select the feature. Requests bound under this feature cannot be applied by a provider with a different compatibility context.

An ordinary registered attribute path takes precedence if a custom extension identifier happens to equal that qualified path. Selecting this profile therefore cannot reinterpret an existing attribute target as an extension container.
