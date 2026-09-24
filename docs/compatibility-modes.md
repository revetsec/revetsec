# Compatibility Modes

**Status: skeleton.** RevetSec contains no protocol code yet, so no compatibility mode exists. Each mode is registered here when it lands, and the registry is complete before 1.0.0.

A compatibility mode is a named, explicit relaxation that lets RevetSec work with a provider that departs from a specification or from RevetSec's defaults. The rules for every mode:

- It is off by default.
- It is set per instance: per client, per identity provider or per tenant, never globally.
- It is reported to the observer when the configured object is built and every time the mode is used.
- It has an entry on this page, and tests cover both the enabled and the disabled state.
- It is never switched on by detecting a provider automatically.
- Named presets bundle modes for one provider. A preset only widens what is accepted, and every change to a preset is recorded in the CHANGELOG.

Some relaxations are never available as a mode: accepting an unsigned message where a signature is required, the JOSE `none` algorithm, and unauthenticated AES-CBC decryption.

## Registry

Each entry will give the mode's name, protocol area, effect, conditions and safeguards, and the release that added it.

## saml2int deviations

The SAML service provider is being designed against the SP requirements of the saml2int profile (v2.0). Each deviation from it will be listed here with its reason.
