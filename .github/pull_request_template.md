# Example Client Change

## Summary

Describe the intended change to the Example client configuration and why it is needed.

## Safety Review

- [ ] I confirmed that no password, token, private key, recovery material, provider credential, real Secret manifest, or other confidential value is included.
- [ ] Client facts remain in `config/client.yaml`, product values remain in their product package, and cluster composition remains under `clusters/prod-eu-1/`.
- [ ] I reviewed compatibility and migration effects, including stateful data, CRDs, APIs, resource identities, and staged client/platform reconciliation.
- [ ] I ran `make check` and recorded any check that could not be run.

## Platform Release

- Current exact signed platform pin: `<!-- vX.Y.Z -->`
- Proposed exact signed platform pin: `<!-- unchanged or vX.Y.Z -->`
- [ ] The pin remains one exact `vX.Y.Z` tag with Flux tag verification enabled.
- [ ] `platform.neurwerk.com/adoption-target` equals the proposed tag and `platform.neurwerk.com/adoption-mode` is exactly `upgrade` or `fresh-install`.
- [ ] I reviewed the target release manifest, published GitHub Release, and `release/migrations/vX.Y.Z.md`.
- [ ] Every changed pin receives reviewer approval through the protected `platform-adoption` environment.
- [ ] For `upgrade`, the target manifest lists the current pin in `upgradesFrom`; for `fresh-install`, the environment reviewer independently confirmed the operator's empty-target attestation.

Compatibility or fresh-install evidence:

<!-- Link the platform release and summarize required pre/post checks and recovery limits. -->

## Reconciliation Boundary

Creating or updating this pull request does not authorize deployment or cluster access. Merging to `main` may allow the configured GitOps controllers to reconcile this repository; reviewers must therefore treat merge approval as a potentially deployment-affecting action.
