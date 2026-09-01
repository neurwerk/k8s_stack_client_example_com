# Example Client Change

## Summary

Describe the intended change to the Example client configuration and why it is needed.

## Safety Review

- [ ] I confirmed that no password, token, private key, recovery material, provider credential, real Secret manifest, or other confidential value is included.
- [ ] Client facts remain in `config/client.yaml`, product values remain in their product package, and cluster composition remains under `clusters/prod-eu-1/`.
- [ ] I reviewed compatibility and migration effects, including stateful data, CRDs, APIs, resource identities, and staged client/platform reconciliation.
- [ ] I ran `make check` and recorded any check that could not be run.

## Platform Source

- Current channel and selector: `<!-- stable tag:vX.Y.Z, alpha branch:main, or alpha commit:SHA -->`
- Proposed channel and selector: `<!-- unchanged or one canonical channel/selector -->`
- [ ] The source has the canonical closed shape for its selected channel; channel selection is independent of cluster environment.
- [ ] Stable uses one exact signed tag and release trust; alpha uses Base `main` or a full commit SHA with Flux `HEAD` verification and alpha trust.
- [ ] I reviewed the applicable release or alpha ancestry evidence.
- [ ] Maintainer review covers the exact source transition; merging that reviewed commit is the adoption authorization.
- [ ] A moving alpha branch is frozen and reconciled before stable promotion; a forward upgrade records the frozen SHA and both release compatibility declarations use the same set and list it.

Compatibility or fresh-install evidence:

<!-- Link applicable evidence and summarize required pre/post checks and recovery limits. -->

## Reconciliation Boundary

Creating or updating this pull request does not authorize deployment or cluster access. Merging to `main` may allow the configured GitOps controllers to reconcile this repository; reviewers must therefore treat merge approval as a potentially deployment-affecting action.
