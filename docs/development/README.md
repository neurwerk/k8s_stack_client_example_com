# Development

## Edit settings

Run commands from the client repository root. Put client-wide facts in [`config/client.yaml`](../../config/client.yaml) and product overrides in the relevant `apps/` or `infrastructure/` values file. Preserve generated ConfigMap names expected by the selected Base HelmReleases. Review model definitions together with the `authKeycloak` role mappings and PII policy when changing destinations.

## Local checks

Use the tool versions in [`.tool-versions`](../../.tool-versions) with an approved Mise installation. The [Makefile](../../Makefile) also requires `uv`, Bash, and Python satisfying [`pyproject.toml`](../../pyproject.toml). `uv` uses the committed lockfile. Schema validation can require network access for Kubernetes schemas.

```bash
mise exec -- make check
```

This checks required tools, validates Kubernetes YAML, builds the application values, infrastructure values, and cluster roots, and runs the focused Python checks. Builds use local files and do not contact a cluster. Kubeconform skips unsupported custom-resource schemas in rendered output. The Python checks cover credential exclusion, destination policy, permission consistency, and Flux export handling.

Passing these checks does not validate the selected Base charts against all client values: the local builds render ConfigMaps and Flux resources, not the remote platform's Helm charts. They also do not verify DNS, storage hardware, credential delivery, or running applications.

## CI and release compatibility

[`validate.yaml`](../../.github/workflows/validate.yaml) verifies the Python lockfile, runs the lightweight hooks in [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml), and runs `make check`.

Platform compatibility is a separate workflow. [`platform-compatibility-evaluate.yaml`](../../.github/workflows/platform-compatibility-evaluate.yaml) reads [`config/validation-revision`](../../config/validation-revision) from the trusted PR base, checks out Base validation at that exact commit, and evaluates the current base, head, and test-merge revisions. Source changes require the `platform-adoption` environment step; a changed tuple requires fresh authorization. The workflow requires the configured status GitHub App and `platform-status` environment. These repository settings are external prerequisites, not created by the YAML.

The Makefile's `platform-compatibility` target is not part of `make check`. It requires a Base validation checkout at `.ci/validation` matching the pin, `BASE_SHA`, and `HEAD_SHA`; supplying `PR_NUMBER` also requires `MERGE_SHA`. `VALIDATION_WORKTREE` is an explicit candidate-validator override, not evidence that the pinned validator passed. Use the trusted CI result for an adoption review.
