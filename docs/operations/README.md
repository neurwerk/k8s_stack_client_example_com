# Operations

## Prepare a client

The client owner supplies the environment settings below before an operator attempts installation. The example's `production` identity label and `fresh-install` annotation do not establish that a real target is production-ready or empty.

| Input or decision | Source to review |
| --- | --- |
| Client repository URL, branch, cluster path, and read-only source authentication | [`flux-system/gotk-sync.yaml`](../../clusters/prod-eu-1/flux-system/gotk-sync.yaml). Point the adopted repository at its own source. |
| Client name, environment, and unique cluster identity | [`cluster-identity.yaml`](../../clusters/prod-eu-1/cluster-identity.yaml). Setup uses this identity to check the target. |
| Approved platform tag, transition, and release verification trust | [`platform-source.yaml`](../../clusters/prod-eu-1/platform-source.yaml) and the selected Base `release/manifest.yaml`. |
| Public DNS names, OIDC callbacks/origins, realm, and application identity | [`config/client.yaml`](../../config/client.yaml). Replace example domains consistently, including Studio's authority and realm. Review `canonicalEndpointRouting.mode` and `publicCertificates.useProduction` for the chosen endpoint and certificate setup. |
| Certificate contact and DNS zones | [`cert-manager/values.yaml`](../../infrastructure/security/cert-manager/values.yaml). Supply the actual managed zones and operator contact. |
| Stable Kubernetes API endpoint | [`openbao/values.yaml`](../../infrastructure/security/openbao/values.yaml). Replace the documentation-only address with the reserved server IPv4 address and correct API port. |
| Storage node and raw disk | [`rook-ceph/values.yaml`](../../infrastructure/storage/rook-ceph/values.yaml). Supply `infraRookCeph.storage.nodeName` and `devicePath`; neither is populated. Review the storage classes and capacities in product values against the selected storage design. |
| Reachable local inference and approved remote models | [`agentgateway/values.yaml`](../../infrastructure/networking/agentgateway/values.yaml). Replace the illustrative local host or redesign the local-model and PII-reroute selections together. |
| Permissions, content tracing, and PII handling | Shared `authKeycloak`, `guardrails`, and `monitorPiiEngine` settings plus gateway model entries. The example enables content tracing for its models and permits unmasked local reroutes; these are explicit adopter decisions. |
| Initial administrator and project identities, email delivery, and alert recipient policy | [`keycloak/values.yaml`](../../apps/keycloak/values.yaml), [`langfuse/values.yaml`](../../apps/langfuse/values.yaml), and [`kube-prometheus-stack/values.yaml`](../../infrastructure/observability/kube-prometheus-stack/values.yaml). SMTP and alert email are disabled in the example. |

The operator supplies source-authentication and release-trust Secrets outside Git. Application credentials follow the selected release's secret catalog and the [shared OpenBao procedure](https://github.com/neurwerk/docs/blob/main/dev/operations/openbao.md), using its required Tooling revision and [recovery custody](https://github.com/neurwerk/docs/blob/main/dev/operations/recovery-custody.md). Do not substitute credential values into client YAML.

## Adopt or change a release

1. Read the selected target's manifest, release composition, and migration notes. Confirm the target accepts the current installation or is approved for a genuinely new installation. Compare every required `valuesFrom` ConfigMap with the client generators; local validation alone does not check this boundary.
2. Supply the environment inputs above and select eligible optional packages explicitly. Follow [platform upgrades](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md) for prerequisites, compatibility evidence, backups, and ordering of values, secret delivery, and consumers.
3. Run the [local checks](../development/README.md) and obtain the trusted compatibility result and adoption approval. Keep `spec.ref.tag`, `platform.neurwerk.com/adoption-target`, and the approved adoption mode consistent. Stable production selection uses an exact reviewed signed tag with tag verification.
4. The authorized operator performs setup and reconciliation under the shared procedures. After deployment, use the shared [post-deployment checks](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md#after-deployment) to verify applied source revisions, Flux stages, releases, warnings, affected applications, and data.

## Diagnose and recover

Use the [dependency table](../architecture/README.md#deployment-order) to locate the earliest failing stage. Source authentication and signature trust belong to the operator; missing client ConfigMaps or incorrect overrides belong to the client owner; chart rendering and packaged workload behavior belong to Base or the selected add-on owner. OpenBao setup and credential reconciliation use Tooling's supported procedures.

Recovery follows the adopted release's declared recovery path and the affected component's procedure. A Git revert cannot reverse database migrations or persistent-state changes. Follow [shared recovery guidance](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md#recovery) rather than moving a platform tag backward or deleting storage to retry setup.
