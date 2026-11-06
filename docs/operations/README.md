# Operations

## Prepare a client

The client owner supplies the environment settings below before an operator attempts installation. This fully selected example uses synthetic domains, network addresses and setup placeholders. It is a configuration template, not evidence that a target is empty or ready for deployment.

| Input or decision | Source to review |
| --- | --- |
| Client repository URL, branch, cluster path, and read-only source authentication | [`flux-system/gotk-sync.yaml`](../../clusters/prod-eu-1/flux-system/gotk-sync.yaml). Point the adopted repository at its own source. |
| Client name, environment, and unique cluster identity | [`cluster-identity.yaml`](../../clusters/prod-eu-1/cluster-identity.yaml). Setup uses this identity to check the target. |
| Approved platform revision, add-on sources and verification trust | [`platform-source.yaml`](../../clusters/prod-eu-1/platform-source.yaml), the add-on source files and their selected release manifests. The example selects exact alpha commits. |
| Public DNS names, OIDC callbacks/origins, realm, and application identity | [`config/client.yaml`](../../config/client.yaml). Replace example domains consistently, including Studio's authority and realm. Review `canonicalEndpointRouting.mode` and `publicCertificates.useProduction` for the chosen endpoint and certificate setup. |
| Certificate contact and DNS zones | [`cert-manager/values.yaml`](../../infrastructure/security/cert-manager/values.yaml). Supply the actual managed zones and operator contact. |
| Stable Kubernetes API endpoint | [`openbao/values.yaml`](../../infrastructure/security/openbao/values.yaml). Replace the documentation-only address with the reserved server IPv4 address and correct API port. |
| Storage node and raw disk | [`rook-ceph/values.yaml`](../../infrastructure/storage/rook-ceph/values.yaml). Replace the synthetic node and disk placeholders with an approved dedicated OSD device. Review storage classes and capacities against your design. |
| Reachable local inference and approved remote models | [`agentgateway/values.yaml`](../../infrastructure/networking/agentgateway/values.yaml). Replace the illustrative local host or redesign the local-model and PII-reroute selections together. |
| Permissions, content tracing, and PII handling | Shared `authKeycloak`, `guardrails`, and `monitorPiiEngine` settings plus gateway model entries. The example enables content tracing for its models and permits unmasked local reroutes; these are explicit adopter decisions. |
| Initial identities, email and alerts | [`keycloak/values.yaml`](../../apps/keycloak/values.yaml), [`langfuse/values.yaml`](../../apps/langfuse/values.yaml), and [`kube-prometheus-stack/values.yaml`](../../infrastructure/observability/kube-prometheus-stack/values.yaml). Email is enabled; supply your relay, verified sender, recipients and credentials. |
| Inspection trust | [`inspection-trust/values.yaml`](../../apps/agentgateway/inspection-trust/values.yaml). Replace the all-zero fingerprint with your verified public root fingerprint. Initialize publication, then set Studio's required snapshot version before enabling client use. |
| MCP and private management access | Shared MCP settings, [`contextforge/values.yaml`](../../apps/contextforge/values.yaml) and [`tailscale/values.yaml`](../../infrastructure/tailscale/values.yaml). Replace the OAuth application ID, Service/API CIDRs and tailnet settings. Personal credentials belong in the supported connection flow. |
| Reporting startup | [`glitchtip/values.yaml`](../../apps/glitchtip/values.yaml). Initially disable both adapter flags and enable provisioning. Provision the native organization/project, import its private DSN and verify reader/CA delivery, then disable provisioning before enabling the adapter. Verify notifications before adding `verifiedGlitchtipScopeIds`. |
| Branding and maintenance | Replace the synthetic [`company-logo.svg`](../../apps/keycloak/company-logo.svg) if desired; both Keycloak and maintenance receive namespace-local copies. Maintenance's chart rejects example domains, so replace the canonical hostnames before rendering it. |
| Pipecat application bundle | [`pipecat/values.yaml`](../../apps/pipecat/values.yaml). Upload your own immutable bundle and replace the all-zero object key/digest. Sessions and TURN remain off until their speech/network prerequisites are configured. |
| Model observations and synchronization | Refresh [`gateway-model-metadata.yaml`](../../config/gateway-model-metadata.yaml) for your actual providers/runtime, then regenerate [`dify-model-sync.yaml`](../../config/dify-model-sync.yaml). Its example revisions assume both shared provider credentials are available; the operator previews/applies native synchronization separately. |

The operator supplies source-authentication and release-trust Secrets outside Git. Application credentials follow the selected release's secret catalog and the [shared OpenBao procedure](https://github.com/neurwerk/docs/blob/main/dev/operations/openbao.md), using its required Tooling revision and [recovery custody](https://github.com/neurwerk/docs/blob/main/dev/operations/recovery-custody.md). Do not substitute credential values into client YAML.

## Adopt or change a release

1. Read the selected target's manifest, release composition, and migration notes. Confirm the target accepts the current installation or is approved for a genuinely new installation. Compare every required `valuesFrom` ConfigMap with the client generators; local validation alone does not check this boundary.
2. Supply the environment inputs above and select eligible optional packages explicitly. Follow [platform upgrades](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md) for prerequisites, compatibility evidence, backups, and ordering of values, secret delivery, and consumers.
3. Run the [local checks](../development/README.md) and obtain the trusted compatibility result and adoption approval. Keep `spec.ref.tag`, `platform.neurwerk.com/adoption-target`, and the approved adoption mode consistent. Stable production selection uses an exact reviewed signed tag with tag verification.
4. The authorized operator performs setup and reconciliation under the shared procedures. After deployment, use the shared [post-deployment checks](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md#after-deployment) to verify applied source revisions, Flux stages, releases, warnings, affected applications, and data.

## Diagnose and recover

Use the [dependency table](../architecture/README.md#deployment-order) to locate the earliest failing stage. Source authentication and signature trust belong to the operator; missing client ConfigMaps or incorrect overrides belong to the client owner; chart rendering and packaged workload behavior belong to Base or the selected add-on owner. OpenBao setup and credential reconciliation use Tooling's supported procedures.

Recovery follows the adopted release's declared recovery path and the affected component's procedure. A Git revert cannot reverse database migrations or persistent-state changes. Follow [shared recovery guidance](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md#recovery) rather than moving a platform tag backward or deleting storage to retry setup.
