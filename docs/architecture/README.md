# Architecture

## Sources and ownership

The [cluster root](../../clusters/prod-eu-1/kustomization.yaml) composes the identity ConfigMap, source definitions, deployment stages, and Flux controllers. [Flux sync](../../clusters/prod-eu-1/flux-system/gotk-sync.yaml) reads this repository's `main` branch through the `flux-system` GitRepository and reconciles `./clusters/prod-eu-1`. Its SSH authentication Secret is supplied outside Git.

The separate [`k8s-stack` source](../../clusters/prod-eu-1/platform-source.yaml) selects an exact Base tag, requests tag signature verification, and references the operator-provisioned `k8s-stack-release-trust` Secret. Its adoption annotations describe the intended transition. Read `release/manifest.yaml` and `releases/` at that selected tag for package membership and prerequisites; Base `main` can have a different layout.

There is no separate add-on source or add-on stage in this example. Omitting a product directory under `apps/` does not exclude a product from Base's selected application root. For an add-on-based installation, the client owner must explicitly select compatible immutable add-on sources and their deployment stages under the [shared deployment rules](https://github.com/neurwerk/docs/blob/main/dev/conventions/deployment.md).

## Configuration flow

| Client files | Responsibility |
| --- | --- |
| [`config/client.yaml`](../../config/client.yaml) | Shared hostnames, OIDC identity settings, role mappings, MCP selection, PII policy, and common resource settings. |
| [`apps/`](../../apps/kustomization.yaml) and [`infrastructure/`](../../infrastructure/kustomization.yaml) | Generate namespace-local settings ConfigMaps from shared configuration and product `values.yaml` files. They do not install the applications. |
| [`config/openrouter-catalog.yaml`](../../config/openrouter-catalog.yaml) | Catalog values copied into AgentGateway and LibreChat ConfigMaps. |
| [`config/openrouter-catalog-policy.json`](../../config/openrouter-catalog-policy.json) | Catalog selection and pricing policy data; it is not a Flux root. |
| [`infrastructure/networking/agentgateway/`](../../infrastructure/networking/agentgateway/kustomization.yaml) | Gateway overrides, local-model destination, and model cost catalog ConfigMap. |
| [`clusters/prod-eu-1/`](../../clusters/prod-eu-1/kustomization.yaml) | Sources, cluster identity, and Flux dependency order. |

Generators use stable ConfigMap names such as `client-values` and `agentgateway-product-values`, with `values.yaml` as the data key. Base's HelmReleases decide which maps they consume and in what order. Check the selected release's `valuesFrom` entries before adding settings: generating a ConfigMap does not prove that the selected chart reads it. Ordinary later values entries override earlier ones; inline HelmRelease values can take precedence.

Credentials do not belong in these ConfigMaps. Base supplies secret-delivery resources, OpenBao stores application credentials, and External Secrets delivers the approved fields. [Shared authentication](https://github.com/neurwerk/docs/blob/main/dev/authentication/README.md) explains the identity boundaries; the selected release defines which configuration format implements them.

## Deployment order

All stages below run in `flux-system`. The explicit dependencies are defined in [`namespaces.yaml`](../../clusters/prod-eu-1/namespaces.yaml), [`client-values.yaml`](../../clusters/prod-eu-1/client-values.yaml), [`infrastructure.yaml`](../../clusters/prod-eu-1/infrastructure.yaml), and [`applications.yaml`](../../clusters/prod-eu-1/applications.yaml).

| Stage | Source and path | Waits for |
| --- | --- | --- |
| `namespaces` | Base: `./releases/namespaces` | Source availability |
| `client-app-values` | Client: `./apps` | `namespaces` |
| `client-infrastructure-values` | Client: `./infrastructure` | `namespaces` |
| `infrastructure` | Base: `./releases/infrastructure` | `namespaces`, `client-infrastructure-values` |
| `applications` | Base: `./releases/applications` | `infrastructure`, `client-app-values` |

These stages enable `wait` and `prune`. Infrastructure and applications also define Gateway readiness expressions. HelmRelease dependencies inside Base add product-level ordering. The client and Base sources reconcile independently, so changing values and a platform tag requires an adoption sequence that keeps their intermediate states compatible.

LibreChat's client root includes only `core`; its Code Interpreter values directory is not included. RAG and Code Interpreter are disabled in the product values, and MCP is disabled in shared settings. Enabling a value alone does not compose an optional package or make an excluded release package eligible.
