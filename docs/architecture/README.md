# Architecture

## Sources and ownership

The [cluster root](../../clusters/prod-eu-1/kustomization.yaml) composes the identity ConfigMap, source definitions, deployment stages, and Flux controllers. [Flux sync](../../clusters/prod-eu-1/flux-system/gotk-sync.yaml) reads this repository's `main` branch through the `flux-system` GitRepository and reconciles `./clusters/prod-eu-1`. Its SSH authentication Secret is supplied outside Git.

The separate [`k8s-stack` source](../../clusters/prod-eu-1/platform-source.yaml) selects an exact alpha commit, requests commit signature verification, and references the operator-provisioned `k8s-stack-alpha-trust` Secret. Read `release/manifest.yaml` and `releases/` at that selected revision for package membership and prerequisites. Stable production adoption requires a separately reviewed, signed tag.

The example selects the public Dify, LibreChat, Open WebUI and Pipecat add-ons through immutable Flux sources. [`config/addons.yaml`](../../config/addons.yaml) approves their credential readers and identities; [`addon-selection.yaml`](../../clusters/prod-eu-1/addon-selection.yaml) is its generated setup projection. Product values alone do not select a release package.

## Configuration flow

| Client files | Responsibility |
| --- | --- |
| [`config/client.yaml`](../../config/client.yaml) | Shared hostnames, OIDC identity settings, role mappings, MCP selection, PII policy, and common resource settings. |
| [`apps/`](../../apps/kustomization.yaml) and [`infrastructure/`](../../infrastructure/kustomization.yaml) | Generate namespace-local settings ConfigMaps from shared configuration and product `values.yaml` files. They do not install the applications. |
| [`config/openrouter-catalog.yaml`](../../config/openrouter-catalog.yaml) | Catalog values copied into AgentGateway and LibreChat ConfigMaps. |
| [`config/openrouter-catalog-policy.json`](../../config/openrouter-catalog-policy.json) | Catalog selection and pricing policy data; it is not a Flux root. |
| [`config/gateway-model-metadata.yaml`](../../config/gateway-model-metadata.yaml) and [`config/dify-model-sync.yaml`](../../config/dify-model-sync.yaml) | Metadata companion and generated Dify selection. Refresh observations for the adopted deployment; missing capabilities remain unknown. |
| [`infrastructure/networking/agentgateway/`](../../infrastructure/networking/agentgateway/kustomization.yaml) | Gateway overrides, local-model destination, and model cost catalog ConfigMap. |
| [`clusters/prod-eu-1/`](../../clusters/prod-eu-1/kustomization.yaml) | Sources, cluster identity, and Flux dependency order. |

Generators use stable ConfigMap names such as `client-values` and `agentgateway-product-values`, with `values.yaml` as the data key. Base's HelmReleases decide which maps they consume and in what order. Check the selected release's `valuesFrom` entries before adding settings: generating a ConfigMap does not prove that the selected chart reads it. Ordinary later values entries override earlier ones; inline HelmRelease values can take precedence.

Credentials do not belong in these ConfigMaps. Base supplies secret-delivery resources, OpenBao stores application credentials, and External Secrets delivers the approved fields. [Shared authentication](https://github.com/neurwerk/docs/blob/main/dev/authentication/README.md) explains the identity boundaries; the selected release defines which configuration format implements them.

## Deployment order

All stages below run in `flux-system`. The explicit dependencies are defined in [`namespaces.yaml`](../../clusters/prod-eu-1/namespaces.yaml), [`client-values.yaml`](../../clusters/prod-eu-1/client-values.yaml), [`infrastructure.yaml`](../../clusters/prod-eu-1/infrastructure.yaml), and [`applications.yaml`](../../clusters/prod-eu-1/applications.yaml).

| Stage | Source and path | Waits for |
| --- | --- | --- |
| `namespaces` | Base: `./releases/namespaces` | Source availability |
| `client-app-values` | Client: `./apps` | Base and LibreChat namespaces |
| `client-infrastructure-values` | Client: `./infrastructure` | `namespaces` |
| `infrastructure` | Base: `./releases/infrastructure` | Namespace/value stages, early External Secrets controller, Docling reloader values |
| `applications` | Base: `./releases/applications` | Infrastructure, application values, Studio and API-key-bridge credential readiness |
| Product stages | Base or selected add-on: `./releases/<product>/...` | Product values, delivery, database, identity, certificate and setup prerequisites |

Stages use `wait` or explicit readiness checks and enable `prune`. Delivery resources are created before waiting for operator-prepared credentials. Separate ContextForge, inspection/trust, Docling, maintenance, Tailscale and GlitchTip stages preserve their startup dependencies. The YAML files are authoritative for the full dependency graph.

The gateway selects exactly one local Llama model, one OpenRouter model, one direct DeepSeek model and one Codex subscription integration/model. Managed MCP enables Context7, Brave, GitHub and GlitchTip. LibreChat RAG and Code Interpreter remain optional; their separate embedding/execution prerequisites are not selected. Pipecat sessions and TURN need their own speech/network setup before activation.
