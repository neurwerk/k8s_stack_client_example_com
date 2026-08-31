# Label Taxonomy

Issue forms do not assign labels because repository labels are managed out of band. After triage, apply one label from each mandatory category defined by the workspace GitHub workflow convention.

- Type: `type: bug`, `type: task`, `type: architecture`
- Priority: `priority: p0`, `priority: p1`, `priority: p2`, `priority: p3`, `priority: p4`
- Area: `area: docs`, `area: platform`, `area: client`, `area: service`, `area: operations`, `area: security`
- Release: `release: none`, `release: notes`, `release: platform`, `release: client`

The additional `platform: fresh-install` label records fresh-install intent when the target release does not support the current pin. It is classification only; it does not authorize adoption, attest that a cluster is empty, or replace approval through the protected `platform-adoption` environment.
