# Example client

This repository shows how a client supplies non-secret settings and orders Flux deployment of Base releases. It is a starting point for a client repository, not a ready-to-deploy cluster: hostnames, storage placement, cluster identity, external services, and release compatibility need adopter review.

- [Architecture](architecture/README.md): source selection, configuration ownership, and deployment dependencies.
- [Development](development/README.md): local editing and validation.
- [Operations](operations/README.md): required inputs, adoption, and recovery ownership.

Base owns charts and platform releases. Add-ons own optional product packages. Tooling owns setup automation, including `stack-setup`. The [shared guides](https://github.com/neurwerk/docs/blob/main/dev/architecture/README.md) describe platform-wide behavior and procedures; access to that repository may be required.
