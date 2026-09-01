# client_example_com

Reference client values and Flux composition for an example production cluster.
The client repository supplies non-secret values and cluster composition; the
[`k8s_stack_base`](https://github.com/neurwerk/k8s_stack_base) repository
supplies signed platform releases and charts.

## Platform Channels

The committed example selects the stable channel with one exact signed release
tag. A reviewed source change may instead opt into the alpha channel using Base
`main` or one full commit SHA. Both alpha selectors use Flux `HEAD` verification
with the separate alpha trust root. Channel selection is independent of the
cluster environment.

Returning from alpha to stable requires first freezing a moving `main` source to
the exact observed commit and reconciling that commit source. Promotion binds to
the frozen SHA. A forward upgrade is accepted only when its release manifest
and migration document declare the same alpha revision set and include that
SHA. Fresh installation instead requires explicit fresh-install support.

## Validate The Repository

From this repository:

```bash
make check
```

## Proxmox CPU Prerequisite

Before installing or bootstrapping K3s for a deployment based on this example,
configure the VM CPU type as `x86-64-v3` (recommended) or `host`. The upstream
DocumentDB gateway for amd64 is compiled for the complete `x86-64-v3` baseline
and exits with `Illegal instruction` when Proxmox exposes only `kvm64`,
`x86-64-v2`, or `x86-64-v2-AES`. A physical CPU that supports AVX2 does not help
when the virtual CPU model masks those flags.

Apply a CPU type change with a complete VM shutdown and start, not an in-guest
restart. Every possible live-migration target must support the selected model.
`x86-64-v4` and `host` are compatible, but neither is required by the platform
and both reduce migration compatibility compared with `x86-64-v3`. See the
[Proxmox CPU type documentation](https://pve.proxmox.com/pve-docs/chapter-qm.html#qm_cpu).

After starting the VM, inspect the CPU flags:

```bash
grep -m1 '^flags' /proc/cpuinfo
```

Continue only when the flags include `avx`, `avx2`, `bmi1`, `bmi2`, `f16c`,
`fma`, `abm`, `movbe`, and `xsave`.
