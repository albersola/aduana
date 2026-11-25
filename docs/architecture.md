# Architecture

> Long-term document. It describes the stable principles and boundaries of the project. Concrete implementation details live in the code.

## Purpose

**Aduana** is an outbound HTTP/HTTPS proxy designed for self-hosted servers. Its job is to concentrate all outbound web traffic in order to:

1. **Allow only authorized traffic** through an explicit allowlist.
2. **Inspect HTTPS** by terminating TLS with an own CA that the client servers trust.
3. **Transform requests in flight** (add or replace headers or values according to rules).
4. **Log accessed domains and content** for auditing and debugging.

## Design principles

- **Small, simple and self-contained**: code that is easy to audit and maintain takes priority over covering every use case of a generic proxy.
- **A single static Rust binary (`musl`), no Docker**: run directly by `systemd` on the operating system.
- **Few dependencies**: rely on standard system tools when that simplifies the binary and reduces the attack surface.
- **Explicit proxy (`HTTP_PROXY` / `HTTPS_PROXY` + `CONNECT`)**: clients send the destination to the proxy without resolving external DNS; the proxy validates, resolves and connects.
- **Rules with an own grammar**: start with a simple, extensible set rather than importing complex languages from the beginning.
- **Incremental protocol support**: HTTP/1.1 on both sides in v1, with HTTP/2 planned for a later phase.

## Responsibility boundaries

The system clearly splits responsibilities between the proxy and the existing infrastructure:

| Component | Responsibility |
| --- | --- |
| **Proxmox (firewall)** | Closes all direct internet egress for the client servers and only allows outbound traffic towards the proxy. |
| **Internal DNS** | Prevents DNS exfiltration from the client servers (keeping internal rewrites) and allows external resolution only from the proxy. |
| **Aduana (proxy)** | Receives the explicit HTTP/HTTPS traffic from the servers, evaluates rules, resolves external DNS, decrypts HTTPS with its own CA, applies transformations and logs the activity. |
| **Client servers** | Trust the own CA and send their outbound traffic through `HTTP_PROXY`/`HTTPS_PROXY` to Aduana. |

## Threat model

Aduana assumes that **a client server may be compromised up to `root`**, while Proxmox, the internal DNS and the Aduana host remain trusted. The details of the trust boundary, evasion vectors and per-layer defenses live in [docs/security.md](security.md).
