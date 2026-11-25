# Security and threat model

> Long-term document. It defines what Aduana assumes about attackers, where the trust boundary lies and which layer stops each kind of evasion.

## Trust boundary

- **Trusted zone**: the Proxmox hypervisor (and its firewall), the host where Aduana runs, the internal DNS server and the CA private key (`ca.key`, readable only by `root`).
- **Untrusted zone**: the client servers (VMs/LXCs). An attacker is assumed to be able to exploit an application or dependency on a client server and **escalate to `root` inside that server**.
- **Out of scope**: compromise of the Proxmox hypervisor itself, of the Aduana host, of the DNS server, or covert exfiltration through a domain and path explicitly authorized in the allowlist (although request and body logging mitigates its impact and makes detection easier).

## Contemplated attack vectors and defenses

| What an attacker with `root` on a client might try | Layer that stops it |
| --- | --- |
| Bypass `HTTP_PROXY` and open direct connections to the internet | **Proxmox firewall**: closes all direct egress; only allows traffic towards the proxy. |
| Exfiltrate data through DNS queries (`data.attacker.com`) | **Internal DNS**: blocks external resolution from the clients; only Aduana resolves external domains. |
| Change its own IP to impersonate another server with more permissions | **Proxmox (`ipfilter`)**: prevents source-IP spoofing at the virtual interface level. |
| Read external API keys from disk or environment variables | **Aduana (secret injection)**: the real credentials live only in Aduana; the client uses a dummy value or none, and Aduana injects them only towards the exact host and the paths allowed over HTTPS. |
| Fool the proxy with destination mismatches (`CONNECT api.stripe.com:443` + a different SNI or `Host` header) | **Aduana (strict validation)**: checks that `CONNECT`, SNI and the `Host` header match. |
| Evade path rules with ambiguous normalizations (`/v1/charges/../../admin`, `/v1/%2e%2e/admin`) | **Aduana (path validation)**: rejects ambiguous paths or paths with encoded traversal. |
| Use the proxy to reach internal services or metadata endpoints (SSRF / DNS rebinding) | **Aduana (validation on connect)**: blocks connections to private and metadata ranges after resolving DNS. |
| Tamper with control headers (`host`, `content-length`, `transfer-encoding`, `connection`) or smuggle requests | **Aduana**: prevents modifying protected headers and rejects ambiguous requests. |

## Defense in depth on the Aduana host

- The network-facing process (`aduana serve`) runs under an unprivileged user (`aduana`) and is hardened with `systemd`.
- **`ca.key` is never accessible** to the network-exposed process: only `root` signs certificates (when applying rules) and the service only reads the already-issued host certificates.
- On failure or invalid configuration the behavior is **fail-closed**: rules are never relaxed and egress without the proxy is never allowed.
