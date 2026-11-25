# Aduana — Repository Guide

Outbound HTTP/HTTPS proxy for self-hosted servers: inspects, limits, logs and transforms outgoing traffic.

## Documentation convention

- **`README.md`** is for humans only: short, clear and aimed at whoever uses or deploys Aduana. Do not put internal agent guides or volatile details in it.
- **`docs/`** contains long-term architecture and security documentation that rarely changes.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (semantic commits): `type(scope): short description`, with types such as `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build` and `ci`. Write messages in English, in the imperative mood.

## Documentation index

| Document | Description | When to read it |
| --- | --- | --- |
| [docs/architecture.md](docs/architecture.md) | System overview, design principles and boundaries between the proxy and the infrastructure (Proxmox, DNS, CA). | Before designing components, changing system boundaries or adding new capabilities. |
| [docs/security.md](docs/security.md) | Threat model (client compromised up to `root`), trust boundary and table of evasion vectors and defenses. | Before designing network/protocol validations, secret management, certificates or evasion tests. |
