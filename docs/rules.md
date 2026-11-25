# Rules Reference

> Syntax and semantics of `/etc/aduana/rules.conf` and `/etc/aduana/secrets.env`. See [rules.example.conf](../rules.example.conf) for a complete example.

## Core model

- **Pure allowlist (default-deny)**: anything that does not match an `allow` directive is blocked. There is no `deny` directive.
- **First match wins**: rules are evaluated from top to bottom; the first rule matching `(client, target, method, path)` authorizes the request and applies only its own transforms (rules are never merged).
- **Comments**: `#` starts a comment until the end of the line.
- **Identifiers** (client names, rule names and secret names): start with an ASCII letter or digit, followed by ASCII letters, digits, `-` or `_`.

## Clients

Every allowed source must be declared with `client`:

```conf
client dev-vm 10.0.10.21
client workers 10.0.20.0/24
```

- Accepts an exact IPv4/IPv6 address or a canonical CIDR block (no host bits set).
- Client names must be unique and address ranges must not overlap.
- Undeclared IPs are always denied, even for rules with `from *`.

## Rules

```conf
rule github-git {
  from  dev-vm
  to    github.com
  allow GET  /*/*/info/refs
  allow POST /*/*/git-upload-pack
  allow POST /*/*/git-receive-pack
  remove header cookie
  set header authorization "Basic ${base64(x-access-token:${secret.github_pat})}"
}
```

A rule must contain at least one `from`, one `to` and one `allow`.

### `from`

Matches declared clients:

- Specific clients (comma- or space-separated): `from web-01, workers`
- Any declared client: `from *` (cannot be mixed with specific names)

### `to`

Matches destination `(scheme, host, port)` (comma- or space-separated, or repeated `to` lines):

| Form | Matches |
| --- | --- |
| `api.github.com` | `https://api.github.com:443` (default scheme is `https`) |
| `api.example.com:8443` | `https://api.example.com:8443` |
| `http://hooks.example.org` | `http://hooks.example.org:80` |
| `http://hooks.example.org:8080` | `http://hooks.example.org:8080` |
| `*.s3.amazonaws.com` | Single-level subdomain wildcard over HTTPS (`bucket.s3.amazonaws.com`, not `a.b.s3.amazonaws.com` or `s3.amazonaws.com`) |

- `to *`, bare IP addresses and single-label wildcards (`*.com`) are rejected.

### `allow`

```conf
allow <methods> <path>
```

- **Methods**: comma-separated list of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, or `*` for all of them.
- **Path patterns**:
  - Must start with `/` and must not include a query string (`?`) or fragment (`#`). Incoming query strings are ignored when matching paths.
  - `*` matches a single non-empty path segment (`/repos/*/*`).
  - `**` matches zero or more segments and may only appear as the last segment (`/v1/customers/**` matches `/v1/customers`, `/v1/customers/` and `/v1/customers/123/cards`).
  - Trailing slashes are matched literally unless `**` is used.
  - Incoming paths with `.`, `..`, `//`, `\`, control bytes or percent-encoded `.`/`/`/`\` are always rejected.

## Header transforms

Applied in declaration order after authorization:

| Directive | Behavior |
| --- | --- |
| `set header <name> "<value>"` | Sets the header unconditionally (adds if absent, overwrites and collapses duplicates if present). |
| `replace header <name> "<value>"` | Replaces the header only if it is already present in the incoming request. |
| `remove header <name>` | Removes all occurrences of the header. |

Protected control headers cannot be modified or removed: `host`, `content-length`, `transfer-encoding`, `connection`, `keep-alive`, `proxy-connection`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `upgrade`.

### Value templates and secrets

Double-quoted header values support `\"` and `\\` escapes and three template expressions:

| Expression | Result |
| --- | --- |
| `${client.name}` | Name of the matched client (`dev-vm`). |
| `${secret.<name>}` | Secret value loaded from `secrets.env`. |
| `${base64(<inner>)}` | Standard Base64 (RFC 4648) of `<inner>`, which may combine literals, `${client.name}` and `${secret.<name>}` (e.g. `"Basic ${base64(x-access-token:${secret.github_pat})}"`). Nested `base64(...)` is not allowed. |

**Secret rules**:
- `secrets.env` uses `KEY=value` lines (optional `export ` prefix, single/double quotes and `#` comments).
- Any rule referencing a secret (directly or inside `${base64(...)}`) must only target `https://` and exact hosts (no wildcards).
- Every referenced secret must exist in `secrets.env`; missing secrets fail `aduana check`, startup and `SIGHUP` reload (fail-closed).
- Sensitive headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, etc.), raw secret values and Base64-derived secret values are always redacted as `[REDACTED]` in logs and kept as placeholders in `aduana test`.

## Body logging

Add `log body` inside a rule to record request/response headers and up to 64 KiB of text bodies in the JSONL logs (binary and compressed bodies are summarized with their size, never dumped raw).

## Validating and applying changes

```bash
aduana check -c /etc/aduana/rules.conf --secrets-file /etc/aduana/secrets.env
aduana test  -c /etc/aduana/rules.conf --from dev-vm GET https://github.com/acme/demo.git/info/refs
sudo aduana apply
```
