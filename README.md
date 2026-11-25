# Aduana

A lightweight outbound HTTP/HTTPS proxy for self-hosted servers.

Aduana centralizes the outbound web traffic of your servers in a single Rust binary so that only what is allowed gets out. It lets you inspect and log HTTPS requests using your own CA, and transform headers or inject credentials without exposing them to the clients.

## What it does

- **Explicit allowlist**: blocks all unauthorized outbound traffic by default.
- **HTTPS inspection**: terminates TLS with an internal CA that your servers trust.
- **In-flight transformations**: adds or replaces headers (such as API secrets) before the request leaves for the outside world.
- **Logging and auditing**: records allowed requests and blocked attempts.
- **Minimal deployment**: a single static binary (`musl`) run by `systemd`, no Docker.

## Main commands

```bash
aduana check  -c /etc/aduana/rules.conf                         # validate rules (and --secrets-file)
aduana test   -c /etc/aduana/rules.conf --from web-01 POST https://api.stripe.com/v1/charges
sudo aduana apply                                               # issue/renew certificates and reload (SIGHUP)
aduana serve  -c /etc/aduana/rules.conf -l 0.0.0.0:3128         # start the proxy
aduana log    --client web-01 --limit 20                        # query logged traffic
aduana denied --limit 20                                        # query blocked attempts
```

## Installing on the proxy server

```bash
sudo ./scripts/install.sh --skip-binary   # prepare user, directories, CA and systemd
sudo ./scripts/install.sh                 # install the compiled binary and start the service
```

When it finishes, the script prints the manual steps to install `/etc/aduana/ca.crt` and to configure `HTTP_PROXY` / `HTTPS_PROXY` on each client server.

## Documentation

- [Rules reference](docs/rules.md) — syntax for `rules.conf`, templates (`${secret.*}`, `${base64(...)}`) and `secrets.env` (see also [rules.example.conf](rules.example.conf))
- [Architecture](docs/architecture.md)
- [Security and threat model](docs/security.md)

## License

[MIT](LICENSE)
