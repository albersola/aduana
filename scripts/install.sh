#!/usr/bin/env bash
set -euo pipefail

# Installs the Aduana proxy with systemd and generates its own CA.
# Usage:
#   sudo ./scripts/install.sh [path/to/binary]
#   sudo ./scripts/install.sh --skip-binary
#
# Optional variables:
#   CA_CN="Aduana Internal Root CA"   Common name (CN) of the CA
#   CA_DAYS=3650                      CA validity in days (default: 10 years)

BIN_NAME="aduana"
INSTALL_BIN="/usr/local/bin/${BIN_NAME}"
SERVICE_USER="aduana"
SERVICE_GROUP="aduana"

ETC_DIR="/etc/${BIN_NAME}"
CA_PRIVATE_DIR="${ETC_DIR}/ca"
CA_KEY="${CA_PRIVATE_DIR}/ca.key"
CA_CERT="${ETC_DIR}/ca.crt"
SECRETS_FILE="${ETC_DIR}/secrets.env"
RULES_FILE="${ETC_DIR}/rules.conf"

STATE_DIR="/var/lib/${BIN_NAME}"
CERTS_DIR="${STATE_DIR}/certs"
LOG_DIR="/var/log/${BIN_NAME}"
UNIT_FILE="/etc/systemd/system/${BIN_NAME}.service"
RENEW_SERVICE_FILE="/etc/systemd/system/${BIN_NAME}-renew.service"
RENEW_TIMER_FILE="/etc/systemd/system/${BIN_NAME}-renew.timer"

CA_CN="${CA_CN:-Aduana Internal Root CA}"
CA_DAYS="${CA_DAYS:-3650}"

SKIP_BINARY=false
BINARY_SRC=""

usage() {
  cat <<EOF
Usage:
  sudo $0 [path/to/binary]
  sudo $0 --skip-binary

Options:
  --skip-binary   Create the user, directories, CA and systemd unit without installing or starting the binary.
  -h, --help      Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-binary)
      SKIP_BINARY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "$BINARY_SRC" ]]; then
        echo "Error: expected a single binary path" >&2
        exit 1
      fi
      BINARY_SRC="$1"
      shift
      ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "Error: run this script as root (sudo)." >&2
  exit 1
fi

for cmd in openssl systemctl install; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: missing required tool '$cmd'." >&2
    exit 1
  fi
done

if [[ "$SKIP_BINARY" == false ]]; then
  if [[ -z "$BINARY_SRC" ]]; then
    for candidate in \
      "./target/x86_64-unknown-linux-musl/release/${BIN_NAME}" \
      "./target/release/${BIN_NAME}" \
      "./target/debug/${BIN_NAME}"; do
      if [[ -f "$candidate" ]]; then
        BINARY_SRC="$candidate"
        break
      fi
    done
  fi

  if [[ -z "$BINARY_SRC" || ! -f "$BINARY_SRC" ]]; then
    echo "Error: binary '${BIN_NAME}' not found." >&2
    echo "Build with cargo first, pass the path as an argument, or use --skip-binary." >&2
    exit 1
  fi
fi

echo "==> 1. Creating system user and group '${SERVICE_USER}'..."
if ! getent group "${SERVICE_GROUP}" >/dev/null; then
  groupadd --system "${SERVICE_GROUP}"
fi
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "${SERVICE_GROUP}" \
    --home-dir "${STATE_DIR}" \
    --no-create-home \
    --shell /usr/sbin/nologin \
    "${SERVICE_USER}"
fi

echo "==> 2. Creating directories with separate permissions..."
# General configuration: root writes, aduana reads
install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${ETC_DIR}"
# CA private key: root ONLY (aduana must never read ca.key)
install -d -o root -g root -m 0700 "${CA_PRIVATE_DIR}"
# Per-host issued certificates: root generates them in apply, SGID keeps the aduana group for reading
install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${STATE_DIR}"
install -d -o root -g "${SERVICE_GROUP}" -m 2750 "${CERTS_DIR}"
# Logs: aduana writes
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${LOG_DIR}"

if [[ ! -f "${RULES_FILE}" ]]; then
  cat >"${RULES_FILE}" <<'EOF'
# Aduana rules
# Add clients and rules here, validate with `aduana check` and apply with `aduana apply`.
EOF
  chown root:"${SERVICE_GROUP}" "${RULES_FILE}"
  chmod 0640 "${RULES_FILE}"
  echo "    Created initial file ${RULES_FILE}"
fi

if [[ ! -f "${SECRETS_FILE}" ]]; then
  cat >"${SECRETS_FILE}" <<'EOF'
# Aduana secrets in .env format (KEY=value)
# Example:
# github_pat=ghp_xxxxxxxxxxxxxxxxxxxx
EOF
  chown root:"${SERVICE_GROUP}" "${SECRETS_FILE}"
  chmod 0640 "${SECRETS_FILE}"
  echo "    Created initial file ${SECRETS_FILE} (permissions 0640 root:${SERVICE_GROUP})"
fi

echo "==> 3. Generating own CA with OpenSSL (if it does not exist)..."
if [[ -f "${CA_KEY}" && -f "${CA_CERT}" ]]; then
  echo "    The CA already exists at ${CA_CERT} and ${CA_KEY}; not overwriting it."
elif [[ -f "${CA_KEY}" || -f "${CA_CERT}" ]]; then
  echo "Error: inconsistent state: only one of ${CA_KEY} or ${CA_CERT} exists." >&2
  exit 1
else
  umask 077
  openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "${CA_KEY}"

  openssl req \
    -x509 \
    -new \
    -key "${CA_KEY}" \
    -sha256 \
    -days "${CA_DAYS}" \
    -subj "/CN=${CA_CN}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "${CA_CERT}"

  chown root:root "${CA_KEY}" "${CA_CERT}"
  chmod 0600 "${CA_KEY}"
  chmod 0644 "${CA_CERT}"
  echo "    CA generated:"
  echo "      Private key (root only):   ${CA_KEY}"
  echo "      Public certificate:        ${CA_CERT}"
fi

if [[ "$SKIP_BINARY" == false ]]; then
  echo "==> 4. Installing binary at ${INSTALL_BIN}..."
  install -o root -g root -m 0755 "${BINARY_SRC}" "${INSTALL_BIN}"
else
  echo "==> 4. Skipping binary installation (--skip-binary)."
fi

echo "==> 5. Installing systemd unit and renewal timer..."
cat >"${UNIT_FILE}" <<EOF
[Unit]
Description=Aduana outbound HTTP/HTTPS proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${INSTALL_BIN} serve --config ${RULES_FILE} --certs-dir ${CERTS_DIR} --secrets-file ${SECRETS_FILE} --log-dir ${LOG_DIR}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536

# Hardening: the service never accesses ${CA_PRIVATE_DIR}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${LOG_DIR}
ReadOnlyPaths=${ETC_DIR} ${CERTS_DIR}
InaccessiblePaths=${CA_PRIVATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "${UNIT_FILE}"

cat >"${RENEW_SERVICE_FILE}" <<EOF
[Unit]
Description=Automatic renewal of Aduana certificates
After=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_BIN} apply --config ${RULES_FILE} --ca-key ${CA_KEY} --ca-cert ${CA_CERT} --certs-dir ${CERTS_DIR}
EOF
chmod 0644 "${RENEW_SERVICE_FILE}"

cat >"${RENEW_TIMER_FILE}" <<EOF
[Unit]
Description=Daily check for Aduana certificate renewal

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "${RENEW_TIMER_FILE}"

systemctl daemon-reload

if [[ "$SKIP_BINARY" == false ]]; then
  echo "==> 6. Enabling and starting ${BIN_NAME}.service and ${BIN_NAME}-renew.timer..."
  systemctl enable --now "${BIN_NAME}.service"
  systemctl enable --now "${BIN_NAME}-renew.timer"
  systemctl --no-pager --full status "${BIN_NAME}.service" || true
else
  echo "==> 6. Units created but not started (--skip-binary)."
  echo "    Once you have built the binary, run: sudo $0 path/to/binary"
fi

cat <<EOF

========================================================================
Installation on the proxy server completed.

Manual installation on each CLIENT server (Debian/Ubuntu):
  1. Copy ${CA_CERT} to the client:
       scp ${CA_CERT} user@client:/tmp/aduana-ca.crt
  2. Install it in the client's trust store:
       sudo cp /tmp/aduana-ca.crt /usr/local/share/ca-certificates/aduana-ca.crt
       sudo update-ca-certificates
  3. Configure the proxy on the client (e.g. /etc/environment or a systemd drop-in):
       HTTP_PROXY="http://<PROXY_IP>:3128"
       HTTPS_PROXY="http://<PROXY_IP>:3128"
       NO_PROXY="localhost,127.0.0.1,<internal_domains>"
  4. Note for runtimes that do not read the OS trust store by default:
       - Node.js: NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/aduana-ca.crt
       - Python (requests): REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
========================================================================
EOF
