#!/usr/bin/env bash
set -euo pipefail

# Installs or updates the Aduana proxy with systemd, generating its own CA the first time.
# Existing rules, secrets and CA are never overwritten. See usage() below.

REPO_URL="https://github.com/albersola/aduana"
ASSET_NAME="aduana-linux-amd64"

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
ENV_FILE="${ETC_DIR}/aduana.env"

STATE_DIR="/var/lib/${BIN_NAME}"
CERTS_DIR="${STATE_DIR}/certs"
LOG_DIR="/var/log/${BIN_NAME}"
UNIT_DIR="/etc/systemd/system"
UNIT_FILE="${UNIT_DIR}/${BIN_NAME}.service"
RENEW_SERVICE_FILE="${UNIT_DIR}/${BIN_NAME}-renew.service"
RENEW_TIMER_FILE="${UNIT_DIR}/${BIN_NAME}-renew.timer"

CA_CN="${CA_CN:-Aduana Internal Root CA}"
CA_DAYS="${CA_DAYS:-3650}"

# The new binary is staged next to the final one: same filesystem (atomic mv) and never `noexec`.
STAGED_BIN="${INSTALL_BIN}.new"
# Files that an update may change and a rollback restores.
MANAGED_FILES=("${INSTALL_BIN}" "${ENV_FILE}" "${UNIT_FILE}" "${RENEW_SERVICE_FILE}" "${RENEW_TIMER_FILE}")

WORK_DIR=""
SWAPPING=false
WAS_INSTALLED=false
WAS_ACTIVE=false

usage() {
  cat <<EOF
Installs Aduana or updates it to another version.

Usage:
  install.sh [options]                  Download the latest release
  install.sh [options] path/to/binary   Install a locally built binary

Options:
  --listen <ip:port>   Address to listen on. Required the first time, kept on updates.
  --version <x.y.z>    Install this release instead of the latest one.
  --skip-binary        Create the user, directories, CA and systemd units without installing or starting the binary.
  -h, --help           Show this help.

Optional variables:
  CA_CN="Aduana Internal Root CA"   Common name (CN) of the CA
  CA_DAYS=3650                      CA validity in days (default: 10 years)
EOF
}

die() {
  echo "Error: $*" >&2
  exit 1
}

# Version line of a binary ("aduana 1.2.3"), or "none" if it is not there or does not run.
version_of() {
  "$1" --version 2>/dev/null || echo "none"
}

require_system() {
  local cmd
  [[ "$EUID" -eq 0 ]] || die "run this script as root (sudo)."
  [[ -d /run/systemd/system ]] || die "this server is not running systemd."
  for cmd in openssl systemctl install sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required tool '$cmd'."
  done
}

download_release() {
  local version="$1" base
  command -v curl >/dev/null 2>&1 || die "missing required tool 'curl'."
  [[ "$(uname -m)" == "x86_64" ]] || die "releases are only built for x86_64 (amd64), this server is $(uname -m)."

  if [[ -n "$version" ]]; then
    base="${REPO_URL}/releases/download/${version}"
  else
    base="${REPO_URL}/releases/latest/download"
  fi

  echo "==> Downloading Aduana (${version:-latest release})..."
  curl -fsSL --retry 3 --proto '=https' -o "${WORK_DIR}/${ASSET_NAME}" "${base}/${ASSET_NAME}" \
    || die "could not download ${base}/${ASSET_NAME}. Does that release exist?"
  curl -fsSL --retry 3 --proto '=https' -o "${WORK_DIR}/SHA256SUMS" "${base}/SHA256SUMS" \
    || die "could not download ${base}/SHA256SUMS."

  grep "  ${ASSET_NAME}\$" "${WORK_DIR}/SHA256SUMS" >"${WORK_DIR}/checksum" \
    || die "SHA256SUMS does not contain ${ASSET_NAME}."
  (cd "${WORK_DIR}" && sha256sum --quiet --check checksum) \
    || die "the checksum does not match, nothing was changed."
  echo "    Checksum OK"
}

prepare_system() {
  echo "==> Creating system user and group '${SERVICE_USER}'..."
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

  echo "==> Creating directories with separate permissions..."
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

  echo "==> Generating own CA with OpenSSL (if it does not exist)..."
  if [[ -f "${CA_KEY}" && -f "${CA_CERT}" ]]; then
    echo "    The CA already exists at ${CA_CERT} and ${CA_KEY}; not overwriting it."
  elif [[ -f "${CA_KEY}" || -f "${CA_CERT}" ]]; then
    echo "Error: inconsistent state: only one of ${CA_KEY} or ${CA_CERT} exists." >&2
    exit 1
  else
    local previous_umask
    previous_umask="$(umask)"
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

    umask "${previous_umask}"
    chown root:root "${CA_KEY}" "${CA_CERT}"
    chmod 0600 "${CA_KEY}"
    chmod 0644 "${CA_CERT}"
    echo "    CA generated:"
    echo "      Private key (root only):   ${CA_KEY}"
    echo "      Public certificate:        ${CA_CERT}"
  fi
}

write_config() {
  local listen="$1"
  cat >"${ENV_FILE}" <<EOF
# Managed by install.sh: change it with "install.sh --listen <ip:port>"
ADUANA_LISTEN=${listen}
EOF
  chown root:"${SERVICE_GROUP}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"

  cat >"${UNIT_FILE}" <<EOF
[Unit]
Description=Aduana outbound HTTP/HTTPS proxy
After=network-online.target
Wants=network-online.target
# Keep retrying at boot: the listen address may appear late (VPN, bridge...)
StartLimitIntervalSec=0

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_BIN} serve --config ${RULES_FILE} --certs-dir ${CERTS_DIR} --secrets-file ${SECRETS_FILE} --log-dir ${LOG_DIR} --listen \${ADUANA_LISTEN}
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
}

backup_file() {
  if [[ -e "$1" ]]; then
    cp -p "$1" "${WORK_DIR}/backup/"
  fi
}

changed_since_backup() {
  ! cmp -s "$1" "${WORK_DIR}/backup/$(basename "$1")"
}

# Healthy: the same process keeps running and its port accepts connections.
service_healthy() {
  local listen="$1" host port pid
  host="${listen%:*}"
  port="${listen##*:}"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    0.0.0.0) host="127.0.0.1" ;;
    ::) host="::1" ;;
  esac

  sleep 1
  pid="$(systemctl show -p MainPID --value "${BIN_NAME}.service")"
  sleep 3
  # shellcheck disable=SC2016
  [[ "$pid" != "0" ]] \
    && systemctl is-active --quiet "${BIN_NAME}.service" \
    && [[ "$(systemctl show -p MainPID --value "${BIN_NAME}.service")" == "$pid" ]] \
    && timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null
}

rollback() {
  local file backup
  if [[ "$WAS_INSTALLED" == false ]]; then
    systemctl stop "${BIN_NAME}.service" 2>/dev/null || true
    echo "The service has been stopped. Fix the problem and run the installer again." >&2
    return
  fi

  echo "Restoring the previous version..." >&2
  for file in "${MANAGED_FILES[@]}"; do
    backup="${WORK_DIR}/backup/$(basename "$file")"
    if [[ -e "$backup" ]]; then
      # Through a temporary name: a running binary cannot be overwritten in place.
      cp -p "$backup" "${file}.restore" && mv -f "${file}.restore" "$file"
    else
      rm -f "$file"
    fi
  done
  systemctl daemon-reload || true
  systemctl reset-failed "${BIN_NAME}.service" 2>/dev/null || true
  if [[ "$WAS_ACTIVE" == false ]]; then
    systemctl stop "${BIN_NAME}.service" 2>/dev/null || true
    echo "Restored $(version_of "${INSTALL_BIN}"); the service was not running before and has been left stopped." >&2
  elif systemctl restart "${BIN_NAME}.service" && sleep 3 && systemctl is-active --quiet "${BIN_NAME}.service"; then
    echo "Restored and running: $(version_of "${INSTALL_BIN}")" >&2
  else
    echo "The previous version did not start either, check: journalctl -u ${BIN_NAME}" >&2
  fi
}

on_exit() {
  local status=$?
  trap - EXIT
  set +e
  if [[ "$SWAPPING" == true ]]; then
    rollback
  fi
  rm -f "${STAGED_BIN}"
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf "${WORK_DIR}"
  fi
  exit "$status"
}

print_next_steps() {
  local listen="$1"
  cat <<EOF

========================================================================
Next steps on this server:
  1. Edit ${RULES_FILE} and ${SECRETS_FILE}
  2. sudo aduana check --secrets-file ${SECRETS_FILE} && sudo aduana apply

Manual installation on each CLIENT server (Debian/Ubuntu):
  1. Copy ${CA_CERT} to the client:
       scp ${CA_CERT} user@client:/tmp/aduana-ca.crt
  2. Install it in the client's trust store:
       sudo cp /tmp/aduana-ca.crt /usr/local/share/ca-certificates/aduana-ca.crt
       sudo update-ca-certificates
  3. Configure the proxy on the client (e.g. /etc/environment or a systemd drop-in):
       HTTP_PROXY="http://${listen}"
       HTTPS_PROXY="http://${listen}"
       NO_PROXY="localhost,127.0.0.1,<internal_domains>"
  4. Note for runtimes that do not read the OS trust store by default:
       - Node.js: NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/aduana-ca.crt
       - Python (requests): REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
========================================================================
EOF
}

main() {
  local listen="" version="" binary_src="" skip_binary=false old_version new_version changed=false first_start=false file

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --listen)
        [[ $# -ge 2 ]] || die "--listen needs a value."
        listen="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || die "--version needs a value."
        version="$2"
        shift 2
        ;;
      --skip-binary)
        skip_binary=true
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      -*)
        usage >&2
        die "unknown option '$1'"
        ;;
      *)
        [[ -z "$binary_src" ]] || die "expected a single binary path"
        binary_src="$1"
        shift
        ;;
    esac
  done

  [[ -z "$version" || "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version '$version', expected x.y.z"
  [[ -z "$version" || -z "$binary_src" ]] || die "--version cannot be used with a local binary"
  [[ -z "$binary_src" || -f "$binary_src" ]] || die "binary '$binary_src' not found."
  require_system

  if [[ -z "$listen" && -f "${ENV_FILE}" ]]; then
    listen="$(sed -n 's/^ADUANA_LISTEN=//p' "${ENV_FILE}" | tail -n 1)"
  fi
  [[ -n "$listen" ]] || die "indicate the internal address to listen on, e.g. --listen 10.0.10.5:3128"
  [[ "$listen" =~ ^([0-9.]+|\[[0-9a-fA-F:.]+\]):[0-9]{1,5}$ ]] || die "invalid address '$listen', expected ip:port"

  trap on_exit EXIT
  WORK_DIR="$(mktemp -d)"
  mkdir "${WORK_DIR}/backup"

  if [[ "$skip_binary" == true ]]; then
    prepare_system
    write_config "$listen"
    echo "==> System prepared, without installing or starting the binary (--skip-binary)."
    return
  fi

  if [[ -z "$binary_src" ]]; then
    download_release "$version"
    binary_src="${WORK_DIR}/${ASSET_NAME}"
  fi
  install -o root -g root -m 0755 "$binary_src" "${STAGED_BIN}"
  new_version="$(version_of "${STAGED_BIN}")"
  [[ "$new_version" != "none" ]] || die "the new binary does not run on this server, nothing was changed."

  if [[ -e "${INSTALL_BIN}" ]]; then
    WAS_INSTALLED=true
  fi
  if systemctl is-active --quiet "${BIN_NAME}.service"; then
    WAS_ACTIVE=true
  fi
  if ! systemctl is-enabled --quiet "${BIN_NAME}.service" 2>/dev/null; then
    first_start=true
  fi
  old_version="$(version_of "${INSTALL_BIN}")"
  echo "==> Installed: ${old_version}, new: ${new_version}"

  prepare_system

  echo "==> Validating the current rules with the new version..."
  "${STAGED_BIN}" check --config "${RULES_FILE}" --secrets-file "${SECRETS_FILE}" \
    || die "the new version does not accept the current rules, so it was not installed."

  for file in "${MANAGED_FILES[@]}"; do
    backup_file "$file"
  done

  SWAPPING=true
  write_config "$listen"
  mv -f "${STAGED_BIN}" "${INSTALL_BIN}"
  for file in "${MANAGED_FILES[@]}"; do
    if changed_since_backup "$file"; then
      changed=true
    fi
  done

  if [[ "$changed" == false && "$WAS_ACTIVE" == true ]]; then
    SWAPPING=false
    echo "==> Already up to date, the service was not restarted."
    return
  fi

  echo "==> Starting ${BIN_NAME}.service..."
  systemctl reset-failed "${BIN_NAME}.service" 2>/dev/null || true
  systemctl restart "${BIN_NAME}.service"
  if ! service_healthy "$listen"; then
    journalctl -u "${BIN_NAME}.service" -n 10 --no-pager >&2 || true
    die "the service did not start correctly on ${listen}."
  fi
  SWAPPING=false
  systemctl enable --quiet "${BIN_NAME}.service" "${BIN_NAME}-renew.timer"
  systemctl restart "${BIN_NAME}-renew.timer"

  echo "==> ${new_version} running on ${listen}"
  if [[ "$first_start" == true ]]; then
    print_next_steps "$listen"
  fi
}

# Last line on purpose: a truncated download runs nothing.
main "$@"
