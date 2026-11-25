//! Host certificate management with OpenSSL (`aduana apply`) and in-memory TLS store (`aduana serve`).
//!
//! `aduana serve` only reads the certificates already issued in `certs_dir` and **never** accesses `ca.key`.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::rules::{HostPattern, Policy};

/// Default validity of the host certificates issued by `aduana apply`.
pub const DEFAULT_HOST_CERT_DAYS: u32 = 90;

/// Default renewal margin: renew if it expires in less than 30 days.
pub const DEFAULT_RENEW_BEFORE_DAYS: u32 = 30;

/// Returns the pure-Rust crypto provider (`rustls-rustcrypto`) for `rustls`.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

/// Result of synchronizing certificates for a policy in `aduana apply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyCertReport {
    pub issued: Vec<String>,
    pub valid: Vec<String>,
}

/// Generates an EC P-256 root CA with OpenSSL (useful for tests and automation).
pub fn generate_ca(
    ca_key: &Path,
    ca_cert: &Path,
    common_name: &str,
    days: u32,
) -> Result<(), String> {
    if let Some(parent) = ca_key.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }
    if let Some(parent) = ca_cert.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
    }

    run_openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        path_str(ca_key)?,
    ])?;
    let _ = fs::set_permissions(ca_key, fs::Permissions::from_mode(0o600));

    let subj = format!("/CN={common_name}");
    let days_s = days.to_string();
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        path_str(ca_key)?,
        "-sha256",
        "-days",
        &days_s,
        "-subj",
        &subj,
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-out",
        path_str(ca_cert)?,
    ])?;
    let _ = fs::set_permissions(ca_cert, fs::Permissions::from_mode(0o644));
    Ok(())
}

/// Synchronizes the certificates of all HTTPS hosts in the policy:
/// issues the ones that are missing or expire in less than `renew_before_days`.
pub fn ensure_policy_certs(
    policy: &Policy,
    ca_key: &Path,
    ca_cert: &Path,
    certs_dir: &Path,
    days: u32,
    renew_before_days: u32,
) -> Result<ApplyCertReport, String> {
    let hosts = policy.required_tls_hosts();
    if hosts.is_empty() {
        return Ok(ApplyCertReport::default());
    }

    fs::create_dir_all(certs_dir)
        .map_err(|e| format!("could not create '{}': {e}", certs_dir.display()))?;

    let mut report = ApplyCertReport::default();
    let check_secs = u64::from(renew_before_days) * 86_400;

    for pattern in hosts {
        let (cert_path, key_path) = host_cert_paths(certs_dir, pattern);
        let label = pattern.to_string();

        let needs_issue = if cert_path.exists() && key_path.exists() {
            !cert_valid_for(&cert_path, check_secs)?
        } else {
            true
        };

        if needs_issue {
            issue_host_cert(pattern, ca_key, ca_cert, certs_dir, days)?;
            report.issued.push(label);
        } else {
            report.valid.push(label);
        }
    }

    Ok(report)
}

/// Issues (or atomically renews) a host or 1-level wildcard certificate signed by the CA.
pub fn issue_host_cert(
    pattern: &HostPattern,
    ca_key: &Path,
    ca_cert: &Path,
    certs_dir: &Path,
    days: u32,
) -> Result<(PathBuf, PathBuf), String> {
    if !ca_key.exists() {
        return Err(format!(
            "CA private key does not exist at '{}' (run install.sh or `aduana apply` as root)",
            ca_key.display()
        ));
    }
    if !ca_cert.exists() {
        return Err(format!(
            "CA certificate does not exist at '{}'",
            ca_cert.display()
        ));
    }

    fs::create_dir_all(certs_dir)
        .map_err(|e| format!("could not create '{}': {e}", certs_dir.display()))?;

    let (cert_path, key_path) = host_cert_paths(certs_dir, pattern);
    let stem = cert_filename_stem(pattern);
    let pid = std::process::id();

    let tmp_key = certs_dir.join(format!(".{stem}.{pid}.key.tmp"));
    let tmp_csr = certs_dir.join(format!(".{stem}.{pid}.csr.tmp"));
    let tmp_ext = certs_dir.join(format!(".{stem}.{pid}.ext.tmp"));
    let tmp_crt = certs_dir.join(format!(".{stem}.{pid}.crt.tmp"));

    let cleanup = || {
        let _ = fs::remove_file(&tmp_key);
        let _ = fs::remove_file(&tmp_csr);
        let _ = fs::remove_file(&tmp_ext);
        let _ = fs::remove_file(&tmp_crt);
    };

    let result = (|| -> Result<(), String> {
        run_openssl(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            path_str(&tmp_key)?,
        ])?;
        let _ = fs::set_permissions(&tmp_key, fs::Permissions::from_mode(0o640));

        let dns_name = pattern.to_string();
        let subj = format!("/CN={dns_name}");
        run_openssl(&[
            "req",
            "-new",
            "-key",
            path_str(&tmp_key)?,
            "-subj",
            &subj,
            "-out",
            path_str(&tmp_csr)?,
        ])?;

        let ext_content = format!(
            "basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature\n\
             extendedKeyUsage=serverAuth\n\
             subjectAltName=DNS:{dns_name}\n"
        );
        fs::write(&tmp_ext, ext_content)
            .map_err(|e| format!("could not write OpenSSL extensions file: {e}"))?;

        let days_s = days.to_string();
        run_openssl(&[
            "x509",
            "-req",
            "-in",
            path_str(&tmp_csr)?,
            "-CA",
            path_str(ca_cert)?,
            "-CAkey",
            path_str(ca_key)?,
            "-CAcreateserial",
            "-out",
            path_str(&tmp_crt)?,
            "-days",
            &days_s,
            "-sha256",
            "-extfile",
            path_str(&tmp_ext)?,
        ])?;
        let _ = fs::set_permissions(&tmp_crt, fs::Permissions::from_mode(0o644));

        fs::rename(&tmp_key, &key_path)
            .map_err(|e| format!("could not install '{}': {e}", key_path.display()))?;
        fs::rename(&tmp_crt, &cert_path)
            .map_err(|e| format!("could not install '{}': {e}", cert_path.display()))?;
        Ok(())
    })();

    let _ = fs::remove_file(&tmp_csr);
    let _ = fs::remove_file(&tmp_ext);
    if result.is_err() {
        cleanup();
    }
    result?;

    Ok((cert_path, key_path))
}

/// Uses OpenSSL to check whether the certificate remains valid for at least `seconds`.
pub fn cert_valid_for(cert_path: &Path, seconds: u64) -> Result<bool, String> {
    let secs_s = seconds.to_string();
    let status = Command::new("openssl")
        .args(["x509", "-in", path_str(cert_path)?, "-noout", "-checkend", &secs_s])
        .output()
        .map_err(|e| format!("could not run 'openssl': {e}"))?;
    Ok(status.status.success())
}

/// Computes the `(cert.crt, cert.key)` paths corresponding to a host pattern.
pub fn host_cert_paths(certs_dir: &Path, pattern: &HostPattern) -> (PathBuf, PathBuf) {
    let stem = cert_filename_stem(pattern);
    (
        certs_dir.join(format!("{stem}.crt")),
        certs_dir.join(format!("{stem}.key")),
    )
}

/// Deterministic, safe file name for an exact or wildcard host pattern.
pub fn cert_filename_stem(pattern: &HostPattern) -> String {
    match pattern {
        HostPattern::Exact(host) => host.clone(),
        HostPattern::Wildcard { suffix } => format!("_wildcard_.{suffix}"),
    }
}

/// In-memory store of preloaded host certificates for `aduana serve`.
#[derive(Debug, Default)]
pub struct CertStore {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcards: HashMap<String, Arc<CertifiedKey>>,
}

/// Record of the SNI observed during the TLS handshake of a `CONNECT` connection.
pub type SeenSni = Arc<Mutex<Option<String>>>;

impl CertStore {
    /// Loads all certificates required by `policy` from `certs_dir`.
    /// If any required HTTPS certificate is missing, returns an error (fail-closed).
    pub fn load_for_policy(policy: &Policy, certs_dir: &Path) -> Result<Self, String> {
        let mut store = Self::default();
        let provider = crypto_provider();

        for pattern in policy.required_tls_hosts() {
            let (cert_path, key_path) = host_cert_paths(certs_dir, pattern);
            if !cert_path.exists() || !key_path.exists() {
                return Err(format!(
                    "missing certificate for '{}' at '{}' (run `aduana apply`)",
                    pattern,
                    certs_dir.display()
                ));
            }
            let certified = load_certified_key(&cert_path, &key_path, &provider)?;
            match pattern {
                HostPattern::Exact(host) => {
                    store.exact.insert(host.clone(), Arc::new(certified));
                }
                HostPattern::Wildcard { suffix } => {
                    store.wildcards.insert(suffix.clone(), Arc::new(certified));
                }
            }
        }

        Ok(store)
    }

    /// Resolves the certificate for a lowercase host: exact match first, then 1-level wildcard.
    pub fn resolve_host(&self, host_lower: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(exact) = self.exact.get(host_lower) {
            return Some(Arc::clone(exact));
        }
        let (label, suffix) = host_lower.split_once('.')?;
        if !label.is_empty() && !label.contains('.') {
            return self.wildcards.get(suffix).map(Arc::clone);
        }
        None
    }

    /// Builds a TLS `ServerConfig` strictly pinned to the `CONNECT`'s `expected_host`.
    ///
    /// If the client sends no SNI or sends an SNI different from `expected_host`, the TLS handshake
    /// is rejected immediately before reading any HTTP request.
    pub fn server_config_for_host(
        &self,
        expected_host_lower: &str,
    ) -> Result<(Arc<ServerConfig>, SeenSni), String> {
        let cert = self.resolve_host(expected_host_lower).ok_or_else(|| {
            format!(
                "no certificate loaded for '{expected_host_lower}' (run `aduana apply`)"
            )
        })?;
        let seen_sni = Arc::new(Mutex::new(None));
        let resolver = Arc::new(PinnedSniResolver {
            expected_host: expected_host_lower.to_string(),
            cert,
            seen_sni: Arc::clone(&seen_sni),
        });

        let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("error configuring TLS server: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok((Arc::new(cfg), seen_sni))
    }
}

#[derive(Debug)]
struct PinnedSniResolver {
    expected_host: String,
    cert: Arc<CertifiedKey>,
    seen_sni: Arc<Mutex<Option<String>>>,
}

impl ResolvesServerCert for PinnedSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?.to_ascii_lowercase();
        if let Ok(mut guard) = self.seen_sni.lock() {
            *guard = Some(sni.clone());
        }
        if sni != self.expected_host {
            return None;
        }
        Some(Arc::clone(&self.cert))
    }
}

/// Builds the client TLS configuration for connecting to HTTPS upstreams, verifying
/// against the system CAs (and optionally an additional CA for tests).
pub fn build_upstream_tls_config(extra_ca_pem: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    if let Some(ca_path) = extra_ca_pem {
        let certs = load_certs_pem(ca_path)?;
        for cert in certs {
            roots.add(cert).map_err(|e| {
                format!(
                    "could not add additional CA '{}': {e}",
                    ca_path.display()
                )
            })?;
        }
    }

    if roots.is_empty() {
        return Err(
            "no system root certificates found to validate HTTPS upstreams".into(),
        );
    }

    let mut cfg = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("error configuring TLS client: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Loads PEM certificates from a file.
pub fn load_certs_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path)
        .map_err(|e| format!("could not open certificate '{}': {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid PEM certificate '{}': {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("'{}' no contiene certificados PEM", path.display()));
    }
    Ok(certs)
}

/// Loads a PEM private key from a file.
pub fn load_private_key_pem(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path)
        .map_err(|e| format!("could not open private key '{}': {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("invalid PEM private key '{}': {e}", path.display()))?
        .ok_or_else(|| format!("'{}' contains no PEM private key", path.display()))
}

fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, String> {
    let certs = load_certs_pem(cert_path)?;
    let key_der = load_private_key_pem(key_path)?;
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| format!("could not load key '{}': {e}", key_path.display()))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

fn path_str(p: &Path) -> Result<&str, String> {
    p.to_str()
        .ok_or_else(|| format!("non-UTF-8 path: '{}'", p.display()))
}

fn run_openssl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|e| format!("could not run 'openssl': {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("openssl failed ({}): {}", out.status, stderr.trim()));
    }
    Ok(())
}
