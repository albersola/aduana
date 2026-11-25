//! Aduana command-line interface (`check`, `test`, `serve`, `apply`, `log`, `denied`).

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Serialize;

use crate::certs::{DEFAULT_HOST_CERT_DAYS, DEFAULT_RENEW_BEFORE_DAYS, ensure_policy_certs};
use crate::logging::{DEFAULT_RETENTION_DAYS, LogFilter, is_valid_date_ymd, query_logs};
use crate::proxy::{
    DEFAULT_LISTEN_ADDR, DEFAULT_MAX_CONNECTIONS, ProxyConfig, ProxyServer, block_on,
};
use crate::rules::{
    ClientAddr, Decision, EvalRequest, Policy, ResolvedTransform, Scheme, Transform,
    apply_transforms, parse_rules,
};
use crate::secrets::SecretStore;

/// Version of the GitHub release this binary was built for, or the development version in `Cargo.toml`.
pub const VERSION: &str = match option_env!("ADUANA_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/aduana/rules.conf";
pub const DEFAULT_CA_KEY_PATH: &str = "/etc/aduana/ca/ca.key";
pub const DEFAULT_CA_CERT_PATH: &str = "/etc/aduana/ca.crt";
pub const DEFAULT_CERTS_DIR: &str = "/var/lib/aduana/certs";
pub const DEFAULT_SECRETS_PATH: &str = "/etc/aduana/secrets.env";
pub const DEFAULT_LOG_DIR: &str = "/var/log/aduana";

pub fn run(args: &[String]) -> ExitCode {
    let Some(cmd) = args.first().map(String::as_str) else {
        print_help();
        return ExitCode::SUCCESS;
    };

    match cmd {
        "--version" | "-V" => {
            println!("aduana {VERSION}");
            ExitCode::SUCCESS
        }
        "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        "check" => match cmd_check(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        "test" => match cmd_test(&args[1..]) {
            Ok(allowed) => {
                if allowed {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(3)
                }
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(2)
            }
        },
        "serve" => match cmd_serve(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        "apply" => match cmd_apply(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        "log" => match cmd_log(&args[1..], false) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        "denied" => match cmd_log(&args[1..], true) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        other => {
            eprintln!("aduana: unknown command '{other}' (try --help)");
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("aduana {VERSION} — outbound HTTP/HTTPS proxy");
    println!();
    println!("Uso: aduana <comando> [opciones]");
    println!();
    println!("Comandos:");
    println!("  check   Validate the syntax and semantics of rules.conf (and secrets, if given)");
    println!("  test    Simulate a request against the rules without using the network");
    println!("  serve   Run the HTTP/HTTPS proxy server");
    println!("  apply   Validate rules, generate/renew certificates and reload the service");
    println!("  log     Query the logged traffic in JSONL format");
    println!("  denied  Query the blocked attempts");
    println!();
    println!("Opciones globales:");
    println!("  -h, --help       Show this help");
    println!("  -V, --version    Show the version");
}

fn load_policy_file(path: &Path) -> Result<Policy, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    parse_rules(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut secrets_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: aduana check [-c|--config <path>] [--secrets-file <path>]"
                );
                return Ok(());
            }
            "-c" | "--config" => {
                i += 1;
                config_path = PathBuf::from(req_arg(args, i, "--config")?);
            }
            "--secrets-file" => {
                i += 1;
                secrets_path = Some(PathBuf::from(req_arg(args, i, "--secrets-file")?));
            }
            other => return Err(format!("unknown option in 'check': '{other}'")),
        }
        i += 1;
    }

    let policy = load_policy_file(&config_path)?;
    let referenced = policy.referenced_secrets();
    let tls_hosts = policy.required_tls_hosts();

    if let Some(ref sp) = secrets_path {
        let store = SecretStore::load_env_file(sp)?;
        let missing = store.missing(&referenced);
        if !missing.is_empty() {
            return Err(format!(
                "missing secrets in '{}': {}",
                sp.display(),
                missing.join(", ")
            ));
        }
    }

    println!(
        "OK: {} clients, {} rules, {} TLS hosts, {} referenced secrets",
        policy.clients.len(),
        policy.rules.len(),
        tls_hosts.len(),
        referenced.len()
    );
    Ok(())
}

#[derive(Serialize)]
struct TestJsonOutput {
    decision: &'static str,
    client: Option<String>,
    client_ip: String,
    scheme: String,
    host: String,
    port: u16,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    log_body: bool,
    transforms: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resulting_headers: Option<Vec<(String, String)>>,
}

fn cmd_test(args: &[String]) -> Result<bool, String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut from_arg: Option<String> = None;
    let mut json_output = false;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: aduana test [-c|--config <path>] [--json] --from <client|ip> [-H \"Name: Value\"] <METHOD> <URL>"
                );
                return Ok(true);
            }
            "-c" | "--config" => {
                i += 1;
                config_path = PathBuf::from(req_arg(args, i, "--config")?);
            }
            "--from" | "-f" => {
                i += 1;
                from_arg = Some(req_arg(args, i, "--from")?.to_string());
            }
            "-H" | "--header" => {
                i += 1;
                let raw_h = req_arg(args, i, "--header")?;
                let (k, v) = raw_h.split_once(':').ok_or_else(|| {
                    format!("invalid header '{raw_h}' (expected format: 'Name: Value')")
                })?;
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            "--json" => json_output = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option in 'test': '{other}'"));
            }
            pos => positional.push(pos.to_string()),
        }
        i += 1;
    }

    if positional.len() != 2 {
        return Err(
            "expected usage: aduana test --from <client|ip> <METHOD> <URL>".into(),
        );
    }
    let from_raw = from_arg
        .ok_or_else(|| "missing --from <client|ip> to simulate the origin".to_string())?;
    let method = &positional[0];
    let url = &positional[1];

    let policy = load_policy_file(&config_path)?;
    let client_ip = resolve_test_client_ip(&policy, &from_raw)?;
    let (scheme, host, port, path) = parse_test_url(url)?;

    let decision = policy.evaluate(&EvalRequest {
        client_ip,
        scheme,
        host: &host,
        port,
        method,
        path: &path,
    });

    match decision {
        Decision::Allow(matched) => {
            let transform_descs: Vec<String> = matched
                .transforms
                .iter()
                .map(|t| describe_transform_redacted(t, &matched.client_name))
                .collect();

            let resulting_headers = if !headers.is_empty() {
                let resolved_redacted: Vec<ResolvedTransform> = matched
                    .transforms
                    .iter()
                    .map(|t| match t {
                        Transform::SetHeader { name, value } => ResolvedTransform::SetHeader {
                            name: name.clone(),
                            value: value.render_redacted(&matched.client_name),
                        },
                        Transform::ReplaceHeader { name, value } => {
                            ResolvedTransform::ReplaceHeader {
                                name: name.clone(),
                                value: value.render_redacted(&matched.client_name),
                            }
                        }
                        Transform::RemoveHeader { name } => ResolvedTransform::RemoveHeader {
                            name: name.clone(),
                        },
                    })
                    .collect();
                let mut simulated = headers.clone();
                apply_transforms(&mut simulated, &resolved_redacted);
                Some(simulated)
            } else {
                None
            };

            if json_output {
                let out = TestJsonOutput {
                    decision: "allow",
                    client: Some(matched.client_name),
                    client_ip: client_ip.to_string(),
                    scheme: scheme.as_str().to_string(),
                    host,
                    port,
                    method: method.to_ascii_uppercase(),
                    path,
                    rule: Some(matched.rule_name),
                    reason: None,
                    log_body: matched.log_body,
                    transforms: transform_descs,
                    resulting_headers,
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
            } else {
                println!("ALLOW");
                println!("  client:   {} ({client_ip})", matched.client_name);
                println!("  rule:     {}", matched.rule_name);
                println!("  target:   {} {scheme}://{host}:{port}{path}", method.to_ascii_uppercase());
                println!("  log_body: {}", if matched.log_body { "yes" } else { "no" });
                if !transform_descs.is_empty() {
                    println!("  transforms:");
                    for t in &transform_descs {
                        println!("    - {t}");
                    }
                }
                if let Some(ref res_h) = resulting_headers {
                    println!("  resulting headers (simulated):");
                    for (k, v) in res_h {
                        println!("    {k}: {v}");
                    }
                }
            }
            Ok(true)
        }
        Decision::Deny {
            reason,
            client_name,
        } => {
            if json_output {
                let out = TestJsonOutput {
                    decision: "deny",
                    client: client_name,
                    client_ip: client_ip.to_string(),
                    scheme: scheme.as_str().to_string(),
                    host,
                    port,
                    method: method.to_ascii_uppercase(),
                    path,
                    rule: None,
                    reason: Some(reason.to_string()),
                    log_body: false,
                    transforms: Vec::new(),
                    resulting_headers: None,
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
            } else {
                println!("DENY");
                println!(
                    "  client: {} ({client_ip})",
                    client_name.as_deref().unwrap_or("<unknown>")
                );
                println!("  target: {} {scheme}://{host}:{port}{path}", method.to_ascii_uppercase());
                println!("  reason: {reason}");
            }
            Ok(false)
        }
    }
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let mut cfg = ProxyConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("Uso: aduana serve [opciones]");
                println!("  -c, --config <path>          Rules file (default: {DEFAULT_CONFIG_PATH})");
                println!("  -l, --listen <ip:port>       Listen address (default: {DEFAULT_LISTEN_ADDR})");
                println!("      --certs-dir <dir>        Certificates directory (default: {DEFAULT_CERTS_DIR})");
                println!("      --secrets-file <path>    Secrets .env file (default: {DEFAULT_SECRETS_PATH})");
                println!("      --log-dir <dir>          JSONL logs directory (default: {DEFAULT_LOG_DIR})");
                println!("      --retention-days <N>     Log retention in days (default: {DEFAULT_RETENTION_DAYS})");
                println!("      --max-connections <N>    Concurrent connections (default: {DEFAULT_MAX_CONNECTIONS})");
                return Ok(());
            }
            "-c" | "--config" => {
                i += 1;
                cfg.rules_path = PathBuf::from(req_arg(args, i, "--config")?);
            }
            "-l" | "--listen" => {
                i += 1;
                let addr_s = req_arg(args, i, "--listen")?;
                cfg.listen = addr_s
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("invalid --listen address: '{addr_s}'"))?;
            }
            "--certs-dir" => {
                i += 1;
                cfg.certs_dir = PathBuf::from(req_arg(args, i, "--certs-dir")?);
            }
            "--secrets-file" => {
                i += 1;
                cfg.secrets_path = Some(PathBuf::from(req_arg(args, i, "--secrets-file")?));
            }
            "--log-dir" => {
                i += 1;
                cfg.log_dir = Some(PathBuf::from(req_arg(args, i, "--log-dir")?));
            }
            "--retention-days" => {
                i += 1;
                let s = req_arg(args, i, "--retention-days")?;
                cfg.retention_days = s
                    .parse()
                    .map_err(|_| format!("invalid value for --retention-days: '{s}'"))?;
            }
            "--max-connections" => {
                i += 1;
                let s = req_arg(args, i, "--max-connections")?;
                cfg.max_connections = s
                    .parse()
                    .map_err(|_| format!("invalid value for --max-connections: '{s}'"))?;
            }
            other => return Err(format!("unknown option in 'serve': '{other}'")),
        }
        i += 1;
    }

    let server = ProxyServer::new(cfg)?;
    block_on(server.run_with_signals())?
}

fn cmd_apply(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut ca_key = PathBuf::from(DEFAULT_CA_KEY_PATH);
    let mut ca_cert = PathBuf::from(DEFAULT_CA_CERT_PATH);
    let mut certs_dir = PathBuf::from(DEFAULT_CERTS_DIR);
    let mut days = DEFAULT_HOST_CERT_DAYS;
    let mut renew_before = DEFAULT_RENEW_BEFORE_DAYS;
    let mut reload_service = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("Uso: aduana apply [opciones]");
                println!("  -c, --config <path>         Rules file (default: {DEFAULT_CONFIG_PATH})");
                println!("      --ca-key <path>         CA private key (default: {DEFAULT_CA_KEY_PATH})");
                println!("      --ca-cert <path>        CA certificate (default: {DEFAULT_CA_CERT_PATH})");
                println!("      --certs-dir <dir>       Output directory (default: {DEFAULT_CERTS_DIR})");
                println!("      --days <N>              Host certificate validity (default: {DEFAULT_HOST_CERT_DAYS})");
                println!("      --renew-before <N>      Renew if it expires in < N days (default: {DEFAULT_RENEW_BEFORE_DAYS})");
                println!("      --no-reload             No enviar recarga a systemd");
                return Ok(());
            }
            "-c" | "--config" => {
                i += 1;
                config_path = PathBuf::from(req_arg(args, i, "--config")?);
            }
            "--ca-key" => {
                i += 1;
                ca_key = PathBuf::from(req_arg(args, i, "--ca-key")?);
            }
            "--ca-cert" => {
                i += 1;
                ca_cert = PathBuf::from(req_arg(args, i, "--ca-cert")?);
            }
            "--certs-dir" => {
                i += 1;
                certs_dir = PathBuf::from(req_arg(args, i, "--certs-dir")?);
            }
            "--days" => {
                i += 1;
                let s = req_arg(args, i, "--days")?;
                days = s
                    .parse()
                    .map_err(|_| format!("invalid value for --days: '{s}'"))?;
            }
            "--renew-before" => {
                i += 1;
                let s = req_arg(args, i, "--renew-before")?;
                renew_before = s
                    .parse()
                    .map_err(|_| format!("invalid value for --renew-before: '{s}'"))?;
            }
            "--no-reload" => reload_service = false,
            other => return Err(format!("unknown option in 'apply': '{other}'")),
        }
        i += 1;
    }

    let policy = load_policy_file(&config_path)?;
    let report = ensure_policy_certs(&policy, &ca_key, &ca_cert, &certs_dir, days, renew_before)?;

    println!(
        "Valid rules ({} clients, {} rules).",
        policy.clients.len(),
        policy.rules.len()
    );
    if !report.issued.is_empty() {
        println!("Certificados emitidos/renovados ({}):", report.issued.len());
        for host in &report.issued {
            println!("  + {host}");
        }
    }
    if !report.valid.is_empty() {
        println!("Certificados vigentes ({}):", report.valid.len());
        for host in &report.valid {
            println!("  = {host}");
        }
    }

    if reload_service {
        match Command::new("systemctl")
            .args(["is-active", "--quiet", "aduana.service"])
            .status()
        {
            Ok(st) if st.success() => {
                let rel = Command::new("systemctl")
                    .args(["reload", "aduana.service"])
                    .status()
                    .map_err(|e| format!("could not reload aduana.service: {e}"))?;
                if !rel.success() {
                    return Err("systemctl reload aduana.service returned an error".into());
                }
                println!("Servicio aduana.service recargado (SIGHUP).");
            }
            _ => {
                println!("Service aduana.service is not active; reload skipped.");
            }
        }
    }

    Ok(())
}

fn cmd_log(args: &[String], denied_only: bool) -> Result<(), String> {
    let mut log_dir = PathBuf::from(DEFAULT_LOG_DIR);
    let mut filter = LogFilter {
        decision: if denied_only {
            Some("deny".into())
        } else {
            None
        },
        limit: 50,
        ..Default::default()
    };
    let mut json_output = false;

    let cmd_name = if denied_only { "denied" } else { "log" };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("Uso: aduana {cmd_name} [opciones]");
                println!("      --log-dir <dir>       Logs directory (default: {DEFAULT_LOG_DIR})");
                println!("      --client <name|ip>    Filter by client or IP");
                println!("      --host <domain>       Filter by domain (substring)");
                println!("      --since <YYYY-MM-DD>  Filter from a UTC date");
                println!("  -n, --limit <N>           Maximum number of records (default: 50, 0 = unlimited)");
                println!("      --json                Salida JSONL");
                return Ok(());
            }
            "--log-dir" => {
                i += 1;
                log_dir = PathBuf::from(req_arg(args, i, "--log-dir")?);
            }
            "--client" => {
                i += 1;
                filter.client = Some(req_arg(args, i, "--client")?.to_string());
            }
            "--host" => {
                i += 1;
                filter.host = Some(req_arg(args, i, "--host")?.to_string());
            }
            "--since" => {
                i += 1;
                let date = req_arg(args, i, "--since")?;
                if !is_valid_date_ymd(date) {
                    return Err(format!("invalid --since date '{date}' (use YYYY-MM-DD)"));
                }
                filter.since = Some(date.to_string());
            }
            "-n" | "--limit" => {
                i += 1;
                let s = req_arg(args, i, "--limit")?;
                filter.limit = s
                    .parse()
                    .map_err(|_| format!("invalid value for --limit: '{s}'"))?;
            }
            "--json" => json_output = true,
            other => return Err(format!("unknown option in '{cmd_name}': '{other}'")),
        }
        i += 1;
    }

    let events = query_logs(&log_dir, &filter)?;
    if json_output {
        for ev in &events {
            if let Ok(line) = serde_json::to_string(ev) {
                println!("{line}");
            }
        }
        return Ok(());
    }

    if events.is_empty() {
        println!("No events match the filter.");
        return Ok(());
    }

    for ev in &events {
        let client = ev.client.as_deref().unwrap_or("-");
        let path = ev.path.as_deref().unwrap_or("");
        let status = ev
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        let detail = ev
            .rule
            .as_deref()
            .or(ev.reason.as_deref())
            .unwrap_or("-");
        println!(
            "{} {:<5} client={}({}) {} {}://{}:{}{} status={} ({}) {}ms",
            ev.timestamp,
            ev.decision.to_ascii_uppercase(),
            client,
            ev.client_ip,
            ev.method,
            ev.scheme,
            ev.host,
            ev.port,
            path,
            status,
            detail,
            ev.duration_ms
        );
    }
    Ok(())
}

fn req_arg<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str, String> {
    args.get(idx)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn resolve_test_client_ip(policy: &Policy, raw: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some(client) = policy.find_client_by_name(raw) {
        return Ok(match client.addr {
            ClientAddr::Exact(ip) => ip,
            ClientAddr::Cidr { network, .. } => network,
        });
    }
    Err(format!(
        "'{raw}' is neither a valid IP nor a client declared in rules.conf"
    ))
}

fn parse_test_url(raw: &str) -> Result<(Scheme, String, u16, String), String> {
    let (scheme, rest) = if let Some(after) = raw.strip_prefix("https://") {
        (Scheme::Https, after)
    } else if let Some(after) = raw.strip_prefix("http://") {
        (Scheme::Http, after)
    } else if raw.contains("://") {
        return Err(format!("esquema no soportado en URL '{raw}'"));
    } else {
        (Scheme::Https, raw)
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid port in URL '{raw}'"))?;
            (h.to_ascii_lowercase(), port)
        }
        None => (authority.to_ascii_lowercase(), scheme.default_port()),
    };

    if host.is_empty() {
        return Err(format!("empty host in URL '{raw}'"));
    }

    Ok((scheme, host, port, path))
}

fn describe_transform_redacted(transform: &Transform, client_name: &str) -> String {
    match transform {
        Transform::SetHeader { name, value } => {
            format!("set header {name} \"{}\"", value.render_redacted(client_name))
        }
        Transform::ReplaceHeader { name, value } => {
            format!(
                "replace header {name} \"{}\"",
                value.render_redacted(client_name)
            )
        }
        Transform::RemoveHeader { name } => format!("remove header {name}"),
    }
}
