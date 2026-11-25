use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use aduana::certs::{ensure_policy_certs, generate_ca};
use aduana::logging::{LogEvent, LogWriter, cleanup_old_logs, utc_date_string, utc_rfc3339};
use aduana::rules::parse_rules;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aduana-test-{prefix}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aduana")
}

#[test]
fn cli_check_and_test_subcommands() {
    let dir = temp_dir("cli-check-test");
    let rules_path = dir.join("rules.conf");
    let secrets_path = dir.join("secrets.env");

    fs::write(
        &rules_path,
        r#"
client web-01 10.0.10.21

rule github {
  from  web-01
  to    api.github.com
  allow GET /repos/**
  replace header authorization "Bearer ${secret.github_pat}"
  set header x-client "${client.name}"
}
"#,
    )
    .unwrap();
    fs::write(&secrets_path, "github_pat=ghp_super_secret\n").unwrap();

    // 1. check OK with secrets
    let out = Command::new(bin())
        .args([
            "check",
            "-c",
            rules_path.to_str().unwrap(),
            "--secrets-file",
            secrets_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "check should pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK: 1 clients, 1 rules"));

    // 2. check fails if a secret is missing
    let empty_secrets = dir.join("empty.env");
    fs::write(&empty_secrets, "# empty\n").unwrap();
    let bad_sec = Command::new(bin())
        .args([
            "check",
            "-c",
            rules_path.to_str().unwrap(),
            "--secrets-file",
            empty_secrets.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_sec.status.success());
    assert!(String::from_utf8_lossy(&bad_sec.stderr).contains("github_pat"));

    // 3. test ALLOW with --json and replace header simulation (with and without Authorization)
    let allow_with_auth = Command::new(bin())
        .args([
            "test",
            "-c",
            rules_path.to_str().unwrap(),
            "--json",
            "--from",
            "web-01",
            "-H",
            "Authorization: Bearer dummy",
            "GET",
            "https://api.github.com/repos/org/repo",
        ])
        .output()
        .unwrap();
    assert!(allow_with_auth.status.success());
    let json: serde_json::Value = serde_json::from_slice(&allow_with_auth.stdout).unwrap();
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["rule"], "github");
    // Never exposes the real secret, uses a redacted placeholder
    let resulting = json["resulting_headers"].as_array().unwrap();
    assert_eq!(resulting[0][0], "authorization");
    assert_eq!(resulting[0][1], "Bearer ${secret.github_pat}");
    assert_eq!(resulting[1][0], "x-client");
    assert_eq!(resulting[1][1], "web-01");

    // Without Authorization -> replace header does not add it
    let allow_public = Command::new(bin())
        .args([
            "test",
            "-c",
            rules_path.to_str().unwrap(),
            "--json",
            "--from",
            "10.0.10.21",
            "-H",
            "Accept: application/json",
            "GET",
            "https://api.github.com/repos/org/public",
        ])
        .output()
        .unwrap();
    assert!(allow_public.status.success());
    let json_pub: serde_json::Value = serde_json::from_slice(&allow_public.stdout).unwrap();
    let pub_headers = json_pub["resulting_headers"].as_array().unwrap();
    assert!(!pub_headers.iter().any(|h| h[0] == "authorization"));
    assert!(pub_headers.iter().any(|h| h[0] == "x-client"));

    // 4. test DENY returns exit code 3
    let deny = Command::new(bin())
        .args([
            "test",
            "-c",
            rules_path.to_str().unwrap(),
            "--from",
            "web-01",
            "DELETE",
            "https://api.github.com/repos/org/repo",
        ])
        .output()
        .unwrap();
    assert_eq!(deny.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&deny.stdout).contains("DENY"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_check_and_test_base64_basic_auth() {
    let dir = temp_dir("cli-base64");
    let rules_path = dir.join("rules.conf");
    let secrets_path = dir.join("secrets.env");

    fs::write(
        &rules_path,
        r#"
client dev-vm 10.0.10.21

rule github-git {
  from  dev-vm
  to    github.com
  allow GET  /*/*/info/refs
  allow POST /*/*/git-upload-pack
  allow POST /*/*/git-receive-pack
  remove header cookie
  set header authorization "Basic ${base64(x-access-token:${secret.github_pat})}"
}
"#,
    )
    .unwrap();
    fs::write(&secrets_path, "github_pat=ghp_super_secret\n").unwrap();

    let ok = Command::new(bin())
        .args([
            "check",
            "-c",
            rules_path.to_str().unwrap(),
            "--secrets-file",
            secrets_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "check should pass: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let empty_secrets = dir.join("empty.env");
    fs::write(&empty_secrets, "# empty\n").unwrap();
    let missing = Command::new(bin())
        .args([
            "check",
            "-c",
            rules_path.to_str().unwrap(),
            "--secrets-file",
            empty_secrets.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("github_pat"));

    let test_out = Command::new(bin())
        .args([
            "test",
            "-c",
            rules_path.to_str().unwrap(),
            "--json",
            "--from",
            "dev-vm",
            "-H",
            "Cookie: session=abc",
            "GET",
            "https://github.com/acme/demo.git/info/refs?service=git-upload-pack",
        ])
        .output()
        .unwrap();
    assert!(test_out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&test_out.stdout).unwrap();
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["rule"], "github-git");
    let headers = json["resulting_headers"].as_array().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0][0], "authorization");
    assert_eq!(
        headers[0][1],
        "Basic ${base64(x-access-token:${secret.github_pat})}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_apply_issues_reuses_and_renews_certs() {
    let dir = temp_dir("cli-apply");
    let ca_key = dir.join("ca.key");
    let ca_cert = dir.join("ca.crt");
    let certs_dir = dir.join("certs");
    let rules_path = dir.join("rules.conf");

    generate_ca(&ca_key, &ca_cert, "Aduana Test CA", 365).unwrap();
    fs::write(
        &rules_path,
        r#"
client web-01 10.0.10.21

rule apis {
  from  web-01
  to    api.stripe.com *.s3.amazonaws.com
  allow GET /**
}
"#,
    )
    .unwrap();

    // First run via CLI: issues both certificates
    let out1 = Command::new(bin())
        .args([
            "apply",
            "-c",
            rules_path.to_str().unwrap(),
            "--ca-key",
            ca_key.to_str().unwrap(),
            "--ca-cert",
            ca_cert.to_str().unwrap(),
            "--certs-dir",
            certs_dir.to_str().unwrap(),
            "--days",
            "90",
            "--renew-before",
            "30",
            "--no-reload",
        ])
        .output()
        .unwrap();
    assert!(
        out1.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert!(certs_dir.join("api.stripe.com.crt").exists());
    assert!(certs_dir.join("api.stripe.com.key").exists());
    assert!(certs_dir.join("_wildcard_.s3.amazonaws.com.crt").exists());
    assert!(certs_dir.join("_wildcard_.s3.amazonaws.com.key").exists());

    // Second check: still valid, not reissued
    let policy = parse_rules(&fs::read_to_string(&rules_path).unwrap()).unwrap();
    let r2 = ensure_policy_certs(&policy, &ca_key, &ca_cert, &certs_dir, 90, 30).unwrap();
    assert!(r2.issued.is_empty());
    assert_eq!(r2.valid.len(), 2);

    // If we require a margin > 90 days, both are renewed
    let r3 = ensure_policy_certs(&policy, &ca_key, &ca_cert, &certs_dir, 90, 120).unwrap();
    assert_eq!(r3.issued.len(), 2);
    assert!(r3.valid.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_log_denied_and_retention_cleanup() {
    let dir = temp_dir("cli-logs");
    let writer = LogWriter::new(Some(dir.clone()), 30, false).unwrap();

    let now = SystemTime::now();
    let ts = utc_rfc3339(now);

    writer.write(&LogEvent {
        timestamp: ts.clone(),
        decision: "allow".into(),
        client: Some("web-01".into()),
        client_ip: "10.0.10.21".into(),
        scheme: "https".into(),
        host: "api.stripe.com".into(),
        port: 443,
        method: "POST".into(),
        path: Some("/v1/charges".into()),
        rule: Some("stripe".into()),
        reason: None,
        status: Some(200),
        duration_ms: 12,
        request_headers: None,
        request_body: None,
        response_headers: None,
        response_body: None,
    });
    writer.write(&LogEvent {
        timestamp: ts,
        decision: "deny".into(),
        client: Some("web-01".into()),
        client_ip: "10.0.10.21".into(),
        scheme: "https".into(),
        host: "evil.example.com".into(),
        port: 443,
        method: "GET".into(),
        path: Some("/steal".into()),
        rule: None,
        reason: Some("no rule matches".into()),
        status: Some(403),
        duration_ms: 1,
        request_headers: None,
        request_body: None,
        response_headers: None,
        response_body: None,
    });

    // Old file to test retention
    let old_date = utc_date_string(now - Duration::from_secs(45 * 86_400));
    let old_file = dir.join(format!("events-{old_date}.jsonl"));
    fs::write(&old_file, "{}\n").unwrap();
    let removed = cleanup_old_logs(&dir, 30, now).unwrap();
    assert_eq!(removed, 1);
    assert!(!old_file.exists());

    // aduana denied --json only returns the deny event
    let denied_out = Command::new(bin())
        .args(["denied", "--log-dir", dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(denied_out.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&denied_out.stdout)
        .unwrap()
        .lines()
        .collect();
    assert_eq!(lines.len(), 1);
    let ev: LogEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(ev.decision, "deny");
    assert_eq!(ev.host, "evil.example.com");

    // aduana log --host stripe only returns stripe
    let log_out = Command::new(bin())
        .args([
            "log",
            "--log-dir",
            dir.to_str().unwrap(),
            "--host",
            "stripe",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(log_out.status.success());
    let log_lines: Vec<&str> = std::str::from_utf8(&log_out.stdout)
        .unwrap()
        .lines()
        .collect();
    assert_eq!(log_lines.len(), 1);
    let ev2: LogEvent = serde_json::from_str(log_lines[0]).unwrap();
    assert_eq!(ev2.host, "api.stripe.com");

    let _ = fs::remove_dir_all(&dir);
}
