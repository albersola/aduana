//! End-to-end integration tests (HTTP, HTTPS/TLS, transforms, secrets, reload)
//! and the evasion test suite.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aduana::certs::{
    build_upstream_tls_config, crypto_provider, ensure_policy_certs, generate_ca, issue_host_cert,
    load_certs_pem, load_private_key_pem,
};
use aduana::logging::{LogFilter, MAX_LOGGED_BODY_BYTES, query_logs};
use aduana::net::ConnectPolicy;
use aduana::proxy::{ProxyConfig, ProxyServer};
use aduana::rules::{HostPattern, encode_base64, parse_rules};

static TEST_ID: AtomicU64 = AtomicU64::new(0);

fn temp_dir(prefix: &str) -> PathBuf {
    let n = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aduana-e2e-{prefix}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Starts a test HTTP server that echoes back JSON with the method, path, headers and body.
async fn spawn_http_echo_server(
    hit_counter: Arc<AtomicUsize>,
) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = watch::channel(false);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx.changed() => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break };
                    let hits = Arc::clone(&hit_counter);
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let hits = Arc::clone(&hits);
                            async move { Ok::<_, std::convert::Infallible>(echo_handler(req, hits).await) }
                        });
                        let _ = server_http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }
        }
    });

    (addr, tx)
}

/// Starts a test HTTPS server with a certificate signed by the test CA.
async fn spawn_https_echo_server(
    cert_path: PathBuf,
    key_path: PathBuf,
    hit_counter: Arc<AtomicUsize>,
) -> (SocketAddr, watch::Sender<bool>) {
    let certs = load_certs_pem(&cert_path).unwrap();
    let key = load_private_key_pem(&key_path).unwrap();
    let cfg = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = watch::channel(false);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx.changed() => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break };
                    let acceptor = acceptor.clone();
                    let hits = Arc::clone(&hit_counter);
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(stream).await else { return };
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let hits = Arc::clone(&hits);
                            async move { Ok::<_, std::convert::Infallible>(echo_handler(req, hits).await) }
                        });
                        let _ = server_http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    });
                }
            }
        }
    });

    (addr, tx)
}

async fn echo_handler(req: Request<Incoming>, hits: Arc<AtomicUsize>) -> Response<Full<Bytes>> {
    hits.fetch_add(1, Ordering::SeqCst);
    let method = req.method().as_str().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    // Special endpoint to test large bodies (> 64 KiB)
    if path == "/v1/large" {
        let payload = "X".repeat(MAX_LOGGED_BODY_BYTES + 4096);
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(payload)))
            .unwrap();
    }

    let mut hdrs = serde_json::Map::new();
    for (k, v) in req.headers() {
        if let Ok(s) = v.to_str() {
            hdrs.insert(k.as_str().to_string(), serde_json::Value::String(s.to_string()));
        }
    }
    let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let json = serde_json::json!({
        "method": method,
        "path": path,
        "headers": hdrs,
        "body": body_str,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", "session=top_secret_cookie")
        .body(Full::new(Bytes::from(json.to_string())))
        .unwrap()
}

/// Sends a plain-text HTTP/1.1 request over a TCP socket and reads the full response.
async fn send_raw_http(addr: SocketAddr, raw_req: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(raw_req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).to_string()
}

/// Issues `CONNECT host:port`, negotiates TLS with the given `sni` and sends `inner_http_req`.
async fn send_via_https_proxy(
    proxy_addr: SocketAddr,
    ca_cert_path: &Path,
    connect_target: &str,
    sni: &str,
    inner_http_req: &str,
) -> Result<(String, String), String> {
    let mut tcp = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("connect proxy: {e}"))?;
    let connect_req = format!("CONNECT {connect_target} HTTP/1.1\r\nHost: {connect_target}\r\n\r\n");
    tcp.write_all(connect_req.as_bytes())
        .await
        .map_err(|e| format!("write connect: {e}"))?;

    // Read only the CONNECT response up to \r\n\r\n
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    while !header_buf.ends_with(b"\r\n\r\n") {
        let n = tcp
            .read(&mut byte)
            .await
            .map_err(|e| format!("read connect resp: {e}"))?;
        if n == 0 {
            break;
        }
        header_buf.push(byte[0]);
    }
    let connect_resp = String::from_utf8_lossy(&header_buf).to_string();
    if !connect_resp.starts_with("HTTP/1.1 200") {
        return Ok((connect_resp, String::new()));
    }

    let client_tls = build_upstream_tls_config(Some(ca_cert_path))?;
    let connector = TlsConnector::from(client_tls);
    let server_name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls handshake failed: {e}"))?;

    tls.write_all(inner_http_req.as_bytes())
        .await
        .map_err(|e| format!("write inner: {e}"))?;

    let mut resp_buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut resp_buf)).await;
    Ok((connect_resp, String::from_utf8_lossy(&resp_buf).to_string()))
}

fn split_http_response(raw: &str) -> (&str, &str) {
    raw.split_once("\r\n\r\n").unwrap_or((raw, ""))
}

#[tokio::test]
async fn end_to_end_http_https_transforms_secrets_logs_wildcard_and_reload() {
    let dir = temp_dir("full-e2e");
    let rules_path = dir.join("rules.conf");
    let secrets_path = dir.join("secrets.env");
    let log_dir = dir.join("logs");

    // 1. Create the Aduana CA (to inspect clients) and the test upstream CA
    let aduana_ca_key = dir.join("aduana-ca.key");
    let aduana_ca_cert = dir.join("aduana-ca.crt");
    let aduana_certs_dir = dir.join("aduana-certs");
    generate_ca(&aduana_ca_key, &aduana_ca_cert, "Aduana Proxy CA", 365).unwrap();

    let upstream_ca_key = dir.join("upstream-ca.key");
    let upstream_ca_cert = dir.join("upstream-ca.crt");
    let upstream_certs_dir = dir.join("upstream-certs");
    generate_ca(&upstream_ca_key, &upstream_ca_cert, "Upstream Test CA", 365).unwrap();

    // Certs for simulated upstream servers
    let (stripe_crt, stripe_key) = issue_host_cert(
        &HostPattern::Exact("api.stripe.com".into()),
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();
    let (gh_crt, gh_key) = issue_host_cert(
        &HostPattern::Exact("api.github.com".into()),
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();
    let (s3_crt, s3_key) = issue_host_cert(
        &HostPattern::Wildcard {
            suffix: "s3.amazonaws.com".into(),
        },
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();

    // 2. Start upstream servers (HTTP and HTTPS)
    let http_hits = Arc::new(AtomicUsize::new(0));
    let (http_addr, _http_stop) = spawn_http_echo_server(Arc::clone(&http_hits)).await;

    let stripe_hits = Arc::new(AtomicUsize::new(0));
    let (stripe_addr, _stripe_stop) =
        spawn_https_echo_server(stripe_crt, stripe_key, Arc::clone(&stripe_hits)).await;

    let gh_hits = Arc::new(AtomicUsize::new(0));
    let (gh_addr, _gh_stop) =
        spawn_https_echo_server(gh_crt, gh_key, Arc::clone(&gh_hits)).await;

    let s3_hits = Arc::new(AtomicUsize::new(0));
    let (s3_addr, _s3_stop) =
        spawn_https_echo_server(s3_crt, s3_key, Arc::clone(&s3_hits)).await;

    // 3. Write rules.conf and secrets.env, and issue Aduana certificates
    fs::write(
        &rules_path,
        r#"
client local-dev 127.0.0.1

rule stripe {
  from  local-dev
  to    api.stripe.com
  allow POST /v1/charges
  allow GET /v1/large
  set header authorization "Bearer ${secret.stripe_key}"
  set header x-aduana-client "${client.name}"
  remove header x-debug
  log body
}

rule github {
  from  local-dev
  to    api.github.com
  allow GET /repos/**
  replace header authorization "Bearer ${secret.github_pat}"
}

rule buckets {
  from  local-dev
  to    *.s3.amazonaws.com
  allow GET /public/**
}

rule plain-http {
  from  local-dev
  to    http://hooks.example.org
  allow POST /notify/*
  set header x-from-proxy "${client.name}"
  remove header x-drop-me
}
"#,
    )
    .unwrap();
    fs::write(
        &secrets_path,
        "stripe_key=sk_live_REAL_STRIPE_SECRET\ngithub_pat=ghp_REAL_GITHUB_PAT\n",
    )
    .unwrap();

    let policy = parse_rules(&fs::read_to_string(&rules_path).unwrap()).unwrap();
    ensure_policy_certs(
        &policy,
        &aduana_ca_key,
        &aduana_ca_cert,
        &aduana_certs_dir,
        90,
        30,
    )
    .unwrap();

    // 4. Arrancar Aduana
    let mut connect_policy = ConnectPolicy {
        allow_private_ips: true,
        ..Default::default()
    };
    connect_policy
        .host_overrides
        .insert(("api.stripe.com".into(), 443), stripe_addr);
    connect_policy
        .host_overrides
        .insert(("api.github.com".into(), 443), gh_addr);
    connect_policy
        .host_overrides
        .insert(("my-bucket.s3.amazonaws.com".into(), 443), s3_addr);
    connect_policy
        .host_overrides
        .insert(("hooks.example.org".into(), 80), http_addr);

    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        rules_path: rules_path.clone(),
        certs_dir: aduana_certs_dir.clone(),
        secrets_path: Some(secrets_path.clone()),
        log_dir: Some(log_dir.clone()),
        echo_stderr: false,
        connect_policy,
        extra_upstream_ca: Some(upstream_ca_cert),
        ..Default::default()
    };

    let server = ProxyServer::new(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_handle = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = srv_handle.serve_listener(listener, shutdown_rx).await;
    });

    // --- Case 1: Plain HTTP allowed with set/remove header ---
    let raw_http = send_raw_http(
        proxy_addr,
        "POST http://hooks.example.org/notify/build HTTP/1.1\r\n\
         Host: hooks.example.org\r\n\
         X-Drop-Me: secret\r\n\
         Content-Length: 5\r\n\
         Connection: close\r\n\r\nhello",
    )
    .await;
    let (hdr, body) = split_http_response(&raw_http);
    assert!(hdr.starts_with("HTTP/1.1 200"), "esperaba 200, obtuve:\n{raw_http}");
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(json["headers"]["x-from-proxy"], "local-dev");
    assert!(json["headers"].get("x-drop-me").is_none());
    assert_eq!(json["body"], "hello");

    // --- Case 2: Plain HTTP denied (path not allowed) -> 403 without touching the upstream ---
    let before_hits = http_hits.load(Ordering::SeqCst);
    let denied_http = send_raw_http(
        proxy_addr,
        "GET http://hooks.example.org/admin HTTP/1.1\r\nHost: hooks.example.org\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(denied_http.starts_with("HTTP/1.1 403"));
    assert_eq!(http_hits.load(Ordering::SeqCst), before_hits);

    // --- Case 3: HTTPS Stripe with secret injection, remove header and log body ---
    let (conn_resp, stripe_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.stripe.com:443",
        "api.stripe.com",
        "POST /v1/charges HTTP/1.1\r\n\
         Host: api.stripe.com\r\n\
         Content-Type: application/json\r\n\
         X-Debug: true\r\n\
         Content-Length: 27\r\n\
         Connection: close\r\n\r\n{\"amount\":100,\"note\":\"ok!\"}",
    )
    .await
    .unwrap();
    assert!(conn_resp.starts_with("HTTP/1.1 200"));
    let (shdr, sbody) = split_http_response(&stripe_resp);
    assert!(shdr.starts_with("HTTP/1.1 200"), "obtuve:\n{stripe_resp}");
    let sjson: serde_json::Value = serde_json::from_str(sbody).unwrap();
    assert_eq!(
        sjson["headers"]["authorization"],
        "Bearer sk_live_REAL_STRIPE_SECRET"
    );
    assert_eq!(sjson["headers"]["x-aduana-client"], "local-dev");
    assert!(sjson["headers"].get("x-debug").is_none());

    // --- Case 4: HTTPS body > 64 KiB reaches the client intact, truncated in the log ---
    let (_, large_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.stripe.com:443",
        "api.stripe.com",
        "GET /v1/large HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let (_, large_body) = split_http_response(&large_resp);
    assert_eq!(large_body.len(), MAX_LOGGED_BODY_BYTES + 4096);

    // --- Case 5: HTTPS GitHub replace header (authenticated vs public) ---
    let (_, gh_authed) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.github.com:443",
        "api.github.com",
        "GET /repos/me/private HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Authorization: Bearer dummy_token_from_gh\r\n\
         Connection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let (_, gh_authed_body) = split_http_response(&gh_authed);
    let gh_authed_json: serde_json::Value = serde_json::from_str(gh_authed_body).unwrap();
    assert_eq!(
        gh_authed_json["headers"]["authorization"],
        "Bearer ghp_REAL_GITHUB_PAT"
    );

    let (_, gh_public) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.github.com:443",
        "api.github.com",
        "GET /repos/rust-lang/rust HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Connection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let (_, gh_public_body) = split_http_response(&gh_public);
    let gh_public_json: serde_json::Value = serde_json::from_str(gh_public_body).unwrap();
    assert!(
        gh_public_json["headers"].get("authorization").is_none(),
        "public request must NOT receive the PAT"
    );

    // --- Caso 6: HTTPS Wildcard *.s3.amazonaws.com ---
    let (_, s3_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "my-bucket.s3.amazonaws.com:443",
        "my-bucket.s3.amazonaws.com",
        "GET /public/file.txt HTTP/1.1\r\nHost: my-bucket.s3.amazonaws.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(s3_resp.starts_with("HTTP/1.1 200"));

    // --- Case 7: Hot reload (invalid keeps state; valid applies changes) ---
    let original_rules = fs::read_to_string(&rules_path).unwrap();
    fs::write(&rules_path, "this is not valid syntax\n").unwrap();
    assert!(server.reload().is_err());
    // The proxy keeps serving with the previous rules
    let (_, still_ok) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "my-bucket.s3.amazonaws.com:443",
        "my-bucket.s3.amazonaws.com",
        "GET /public/still.txt HTTP/1.1\r\nHost: my-bucket.s3.amazonaws.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(still_ok.starts_with("HTTP/1.1 200"));

    // Restore and add a new allowed path
    let updated_rules = original_rules.replace(
        "allow POST /notify/*",
        "allow POST /notify/*\n  allow GET /health",
    );
    fs::write(&rules_path, updated_rules).unwrap();
    server.reload().unwrap();
    let health_resp = send_raw_http(
        proxy_addr,
        "GET http://hooks.example.org/health HTTP/1.1\r\nHost: hooks.example.org\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(health_resp.starts_with("HTTP/1.1 200"));

    // --- Case 8: Verify JSONL logs, bodies and absolute secret redaction ---
    // Short wait to make sure the CaptureBody drop wrote the final event
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = query_logs(&log_dir, &LogFilter::default()).unwrap();
    assert!(events.len() >= 6, "esperaba al menos 6 eventos, obtuve {}", events.len());

    // No real secret or sensitive cookie may ever appear in the log files
    for entry in fs::read_dir(&log_dir).unwrap().flatten() {
        let raw_log = fs::read_to_string(entry.path()).unwrap();
        assert!(
            !raw_log.contains("sk_live_REAL_STRIPE_SECRET"),
            "STRIPE SECRET LEAK IN LOGS!"
        );
        assert!(
            !raw_log.contains("ghp_REAL_GITHUB_PAT"),
            "GITHUB SECRET LEAK IN LOGS!"
        );
        assert!(
            !raw_log.contains("top_secret_cookie"),
            "SET-COOKIE LEAK IN LOGS!"
        );
    }

    let charge_ev = events
        .iter()
        .find(|e| e.path.as_deref() == Some("/v1/charges"))
        .expect("evento /v1/charges registrado");
    assert_eq!(charge_ev.request_body.as_deref(), Some("{\"amount\":100,\"note\":\"ok!\"}"));
    assert!(charge_ev.response_body.as_deref().unwrap().contains("[REDACTED]"));

    let large_ev = events
        .iter()
        .find(|e| e.path.as_deref() == Some("/v1/large"))
        .expect("evento /v1/large registrado");
    assert!(large_ev
        .response_body
        .as_deref()
        .unwrap()
        .contains("...[truncated,"));

    let _ = shutdown_tx.send(true);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn end_to_end_github_git_and_api_gateway() {
    let dir = temp_dir("github-gateway");
    let rules_path = dir.join("rules.conf");
    let secrets_path = dir.join("secrets.env");
    let log_dir = dir.join("logs");

    let aduana_ca_key = dir.join("aduana-ca.key");
    let aduana_ca_cert = dir.join("aduana-ca.crt");
    let aduana_certs_dir = dir.join("aduana-certs");
    generate_ca(&aduana_ca_key, &aduana_ca_cert, "Aduana GitHub CA", 365).unwrap();

    let upstream_ca_key = dir.join("upstream-ca.key");
    let upstream_ca_cert = dir.join("upstream-ca.crt");
    let upstream_certs_dir = dir.join("upstream-certs");
    generate_ca(&upstream_ca_key, &upstream_ca_cert, "Upstream GitHub CA", 365).unwrap();

    let (git_crt, git_key) = issue_host_cert(
        &HostPattern::Exact("github.com".into()),
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();
    let (api_crt, api_key) = issue_host_cert(
        &HostPattern::Exact("api.github.com".into()),
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();

    let git_hits = Arc::new(AtomicUsize::new(0));
    let (git_addr, _git_stop) =
        spawn_https_echo_server(git_crt, git_key, Arc::clone(&git_hits)).await;

    let api_hits = Arc::new(AtomicUsize::new(0));
    let (api_addr, _api_stop) =
        spawn_https_echo_server(api_crt, api_key, Arc::clone(&api_hits)).await;

    let real_pat = "ghp_REAL_GITHUB_GATEWAY_PAT";
    let expected_b64 = encode_base64(format!("x-access-token:{real_pat}").as_bytes());
    let expected_basic = format!("Basic {expected_b64}");

    fs::write(
        &rules_path,
        r#"
client dev-vm 127.0.0.1

rule github-git {
  from  dev-vm
  to    github.com
  allow GET  /*/*/info/refs
  allow POST /*/*/git-upload-pack
  allow POST /*/*/git-receive-pack
  remove header cookie
  set header authorization "Basic ${base64(x-access-token:${secret.github_pat})}"
  set header x-derived-b64 "${base64(x-access-token:${secret.github_pat})}"
  log body
}

rule github-api {
  from  dev-vm
  to    api.github.com
  allow GET,HEAD,POST,PUT,PATCH,DELETE /**
  remove header cookie
  set header authorization "Bearer ${secret.github_pat}"
  log body
}
"#,
    )
    .unwrap();
    fs::write(&secrets_path, format!("github_pat={real_pat}\n")).unwrap();

    let policy = parse_rules(&fs::read_to_string(&rules_path).unwrap()).unwrap();
    ensure_policy_certs(
        &policy,
        &aduana_ca_key,
        &aduana_ca_cert,
        &aduana_certs_dir,
        90,
        30,
    )
    .unwrap();

    let mut connect_policy = ConnectPolicy {
        allow_private_ips: true,
        ..Default::default()
    };
    connect_policy
        .host_overrides
        .insert(("github.com".into(), 443), git_addr);
    connect_policy
        .host_overrides
        .insert(("api.github.com".into(), 443), api_addr);

    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        rules_path,
        certs_dir: aduana_certs_dir,
        secrets_path: Some(secrets_path),
        log_dir: Some(log_dir.clone()),
        echo_stderr: false,
        connect_policy,
        extra_upstream_ca: Some(upstream_ca_cert),
        ..Default::default()
    };

    let server = ProxyServer::new(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = server.serve_listener(listener, shutdown_rx).await;
    });

    // 1. Git smart HTTP discovery (no Authorization from client, Cookie stripped)
    let (_, refs_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "github.com:443",
        "github.com",
        "GET /acme/demo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
         Host: github.com\r\n\
         Cookie: session=should-be-stripped\r\n\
         Connection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let (hdr, body) = split_http_response(&refs_resp);
    assert!(hdr.starts_with("HTTP/1.1 200"), "got:\n{refs_resp}");
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(json["path"], "/acme/demo.git/info/refs?service=git-upload-pack");
    assert_eq!(json["headers"]["authorization"], expected_basic);
    assert!(json["headers"].get("cookie").is_none());

    // 2. Git upload-pack & receive-pack overwrite dummy client Authorization with Basic PAT
    for endpoint in ["/acme/demo.git/git-upload-pack", "/acme/demo.git/git-receive-pack"] {
        let (_, pack_resp) = send_via_https_proxy(
            proxy_addr,
            &aduana_ca_cert,
            "github.com:443",
            "github.com",
            &format!(
                "POST {endpoint} HTTP/1.1\r\n\
                 Host: github.com\r\n\
                 Authorization: Bearer dummy-vm-token\r\n\
                 Content-Length: 4\r\n\
                 Connection: close\r\n\r\npack"
            ),
        )
        .await
        .unwrap();
        let (phdr, pbody) = split_http_response(&pack_resp);
        assert!(phdr.starts_with("HTTP/1.1 200"), "got:\n{pack_resp}");
        let pjson: serde_json::Value = serde_json::from_str(pbody).unwrap();
        assert_eq!(pjson["headers"]["authorization"], expected_basic);
        assert_eq!(pjson["body"], "pack");
    }

    // 3. Disallowed GitHub web/repo paths are blocked without hitting upstream
    let hits_before = git_hits.load(Ordering::SeqCst);
    for blocked in ["/acme/demo.git/HEAD", "/settings/tokens"] {
        let (_, denied) = send_via_https_proxy(
            proxy_addr,
            &aduana_ca_cert,
            "github.com:443",
            "github.com",
            &format!("GET {blocked} HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"),
        )
        .await
        .unwrap();
        assert!(
            denied.starts_with("HTTP/1.1 403"),
            "expected 403 for {blocked}, got:\n{denied}"
        );
    }
    assert_eq!(git_hits.load(Ordering::SeqCst), hits_before);

    // 4. GitHub REST API (gh style `token dummy`) -> Bearer real PAT, query preserved
    let (_, rest_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.github.com:443",
        "api.github.com",
        "GET /repos/acme/demo/pulls?state=open HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Authorization: token dummy-gh-token\r\n\
         Cookie: gh_sess=strip-me\r\n\
         Connection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let (rhdr, rbody) = split_http_response(&rest_resp);
    assert!(rhdr.starts_with("HTTP/1.1 200"), "got:\n{rest_resp}");
    let rjson: serde_json::Value = serde_json::from_str(rbody).unwrap();
    assert_eq!(rjson["path"], "/repos/acme/demo/pulls?state=open");
    assert_eq!(rjson["headers"]["authorization"], format!("Bearer {real_pat}"));
    assert!(rjson["headers"].get("cookie").is_none());

    // 5. GitHub GraphQL API -> Bearer real PAT
    let gql_payload = r#"{"query":"{ viewer { login } }"}"#;
    let (_, gql_resp) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.github.com:443",
        "api.github.com",
        &format!(
            "POST /graphql HTTP/1.1\r\n\
             Host: api.github.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{gql_payload}",
            gql_payload.len()
        ),
    )
    .await
    .unwrap();
    let (ghdr, gbody) = split_http_response(&gql_resp);
    assert!(ghdr.starts_with("HTTP/1.1 200"), "got:\n{gql_resp}");
    let gjson: serde_json::Value = serde_json::from_str(gbody).unwrap();
    assert_eq!(gjson["headers"]["authorization"], format!("Bearer {real_pat}"));
    assert_eq!(gjson["body"], gql_payload);

    // 6. Logs must NEVER leak either the raw PAT or its Base64-encoded form (even in headers or echoed response bodies)
    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = query_logs(&log_dir, &LogFilter::default()).unwrap();
    assert!(events.len() >= 7);
    for entry in fs::read_dir(&log_dir).unwrap().flatten() {
        let raw_log = fs::read_to_string(entry.path()).unwrap();
        assert!(
            !raw_log.contains(real_pat),
            "RAW GITHUB PAT LEAKED IN LOGS!"
        );
        assert!(
            !raw_log.contains(&expected_b64),
            "BASE64-ENCODED GITHUB PAT LEAKED IN LOGS!"
        );
    }

    let _ = shutdown_tx.send(true);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn security_evasion_suite() {
    let dir = temp_dir("evasion");
    let rules_path = dir.join("rules.conf");
    let log_dir = dir.join("logs");

    let aduana_ca_key = dir.join("aduana-ca.key");
    let aduana_ca_cert = dir.join("aduana-ca.crt");
    let aduana_certs_dir = dir.join("aduana-certs");
    generate_ca(&aduana_ca_key, &aduana_ca_cert, "Aduana Evasion CA", 365).unwrap();

    let upstream_ca_key = dir.join("up-ca.key");
    let upstream_ca_cert = dir.join("up-ca.crt");
    let upstream_certs_dir = dir.join("up-certs");
    generate_ca(&upstream_ca_key, &upstream_ca_cert, "Upstream CA", 365).unwrap();

    let (api_crt, api_key) = issue_host_cert(
        &HostPattern::Exact("api.example.com".into()),
        &upstream_ca_key,
        &upstream_ca_cert,
        &upstream_certs_dir,
        90,
    )
    .unwrap();

    let https_hits = Arc::new(AtomicUsize::new(0));
    let (https_addr, _https_stop) =
        spawn_https_echo_server(api_crt, api_key, Arc::clone(&https_hits)).await;

    let ssrf_hits = Arc::new(AtomicUsize::new(0));
    let (ssrf_addr, _ssrf_stop) = spawn_http_echo_server(Arc::clone(&ssrf_hits)).await;

    fs::write(
        &rules_path,
        r#"
client attacker-vm 127.0.0.1

rule api {
  from  attacker-vm
  to    api.example.com
  allow GET /v1/public/**
}

rule ssrf_target {
  from  attacker-vm
  to    http://rebind.example.com
  allow GET /**
}
"#,
    )
    .unwrap();

    let policy = parse_rules(&fs::read_to_string(&rules_path).unwrap()).unwrap();
    ensure_policy_certs(
        &policy,
        &aduana_ca_key,
        &aduana_ca_cert,
        &aduana_certs_dir,
        90,
        30,
    )
    .unwrap();

    // STRICT SSRF policy (allow_private_ips = false, same as in production!)
    let mut connect_policy = ConnectPolicy {
        allow_private_ips: false,
        ..Default::default()
    };
    connect_policy
        .host_overrides
        .insert(("rebind.example.com".into(), 80), ssrf_addr);
    connect_policy
        .host_overrides
        .insert(("api.example.com".into(), 443), https_addr);

    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        rules_path,
        certs_dir: aduana_certs_dir,
        secrets_path: None,
        log_dir: Some(log_dir.clone()),
        echo_stderr: false,
        connect_policy,
        extra_upstream_ca: Some(upstream_ca_cert),
        ..Default::default()
    };

    let server = ProxyServer::new(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = server.serve_listener(listener, shutdown_rx).await;
    });

    // 1. Evasion: SNI != CONNECT mismatch -> TLS handshake must fail
    let sni_attack = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.example.com:443",
        "evil.attacker.com",
        "GET /v1/public/ok HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        sni_attack.is_err(),
        "SNI different from CONNECT should have failed the TLS handshake"
    );

    // 2. Evasion: Host header != CONNECT/SNI inside TLS -> 403
    let (_, host_mismatch) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.example.com:443",
        "api.example.com",
        "GET /v1/public/ok HTTP/1.1\r\nHost: evil.attacker.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(
        host_mismatch.starts_with("HTTP/1.1 403"),
        "Host mismatch should return 403, got:\n{host_mismatch}"
    );

    // 3. Evasion: multiple Host headers -> 403
    let (_, dup_host) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "api.example.com:443",
        "api.example.com",
        "GET /v1/public/ok HTTP/1.1\r\nHost: api.example.com\r\nHost: evil.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(
        dup_host.starts_with("HTTP/1.1 403") || dup_host.starts_with("HTTP/1.1 400"),
        "multiple Host headers should be rejected, got:\n{dup_host}"
    );

    // 4. Evasion: path traversal and %2e%2e encoding -> 403
    for bad_path in ["/v1/public/../../admin", "/v1/public/%2e%2e/secret", "/v1/public/%2fadmin"] {
        let (_, resp) = send_via_https_proxy(
            proxy_addr,
            &aduana_ca_cert,
            "api.example.com:443",
            "api.example.com",
            &format!("GET {bad_path} HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"),
        )
        .await
        .unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "ambiguous path {bad_path} should return 403, got:\n{resp}"
        );
    }

    // 5. Evasion: SSRF / DNS rebinding to 127.0.0.1 with the anti-SSRF policy active -> 403
    let ssrf_resp = send_raw_http(
        proxy_addr,
        "GET http://rebind.example.com/latest/meta-data HTTP/1.1\r\nHost: rebind.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        ssrf_resp.starts_with("HTTP/1.1 403"),
        "SSRF to loopback should return 403, got:\n{ssrf_resp}"
    );
    assert_eq!(
        ssrf_hits.load(Ordering::SeqCst),
        0,
        "the internal service must NEVER receive SSRF traffic"
    );

    // 6. Evasion: CONNECT to an unauthorized domain -> 403 before DNS/TLS
    let (denied_conn, _) = send_via_https_proxy(
        proxy_addr,
        &aduana_ca_cert,
        "not-allowed.example.com:443",
        "not-allowed.example.com",
        "",
    )
    .await
    .unwrap();
    assert!(denied_conn.starts_with("HTTP/1.1 403"));

    // 7. Evasion: smuggling with multiple differing Content-Length headers -> 400
    let dup_cl = send_raw_http(
        proxy_addr,
        "GET http://rebind.example.com/a HTTP/1.1\r\n\
         Host: rebind.example.com\r\n\
         Content-Length: 4\r\n\
         Content-Length: 8\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    assert!(
        dup_cl.starts_with("HTTP/1.1 400"),
        "multiple Content-Length headers should be rejected with 400, got:\n{dup_cl}"
    );

    // 8. Evasion: smuggling Content-Length + Transfer-Encoding -> 400 or 403 (never reaches the upstream)
    let smuggle = send_raw_http(
        proxy_addr,
        "POST http://rebind.example.com/a HTTP/1.1\r\n\
         Host: rebind.example.com\r\n\
         Content-Length: 4\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert!(
        smuggle.starts_with("HTTP/1.1 400") || smuggle.starts_with("HTTP/1.1 403"),
        "CL+TE should be rejected with 400 or 403, got:\n{smuggle}"
    );

    // None of the attacks should have reached the HTTPS server or the internal server
    assert_eq!(https_hits.load(Ordering::SeqCst), 0);
    assert_eq!(ssrf_hits.load(Ordering::SeqCst), 0);

    // Verify that the denied attempts were logged
    tokio::time::sleep(Duration::from_millis(50)).await;
    let denied = query_logs(
        &log_dir,
        &LogFilter {
            decision: Some("deny".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        denied.len() >= 7,
        "esperaba >= 7 eventos deny registrados, obtuve {}",
        denied.len()
    );

    let _ = shutdown_tx.send(true);
    let _ = fs::remove_dir_all(&dir);
}
