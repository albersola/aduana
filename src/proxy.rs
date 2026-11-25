//! Explicit HTTP/1.1 and HTTPS proxy server (`CONNECT` with TLS termination and inspection).

use std::fs;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::certs::{CertStore, build_upstream_tls_config};
use crate::logging::{
    DEFAULT_RETENTION_DAYS, LogEvent, LogWriter, MAX_LOGGED_BODY_BYTES, format_body_for_log,
    redact_headers, utc_rfc3339,
};
use crate::net::{ConnectPolicy, NetError, connect_validated};
use crate::rules::{
    ConnectDecision, Decision, EvalRequest, Policy, ResolvedTransform, Scheme, apply_transforms,
    parse_rules,
};
use crate::secrets::SecretStore;

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:3128";
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Configuration of the `aduana serve` proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub rules_path: PathBuf,
    pub certs_dir: PathBuf,
    pub secrets_path: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    pub retention_days: u32,
    pub echo_stderr: bool,
    pub connect_timeout: Duration,
    pub header_read_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_connections: usize,
    pub connect_policy: ConnectPolicy,
    pub extra_upstream_ca: Option<PathBuf>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN_ADDR.parse().unwrap(),
            rules_path: PathBuf::from("/etc/aduana/rules.conf"),
            certs_dir: PathBuf::from("/var/lib/aduana/certs"),
            secrets_path: Some(PathBuf::from("/etc/aduana/secrets.env")),
            log_dir: Some(PathBuf::from("/var/log/aduana")),
            retention_days: DEFAULT_RETENTION_DAYS,
            echo_stderr: true,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_policy: ConnectPolicy::default(),
            extra_upstream_ca: None,
        }
    }
}

/// State that can be hot-reloaded without cutting active connections.
pub struct RuntimeState {
    pub policy: Policy,
    pub certs: CertStore,
    pub secrets: SecretStore,
}

impl RuntimeState {
    pub fn load(config: &ProxyConfig) -> Result<Self, String> {
        let rules_text = fs::read_to_string(&config.rules_path).map_err(|e| {
            format!(
                "could not read rules file '{}': {e}",
                config.rules_path.display()
            )
        })?;
        let policy = parse_rules(&rules_text).map_err(|e| {
            format!(
                "error in rules '{}': {e}",
                config.rules_path.display()
            )
        })?;

        let secrets = match &config.secrets_path {
            Some(path) => SecretStore::load_optional_env_file(path)?,
            None => SecretStore::new(),
        };

        let missing_secrets = secrets.missing(&policy.referenced_secrets());
        if !missing_secrets.is_empty() {
            return Err(format!(
                "secrets required by the rules are missing: {}",
                missing_secrets.join(", ")
            ));
        }

        let certs = CertStore::load_for_policy(&policy, &config.certs_dir)?;

        Ok(Self {
            policy,
            certs,
            secrets,
        })
    }
}

/// Context shared among all the server's connections.
pub struct ProxyServer {
    config: ProxyConfig,
    state: RwLock<Arc<RuntimeState>>,
    upstream_tls: Arc<ClientConfig>,
    logger: Arc<LogWriter>,
    conn_limit: Arc<Semaphore>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Result<Arc<Self>, String> {
        let initial_state = RuntimeState::load(&config)?;
        let upstream_tls = build_upstream_tls_config(config.extra_upstream_ca.as_deref())?;
        let logger = Arc::new(LogWriter::new(
            config.log_dir.clone(),
            config.retention_days,
            config.echo_stderr,
        )?);
        let conn_limit = Arc::new(Semaphore::new(config.max_connections.max(1)));

        Ok(Arc::new(Self {
            config,
            state: RwLock::new(Arc::new(initial_state)),
            upstream_tls,
            logger,
            conn_limit,
        }))
    }

    /// Reloads rules, secrets and certificates from disk. If anything fails, keeps the previous state.
    pub fn reload(&self) -> Result<(), String> {
        let next = RuntimeState::load(&self.config)?;
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        *guard = Arc::new(next);
        Ok(())
    }

    fn snapshot(&self) -> Arc<RuntimeState> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    /// Starts listening on `config.listen` with `SIGHUP` support and graceful shutdown.
    pub async fn run_with_signals(self: Arc<Self>) -> Result<(), String> {
        let listener = TcpListener::bind(self.config.listen)
            .await
            .map_err(|e| format!("could not listen on {}: {e}", self.config.listen))?;
        let local_addr = listener
            .local_addr()
            .unwrap_or(self.config.listen);
        eprintln!(
            "aduana serve listening on {local_addr} (rules: {})",
            self.config.rules_path.display()
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // SIGHUP handler for hot reload without dropping active connections.
        let reload_server = Arc::clone(&self);
        tokio::spawn(async move {
            let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while sighup.recv().await.is_some() {
                match reload_server.reload() {
                    Ok(()) => {
                        let st = reload_server.snapshot();
                        eprintln!(
                            "SIGHUP: reload completed ({} clients, {} rules)",
                            st.policy.clients.len(),
                            st.policy.rules.len()
                        );
                    }
                    Err(err) => {
                        eprintln!(
                            "SIGHUP: reload rejected (keeping the previous rules): {err}"
                        );
                    }
                }
            }
        });

        // SIGINT / SIGTERM handler for graceful shutdown.
        tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async {
                    if let Some(ref mut s) = sigterm {
                        s.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
            let _ = shutdown_tx.send(true);
        });

        self.serve_listener(listener, shutdown_rx).await
    }

    /// Accepts connections on an already-bound `TcpListener` until a signal is received on `shutdown_rx`.
    pub async fn serve_listener(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), String> {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer_addr) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("error in accept(): {e}");
                            continue;
                        }
                    };
                    let Ok(permit) = Arc::clone(&self.conn_limit).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let _ = stream.set_nodelay(true);
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _permit = permit;
                        server.handle_client_connection(stream, peer_addr.ip()).await;
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_client_connection(self: Arc<Self>, stream: tokio::net::TcpStream, peer_ip: IpAddr) {
        let io = TokioIo::new(stream);
        let server = Arc::clone(&self);
        let svc = service_fn(move |req: Request<Incoming>| {
            let srv = Arc::clone(&server);
            async move { Ok::<_, std::convert::Infallible>(srv.handle_outer_request(req, peer_ip).await) }
        });

        let mut builder = server_http1::Builder::new();
        builder
            .keep_alive(true)
            .timer(TokioTimer::new())
            .header_read_timeout(self.config.header_read_timeout)
            .max_buf_size(self.config.max_header_bytes);

        let conn = builder.serve_connection(io, svc).with_upgrades();
        let _ = conn.await;
    }

    async fn handle_outer_request(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Response<ProxyBody> {
        if req.method() == Method::CONNECT {
            self.handle_connect(req, peer_ip).await
        } else {
            self.handle_plain_http(req, peer_ip).await
        }
    }

    async fn handle_connect(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Response<ProxyBody> {
        let started = Instant::now();

        let (host, port) = match parse_connect_authority(req.uri(), req.headers()) {
            Ok(target) => target,
            Err(reason) => {
                self.log_deny(
                    None,
                    peer_ip,
                    Scheme::Https,
                    req.uri().to_string(),
                    0,
                    "CONNECT",
                    None,
                    reason,
                    StatusCode::BAD_REQUEST,
                    started,
                );
                return text_response(StatusCode::BAD_REQUEST, "invalid CONNECT request\n");
            }
        };

        let host_lower = host.to_ascii_lowercase();
        let state = self.snapshot();

        // 1. Evaluate client, host and port BEFORE resolving DNS or accepting TLS.
        let client_name = match state
            .policy
            .can_connect(peer_ip, Scheme::Https, &host_lower, port)
        {
            ConnectDecision::Allow { client_name, .. } => client_name,
            ConnectDecision::Deny {
                reason,
                client_name,
            } => {
                self.log_deny(
                    client_name,
                    peer_ip,
                    Scheme::Https,
                    host_lower,
                    port,
                    "CONNECT",
                    None,
                    reason.to_string(),
                    StatusCode::FORBIDDEN,
                    started,
                );
                return text_response(StatusCode::FORBIDDEN, "access denied by Aduana\n");
            }
        };

        // 2. Check that we have a certificate loaded to terminate TLS (never a blind tunnel).
        let (tls_cfg, seen_sni) = match state.certs.server_config_for_host(&host_lower) {
            Ok(pair) => pair,
            Err(err) => {
                self.log_deny(
                    Some(client_name),
                    peer_ip,
                    Scheme::Https,
                    host_lower,
                    port,
                    "CONNECT",
                    None,
                    err,
                    StatusCode::BAD_GATEWAY,
                    started,
                );
                return text_response(
                    StatusCode::BAD_GATEWAY,
                    "TLS certificate not available for this host\n",
                );
            }
        };

        // 3. Schedule TLS inspection after replying 200 Connection Established.
        let server = Arc::clone(&self);
        let target_host = host_lower.clone();
        tokio::spawn(async move {
            let upgraded = match hyper::upgrade::on(req).await {
                Ok(u) => u,
                Err(_) => return,
            };

            let acceptor = TlsAcceptor::from(tls_cfg);
            let tls_stream = match tokio::time::timeout(
                server.config.header_read_timeout,
                acceptor.accept(TokioIo::new(upgraded)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    let sni = seen_sni.lock().ok().and_then(|g| g.clone());
                    let detail = match sni {
                        Some(ref s) if s != &target_host => format!(
                            "SNI mismatch with CONNECT: expected '{target_host}', received '{s}'"
                        ),
                        None => format!(
                            "TLS handshake rejected (missing or invalid SNI for '{target_host}'): {err}"
                        ),
                        _ => format!("TLS handshake error for '{target_host}': {err}"),
                    };
                    server.log_deny(
                        Some(client_name),
                        peer_ip,
                        Scheme::Https,
                        target_host,
                        port,
                        "CONNECT",
                        None,
                        detail,
                        StatusCode::FORBIDDEN,
                        started,
                    );
                    return;
                }
                Err(_) => {
                    server.log_deny(
                        Some(client_name),
                        peer_ip,
                        Scheme::Https,
                        target_host,
                        port,
                        "CONNECT",
                        None,
                        "timeout en handshake TLS".into(),
                        StatusCode::GATEWAY_TIMEOUT,
                        started,
                    );
                    return;
                }
            };

            // Double post-handshake check that SNI == CONNECT.
            let negotiated_sni = tls_stream
                .get_ref()
                .1
                .server_name()
                .map(str::to_ascii_lowercase);
            if negotiated_sni.as_deref() != Some(target_host.as_str()) {
                server.log_deny(
                    Some(client_name),
                    peer_ip,
                    Scheme::Https,
                    target_host,
                    port,
                    "CONNECT",
                    None,
                    format!(
                        "desajuste SNI post-handshake: {:?}",
                        negotiated_sni
                    ),
                    StatusCode::FORBIDDEN,
                    started,
                );
                return;
            }

            let inner_server = Arc::clone(&server);
            let inner_host = target_host.clone();
            let svc = service_fn(move |inner_req: Request<Incoming>| {
                let srv = Arc::clone(&inner_server);
                let host_owned = inner_host.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        srv.handle_decrypted_https_request(inner_req, peer_ip, &host_owned, port)
                            .await,
                    )
                }
            });

            let mut builder = server_http1::Builder::new();
            builder
                .keep_alive(true)
                .timer(TokioTimer::new())
                .header_read_timeout(server.config.header_read_timeout)
                .max_buf_size(server.config.max_header_bytes);

            let _ = tokio::time::timeout(
                server.config.idle_timeout,
                builder.serve_connection(TokioIo::new(tls_stream), svc),
            )
            .await;
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(empty_body())
            .unwrap()
    }

    async fn handle_decrypted_https_request(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_ip: IpAddr,
        connect_host: &str,
        connect_port: u16,
    ) -> Response<ProxyBody> {
        let started = Instant::now();
        let method_str = req.method().as_str().to_string();

        if req.method() == Method::CONNECT {
            self.log_deny(
                None,
                peer_ip,
                Scheme::Https,
                connect_host.to_string(),
                connect_port,
                &method_str,
                None,
                "nested CONNECT inside TLS is forbidden".into(),
                StatusCode::BAD_REQUEST,
                started,
            );
            return text_response(StatusCode::BAD_REQUEST, "nested CONNECT not allowed\n");
        }

        // Validate strict Host consistency with respect to CONNECT and SNI.
        if let Err(reason) = validate_inner_host(req.headers(), req.uri(), connect_host, connect_port) {
            let state = self.snapshot();
            let client_name = state
                .policy
                .find_client_by_ip(peer_ip)
                .map(|c| c.name.clone());
            self.log_deny(
                client_name,
                peer_ip,
                Scheme::Https,
                connect_host.to_string(),
                connect_port,
                &method_str,
                req.uri().path_and_query().map(|pq| pq.as_str().to_string()),
                reason,
                StatusCode::FORBIDDEN,
                started,
            );
            return text_response(
                StatusCode::FORBIDDEN,
                "Host header inconsistent with CONNECT/SNI\n",
            );
        }

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        self.evaluate_and_forward(
            req,
            peer_ip,
            Scheme::Https,
            connect_host,
            connect_port,
            &path_and_query,
            started,
        )
        .await
    }

    async fn handle_plain_http(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Response<ProxyBody> {
        let started = Instant::now();
        let method_str = req.method().as_str().to_string();

        let (host, port, path_and_query) = match parse_plain_http_target(req.uri(), req.headers()) {
            Ok(parsed) => parsed,
            Err(reason) => {
                let state = self.snapshot();
                let client_name = state
                    .policy
                    .find_client_by_ip(peer_ip)
                    .map(|c| c.name.clone());
                self.log_deny(
                    client_name,
                    peer_ip,
                    Scheme::Http,
                    req.uri().host().unwrap_or("-").to_ascii_lowercase(),
                    req.uri().port_u16().unwrap_or(80),
                    &method_str,
                    req.uri().path_and_query().map(|pq| pq.as_str().to_string()),
                    reason,
                    StatusCode::BAD_REQUEST,
                    started,
                );
                return text_response(StatusCode::BAD_REQUEST, "invalid HTTP proxy request\n");
            }
        };

        self.evaluate_and_forward(
            req,
            peer_ip,
            Scheme::Http,
            &host,
            port,
            &path_and_query,
            started,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_and_forward(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_ip: IpAddr,
        scheme: Scheme,
        host_lower: &str,
        port: u16,
        path_and_query: &str,
        started: Instant,
    ) -> Response<ProxyBody> {
        let method_str = req.method().as_str().to_string();

        // Reject Content-Length / Transfer-Encoding ambiguities as defense in depth.
        if let Err(reason) = validate_framing_headers(req.headers()) {
            let state = self.snapshot();
            let client_name = state
                .policy
                .find_client_by_ip(peer_ip)
                .map(|c| c.name.clone());
            self.log_deny(
                client_name,
                peer_ip,
                scheme,
                host_lower.to_string(),
                port,
                &method_str,
                Some(path_and_query.to_string()),
                reason,
                StatusCode::BAD_REQUEST,
                started,
            );
            return text_response(StatusCode::BAD_REQUEST, "ambiguous framing headers\n");
        }

        let state = self.snapshot();
        let eval_req = EvalRequest {
            client_ip: peer_ip,
            scheme,
            host: host_lower,
            port,
            method: &method_str,
            path: path_and_query,
        };

        let matched = match state.policy.evaluate(&eval_req) {
            Decision::Allow(m) => m,
            Decision::Deny {
                reason,
                client_name,
            } => {
                self.log_deny(
                    client_name,
                    peer_ip,
                    scheme,
                    host_lower.to_string(),
                    port,
                    &method_str,
                    Some(path_and_query.to_string()),
                    reason.to_string(),
                    StatusCode::FORBIDDEN,
                    started,
                );
                return text_response(StatusCode::FORBIDDEN, "access denied by Aduana\n");
            }
        };

        // Resolve transforms and secrets ONLY after authorization.
        let (resolved_transforms, derived_secrets) = match matched
            .resolve_transforms_with_redactions(|name| state.secrets.get(name).map(str::to_string))
        {
            Ok(pair) => pair,
            Err(err) => {
                self.log_deny(
                    Some(matched.client_name),
                    peer_ip,
                    scheme,
                    host_lower.to_string(),
                    port,
                    &method_str,
                    Some(path_and_query.to_string()),
                    format!("error resolving secrets: {err}"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    started,
                );
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal secrets configuration error\n",
                );
            }
        };
        let log_secrets = if derived_secrets.is_empty() {
            state.secrets.clone()
        } else {
            state.secrets.with_extra_redactions(derived_secrets)
        };

        // Connect with anti-SSRF / anti-DNS-rebinding validation (single resolution).
        let (tcp_stream, _resolved_addr) = match connect_validated(
            host_lower,
            port,
            self.config.connect_timeout,
            &self.config.connect_policy,
        )
        .await
        {
            Ok(conn) => conn,
            Err(err) => {
                let status = match err {
                    NetError::BlockedPrivateIp(_) => StatusCode::FORBIDDEN,
                    NetError::ConnectTimeout => StatusCode::GATEWAY_TIMEOUT,
                    NetError::DnsFailed(_) | NetError::ConnectFailed(_) => StatusCode::BAD_GATEWAY,
                };
                self.log_deny(
                    Some(matched.client_name),
                    peer_ip,
                    scheme,
                    host_lower.to_string(),
                    port,
                    &method_str,
                    Some(path_and_query.to_string()),
                    err.to_string(),
                    status,
                    started,
                );
                return text_response(status, &format!("{err}\n"));
            }
        };

        // Prepare headers for the upstream applying hop-by-hop cleanup and transforms.
        let (parts, incoming_body) = req.into_parts();
        let req_content_encoding = header_str(&parts.headers, "content-encoding");
        let req_content_type = header_str(&parts.headers, "content-type");

        let (upstream_headers, logged_req_headers) = build_upstream_headers(
            &parts.headers,
            scheme,
            host_lower,
            port,
            &resolved_transforms,
            &log_secrets,
        );

        let origin_uri: Uri = match path_and_query.parse() {
            Ok(u) => u,
            Err(_) => {
                return text_response(StatusCode::BAD_REQUEST, "invalid path\n");
            }
        };

        let req_capture = Arc::new(Mutex::new(BodyCapture::default()));
        let upstream_body = if matched.log_body {
            CaptureBody::new(incoming_body, Arc::clone(&req_capture), None)
        } else {
            CaptureBody::passthrough(incoming_body)
        };

        let mut upstream_req_builder = Request::builder().method(parts.method).uri(origin_uri);
        for (k, v) in upstream_headers {
            upstream_req_builder = upstream_req_builder.header(k, v);
        }
        let upstream_req = match upstream_req_builder.body(upstream_body) {
            Ok(r) => r,
            Err(e) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("error building upstream request: {e}\n"),
                );
            }
        };

        // Send to the upstream (plain HTTP or HTTPS validating the certificate against the system CAs).
        let upstream_resp = match scheme {
            Scheme::Http => {
                send_upstream_http1(tcp_stream, upstream_req, self.config.idle_timeout).await
            }
            Scheme::Https => {
                let server_name = match ServerName::try_from(host_lower.to_string()) {
                    Ok(sn) => sn,
                    Err(_) => {
                        return text_response(StatusCode::BAD_REQUEST, "invalid DNS name\n");
                    }
                };
                let connector = TlsConnector::from(Arc::clone(&self.upstream_tls));
                let tls = match tokio::time::timeout(
                    self.config.connect_timeout,
                    connector.connect(server_name, tcp_stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        self.log_deny(
                            Some(matched.client_name),
                            peer_ip,
                            scheme,
                            host_lower.to_string(),
                            port,
                            &method_str,
                            Some(path_and_query.to_string()),
                            format!("TLS failure towards upstream: {e}"),
                            StatusCode::BAD_GATEWAY,
                            started,
                        );
                        return text_response(
                            StatusCode::BAD_GATEWAY,
                            "TLS verification error with the destination server\n",
                        );
                    }
                    Err(_) => {
                        self.log_deny(
                            Some(matched.client_name),
                            peer_ip,
                            scheme,
                            host_lower.to_string(),
                            port,
                            &method_str,
                            Some(path_and_query.to_string()),
                            "TLS timeout towards upstream".into(),
                            StatusCode::GATEWAY_TIMEOUT,
                            started,
                        );
                        return text_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "TLS timeout towards upstream\n",
                        );
                    }
                };
                send_upstream_http1(tls, upstream_req, self.config.idle_timeout).await
            }
        };

        let upstream_resp = match upstream_resp {
            Ok(r) => r,
            Err(err) => {
                self.log_deny(
                    Some(matched.client_name),
                    peer_ip,
                    scheme,
                    host_lower.to_string(),
                    port,
                    &method_str,
                    Some(path_and_query.to_string()),
                    err,
                    StatusCode::BAD_GATEWAY,
                    started,
                );
                return text_response(
                    StatusCode::BAD_GATEWAY,
                    "error communicating with the destination server\n",
                );
            }
        };

        let (resp_parts, resp_body) = upstream_resp.into_parts();
        let resp_status = resp_parts.status;
        let resp_content_encoding = header_str(&resp_parts.headers, "content-encoding");
        let resp_content_type = header_str(&resp_parts.headers, "content-type");

        let clean_resp_headers = strip_hop_by_hop_headers(&resp_parts.headers);
        let logged_resp_headers = if matched.log_body {
            Some(redact_headers(
                &headers_to_pairs(&clean_resp_headers),
                &log_secrets,
            ))
        } else {
            None
        };

        let mut client_resp = Response::builder().status(resp_status);
        for (name, val) in &clean_resp_headers {
            client_resp = client_resp.header(name, val);
        }

        if matched.log_body {
            let logger = Arc::clone(&self.logger);
            let secrets = log_secrets;
            let req_cap = Arc::clone(&req_capture);
            let resp_cap = Arc::new(Mutex::new(BodyCapture::default()));
            let client_name = matched.client_name;
            let rule_name = matched.rule_name;
            let host_owned = host_lower.to_string();
            let path_owned = path_and_query.to_string();

            let on_done: Box<dyn FnOnce(BodyCapture) + Send> = Box::new(move |resp_captured| {
                let req_captured = req_cap
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_default();
                let req_body_str = format_body_for_log(
                    &req_captured.bytes,
                    req_captured.total_len,
                    req_content_encoding.as_deref(),
                    req_content_type.as_deref(),
                    &secrets,
                );
                let resp_body_str = format_body_for_log(
                    &resp_captured.bytes,
                    resp_captured.total_len,
                    resp_content_encoding.as_deref(),
                    resp_content_type.as_deref(),
                    &secrets,
                );

                logger.write(&LogEvent {
                    timestamp: utc_rfc3339(SystemTime::now()),
                    decision: "allow".into(),
                    client: Some(client_name),
                    client_ip: peer_ip.to_string(),
                    scheme: scheme.as_str().into(),
                    host: host_owned,
                    port,
                    method: method_str,
                    path: Some(path_owned),
                    rule: Some(rule_name),
                    reason: None,
                    status: Some(resp_status.as_u16()),
                    duration_ms: started.elapsed().as_millis() as u64,
                    request_headers: Some(logged_req_headers),
                    request_body: Some(req_body_str),
                    response_headers: logged_resp_headers,
                    response_body: Some(resp_body_str),
                });
            });

            let wrapped = CaptureBody::new(resp_body, resp_cap, Some(on_done));
            client_resp.body(ProxyBody::Stream(wrapped)).unwrap()
        } else {
            self.logger.write(&LogEvent {
                timestamp: utc_rfc3339(SystemTime::now()),
                decision: "allow".into(),
                client: Some(matched.client_name),
                client_ip: peer_ip.to_string(),
                scheme: scheme.as_str().into(),
                host: host_lower.to_string(),
                port,
                method: method_str,
                path: Some(path_and_query.to_string()),
                rule: Some(matched.rule_name),
                reason: None,
                status: Some(resp_status.as_u16()),
                duration_ms: started.elapsed().as_millis() as u64,
                request_headers: Some(logged_req_headers),
                request_body: None,
                response_headers: None,
                response_body: None,
            });
            client_resp
                .body(ProxyBody::Stream(CaptureBody::passthrough(resp_body)))
                .unwrap()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_deny(
        &self,
        client: Option<String>,
        client_ip: IpAddr,
        scheme: Scheme,
        host: String,
        port: u16,
        method: &str,
        path: Option<String>,
        reason: String,
        status: StatusCode,
        started: Instant,
    ) {
        self.logger.write(&LogEvent {
            timestamp: utc_rfc3339(SystemTime::now()),
            decision: "deny".into(),
            client,
            client_ip: client_ip.to_string(),
            scheme: scheme.as_str().into(),
            host,
            port,
            method: method.to_string(),
            path,
            rule: None,
            reason: Some(reason),
            status: Some(status.as_u16()),
            duration_ms: started.elapsed().as_millis() as u64,
            request_headers: None,
            request_body: None,
            response_headers: None,
            response_body: None,
        });
    }
}

async fn send_upstream_http1<IO>(
    io: IO,
    req: Request<CaptureBody>,
    timeout: Duration,
) -> Result<Response<Incoming>, String>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("error starting HTTP/1.1 connection to upstream: {e}"))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    tokio::time::timeout(timeout, sender.send_request(req))
        .await
        .map_err(|_| "timeout waiting for the destination server's response".to_string())?
        .map_err(|e| format!("error sending request to upstream: {e}"))
}

fn parse_connect_authority(uri: &Uri, headers: &HeaderMap) -> Result<(String, u16), String> {
    if uri.scheme().is_some() || uri.path_and_query().is_some() {
        return Err("CONNECT only supports host:port authority".into());
    }
    let auth = uri
        .authority()
        .ok_or_else(|| "CONNECT requires host:port authority".to_string())?;
    if auth.as_str().contains('@') {
        return Err("CONNECT must not contain credentials in the authority".into());
    }
    let host = auth.host();
    if host.is_empty() {
        return Err("empty host in CONNECT".into());
    }
    let port = auth
        .port_u16()
        .ok_or_else(|| "CONNECT requires an explicit port".to_string())?;
    if port == 0 {
        return Err("invalid port 0 in CONNECT".into());
    }

    // If a Host header is present, it must be unique and match the CONNECT authority.
    let host_headers: Vec<&HeaderValue> = headers.get_all(http::header::HOST).iter().collect();
    if host_headers.len() > 1 {
        return Err("multiple Host headers in CONNECT".into());
    }
    if let Some(hv) = host_headers.first() {
        let hv_str = hv
            .to_str()
            .map_err(|_| "non-UTF-8 Host header in CONNECT".to_string())?;
        let (h, p_opt) = split_host_header(hv_str)?;
        if !h.eq_ignore_ascii_case(host) || p_opt.unwrap_or(port) != port {
            return Err(format!(
                "Host header '{hv_str}' does not match CONNECT '{host}:{port}'"
            ));
        }
    }

    Ok((host.to_ascii_lowercase(), port))
}

fn validate_inner_host(
    headers: &HeaderMap,
    uri: &Uri,
    expected_host: &str,
    expected_port: u16,
) -> Result<(), String> {
    let host_headers: Vec<&HeaderValue> = headers.get_all(http::header::HOST).iter().collect();
    if host_headers.is_empty() {
        return Err("missing Host header in HTTPS request".into());
    }
    if host_headers.len() > 1 {
        return Err("multiple Host headers detected (possible smuggling)".into());
    }
    let hv_str = host_headers[0]
        .to_str()
        .map_err(|_| "invalid Host header".to_string())?;
    let (hdr_host, hdr_port) = split_host_header(hv_str)?;
    let effective_port = hdr_port.unwrap_or(443);
    if !hdr_host.eq_ignore_ascii_case(expected_host) || effective_port != expected_port {
        return Err(format!(
            "Host header '{hv_str}' does not match CONNECT/SNI '{expected_host}:{expected_port}'"
        ));
    }

    if let Some(auth) = uri.authority() {
        let uri_port = auth.port_u16().unwrap_or(443);
        if !auth.host().eq_ignore_ascii_case(expected_host) || uri_port != expected_port {
            return Err(format!(
                "URI authority '{}' does not match CONNECT/SNI '{expected_host}:{expected_port}'",
                auth
            ));
        }
    }
    Ok(())
}

fn parse_plain_http_target(
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(String, u16, String), String> {
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "HTTP proxy request requires an absolute URI with an http:// scheme".to_string())?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(format!(
            "scheme '{scheme}' not allowed in a direct HTTP request (use CONNECT for HTTPS)"
        ));
    }
    let auth = uri
        .authority()
        .ok_or_else(|| "HTTP URI without authority".to_string())?;
    if auth.as_str().contains('@') {
        return Err("HTTP URI must not include credentials in the authority".into());
    }
    let host = auth.host().to_ascii_lowercase();
    let port = auth.port_u16().unwrap_or(80);
    if host.is_empty() || port == 0 {
        return Err("invalid host or port in HTTP URI".into());
    }

    let host_headers: Vec<&HeaderValue> = headers.get_all(http::header::HOST).iter().collect();
    if host_headers.len() > 1 {
        return Err("multiple Host headers in HTTP request".into());
    }
    if let Some(hv) = host_headers.first() {
        let hv_str = hv
            .to_str()
            .map_err(|_| "invalid Host header".to_string())?;
        let (hdr_host, hdr_port) = split_host_header(hv_str)?;
        if !hdr_host.eq_ignore_ascii_case(&host) || hdr_port.unwrap_or(80) != port {
            return Err(format!(
                "Host header '{hv_str}' does not match URI 'http://{host}:{port}'"
            ));
        }
    }

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok((host, port, path_and_query))
}

fn split_host_header(raw: &str) -> Result<(&str, Option<u16>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('@') || trimmed.contains(' ') {
        return Err(format!("malformed Host header: '{raw}'"));
    }
    if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        let port: u16 = p_str
            .parse()
            .map_err(|_| format!("invalid port in Host header: '{raw}'"))?;
        if port == 0 {
            return Err("invalid port 0 in Host header".into());
        }
        Ok((h, Some(port)))
    } else {
        Ok((trimmed, None))
    }
}

fn validate_framing_headers(headers: &HeaderMap) -> Result<(), String> {
    let cl_count = headers.get_all(http::header::CONTENT_LENGTH).iter().count();
    let te_count = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .count();
    if cl_count > 1 {
        return Err("multiple Content-Length headers (possible request smuggling)".into());
    }
    if cl_count > 0 && te_count > 0 {
        return Err("conflicto Content-Length y Transfer-Encoding (posible request smuggling)".into());
    }
    Ok(())
}

fn strip_hop_by_hop_headers(headers: &HeaderMap) -> HeaderMap {
    let mut extra_drop: Vec<String> = Vec::new();
    for val in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    extra_drop.push(t);
                }
            }
        }
    }

    let mut clean = HeaderMap::new();
    for (name, val) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        let is_hop = matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) || extra_drop.iter().any(|d| d == &lower);
        if !is_hop {
            clean.append(name.clone(), val.clone());
        }
    }
    clean
}

type PreparedHeaders = (Vec<(HeaderName, HeaderValue)>, Vec<(String, String)>);

fn build_upstream_headers(
    incoming: &HeaderMap,
    scheme: Scheme,
    host_lower: &str,
    port: u16,
    transforms: &[ResolvedTransform],
    secrets: &SecretStore,
) -> PreparedHeaders {
    let clean = strip_hop_by_hop_headers(incoming);
    let mut pairs: Vec<(String, String)> = Vec::new();

    for (name, val) in &clean {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "host" {
            continue;
        }
        if let Ok(v) = val.to_str() {
            pairs.push((lower, v.to_string()));
        }
    }

    apply_transforms(&mut pairs, transforms);

    let canonical_host = if port == scheme.default_port() {
        host_lower.to_string()
    } else {
        format!("{host_lower}:{port}")
    };

    let mut out = Vec::with_capacity(pairs.len() + 1);
    if let Ok(hv) = HeaderValue::from_str(&canonical_host) {
        out.push((http::header::HOST, hv));
    }
    for (k, v) in &pairs {
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            out.push((hn, hv));
        }
    }

    let mut log_pairs = Vec::with_capacity(pairs.len() + 1);
    log_pairs.push(("host".to_string(), canonical_host));
    log_pairs.extend(pairs);
    let redacted = redact_headers(&log_pairs, secrets);

    (out, redacted)
}

fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
        .collect()
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn empty_body() -> ProxyBody {
    ProxyBody::Full(Full::new(Bytes::new()))
}

fn text_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ProxyBody::Full(Full::new(Bytes::from(body.to_string()))))
        .unwrap()
}

#[derive(Debug, Clone, Default)]
struct BodyCapture {
    bytes: Vec<u8>,
    total_len: usize,
}

/// Streaming HTTP body that passes all bytes through intact while capturing at most
/// `MAX_LOGGED_BODY_BYTES` in memory when `log body` is active.
struct CaptureBody {
    inner: Incoming,
    capture: Option<Arc<Mutex<BodyCapture>>>,
    on_complete: Option<Box<dyn FnOnce(BodyCapture) + Send>>,
}

impl CaptureBody {
    fn new(
        inner: Incoming,
        capture: Arc<Mutex<BodyCapture>>,
        on_complete: Option<Box<dyn FnOnce(BodyCapture) + Send>>,
    ) -> Self {
        Self {
            inner,
            capture: Some(capture),
            on_complete,
        }
    }

    fn passthrough(inner: Incoming) -> Self {
        Self {
            inner,
            capture: None,
            on_complete: None,
        }
    }

    fn finish(&mut self) {
        if let Some(cb) = self.on_complete.take() {
            let captured = self
                .capture
                .as_ref()
                .and_then(|c| c.lock().ok().map(|g| g.clone()))
                .unwrap_or_default();
            cb(captured);
        }
    }
}

impl Drop for CaptureBody {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Body for CaptureBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let res = Pin::new(&mut self.inner).poll_frame(cx);
        match res {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(cap), Some(data)) = (&self.capture, frame.data_ref())
                    && let Ok(mut guard) = cap.lock()
                {
                    guard.total_len += data.len();
                    let remaining = MAX_LOGGED_BODY_BYTES.saturating_sub(guard.bytes.len());
                    if remaining > 0 {
                        let take = remaining.min(data.len());
                        guard.bytes.extend_from_slice(&data[..take]);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                self.finish();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Body returned by the proxy's responses (synthetic response or upstream stream).
enum ProxyBody {
    Full(Full<Bytes>),
    Stream(CaptureBody),
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ProxyBody::Full(full) => Pin::new(full).poll_frame(cx).map_err(|never| match never {}),
            ProxyBody::Stream(stream) => Pin::new(stream).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(full) => full.is_end_stream(),
            ProxyBody::Stream(stream) => stream.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ProxyBody::Full(full) => full.size_hint(),
            ProxyBody::Stream(stream) => stream.size_hint(),
        }
    }
}

/// Helper to run an async future in tests or CLI.
pub fn block_on<F: Future>(fut: F) -> Result<F::Output, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the tokio runtime: {e}"))?;
    Ok(rt.block_on(fut))
}
