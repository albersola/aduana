use std::net::IpAddr;

use aduana::rules::{
    ConnectDecision, Decision, DenyReason, EvalRequest, HostPattern, ResolvedTransform, Scheme,
    Transform, apply_transforms, encode_base64, format_policy, parse_rules, validate_request_path,
};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IP in test")
}

#[test]
fn parses_and_evaluates_full_stripe_example() {
    let config = r#"
# Comentario de cabecera
client web-01 10.0.10.21
client workers 10.0.20.0/24

rule stripe {
  from  web-01
  to    api.stripe.com
  allow POST /v1/charges
  allow GET /v1/customers/**
  set header authorization "Bearer ${secret.stripe_key}"
  set header x-client "${client.name}"
  remove header x-debug
  log body
}
"#;

    let policy = parse_rules(config).expect("should parse");
    assert_eq!(policy.clients.len(), 2);
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.referenced_secrets(), vec!["stripe_key"]);
    assert_eq!(
        policy.required_tls_hosts(),
        vec![&HostPattern::Exact("api.stripe.com".into())]
    );

    // POST allowed + query ignored
    let decision = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.21"),
        scheme: Scheme::Https,
        host: "API.STRIPE.COM",
        port: 443,
        method: "POST",
        path: "/v1/charges?expand[]=customer",
    });

    let matched = match decision {
        Decision::Allow(m) => m,
        other => panic!("esperaba Allow, obtuve {other:?}"),
    };
    assert_eq!(matched.client_name, "web-01");
    assert_eq!(matched.rule_name, "stripe");
    assert!(matched.log_body);

    let resolved = matched
        .resolve_transforms(|name| match name {
            "stripe_key" => Some("sk_live_real".into()),
            _ => None,
        })
        .expect("secrets resolved");
    assert_eq!(
        resolved,
        vec![
            ResolvedTransform::SetHeader {
                name: "authorization".into(),
                value: "Bearer sk_live_real".into(),
            },
            ResolvedTransform::SetHeader {
                name: "x-client".into(),
                value: "web-01".into(),
            },
            ResolvedTransform::RemoveHeader {
                name: "x-debug".into(),
            },
        ]
    );

    // Redacted version does not expose secrets but does expose ${client.name}
    if let Transform::SetHeader { value, .. } = &matched.transforms[0] {
        assert_eq!(value.render_redacted("web-01"), "Bearer ${secret.stripe_key}");
    } else {
        panic!("esperaba SetHeader");
    }

    // DELETE is not allowed (default-deny)
    let denied = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.21"),
        scheme: Scheme::Https,
        host: "api.stripe.com",
        port: 443,
        method: "DELETE",
        path: "/v1/charges",
    });
    assert_eq!(
        denied,
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
            client_name: Some("web-01".into()),
        }
    );

    // Another declared client has no permission for stripe
    let wrong_client = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.20.99"),
        scheme: Scheme::Https,
        host: "api.stripe.com",
        port: 443,
        method: "POST",
        path: "/v1/charges",
    });
    assert_eq!(
        wrong_client,
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
            client_name: Some("workers".into()),
        }
    );
}

#[test]
fn first_matching_rule_wins_without_merging_transforms() {
    let config = r#"
client web-01 10.0.10.21

rule first {
  from web-01
  to api.example.com
  allow GET /v1/**
  set header x-rule "first"
}

rule second {
  from web-01
  to api.example.com
  allow GET /v1/items
  set header x-rule "second"
  log body
}
"#;
    let policy = parse_rules(config).unwrap();
    let decision = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.21"),
        scheme: Scheme::Https,
        host: "api.example.com",
        port: 443,
        method: "GET",
        path: "/v1/items",
    });
    match decision {
        Decision::Allow(m) => {
            assert_eq!(m.rule_name, "first");
            assert!(!m.log_body);
            assert_eq!(m.transforms.len(), 1);
        }
        other => panic!("esperaba Allow(first), obtuve {other:?}"),
    }
}

#[test]
fn from_star_only_matches_declared_clients() {
    let config = r#"
client web-01 10.0.10.21

rule public_read {
  from *
  to api.github.com
  allow GET,HEAD /repos/*/*
}
"#;
    let policy = parse_rules(config).unwrap();

    // Declared client passes
    let ok = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.21"),
        scheme: Scheme::Https,
        host: "api.github.com",
        port: 443,
        method: "HEAD",
        path: "/repos/rust-lang/rust",
    });
    assert!(matches!(ok, Decision::Allow(_)));

    // Undeclared IP is ALWAYS rejected even with `from *`
    let unknown = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.99"),
        scheme: Scheme::Https,
        host: "api.github.com",
        port: 443,
        method: "GET",
        path: "/repos/rust-lang/rust",
    });
    assert_eq!(
        unknown,
        Decision::Deny {
            reason: DenyReason::UnknownClient,
            client_name: None,
        }
    );
}

#[test]
fn host_wildcard_matches_single_level_only() {
    let config = r#"
client web-01 10.0.10.21

rule buckets {
  from web-01
  to *.s3.amazonaws.com
  allow GET /**
}
"#;
    let policy = parse_rules(config).unwrap();

    let eval_host = |host: &str| {
        policy.evaluate(&EvalRequest {
            client_ip: ip("10.0.10.21"),
            scheme: Scheme::Https,
            host,
            port: 443,
            method: "GET",
            path: "/object",
        })
    };

    assert!(matches!(eval_host("my-bucket.s3.amazonaws.com"), Decision::Allow(_)));
    assert!(matches!(eval_host("MY-BUCKET.S3.AMAZONAWS.COM"), Decision::Allow(_)));
    assert!(matches!(eval_host("s3.amazonaws.com"), Decision::Deny { .. }));
    assert!(matches!(
        eval_host("a.b.s3.amazonaws.com"),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        eval_host("evils3.amazonaws.com"),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        eval_host("my-bucket.s3.amazonaws.com."),
        Decision::Deny {
            reason: DenyReason::InvalidHost,
            ..
        }
    ));
}

#[test]
fn path_patterns_single_wildcard_and_trailing_glob() {
    let config = r#"
client web-01 10.0.10.21

rule api {
  from web-01
  to api.example.com
  allow GET /
  allow GET /exact
  allow GET /items/*/detail
  allow GET /v1/customers/**
}
"#;
    let policy = parse_rules(config).unwrap();
    let allowed = |path: &str| {
        matches!(
            policy.evaluate(&EvalRequest {
                client_ip: ip("10.0.10.21"),
                scheme: Scheme::Https,
                host: "api.example.com",
                port: 443,
                method: "GET",
                path,
            }),
            Decision::Allow(_)
        )
    };

    assert!(allowed("/"));
    assert!(allowed("/exact"));
    assert!(!allowed("/exact/"));
    assert!(!allowed("/exact/more"));

    assert!(allowed("/items/42/detail"));
    assert!(allowed("/items/john%20doe/detail"));
    assert!(!allowed("/items/detail"));
    assert!(!allowed("/items/42/99/detail"));

    assert!(allowed("/v1/customers"));
    assert!(allowed("/v1/customers/"));
    assert!(allowed("/v1/customers/cus_123"));
    assert!(allowed("/v1/customers/cus_123/cards/card_1"));
    assert!(!allowed("/v1/customers2"));
    assert!(!allowed("/v1/customer"));
}

#[test]
fn schemes_and_ports_in_targets() {
    let config = r#"
client web-01 10.0.10.21

rule mixed {
  from web-01
  to http://legacy.example.com http://legacy.example.com:8080 api.example.com:8443
  allow * /**
}
"#;
    let policy = parse_rules(config).unwrap();

    assert!(matches!(
        policy.can_connect(ip("10.0.10.21"), Scheme::Http, "legacy.example.com", 80),
        ConnectDecision::Allow { .. }
    ));
    assert!(matches!(
        policy.can_connect(ip("10.0.10.21"), Scheme::Http, "legacy.example.com", 8080),
        ConnectDecision::Allow { .. }
    ));
    assert!(matches!(
        policy.can_connect(ip("10.0.10.21"), Scheme::Https, "api.example.com", 8443),
        ConnectDecision::Allow { .. }
    ));
    // Same host but different port/scheme → denied before DNS
    assert!(matches!(
        policy.can_connect(ip("10.0.10.21"), Scheme::Https, "legacy.example.com", 443),
        ConnectDecision::Deny {
            reason: DenyReason::NoMatchingRule,
            ..
        }
    ));
    assert!(matches!(
        policy.can_connect(ip("10.0.10.21"), Scheme::Https, "api.example.com", 443),
        ConnectDecision::Deny {
            reason: DenyReason::NoMatchingRule,
            ..
        }
    ));
}

#[test]
fn rejects_ambiguous_and_traversal_paths() {
    let config = r#"
client web-01 10.0.10.21

rule all_paths {
  from web-01
  to api.example.com
  allow GET /**
}
"#;
    let policy = parse_rules(config).unwrap();

    let bad_paths = [
        "",
        "v1/charges",
        "/v1/../admin",
        "/v1/./charges",
        "/..",
        "/.",
        "/v1/%2e%2e/admin",
        "/v1/%2E%2e/admin",
        "/v1/.%2e/admin",
        "/v1/%2fadmin",
        "/v1/%2Fadmin",
        "/v1/%5cadmin",
        "/v1\\admin",
        "/v1//charges",
        "/v1/%00",
        "/v1/%0d%0a",
        "/v1/%2",
        "/v1/%zz",
        "/v1/charges#frag",
        "/v1/charges\r\n",
    ];

    for bad in bad_paths {
        assert!(
            validate_request_path(bad).is_err(),
            "should reject ambiguous path: {bad:?}"
        );
        let res = policy.evaluate(&EvalRequest {
            client_ip: ip("10.0.10.21"),
            scheme: Scheme::Https,
            host: "api.example.com",
            port: 443,
            method: "GET",
            path: bad,
        });
        assert!(
            matches!(
                res,
                Decision::Deny {
                    reason: DenyReason::AmbiguousPath(_),
                    ..
                }
            ),
            "expected AmbiguousPath for {bad:?}, got {res:?}"
        );
    }
}

#[test]
fn static_validation_rejects_security_and_syntax_errors() {
    let cases: &[(&str, &str)] = &[
        // deny does not exist
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  deny GET /\n}\n",
            "default-deny",
        ),
        // protected header in set
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header Host \"evil.com\"\n}\n",
            "protected",
        ),
        // protected header in replace
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  replace header Host \"evil.com\"\n}\n",
            "protected",
        ),
        // invalid syntax in replace
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  replace authorization \"Bearer x\"\n}\n",
            "replace header",
        ),
        // protected header in remove
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  remove header Transfer-Encoding\n}\n",
            "protected",
        ),
        // secret over plain HTTP
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to http://api.example.com\n  allow GET /\n  set header authorization \"Bearer ${secret.k}\"\n}\n",
            "non-HTTPS",
        ),
        // secret in replace over plain HTTP
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to http://api.example.com\n  allow GET /\n  replace header authorization \"Bearer ${secret.k}\"\n}\n",
            "non-HTTPS",
        ),
        // secret over wildcard host
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to *.example.com\n  allow GET /\n  set header authorization \"Bearer ${secret.k}\"\n}\n",
            "wildcard",
        ),
        // secret in replace over wildcard host
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to *.example.com\n  allow GET /\n  replace header authorization \"Bearer ${secret.k}\"\n}\n",
            "wildcard",
        ),
        // to * prohibido
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to *\n  allow GET /\n}\n",
            "to *",
        ),
        // *.com too broad
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to *.com\n  allow GET /\n}\n",
            "too broad",
        ),
        // ** outside the last position
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /v1/**/charges\n}\n",
            "last segment",
        ),
        // query string in path pattern
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /v1/charges?foo=1\n}\n",
            "query string",
        ),
        // undeclared client
        (
            "client a 10.0.0.1\nrule r {\n  from ghost\n  to api.example.com\n  allow GET /\n}\n",
            "undeclared",
        ),
        // overlapping IPs/CIDRs
        (
            "client net 10.0.10.0/24\nclient one 10.0.10.21\n",
            "overlaps",
        ),
        // CIDR with host bits set
        ("client bad 10.0.10.21/24\n", "host bits"),
        // unknown variable
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header x-a \"${env.HOME}\"\n}\n",
            "unknown variable",
        ),
        // duplicate rule
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n}\nrule r {\n  from a\n  to api.example.com\n  allow POST /\n}\n",
            "duplicate rule",
        ),
        // CONNECT method forbidden in allow
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow CONNECT /\n}\n",
            "unsupported HTTP method",
        ),
        // missing allow
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n}\n",
            "allow",
        ),
    ];

    for (input, expected_substr) in cases {
        let err = parse_rules(input).expect_err(&format!("should fail:\n{input}"));
        assert!(
            err.message.contains(expected_substr),
            "expected error containing '{expected_substr}', got '{err}' for:\n{input}"
        );
    }
}

#[test]
fn round_trip_formatting_and_exact_spans() {
    let original = "# Header comment\nclient web-01 10.0.10.21\n\nrule stripe {\n  from web-01\n  to api.stripe.com\n  allow POST /v1/charges\n  set header x-note \"hi \\\"#1\\\" ${client.name}\"\n  replace header authorization \"Bearer ${secret.stripe_key}\"\n  log body\n}\n";

    let parsed = parse_rules(original).unwrap();

    // Spans make it possible to locate and edit exact blocks in rules.conf without touching comments
    let client_slice = &original[parsed.clients[0].span.start_byte..parsed.clients[0].span.end_byte];
    assert_eq!(client_slice, "client web-01 10.0.10.21\n");

    let rule_slice = &original[parsed.rules[0].span.start_byte..parsed.rules[0].span.end_byte];
    assert!(rule_slice.starts_with("rule stripe {"));
    assert!(rule_slice.ends_with("}\n"));

    // Formatting and re-parsing preserves all the semantics
    let formatted = format_policy(&parsed);
    let reparsed = parse_rules(&formatted).expect("canonical format must re-parse");
    assert_eq!(parsed.clients.len(), reparsed.clients.len());
    assert_eq!(parsed.rules.len(), reparsed.rules.len());
    assert_eq!(parsed.rules[0].name, reparsed.rules[0].name);
    assert_eq!(parsed.rules[0].from, reparsed.rules[0].from);
    assert_eq!(parsed.rules[0].to, reparsed.rules[0].to);
    assert_eq!(parsed.rules[0].allows, reparsed.rules[0].allows);
    assert_eq!(parsed.rules[0].transforms, reparsed.rules[0].transforms);
    assert_eq!(parsed.rules[0].log_body, reparsed.rules[0].log_body);
}

#[test]
fn replace_header_only_modifies_when_present() {
    let config = r#"
client dev-01 10.0.10.50

rule github {
  from  dev-01
  to    api.github.com
  allow GET /repos/**
  replace header Authorization "Bearer ${secret.github_pat}"
  set header x-aduana-client "${client.name}"
  remove header x-debug
}
"#;
    let policy = parse_rules(config).expect("should parse replace header");
    assert_eq!(policy.referenced_secrets(), vec!["github_pat"]);

    let decision = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.50"),
        scheme: Scheme::Https,
        host: "api.github.com",
        port: 443,
        method: "GET",
        path: "/repos/org/private-repo",
    });
    let matched = match decision {
        Decision::Allow(m) => m,
        other => panic!("esperaba Allow, obtuve {other:?}"),
    };
    assert!(matches!(
        &matched.transforms[0],
        Transform::ReplaceHeader { name, .. } if name == "authorization"
    ));

    let resolved = matched
        .resolve_transforms(|name| match name {
            "github_pat" => Some("ghp_real_secret".into()),
            _ => None,
        })
        .expect("secret resolved");
    assert_eq!(
        resolved,
        vec![
            ResolvedTransform::ReplaceHeader {
                name: "authorization".into(),
                value: "Bearer ghp_real_secret".into(),
            },
            ResolvedTransform::SetHeader {
                name: "x-aduana-client".into(),
                value: "dev-01".into(),
            },
            ResolvedTransform::RemoveHeader {
                name: "x-debug".into(),
            },
        ]
    );

    // 1. Authenticated request (gh sends a dummy Authorization): it is replaced by the real PAT.
    let mut authed_headers = vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("Authorization".into(), "Bearer dummy-token".into()),
        ("X-Debug".into(), "1".into()),
    ];
    apply_transforms(&mut authed_headers, &resolved);
    assert_eq!(
        authed_headers,
        vec![
            ("Accept".into(), "application/vnd.github+json".into()),
            ("authorization".into(), "Bearer ghp_real_secret".into()),
            ("x-aduana-client".into(), "dev-01".into()),
        ]
    );

    // 2. Public request (no Authorization): the PAT is NOT injected, but set header is still applied.
    let mut public_headers = vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("X-Debug".into(), "1".into()),
    ];
    apply_transforms(&mut public_headers, &resolved);
    assert_eq!(
        public_headers,
        vec![
            ("Accept".into(), "application/vnd.github+json".into()),
            ("x-aduana-client".into(), "dev-01".into()),
        ]
    );

    // 3. Duplicate header in the input: all occurrences collapse into a single safe value.
    let mut dup_headers = vec![
        ("Authorization".into(), "Bearer fake1".into()),
        ("authorization".into(), "Bearer fake2".into()),
    ];
    apply_transforms(&mut dup_headers, &resolved);
    assert_eq!(
        dup_headers,
        vec![
            ("authorization".into(), "Bearer ghp_real_secret".into()),
            ("x-aduana-client".into(), "dev-01".into()),
        ]
    );
}

#[test]
fn base64_template_parsing_resolution_formatting_and_validation() {
    // RFC 4648 Section 10 test vectors
    assert_eq!(encode_base64(b""), "");
    assert_eq!(encode_base64(b"f"), "Zg==");
    assert_eq!(encode_base64(b"fo"), "Zm8=");
    assert_eq!(encode_base64(b"foo"), "Zm9v");
    assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
    assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(
        encode_base64(b"x-access-token:ghp_abc123"),
        "eC1hY2Nlc3MtdG9rZW46Z2hwX2FiYzEyMw=="
    );

    let config = r#"
client dev-01 10.0.10.50

rule github-git {
  from  dev-01
  to    github.com
  allow GET  /*/*/info/refs
  allow POST /*/*/git-upload-pack
  allow POST /*/*/git-receive-pack
  set header authorization "Basic ${base64(x-access-token:${secret.github_pat})}"
  set header x-pair "${base64(${secret.api_user}:${secret.api_pass})}"
  set header x-key-only "${base64(${secret.api_user}:)}"
}

rule plain-b64 {
  from  dev-01
  to    http://hooks.example.org
  allow GET /ping
  set header x-client-b64 "${base64(client:${client.name})}"
}
"#;
    let policy = parse_rules(config).expect("base64 templates should parse");
    assert_eq!(
        policy.referenced_secrets(),
        vec!["github_pat", "api_user", "api_pass"]
    );

    // Format round-trip preserves Base64 template structure
    let formatted = format_policy(&policy);
    let reparsed = parse_rules(&formatted).expect("formatted policy must re-parse");
    assert_eq!(policy.rules[0].transforms, reparsed.rules[0].transforms);
    assert_eq!(policy.rules[1].transforms, reparsed.rules[1].transforms);

    // Evaluate GitHub Git rule
    let decision = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.50"),
        scheme: Scheme::Https,
        host: "github.com",
        port: 443,
        method: "GET",
        path: "/acme/demo.git/info/refs?service=git-upload-pack",
    });
    let matched = match decision {
        Decision::Allow(m) => m,
        other => panic!("expected Allow, got {other:?}"),
    };
    assert_eq!(matched.rule_name, "github-git");

    // Redacted rendering keeps secrets hidden
    if let Transform::SetHeader { value, .. } = &matched.transforms[0] {
        assert_eq!(
            value.render_redacted("dev-01"),
            "Basic ${base64(x-access-token:${secret.github_pat})}"
        );
    } else {
        panic!("expected SetHeader");
    }

    let (resolved, derived) = matched
        .resolve_transforms_with_redactions(|name| match name {
            "github_pat" => Some("ghp_abc123".into()),
            "api_user" => Some("u1".into()),
            "api_pass" => Some("p2".into()),
            _ => None,
        })
        .expect("secrets resolved");

    assert_eq!(
        resolved,
        vec![
            ResolvedTransform::SetHeader {
                name: "authorization".into(),
                value: "Basic eC1hY2Nlc3MtdG9rZW46Z2hwX2FiYzEyMw==".into(),
            },
            ResolvedTransform::SetHeader {
                name: "x-pair".into(),
                value: encode_base64(b"u1:p2"),
            },
            ResolvedTransform::SetHeader {
                name: "x-key-only".into(),
                value: encode_base64(b"u1:"),
            },
        ]
    );
    assert_eq!(
        derived,
        vec![
            "eC1hY2Nlc3MtdG9rZW46Z2hwX2FiYzEyMw==".to_string(),
            encode_base64(b"u1:p2"),
            encode_base64(b"u1:"),
        ]
    );

    // Non-secret base64 works over HTTP and does not add derived secret redactions
    let plain_decision = policy.evaluate(&EvalRequest {
        client_ip: ip("10.0.10.50"),
        scheme: Scheme::Http,
        host: "hooks.example.org",
        port: 80,
        method: "GET",
        path: "/ping",
    });
    let plain_matched = match plain_decision {
        Decision::Allow(m) => m,
        other => panic!("expected Allow, got {other:?}"),
    };
    if let Transform::SetHeader { value, .. } = &plain_matched.transforms[0] {
        assert_eq!(value.render_redacted("dev-01"), "${base64(client:dev-01)}");
    }
    let (plain_resolved, plain_derived) = plain_matched
        .resolve_transforms_with_redactions(|_| None)
        .expect("no secret needed");
    assert_eq!(
        plain_resolved,
        vec![ResolvedTransform::SetHeader {
            name: "x-client-b64".into(),
            value: encode_base64(b"client:dev-01"),
        }]
    );
    assert!(plain_derived.is_empty());

    // Static validation errors for base64 templates
    let bad_cases: &[(&str, &str)] = &[
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to http://api.example.com\n  allow GET /\n  set header authorization \"Basic ${base64(u:${secret.k})}\"\n}\n",
            "non-HTTPS",
        ),
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to *.example.com\n  allow GET /\n  set header authorization \"Basic ${base64(u:${secret.k})}\"\n}\n",
            "wildcard",
        ),
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header x-a \"${base64(foo${base64(bar)})}\"\n}\n",
            "nested",
        ),
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header x-a \"${base64()}\"\n}\n",
            "must not be empty",
        ),
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header x-a \"${base64(u:${secret.k}}\"\n}\n",
            "unclosed",
        ),
        (
            "client a 10.0.0.1\nrule r {\n  from a\n  to api.example.com\n  allow GET /\n  set header x-a \"${base64(${env.HOME})}\"\n}\n",
            "unknown variable",
        ),
    ];
    for (input, expected) in bad_cases {
        let err = parse_rules(input).expect_err(&format!("should fail:\n{input}"));
        assert!(
            err.message.contains(expected),
            "expected error containing '{expected}', got '{err}' for:\n{input}"
        );
    }
}

#[test]
fn rules_example_conf_is_valid() {
    let example = include_str!("../rules.example.conf");
    let policy = parse_rules(example).expect("rules.example.conf must be valid");
    assert_eq!(policy.clients.len(), 2);
    assert_eq!(policy.rules.len(), 5);
    assert_eq!(policy.referenced_secrets(), vec!["stripe_key", "github_pat"]);
}
