use std::fmt::Write;

use super::ast::{Client, FromMatcher, Policy, Rule, Transform};

/// Formats a `client` declaration in canonical form.
pub fn format_client(client: &Client) -> String {
    format!("client {} {}", client.name, client.addr)
}

/// Formats a `rule` block in readable canonical form.
pub fn format_rule(rule: &Rule) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "rule {} {{", rule.name);

    match &rule.from {
        FromMatcher::AnyDeclared => {
            let _ = writeln!(out, "  from  *");
        }
        FromMatcher::Clients(names) => {
            let _ = writeln!(out, "  from  {}", names.join(", "));
        }
    }

    for target in &rule.to {
        let _ = writeln!(out, "  to    {target}");
    }

    for allow in &rule.allows {
        let _ = writeln!(out, "  allow {} {}", allow.methods, allow.path);
    }

    for transform in &rule.transforms {
        match transform {
            Transform::SetHeader { name, value } => {
                let escaped = escape_quoted(&value.to_string());
                let _ = writeln!(out, "  set header {name} \"{escaped}\"");
            }
            Transform::ReplaceHeader { name, value } => {
                let escaped = escape_quoted(&value.to_string());
                let _ = writeln!(out, "  replace header {name} \"{escaped}\"");
            }
            Transform::RemoveHeader { name } => {
                let _ = writeln!(out, "  remove header {name}");
            }
        }
    }

    if rule.log_body {
        let _ = writeln!(out, "  log body");
    }

    out.push('}');
    out
}

/// Formats a complete `Policy` as valid configuration text (round-trips with `parse_rules`).
pub fn format_policy(policy: &Policy) -> String {
    let mut out = String::new();
    for client in &policy.clients {
        out.push_str(&format_client(client));
        out.push('\n');
    }
    if !policy.clients.is_empty() && !policy.rules.is_empty() {
        out.push('\n');
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format_rule(rule));
        out.push('\n');
    }
    out
}

fn escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}
