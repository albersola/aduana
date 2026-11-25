use std::net::IpAddr;

use super::ast::{
    AllowedMatch, Client, ConnectDecision, Decision, DenyReason, EvalRequest, HostPattern,
    HttpMethod, Policy, ResolvedTransform, Scheme,
};
use super::parser::is_valid_hostname;
use super::path::validate_request_path;

impl Policy {
    /// Finds the declared client that matches `ip`.
    pub fn find_client_by_ip(&self, ip: IpAddr) -> Option<&Client> {
        self.clients.iter().find(|c| c.addr.contains(ip))
    }

    /// Finds a client by its exact name.
    pub fn find_client_by_name(&self, name: &str) -> Option<&Client> {
        self.clients.iter().find(|c| c.name == name)
    }

    /// Returns all secret names referenced in the policy (in order, without duplicates).
    pub fn referenced_secrets(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for rule in &self.rules {
            for secret in rule.referenced_secrets() {
                if !out.contains(&secret) {
                    out.push(secret);
                }
            }
        }
        out
    }

    /// Returns all HTTPS host patterns used in the rules (to issue certificates).
    pub fn required_tls_hosts(&self) -> Vec<&HostPattern> {
        let mut out = Vec::new();
        for rule in &self.rules {
            for target in &rule.to {
                if target.scheme == Scheme::Https && !out.contains(&&target.host) {
                    out.push(&target.host);
                }
            }
        }
        out
    }

    /// Checks whether a client may establish a connection to `(scheme, host, port)`
    /// **before** resolving DNS or opening a `CONNECT` tunnel.
    pub fn can_connect(
        &self,
        client_ip: IpAddr,
        scheme: Scheme,
        host: &str,
        port: u16,
    ) -> ConnectDecision {
        let Some(client) = self.find_client_by_ip(client_ip) else {
            return ConnectDecision::Deny {
                reason: DenyReason::UnknownClient,
                client_name: None,
            };
        };

        let host_lower = host.to_ascii_lowercase();
        if !is_valid_hostname(&host_lower) || port == 0 {
            return ConnectDecision::Deny {
                reason: DenyReason::InvalidHost,
                client_name: Some(client.name.clone()),
            };
        }

        let matching_rules: Vec<String> = self
            .rules
            .iter()
            .filter(|rule| {
                rule.from.matches(&client.name)
                    && rule.to.iter().any(|t| t.matches(scheme, &host_lower, port))
            })
            .map(|r| r.name.clone())
            .collect();

        if matching_rules.is_empty() {
            ConnectDecision::Deny {
                reason: DenyReason::NoMatchingRule,
                client_name: Some(client.name.clone()),
            }
        } else {
            ConnectDecision::Allow {
                client_name: client.name.clone(),
                matching_rules,
            }
        }
    }

    /// Evaluates a complete HTTP/HTTPS request against the policy (default-deny, first matching rule wins).
    pub fn evaluate(&self, req: &EvalRequest<'_>) -> Decision {
        let Some(client) = self.find_client_by_ip(req.client_ip) else {
            return Decision::Deny {
                reason: DenyReason::UnknownClient,
                client_name: None,
            };
        };

        let host_lower = req.host.to_ascii_lowercase();
        if !is_valid_hostname(&host_lower) || req.port == 0 {
            return Decision::Deny {
                reason: DenyReason::InvalidHost,
                client_name: Some(client.name.clone()),
            };
        }

        let Some(method) = HttpMethod::parse(req.method) else {
            return Decision::Deny {
                reason: DenyReason::InvalidMethod,
                client_name: Some(client.name.clone()),
            };
        };

        let clean_path = match validate_request_path(req.path) {
            Ok(p) => p,
            Err(err) => {
                return Decision::Deny {
                    reason: DenyReason::AmbiguousPath(err.to_string()),
                    client_name: Some(client.name.clone()),
                };
            }
        };

        for rule in &self.rules {
            if !rule.from.matches(&client.name) {
                continue;
            }
            if !rule
                .to
                .iter()
                .any(|t| t.matches(req.scheme, &host_lower, req.port))
            {
                continue;
            }
            if !rule
                .allows
                .iter()
                .any(|a| a.methods.matches(method) && a.path.matches_validated(clean_path))
            {
                continue;
            }

            return Decision::Allow(AllowedMatch {
                client_name: client.name.clone(),
                rule_name: rule.name.clone(),
                transforms: rule.transforms.clone(),
                log_body: rule.log_body,
            });
        }

        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
            client_name: Some(client.name.clone()),
        }
    }
}

/// Applies the resolved transforms in order to a list of HTTP headers `(name, value)`.
///
/// - `SetHeader`: overwrites all previous occurrences (case-insensitive) or adds the header if it does not exist.
/// - `ReplaceHeader`: if the header is already present (case-insensitive), replaces all its occurrences
///   with a single value; if it is not in the request, adds nothing.
/// - `RemoveHeader`: removes all occurrences of the header (case-insensitive).
pub fn apply_transforms(headers: &mut Vec<(String, String)>, transforms: &[ResolvedTransform]) {
    for transform in transforms {
        match transform {
            ResolvedTransform::SetHeader { name, value } => {
                if let Some(first_idx) =
                    headers.iter().position(|(k, _)| k.eq_ignore_ascii_case(name))
                {
                    headers[first_idx] = (name.clone(), value.clone());
                    remove_duplicate_headers_after(headers, first_idx, name);
                } else {
                    headers.push((name.clone(), value.clone()));
                }
            }
            ResolvedTransform::ReplaceHeader { name, value } => {
                if let Some(first_idx) =
                    headers.iter().position(|(k, _)| k.eq_ignore_ascii_case(name))
                {
                    headers[first_idx] = (name.clone(), value.clone());
                    remove_duplicate_headers_after(headers, first_idx, name);
                }
            }
            ResolvedTransform::RemoveHeader { name } => {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
            }
        }
    }
}

fn remove_duplicate_headers_after(
    headers: &mut Vec<(String, String)>,
    first_idx: usize,
    name: &str,
) {
    let mut i = first_idx + 1;
    while i < headers.len() {
        if headers[i].0.eq_ignore_ascii_case(name) {
            headers.remove(i);
        } else {
            i += 1;
        }
    }
}
