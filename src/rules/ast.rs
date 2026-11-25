use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Position of a declaration within the rules file (useful for errors and CLI editing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

/// Syntax error or static validation error when parsing a rules file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    pub fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Complete policy loaded from `rules.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub clients: Vec<Client>,
    pub rules: Vec<Rule>,
}

/// Client identified by its IP address or CIDR subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub name: String,
    pub addr: ClientAddr,
    pub span: Span,
}

/// Exact IP address or CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAddr {
    Exact(IpAddr),
    Cidr { network: IpAddr, prefix_len: u8 },
}

impl ClientAddr {
    /// Checks whether `ip` belongs to this address or subnet.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (ClientAddr::Exact(a), b) => a == b,
            (
                ClientAddr::Cidr {
                    network: IpAddr::V4(net),
                    prefix_len,
                },
                IpAddr::V4(addr),
            ) => {
                let mask = ipv4_mask(prefix_len);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (
                ClientAddr::Cidr {
                    network: IpAddr::V6(net),
                    prefix_len,
                },
                IpAddr::V6(addr),
            ) => {
                let mask = ipv6_mask(prefix_len);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }

    /// Returns `true` if the two addresses/CIDRs have at least one IP in common.
    pub fn overlaps(&self, other: &ClientAddr) -> bool {
        match (self.as_v4_cidr(), other.as_v4_cidr()) {
            (Some((n1, p1)), Some((n2, p2))) => {
                let mask = ipv4_mask(p1.min(p2));
                (n1 & mask) == (n2 & mask)
            }
            _ => match (self.as_v6_cidr(), other.as_v6_cidr()) {
                (Some((n1, p1)), Some((n2, p2))) => {
                    let mask = ipv6_mask(p1.min(p2));
                    (n1 & mask) == (n2 & mask)
                }
                _ => false,
            },
        }
    }

    fn as_v4_cidr(&self) -> Option<(u32, u8)> {
        match *self {
            ClientAddr::Exact(IpAddr::V4(ip)) => Some((u32::from(ip), 32)),
            ClientAddr::Cidr {
                network: IpAddr::V4(net),
                prefix_len,
            } => Some((u32::from(net), prefix_len)),
            _ => None,
        }
    }

    fn as_v6_cidr(&self) -> Option<(u128, u8)> {
        match *self {
            ClientAddr::Exact(IpAddr::V6(ip)) => Some((u128::from(ip), 128)),
            ClientAddr::Cidr {
                network: IpAddr::V6(net),
                prefix_len,
            } => Some((u128::from(net), prefix_len)),
            _ => None,
        }
    }
}

pub(crate) fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    }
}

pub(crate) fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - prefix_len)
    }
}

pub(crate) fn ipv4_has_host_bits(ip: Ipv4Addr, prefix_len: u8) -> bool {
    let raw = u32::from(ip);
    (raw & !ipv4_mask(prefix_len)) != 0
}

pub(crate) fn ipv6_has_host_bits(ip: Ipv6Addr, prefix_len: u8) -> bool {
    let raw = u128::from(ip);
    (raw & !ipv6_mask(prefix_len)) != 0
}

impl fmt::Display for ClientAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientAddr::Exact(ip) => write!(f, "{ip}"),
            ClientAddr::Cidr {
                network,
                prefix_len,
            } => write!(f, "{network}/{prefix_len}"),
        }
    }
}

/// Authorization and transformation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub from: FromMatcher,
    pub to: Vec<Target>,
    pub allows: Vec<AllowRule>,
    pub transforms: Vec<Transform>,
    pub log_body: bool,
    pub span: Span,
}

impl Rule {
    /// Returns the secret names referenced by this rule (in order, without duplicates).
    pub fn referenced_secrets(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for transform in &self.transforms {
            if let Transform::SetHeader { value, .. } | Transform::ReplaceHeader { value, .. } =
                transform
            {
                for part in &value.parts {
                    if let TemplatePart::Secret(name) = part
                        && !out.contains(&name.as_str())
                    {
                        out.push(name.as_str());
                    }
                }
            }
        }
        out
    }
}

/// Match on declared source clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromMatcher {
    /// Any client explicitly declared with `client`.
    AnyDeclared,
    /// List of specific client names.
    Clients(Vec<String>),
}

impl FromMatcher {
    pub fn matches(&self, client_name: &str) -> bool {
        match self {
            FromMatcher::AnyDeclared => true,
            FromMatcher::Clients(names) => names.iter().any(|n| n == client_name),
        }
    }
}

/// Allowed destination scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Destination domain pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostPattern {
    /// Exact lowercase-normalized domain (e.g. `api.stripe.com`).
    Exact(String),
    /// Single-level wildcard: `*.foo.com` stores `suffix = "foo.com"`.
    Wildcard { suffix: String },
}

impl HostPattern {
    pub fn is_wildcard(&self) -> bool {
        matches!(self, HostPattern::Wildcard { .. })
    }

    /// Checks whether an already lowercase-normalized host matches the pattern.
    pub fn matches(&self, host_lower: &str) -> bool {
        match self {
            HostPattern::Exact(exact) => host_lower == exact,
            HostPattern::Wildcard { suffix } => {
                let Some(rest) = host_lower.strip_suffix(suffix.as_str()) else {
                    return false;
                };
                let Some(label) = rest.strip_suffix('.') else {
                    return false;
                };
                !label.is_empty() && !label.contains('.')
            }
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => f.write_str(h),
            HostPattern::Wildcard { suffix } => write!(f, "*.{suffix}"),
        }
    }
}

/// Complete destination `(scheme, host, port)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub scheme: Scheme,
    pub host: HostPattern,
    pub port: u16,
}

impl Target {
    pub fn matches(&self, scheme: Scheme, host_lower: &str, port: u16) -> bool {
        self.scheme == scheme && self.port == port && self.host.matches(host_lower)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.scheme, self.port) {
            (Scheme::Https, 443) => write!(f, "{}", self.host),
            (Scheme::Https, port) => write!(f, "{}:{port}", self.host),
            (Scheme::Http, 80) => write!(f, "http://{}", self.host),
            (Scheme::Http, port) => write!(f, "http://{}:{port}", self.host),
        }
    }
}

/// HTTP methods supported in `allow` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl HttpMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP method match in an `allow` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodMatcher {
    Any,
    List(Vec<HttpMethod>),
}

impl MethodMatcher {
    pub fn matches(&self, method: HttpMethod) -> bool {
        match self {
            MethodMatcher::Any => true,
            MethodMatcher::List(list) => list.contains(&method),
        }
    }
}

impl fmt::Display for MethodMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MethodMatcher::Any => f.write_str("*"),
            MethodMatcher::List(list) => {
                for (i, m) in list.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    f.write_str(m.as_str())?;
                }
                Ok(())
            }
        }
    }
}

/// Segment within a path pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Literal(String),
    Wildcard,
}

/// HTTP path pattern (`*` one segment, `**` zero or more segments, last position only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    pub segments: Vec<PathSegment>,
    pub trailing_glob: bool,
    pub trailing_slash: bool,
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            if self.trailing_glob {
                return f.write_str("/**");
            }
            return f.write_str("/");
        }
        for seg in &self.segments {
            f.write_str("/")?;
            match seg {
                PathSegment::Literal(lit) => f.write_str(lit)?,
                PathSegment::Wildcard => f.write_str("*")?,
            }
        }
        if self.trailing_glob {
            f.write_str("/**")?;
        } else if self.trailing_slash {
            f.write_str("/")?;
        }
        Ok(())
    }
}

/// `allow <methods> <path_pattern>` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub methods: MethodMatcher,
    pub path: PathPattern,
}

/// Header transform applied when the rule authorizes a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transform {
    /// Sets a header unconditionally (adds it if missing or overwrites it).
    SetHeader {
        /// Lowercase-normalized name.
        name: String,
        value: ValueTemplate,
    },
    /// Replaces a header only if it is already present in the incoming request.
    ReplaceHeader {
        /// Lowercase-normalized name.
        name: String,
        value: ValueTemplate,
    },
    /// Removes a header if present.
    RemoveHeader {
        /// Lowercase-normalized name.
        name: String,
    },
}

/// Value template with `${secret.x}` and `${client.name}` variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueTemplate {
    pub parts: Vec<TemplatePart>,
}

impl ValueTemplate {
    /// Indicates whether the template references any secret.
    pub fn uses_secrets(&self) -> bool {
        self.parts
            .iter()
            .any(|p| matches!(p, TemplatePart::Secret(_)))
    }

    /// Resolves the template by substituting `${client.name}` and the secrets through `lookup_secret`.
    pub fn resolve<F>(&self, client_name: &str, mut lookup_secret: F) -> Result<String, String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => out.push_str(s),
                TemplatePart::ClientName => out.push_str(client_name),
                TemplatePart::Secret(secret_name) => {
                    let secret = lookup_secret(secret_name)
                        .ok_or_else(|| format!("secret not found: {secret_name}"))?;
                    out.push_str(&secret);
                }
            }
        }
        Ok(out)
    }

    /// Renders the template resolving `${client.name}` but keeping the secrets redacted.
    pub fn render_redacted(&self, client_name: &str) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => out.push_str(s),
                TemplatePart::ClientName => out.push_str(client_name),
                TemplatePart::Secret(secret_name) => {
                    out.push_str("${secret.");
                    out.push_str(secret_name);
                    out.push('}');
                }
            }
        }
        out
    }
}

impl fmt::Display for ValueTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => f.write_str(s)?,
                TemplatePart::ClientName => f.write_str("${client.name}")?,
                TemplatePart::Secret(name) => write!(f, "${{secret.{name}}}")?,
            }
        }
        Ok(())
    }
}

/// Segment of a value template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePart {
    Literal(String),
    ClientName,
    Secret(String),
}

/// Incoming request to evaluate against a `Policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalRequest<'a> {
    pub client_ip: IpAddr,
    pub scheme: Scheme,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
}

/// Decision returned by the evaluator for a complete HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(AllowedMatch),
    Deny {
        reason: DenyReason,
        client_name: Option<String>,
    },
}

/// Result of an authorized request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedMatch {
    pub client_name: String,
    pub rule_name: String,
    pub transforms: Vec<Transform>,
    pub log_body: bool,
}

impl AllowedMatch {
    /// Resolves all transforms by substituting `${client.name}` and `${secret.*}`.
    pub fn resolve_transforms<F>(
        &self,
        mut lookup_secret: F,
    ) -> Result<Vec<ResolvedTransform>, String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut resolved = Vec::with_capacity(self.transforms.len());
        for t in &self.transforms {
            match t {
                Transform::SetHeader { name, value } => {
                    let val = value.resolve(&self.client_name, &mut lookup_secret)?;
                    resolved.push(ResolvedTransform::SetHeader {
                        name: name.clone(),
                        value: val,
                    });
                }
                Transform::ReplaceHeader { name, value } => {
                    let val = value.resolve(&self.client_name, &mut lookup_secret)?;
                    resolved.push(ResolvedTransform::ReplaceHeader {
                        name: name.clone(),
                        value: val,
                    });
                }
                Transform::RemoveHeader { name } => {
                    resolved.push(ResolvedTransform::RemoveHeader { name: name.clone() });
                }
            }
        }
        Ok(resolved)
    }
}

/// Transform ready to be applied to real HTTP headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTransform {
    /// Adds or overwrites the header unconditionally.
    SetHeader { name: String, value: String },
    /// Replaces the header only if it already existed in the request.
    ReplaceHeader { name: String, value: String },
    /// Removes the header.
    RemoveHeader { name: String },
}

/// Reason why a request was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    UnknownClient,
    InvalidHost,
    InvalidMethod,
    AmbiguousPath(String),
    NoMatchingRule,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::UnknownClient => f.write_str("undeclared client"),
            DenyReason::InvalidHost => f.write_str("invalid host"),
            DenyReason::InvalidMethod => f.write_str("HTTP method not allowed"),
            DenyReason::AmbiguousPath(detail) => write!(f, "ambiguous path: {detail}"),
            DenyReason::NoMatchingRule => f.write_str("no rule matches"),
        }
    }
}

/// Decision before DNS / connection (`CONNECT` or HTTP request before resolving).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectDecision {
    Allow {
        client_name: String,
        matching_rules: Vec<String>,
    },
    Deny {
        reason: DenyReason,
        client_name: Option<String>,
    },
}
