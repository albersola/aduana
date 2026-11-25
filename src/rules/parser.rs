use std::collections::HashSet;
use std::net::IpAddr;

use super::ast::{
    AllowRule, Client, ClientAddr, FromMatcher, HostPattern, HttpMethod, MethodMatcher, ParseError,
    PathPattern, Policy, Rule, Scheme, Span, Target, TemplatePart, Transform, ValueTemplate,
    ipv4_has_host_bits, ipv6_has_host_bits,
};

/// HTTP headers that rules may not modify or remove.
pub const PROTECTED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// Returns `true` if the header is protected (case-insensitive).
pub fn is_protected_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PROTECTED_HEADERS.contains(&lower.as_str())
}

#[derive(Debug)]
struct Line<'a> {
    number: usize,
    start_byte: usize,
    end_byte: usize,
    text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    text: String,
    quoted: bool,
}

/// Parses and statically validates a complete rules file.
pub fn parse_rules(input: &str) -> Result<Policy, ParseError> {
    let lines = split_lines_with_spans(input);
    let mut clients: Vec<Client> = Vec::new();
    let mut rules: Vec<Rule> = Vec::new();

    let mut idx = 0;
    while idx < lines.len() {
        let line = &lines[idx];
        let tokens = tokenize_line(line.text, line.number)?;
        if tokens.is_empty() {
            idx += 1;
            continue;
        }

        match tokens[0].text.as_str() {
            "client" => {
                if tokens[0].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected unquoted 'client' directive",
                    ));
                }
                let client = parse_client_line(&tokens, line)?;
                clients.push(client);
                idx += 1;
            }
            "rule" => {
                if tokens[0].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected unquoted 'rule' directive",
                    ));
                }
                let (rule, next_idx) = parse_rule_block(&lines, idx, &tokens)?;
                rules.push(rule);
                idx = next_idx;
            }
            "deny" => {
                return Err(ParseError::new(
                    line.number,
                    "Aduana uses a pure allowlist (default-deny): there is no 'deny' directive",
                ));
            }
            other => {
                return Err(ParseError::new(
                    line.number,
                    format!("directiva desconocida en nivel superior: '{other}'"),
                ));
            }
        }
    }

    validate_policy(&clients, &rules)?;

    Ok(Policy { clients, rules })
}

fn split_lines_with_spans(input: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut offset = 0;
    for (i, raw_line) in input.split_inclusive('\n').enumerate() {
        let end_byte = offset + raw_line.len();
        let text = raw_line
            .strip_suffix('\n')
            .unwrap_or(raw_line)
            .strip_suffix('\r')
            .unwrap_or(raw_line.strip_suffix('\n').unwrap_or(raw_line));
        out.push(Line {
            number: i + 1,
            start_byte: offset,
            end_byte,
            text,
        });
        offset = end_byte;
    }
    out
}

fn tokenize_line(line: &str, line_num: usize) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == '#' {
            break;
        }
        if c == '{' || c == '}' {
            tokens.push(Token {
                text: c.to_string(),
                quoted: false,
            });
            i += 1;
            continue;
        }
        if c == '"' {
            i += 1;
            let mut val = String::new();
            let mut closed = false;
            while i < chars.len() {
                match chars[i] {
                    '"' => {
                        closed = true;
                        i += 1;
                        break;
                    }
                    '\\' => {
                        i += 1;
                        if i >= chars.len() {
                            return Err(ParseError::new(
                                line_num,
                                "incomplete escape inside quotes",
                            ));
                        }
                        match chars[i] {
                            '"' => val.push('"'),
                            '\\' => val.push('\\'),
                            other => {
                                return Err(ParseError::new(
                                    line_num,
                                    format!("unsupported escape sequence: '\\{other}'"),
                                ));
                            }
                        }
                        i += 1;
                    }
                    ch if (ch as u32) <= 0x1f || (ch as u32) == 0x7f => {
                        return Err(ParseError::new(
                            line_num,
                            "control character not allowed inside a string",
                        ));
                    }
                    ch => {
                        val.push(ch);
                        i += 1;
                    }
                }
            }
            if !closed {
                return Err(ParseError::new(line_num, "unclosed quotes"));
            }
            tokens.push(Token {
                text: val,
                quoted: true,
            });
            continue;
        }

        let mut word = String::new();
        while i < chars.len() {
            let ch = chars[i];
            if ch.is_ascii_whitespace() || ch == '#' || ch == '{' || ch == '}' || ch == '"' {
                break;
            }
            word.push(ch);
            i += 1;
        }
        tokens.push(Token {
            text: word,
            quoted: false,
        });
    }

    Ok(tokens)
}

fn parse_client_line(tokens: &[Token], line: &Line<'_>) -> Result<Client, ParseError> {
    if tokens.len() != 3 {
        return Err(ParseError::new(
            line.number,
            "expected syntax: client <name> <ip-or-cidr>",
        ));
    }
    let name = &tokens[1].text;
    validate_identifier(name, line.number, "client name")?;
    let addr = parse_client_addr(&tokens[2].text, line.number)?;
    Ok(Client {
        name: name.clone(),
        addr,
        span: Span {
            start_byte: line.start_byte,
            end_byte: line.end_byte,
            start_line: line.number,
            end_line: line.number,
        },
    })
}

fn parse_client_addr(raw: &str, line_num: usize) -> Result<ClientAddr, ParseError> {
    if let Some((ip_str, prefix_str)) = raw.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| ParseError::new(line_num, format!("invalid IP in CIDR: '{raw}'")))?;
        let prefix_len: u8 = prefix_str.parse().map_err(|_| {
            ParseError::new(line_num, format!("invalid CIDR prefix in '{raw}'"))
        })?;
        match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(ParseError::new(
                        line_num,
                        format!("IPv4 prefix out of range (0..=32): '{raw}'"),
                    ));
                }
                if ipv4_has_host_bits(v4, prefix_len) {
                    return Err(ParseError::new(
                        line_num,
                        format!("non-canonical CIDR (has host bits set): '{raw}'"),
                    ));
                }
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(ParseError::new(
                        line_num,
                        format!("IPv6 prefix out of range (0..=128): '{raw}'"),
                    ));
                }
                if ipv6_has_host_bits(v6, prefix_len) {
                    return Err(ParseError::new(
                        line_num,
                        format!("non-canonical CIDR (has host bits set): '{raw}'"),
                    ));
                }
            }
        }
        Ok(ClientAddr::Cidr {
            network: ip,
            prefix_len,
        })
    } else {
        let ip: IpAddr = raw
            .parse()
            .map_err(|_| ParseError::new(line_num, format!("invalid IP address: '{raw}'")))?;
        Ok(ClientAddr::Exact(ip))
    }
}

fn parse_rule_block(
    lines: &[Line<'_>],
    start_idx: usize,
    header_tokens: &[Token],
) -> Result<(Rule, usize), ParseError> {
    let header_line = &lines[start_idx];
    if header_tokens.len() != 3 || header_tokens[2].text != "{" || header_tokens[2].quoted {
        return Err(ParseError::new(
            header_line.number,
            "expected syntax: rule <name> {",
        ));
    }
    let rule_name = &header_tokens[1].text;
    validate_identifier(rule_name, header_line.number, "rule name")?;

    let mut from_any = false;
    let mut from_clients: Vec<String> = Vec::new();
    let mut targets: Vec<Target> = Vec::new();
    let mut allows: Vec<AllowRule> = Vec::new();
    let mut transforms: Vec<Transform> = Vec::new();
    let mut log_body = false;

    let mut idx = start_idx + 1;
    let mut closed_line: Option<&Line<'_>> = None;

    while idx < lines.len() {
        let line = &lines[idx];
        let tokens = tokenize_line(line.text, line.number)?;
        if tokens.is_empty() {
            idx += 1;
            continue;
        }

        if tokens.len() == 1 && tokens[0].text == "}" && !tokens[0].quoted {
            closed_line = Some(line);
            idx += 1;
            break;
        }

        if tokens[0].quoted {
            return Err(ParseError::new(
                line.number,
                "unexpected quoted directive inside rule",
            ));
        }

        match tokens[0].text.as_str() {
            "from" => {
                let items = split_list_tokens(&tokens[1..], line.number, "from")?;
                for item in items {
                    if item == "*" {
                        if !from_clients.is_empty() {
                            return Err(ParseError::new(
                                line.number,
                                "cannot mix 'from *' with specific client names",
                            ));
                        }
                        from_any = true;
                    } else {
                        if from_any {
                            return Err(ParseError::new(
                                line.number,
                                "cannot mix 'from *' with specific client names",
                            ));
                        }
                        validate_identifier(&item, line.number, "client in from")?;
                        if !from_clients.contains(&item) {
                            from_clients.push(item);
                        }
                    }
                }
            }
            "to" => {
                let items = split_list_tokens(&tokens[1..], line.number, "to")?;
                for item in items {
                    let target = parse_target(&item, line.number)?;
                    if !targets.contains(&target) {
                        targets.push(target);
                    }
                }
            }
            "allow" => {
                if tokens.len() != 3 {
                    return Err(ParseError::new(
                        line.number,
                        "expected syntax: allow <METHOD[,METHOD]|*> <path>",
                    ));
                }
                let methods = parse_methods(&tokens[1].text, line.number)?;
                let path = PathPattern::parse(&tokens[2].text)
                    .map_err(|msg| ParseError::new(line.number, msg))?;
                allows.push(AllowRule { methods, path });
            }
            "deny" => {
                return Err(ParseError::new(
                    line.number,
                    "Aduana uses a pure allowlist (default-deny): there is no 'deny' directive",
                ));
            }
            "set" => {
                if tokens.len() != 4 || tokens[1].text != "header" || tokens[1].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected syntax: set header <name> \"<value>\"",
                    ));
                }
                let header_name = parse_header_name(&tokens[2].text, line.number)?;
                let value = parse_value_template(&tokens[3].text, line.number)?;
                transforms.push(Transform::SetHeader {
                    name: header_name,
                    value,
                });
            }
            "replace" => {
                if tokens.len() != 4 || tokens[1].text != "header" || tokens[1].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected syntax: replace header <name> \"<value>\"",
                    ));
                }
                let header_name = parse_header_name(&tokens[2].text, line.number)?;
                let value = parse_value_template(&tokens[3].text, line.number)?;
                transforms.push(Transform::ReplaceHeader {
                    name: header_name,
                    value,
                });
            }
            "remove" => {
                if tokens.len() != 3 || tokens[1].text != "header" || tokens[1].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected syntax: remove header <name>",
                    ));
                }
                let header_name = parse_header_name(&tokens[2].text, line.number)?;
                transforms.push(Transform::RemoveHeader { name: header_name });
            }
            "log" => {
                if tokens.len() != 2 || tokens[1].text != "body" || tokens[1].quoted {
                    return Err(ParseError::new(
                        line.number,
                        "expected syntax: log body",
                    ));
                }
                log_body = true;
            }
            other => {
                return Err(ParseError::new(
                    line.number,
                    format!("unknown directive inside rule '{rule_name}': '{other}'"),
                ));
            }
        }

        idx += 1;
    }

    let end_line = closed_line.ok_or_else(|| {
        ParseError::new(
            header_line.number,
            format!("rule '{rule_name}' is missing its closing brace '}}'"),
        )
    })?;

    let from = if from_any {
        FromMatcher::AnyDeclared
    } else if !from_clients.is_empty() {
        FromMatcher::Clients(from_clients)
    } else {
        return Err(ParseError::new(
            header_line.number,
            format!("rule '{rule_name}' must include at least one 'from' directive"),
        ));
    };

    if targets.is_empty() {
        return Err(ParseError::new(
            header_line.number,
            format!("rule '{rule_name}' must include at least one 'to' directive"),
        ));
    }

    if allows.is_empty() {
        return Err(ParseError::new(
            header_line.number,
            format!("rule '{rule_name}' must include at least one 'allow' directive"),
        ));
    }

    Ok((
        Rule {
            name: rule_name.clone(),
            from,
            to: targets,
            allows,
            transforms,
            log_body,
            span: Span {
                start_byte: header_line.start_byte,
                end_byte: end_line.end_byte,
                start_line: header_line.number,
                end_line: end_line.number,
            },
        },
        idx,
    ))
}

fn split_list_tokens(
    tokens: &[Token],
    line_num: usize,
    directive: &str,
) -> Result<Vec<String>, ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::new(
            line_num,
            format!("directive '{directive}' requires at least one argument"),
        ));
    }
    let mut items = Vec::new();
    for tok in tokens {
        for part in tok.text.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                items.push(trimmed.to_string());
            }
        }
    }
    if items.is_empty() {
        return Err(ParseError::new(
            line_num,
            format!("directive '{directive}' requires at least one valid argument"),
        ));
    }
    Ok(items)
}

fn parse_target(raw: &str, line_num: usize) -> Result<Target, ParseError> {
    if raw == "*" {
        return Err(ParseError::new(
            line_num,
            "'to *' is not allowed: destinations must be explicit domains or '*.domain.tld'",
        ));
    }

    let (scheme, rest) = if let Some(after) = raw.strip_prefix("https://") {
        (Scheme::Https, after)
    } else if let Some(after) = raw.strip_prefix("http://") {
        (Scheme::Http, after)
    } else if raw.contains("://") {
        return Err(ParseError::new(
            line_num,
            format!("unsupported scheme in destination '{raw}' (only http or https)"),
        ));
    } else {
        (Scheme::Https, raw)
    };

    if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err(ParseError::new(
            line_num,
            format!("destination '{raw}' may only contain scheme, host and optional port"),
        ));
    }

    let (host_str, port) = match rest.rsplit_once(':') {
        Some((h, p_str)) => {
            let port: u16 = p_str.parse().map_err(|_| {
                ParseError::new(line_num, format!("invalid port in destination '{raw}'"))
            })?;
            if port == 0 {
                return Err(ParseError::new(
                    line_num,
                    format!("port cannot be 0 in '{raw}'"),
                ));
            }
            (h, port)
        }
        None => (rest, scheme.default_port()),
    };

    let host = parse_host_pattern(host_str, line_num)?;
    Ok(Target { scheme, host, port })
}

fn parse_host_pattern(raw: &str, line_num: usize) -> Result<HostPattern, ParseError> {
    let lower = raw.to_ascii_lowercase();
    if lower.is_empty() {
        return Err(ParseError::new(line_num, "host must not be empty"));
    }

    if let Some(suffix) = lower.strip_prefix("*.") {
        if !suffix.contains('.') {
            return Err(ParseError::new(
                line_num,
                format!(
                    "wildcard too broad '{raw}': requires at least two labels (e.g. '*.example.com')"
                ),
            ));
        }
        validate_hostname(suffix, line_num)?;
        Ok(HostPattern::Wildcard {
            suffix: suffix.to_string(),
        })
    } else {
        if lower.contains('*') {
            return Err(ParseError::new(
                line_num,
                format!(
                    "invalid host wildcard '{raw}': only single-level '*.domain.tld' is allowed"
                ),
            ));
        }
        validate_hostname(&lower, line_num)?;
        Ok(HostPattern::Exact(lower))
    }
}

pub(crate) fn validate_hostname(host: &str, line_num: usize) -> Result<(), ParseError> {
    if !is_valid_hostname(host) {
        return Err(ParseError::new(
            line_num,
            format!("invalid host name: '{host}'"),
        ));
    }
    Ok(())
}

/// Checks that a lowercase-normalized host is a valid DNS name (not an IP, no trailing dot).
pub(crate) fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
    }
    true
}

fn parse_methods(raw: &str, line_num: usize) -> Result<MethodMatcher, ParseError> {
    if raw == "*" {
        return Ok(MethodMatcher::Any);
    }
    let mut methods = Vec::new();
    for part in raw.split(',') {
        if part.is_empty() {
            return Err(ParseError::new(
                line_num,
                format!("invalid method list: '{raw}'"),
            ));
        }
        if part == "*" {
            return Err(ParseError::new(
                line_num,
                "cannot mix '*' with specific methods",
            ));
        }
        let method = HttpMethod::parse(part).ok_or_else(|| {
            ParseError::new(
                line_num,
                format!("unsupported HTTP method in allow: '{part}'"),
            )
        })?;
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        return Err(ParseError::new(line_num, "missing HTTP method in allow"));
    }
    Ok(MethodMatcher::List(methods))
}

fn parse_header_name(raw: &str, line_num: usize) -> Result<String, ParseError> {
    if raw.is_empty() {
        return Err(ParseError::new(
            line_num,
            "header name must not be empty",
        ));
    }
    if !raw.bytes().all(is_http_tchar) {
        return Err(ParseError::new(
            line_num,
            format!("invalid HTTP header name: '{raw}'"),
        ));
    }
    let lower = raw.to_ascii_lowercase();
    if is_protected_header(&lower) {
        return Err(ParseError::new(
            line_num,
            format!("header '{lower}' is protected and cannot be modified or removed"),
        ));
    }
    Ok(lower)
}

fn is_http_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
            | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

fn parse_value_template(raw: &str, line_num: usize) -> Result<ValueTemplate, ParseError> {
    if raw.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(ParseError::new(
            line_num,
            "header value contains disallowed characters (CR/LF/NUL)",
        ));
    }

    let parts = parse_value_template_parts(raw, line_num, true)?;
    Ok(ValueTemplate { parts })
}

fn parse_value_template_parts(
    raw: &str,
    line_num: usize,
    allow_base64: bool,
) -> Result<Vec<TemplatePart>, ParseError> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let bytes = raw.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if !literal.is_empty() {
                parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
            }
            let start = i + 2;
            if raw[start..].starts_with("base64(") {
                if !allow_base64 {
                    return Err(ParseError::new(
                        line_num,
                        "nested '${base64(...)}' is not allowed",
                    ));
                }
                let inner_start = start + "base64(".len();
                let inner_end = find_base64_end(raw, inner_start, line_num)?;
                let inner_raw = &raw[inner_start..inner_end];
                if inner_raw.is_empty() {
                    return Err(ParseError::new(
                        line_num,
                        "'${base64(...)}' must not be empty",
                    ));
                }
                let inner_parts = parse_value_template_parts(inner_raw, line_num, false)?;
                parts.push(TemplatePart::Base64(inner_parts));
                i = inner_end + 2; // skip `)}`
                continue;
            }

            let Some(rel_end) = raw[start..].find('}') else {
                return Err(ParseError::new(
                    line_num,
                    "unclosed '${...}' variable in header value",
                ));
            };
            let expr = &raw[start..start + rel_end];
            if expr == "client.name" {
                parts.push(TemplatePart::ClientName);
            } else if let Some(secret_name) = expr.strip_prefix("secret.") {
                validate_identifier(secret_name, line_num, "secret name")?;
                parts.push(TemplatePart::Secret(secret_name.to_string()));
            } else {
                return Err(ParseError::new(
                    line_num,
                    format!(
                        "unknown variable '${{{expr}}}' (only '${{secret.<name>}}', '${{client.name}}' and '${{base64(...)}}' are allowed)"
                    ),
                ));
            }
            i = start + rel_end + 1;
        } else {
            let ch = raw[i..].chars().next().unwrap();
            literal.push(ch);
            i += ch.len_utf8();
        }
    }

    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }

    Ok(parts)
}

fn find_base64_end(raw: &str, inner_start: usize, line_num: usize) -> Result<usize, ParseError> {
    let bytes = raw.as_bytes();
    let mut j = inner_start;
    let mut brace_depth: usize = 0;

    while j < bytes.len() {
        if bytes[j] == b'$' && j + 1 < bytes.len() && bytes[j + 1] == b'{' {
            brace_depth += 1;
            j += 2;
        } else if bytes[j] == b'}' && brace_depth > 0 {
            brace_depth -= 1;
            j += 1;
        } else if brace_depth == 0
            && bytes[j] == b')'
            && j + 1 < bytes.len()
            && bytes[j + 1] == b'}'
        {
            return Ok(j);
        } else if brace_depth == 0 && bytes[j] == b'}' {
            return Err(ParseError::new(
                line_num,
                "unclosed '${base64(...)}' in header value",
            ));
        } else {
            j += 1;
        }
    }

    Err(ParseError::new(
        line_num,
        "unclosed '${base64(...)}' in header value",
    ))
}

fn validate_identifier(s: &str, line_num: usize, kind: &str) -> Result<(), ParseError> {
    let valid = !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(ParseError::new(
            line_num,
            format!("invalid {kind}: '{s}' (use only letters, digits, '-' and '_')"),
        ));
    }
    Ok(())
}

fn validate_policy(clients: &[Client], rules: &[Rule]) -> Result<(), ParseError> {
    // 1. Unique clients with no overlapping IPs/CIDRs.
    let mut client_names = HashSet::new();
    for (i, client) in clients.iter().enumerate() {
        if !client_names.insert(client.name.as_str()) {
            return Err(ParseError::new(
                client.span.start_line,
                format!("duplicate client: '{}'", client.name),
            ));
        }
        for prev in &clients[..i] {
            if prev.addr.overlaps(&client.addr) {
                return Err(ParseError::new(
                    client.span.start_line,
                    format!(
                        "address '{}' of client '{}' overlaps with '{}' of '{}'",
                        client.addr, client.name, prev.addr, prev.name
                    ),
                ));
            }
        }
    }

    // 2. Unique rules, existing clients and secret restrictions.
    let mut rule_names = HashSet::new();
    for rule in rules {
        if !rule_names.insert(rule.name.as_str()) {
            return Err(ParseError::new(
                rule.span.start_line,
                format!("duplicate rule: '{}'", rule.name),
            ));
        }

        if let FromMatcher::Clients(ref names) = rule.from {
            for name in names {
                if !client_names.contains(name.as_str()) {
                    return Err(ParseError::new(
                        rule.span.start_line,
                        format!(
                            "rule '{}' references undeclared client '{}'",
                            rule.name, name
                        ),
                    ));
                }
            }
        }

        let uses_secrets = rule.transforms.iter().any(|t| match t {
            Transform::SetHeader { value, .. } | Transform::ReplaceHeader { value, .. } => {
                value.uses_secrets()
            }
            Transform::RemoveHeader { .. } => false,
        });

        if uses_secrets {
            for target in &rule.to {
                if target.scheme != Scheme::Https {
                    return Err(ParseError::new(
                        rule.span.start_line,
                        format!(
                            "rule '{}' uses secrets but allows a non-HTTPS destination ('{}')",
                            rule.name, target
                        ),
                    ));
                }
                if target.host.is_wildcard() {
                    return Err(ParseError::new(
                        rule.span.start_line,
                        format!(
                            "rule '{}' uses secrets but allows a host with a wildcard ('{}')",
                            rule.name, target
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}
