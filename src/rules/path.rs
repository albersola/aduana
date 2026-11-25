use std::fmt;

use super::ast::{PathPattern, PathSegment};

/// Error validating an incoming HTTP path (protection against normalization-based evasion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    MissingLeadingSlash,
    ContainsFragment,
    ControlChar,
    Backslash,
    DoubleSlash,
    InvalidPercentEncoding,
    EncodedForbiddenChar,
    DotSegment,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Empty => f.write_str("empty path"),
            PathError::MissingLeadingSlash => f.write_str("path must start with '/'"),
            PathError::ContainsFragment => f.write_str("path must not contain '#'"),
            PathError::ControlChar => f.write_str("path contains control characters"),
            PathError::Backslash => f.write_str("path contains '\\'"),
            PathError::DoubleSlash => f.write_str("path contains '//'"),
            PathError::InvalidPercentEncoding => f.write_str("invalid percent-encoding"),
            PathError::EncodedForbiddenChar => {
                f.write_str("forbidden percent-encoding ('.', '/', '\\' or control)")
            }
            PathError::DotSegment => f.write_str("path contains '.' or '..' segments"),
        }
    }
}

impl std::error::Error for PathError {}

/// Strictly validates the path of an HTTP request (without comparing the query string).
///
/// Returns the clean path portion without the query string (e.g. `"/v1/charges"`).
pub fn validate_request_path(raw: &str) -> Result<&str, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    if raw.contains('#') {
        return Err(PathError::ContainsFragment);
    }
    // Reject control characters in the entire target URI, including the query.
    if raw.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err(PathError::ControlChar);
    }

    let path = match raw.find('?') {
        Some(idx) => &raw[..idx],
        None => raw,
    };

    if !path.starts_with('/') {
        return Err(PathError::MissingLeadingSlash);
    }
    if path.contains('\\') {
        return Err(PathError::Backslash);
    }
    if path.contains("//") {
        return Err(PathError::DoubleSlash);
    }

    // Validate %XX sequences and reject encoded '.', '/', '\\' or control bytes.
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(PathError::InvalidPercentEncoding);
            }
            let hi = hex_val(bytes[i + 1]).ok_or(PathError::InvalidPercentEncoding)?;
            let lo = hex_val(bytes[i + 2]).ok_or(PathError::InvalidPercentEncoding)?;
            let decoded = (hi << 4) | lo;
            if decoded == b'.'
                || decoded == b'/'
                || decoded == b'\\'
                || decoded <= 0x1f
                || decoded == 0x7f
            {
                return Err(PathError::EncodedForbiddenChar);
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    // Reject '.' and '..' segments.
    if path != "/" {
        let rest = &path[1..];
        let trimmed = rest.strip_suffix('/').unwrap_or(rest);
        for seg in trimmed.split('/') {
            if seg == "." || seg == ".." {
                return Err(PathError::DotSegment);
            }
        }
    }

    Ok(path)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl PathPattern {
    /// Parses a path pattern declared in `allow <methods> <pattern>`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("path pattern must not be empty".into());
        }
        if !raw.starts_with('/') {
            return Err(format!("path pattern '{raw}' must start with '/'"));
        }
        if raw.contains('?') {
            return Err(format!(
                "path pattern '{raw}' must not include a query string ('?')"
            ));
        }
        if raw.contains('#') {
            return Err(format!(
                "path pattern '{raw}' must not include a fragment ('#')"
            ));
        }
        if raw.contains('\\') || raw.contains("//") {
            return Err(format!("ambiguous path pattern: '{raw}'"));
        }
        if raw.bytes().any(|b| b <= 0x1f || b == 0x7f) {
            return Err("path pattern contains control characters".into());
        }

        if raw == "/" {
            return Ok(PathPattern {
                segments: Vec::new(),
                trailing_glob: false,
                trailing_slash: true,
            });
        }

        let trailing_slash = raw.ends_with('/');
        let inner = &raw[1..];
        let trimmed = if trailing_slash {
            &inner[..inner.len() - 1]
        } else {
            inner
        };

        let raw_segments: Vec<&str> = trimmed.split('/').collect();
        let mut segments = Vec::with_capacity(raw_segments.len());
        let mut trailing_glob = false;

        for (idx, seg) in raw_segments.iter().enumerate() {
            if *seg == "." || *seg == ".." {
                return Err(format!(
                    "path pattern '{raw}' must not contain '.' or '..' segments"
                ));
            }
            if *seg == "**" {
                if idx + 1 != raw_segments.len() || trailing_slash {
                    return Err(format!(
                        "in '{raw}', '**' may only appear as the last segment"
                    ));
                }
                trailing_glob = true;
            } else if *seg == "*" {
                segments.push(PathSegment::Wildcard);
            } else if seg.contains('*') {
                return Err(format!(
                    "in '{raw}', '*' wildcards must occupy a whole segment"
                ));
            } else {
                segments.push(PathSegment::Literal((*seg).to_string()));
            }
        }

        Ok(PathPattern {
            segments,
            trailing_glob,
            trailing_slash: if trailing_glob { false } else { trailing_slash },
        })
    }

    /// Checks whether a path already validated with `validate_request_path` matches this pattern.
    pub fn matches_validated(&self, clean_path: &str) -> bool {
        if clean_path == "/" {
            return self.segments.is_empty();
        }

        let req_trailing_slash = clean_path.ends_with('/');
        let inner = &clean_path[1..];
        let trimmed = if req_trailing_slash {
            &inner[..inner.len() - 1]
        } else {
            inner
        };
        let req_segments: Vec<&str> = trimmed.split('/').collect();

        if self.trailing_glob {
            if req_segments.len() < self.segments.len() {
                return false;
            }
            return segments_match(&self.segments, &req_segments[..self.segments.len()]);
        }

        if req_trailing_slash != self.trailing_slash {
            return false;
        }
        if req_segments.len() != self.segments.len() {
            return false;
        }
        segments_match(&self.segments, &req_segments)
    }
}

fn segments_match(pattern: &[PathSegment], actual: &[&str]) -> bool {
    pattern.iter().zip(actual.iter()).all(|(pat, act)| match pat {
        PathSegment::Literal(lit) => lit == act,
        PathSegment::Wildcard => !act.is_empty(),
    })
}
