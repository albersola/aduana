//! Loading and redaction of secrets from `.env` files.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

/// In-memory store of loaded secrets (never prints their values in `Debug`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretStore {
    values: BTreeMap<String, String>,
    extra_redactions: Vec<String>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<&str> = self.values.keys().map(String::as_str).collect();
        f.debug_struct("SecretStore").field("keys", &keys).finish()
    }
}

impl SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store from key/value pairs (useful for tests).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut values = BTreeMap::new();
        for (k, v) in pairs {
            let key = k.into();
            let val = v.into();
            validate_secret_value(&key, &val)?;
            values.insert(key, val);
        }
        Ok(Self {
            values,
            extra_redactions: Vec::new(),
        })
    }

    /// Loads secrets from a `.env` file. Fails if the file does not exist or is invalid.
    pub fn load_env_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("could not read secrets file '{}': {e}", path.display()))?;
        Self::parse_env(&content)
            .map_err(|e| format!("error in secrets file '{}': {e}", path.display()))
    }

    /// Loads secrets from a `.env` file if it exists; if it does not, returns an empty store.
    pub fn load_optional_env_file(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }
        Self::load_env_file(path)
    }

    /// Parses text in `.env` format (`KEY=value`, `#` comments, single or double quotes).
    pub fn parse_env(input: &str) -> Result<Self, String> {
        let mut values = BTreeMap::new();

        for (idx, raw_line) in input.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let line = trimmed.strip_prefix("export ").map(str::trim_start).unwrap_or(trimmed);
            let Some((raw_key, raw_val)) = line.split_once('=') else {
                return Err(format!("line {line_num}: invalid format, expected KEY=value"));
            };

            let key = raw_key.trim();
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(format!("line {line_num}: invalid secret name '{key}'"));
            }

            let val = parse_env_value(raw_val.trim(), line_num)?;
            validate_secret_value(key, &val)?;
            values.insert(key.to_string(), val);
        }

        Ok(Self {
            values,
            extra_redactions: Vec::new(),
        })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Returns the names of secrets that are missing from a required list.
    pub fn missing<'a>(&self, required: &[&'a str]) -> Vec<&'a str> {
        required
            .iter()
            .copied()
            .filter(|name| !self.values.contains_key(*name))
            .collect()
    }

    /// Returns a clone of this store that also redacts derived secret values (e.g. Base64-encoded
    /// credentials) in logs, without exposing them through `get()`.
    pub fn with_extra_redactions(&self, extra: impl IntoIterator<Item = String>) -> Self {
        let mut cloned = self.clone();
        for val in extra {
            if !val.is_empty() && !cloned.extra_redactions.contains(&val) {
                cloned.extra_redactions.push(val);
            }
        }
        cloned
    }

    /// Replaces any exact occurrence of the loaded secret values (and derived values) with `[REDACTED]`.
    pub fn redact(&self, input: &str) -> String {
        if (self.values.is_empty() && self.extra_redactions.is_empty()) || input.is_empty() {
            return input.to_string();
        }
        // Sort from longest to shortest to avoid partial redactions when one secret contains another.
        let mut secret_vals: Vec<&str> = self
            .values
            .values()
            .chain(self.extra_redactions.iter())
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .collect();
        secret_vals.sort_by_key(|v| std::cmp::Reverse(v.len()));

        let mut out = input.to_string();
        for secret in secret_vals {
            if out.contains(secret) {
                out = out.replace(secret, "[REDACTED]");
            }
        }
        out
    }
}

fn parse_env_value(raw: &str, line_num: usize) -> Result<String, String> {
    if let Some(rest) = raw.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    let trailing = chars.as_str().trim();
                    if !trailing.is_empty() && !trailing.starts_with('#') {
                        return Err(format!(
                            "line {line_num}: unexpected text after closing quote"
                        ));
                    }
                    closed = true;
                    break;
                }
                '\\' => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        return Err(format!(
                            "line {line_num}: unsupported escape sequence '\\{other}'"
                        ));
                    }
                    None => {
                        return Err(format!(
                            "line {line_num}: incomplete escape inside quotes"
                        ));
                    }
                },
                other => out.push(other),
            }
        }
        if !closed {
            return Err(format!("line {line_num}: unterminated double quotes"));
        }
        Ok(out)
    } else if let Some(rest) = raw.strip_prefix('\'') {
        let Some((val, trailing)) = rest.split_once('\'') else {
            return Err(format!("line {line_num}: unterminated single quotes"));
        };
        let trailing = trailing.trim();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return Err(format!(
                "line {line_num}: unexpected text after closing single quote"
            ));
        }
        Ok(val.to_string())
    } else {
        // Unquoted value: strip an inline comment only if preceded by space/tab.
        let mut end = raw.len();
        let bytes = raw.as_bytes();
        for i in 1..bytes.len() {
            if bytes[i] == b'#' && bytes[i - 1].is_ascii_whitespace() {
                end = i;
                break;
            }
        }
        Ok(raw[..end].trim().to_string())
    }
}

fn validate_secret_value(key: &str, value: &str) -> Result<(), String> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(format!(
            "secret '{key}' contains disallowed characters (CR/LF/NUL)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotenv_formats_and_redacts() {
        let env = r#"
# Comentario
stripe_key=sk_live_123456
export github_pat="ghp_super_secret_token"
quoted_single='tok_with_#hash'
inline_comment=val_123 # comentario al final
"#;
        let store = SecretStore::parse_env(env).unwrap();
        assert_eq!(store.get("stripe_key"), Some("sk_live_123456"));
        assert_eq!(store.get("github_pat"), Some("ghp_super_secret_token"));
        assert_eq!(store.get("quoted_single"), Some("tok_with_#hash"));
        assert_eq!(store.get("inline_comment"), Some("val_123"));

        let text = "Bearer ghp_super_secret_token y sk_live_123456";
        assert_eq!(store.redact(text), "Bearer [REDACTED] y [REDACTED]");
        // Debug never exposes values
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("sk_live_123456"));
        assert!(dbg.contains("stripe_key"));
    }
}
