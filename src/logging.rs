//! Structured JSONL logging with daily rotation, retention and secret redaction.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::secrets::SecretStore;

/// Maximum body size recorded in logs (64 KiB). Real traffic passes through in full.
pub const MAX_LOGGED_BODY_BYTES: usize = 64 * 1024;

/// Default retention days for `events-YYYY-MM-DD.jsonl` files.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// Headers whose values are always redacted before writing to disk.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-secret",
    "api-key",
];

/// Event recorded by Aduana (one JSON line in `events-YYYY-MM-DD.jsonl`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEvent {
    pub timestamp: String,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    pub client_ip: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}

/// Filters for querying logs with `aduana log` and `aduana denied`.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub decision: Option<String>,
    pub client: Option<String>,
    pub host: Option<String>,
    /// Minimum inclusive date `YYYY-MM-DD`.
    pub since: Option<String>,
    pub limit: usize,
}

/// JSONL event writer with daily rotation and cleanup of old files.
pub struct LogWriter {
    dir: Option<PathBuf>,
    retention_days: u32,
    echo_stderr: bool,
    lock: Mutex<Option<String>>, // last cleaned date
}

impl LogWriter {
    pub fn new(dir: Option<PathBuf>, retention_days: u32, echo_stderr: bool) -> Result<Self, String> {
        if let Some(ref d) = dir {
            fs::create_dir_all(d).map_err(|e| {
                format!("could not create log directory '{}': {e}", d.display())
            })?;
        }
        let writer = Self {
            dir,
            retention_days,
            echo_stderr,
            lock: Mutex::new(None),
        };
        writer.cleanup_old_files_if_needed(SystemTime::now());
        Ok(writer)
    }

    pub fn write(&self, event: &LogEvent) {
        if self.echo_stderr {
            let client_label = event.client.as_deref().unwrap_or("-");
            let path_label = event.path.as_deref().unwrap_or("");
            let detail = event
                .rule
                .as_deref()
                .or(event.reason.as_deref())
                .unwrap_or("-");
            let status = event
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into());
            eprintln!(
                "{} {} client={}({}) {} {}://{}:{}{} status={} ({}) {}ms",
                event.timestamp,
                event.decision.to_ascii_uppercase(),
                client_label,
                event.client_ip,
                event.method,
                event.scheme,
                event.host,
                event.port,
                path_label,
                status,
                detail,
                event.duration_ms
            );
        }

        let Some(ref dir) = self.dir else {
            return;
        };

        let now = SystemTime::now();
        let date = utc_date_string(now);
        let file_path = dir.join(format!("events-{date}.jsonl"));
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };

        let mut guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_deref() != Some(date.as_str()) {
            let _ = cleanup_old_logs(dir, self.retention_days, now);
            *guard = Some(date);
        }

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&file_path) {
            let _ = writeln!(file, "{line}");
        }
    }

    fn cleanup_old_files_if_needed(&self, now: SystemTime) {
        if let Some(ref dir) = self.dir {
            let _ = cleanup_old_logs(dir, self.retention_days, now);
        }
    }
}

/// Removes `events-YYYY-MM-DD.jsonl` files older than `retention_days`.
pub fn cleanup_old_logs(dir: &Path, retention_days: u32, now: SystemTime) -> Result<usize, String> {
    if retention_days == 0 || !dir.exists() {
        return Ok(0);
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(u64::from(retention_days) * 86_400))
        .unwrap_or(UNIX_EPOCH);
    let cutoff_date = utc_date_string(cutoff);
    let mut removed = 0;

    let entries = fs::read_dir(dir)
        .map_err(|e| format!("could not read '{}': {e}", dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(date_part) = name_str
            .strip_prefix("events-")
            .and_then(|s| s.strip_suffix(".jsonl"))
        else {
            continue;
        };
        if is_valid_date_ymd(date_part) && date_part < cutoff_date.as_str()
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Queries events stored in the JSONL files of `dir`.
pub fn query_logs(dir: &Path, filter: &LogFilter) -> Result<Vec<LogEvent>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("could not read log directory '{}': {e}", dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(date_part) = name_str
            .strip_prefix("events-")
            .and_then(|s| s.strip_suffix(".jsonl"))
        else {
            continue;
        };
        if !is_valid_date_ymd(date_part) {
            continue;
        }
        if let Some(ref since) = filter.since
            && date_part < since.as_str()
        {
            continue;
        }
        files.push((date_part.to_string(), entry.path()));
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut matched = Vec::new();
    for (_, path) in files {
        let file = File::open(&path)
            .map_err(|e| format!("could not open '{}': {e}", path.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let Ok(line) = line else { continue };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<LogEvent>(trimmed) else {
                continue;
            };
            if matches_filter(&event, filter) {
                matched.push(event);
            }
        }
    }

    if filter.limit > 0 && matched.len() > filter.limit {
        let start = matched.len() - filter.limit;
        matched.drain(0..start);
    }

    Ok(matched)
}

fn matches_filter(event: &LogEvent, filter: &LogFilter) -> bool {
    if let Some(ref dec) = filter.decision
        && !event.decision.eq_ignore_ascii_case(dec)
    {
        return false;
    }
    if let Some(ref client) = filter.client {
        let client_match = event
            .client
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(client))
            || event.client_ip == *client;
        if !client_match {
            return false;
        }
    }
    if let Some(ref host) = filter.host {
        let needle = host.to_ascii_lowercase();
        if !event.host.to_ascii_lowercase().contains(&needle) {
            return false;
        }
    }
    if let Some(ref since) = filter.since {
        let event_date = event.timestamp.get(0..10).unwrap_or("");
        if event_date < since.as_str() {
            return false;
        }
    }
    true
}

/// Redacts sensitive headers and any exact value of loaded secrets.
pub fn redact_headers(
    headers: &[(String, String)],
    secrets: &SecretStore,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            let redacted_val = if is_sensitive_header(&lower) {
                "[REDACTED]".to_string()
            } else {
                secrets.redact(v)
            };
            (lower, redacted_val)
        })
        .collect()
}

pub fn is_sensitive_header(name_lower: &str) -> bool {
    SENSITIVE_HEADERS.contains(&name_lower)
}

/// Formats a captured body for the log applying a 64 KiB limit, detection of
/// compression/binary content and secret redaction.
pub fn format_body_for_log(
    captured: &[u8],
    total_len: usize,
    content_encoding: Option<&str>,
    content_type: Option<&str>,
    secrets: &SecretStore,
) -> String {
    if total_len == 0 {
        return String::new();
    }

    if let Some(enc) = content_encoding {
        let enc_lower = enc.trim().to_ascii_lowercase();
        if !enc_lower.is_empty() && enc_lower != "identity" {
            return format!("[compressed/{enc_lower} {total_len} bytes]");
        }
    }

    if let Some(ct) = content_type {
        let ct_lower = ct.to_ascii_lowercase();
        if is_binary_content_type(&ct_lower) {
            return format!("[binary {total_len} bytes]");
        }
    }

    let slice = &captured[..captured.len().min(MAX_LOGGED_BODY_BYTES)];
    let Ok(text) = std::str::from_utf8(slice) else {
        return format!("[binary {total_len} bytes]");
    };
    if text
        .bytes()
        .any(|b| b == 0 || (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')))
    {
        return format!("[binary {total_len} bytes]");
    }

    let mut out = secrets.redact(text);
    if total_len > MAX_LOGGED_BODY_BYTES {
        out.push_str(&format!("\n...[truncated, {total_len} bytes total]"));
    }
    out
}

fn is_binary_content_type(ct_lower: &str) -> bool {
    let media = ct_lower.split(';').next().unwrap_or("").trim();
    media.starts_with("image/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || media.starts_with("font/")
        || matches!(
            media,
            "application/octet-stream"
                | "application/pdf"
                | "application/zip"
                | "application/gzip"
                | "application/x-gzip"
                | "application/zstd"
                | "application/protobuf"
                | "application/grpc"
        )
}

/// Current UTC date in `YYYY-MM-DD` format.
pub fn utc_date_string(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// UTC timestamp in RFC3339 format (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
pub fn utc_rfc3339(time: SystemTime) -> String {
    let dur = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let hour = sod / 3600;
    let min = (sod % 3600) / 60;
    let sec = sod % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Validates the `YYYY-MM-DD` format.
pub fn is_valid_date_ymd(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// Conversion of days since 1970-01-01 to `(year, month, day)` (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_headers_and_secret_values() {
        let secrets = SecretStore::from_pairs([("tok", "super_secret_42")]).unwrap();
        let headers = vec![
            ("Authorization".into(), "Bearer anything".into()),
            ("X-Custom".into(), "prefix-super_secret_42-suffix".into()),
            ("Accept".into(), "application/json".into()),
        ];
        let redacted = redact_headers(&headers, &secrets);
        assert_eq!(
            redacted,
            vec![
                ("authorization".into(), "[REDACTED]".into()),
                ("x-custom".into(), "prefix-[REDACTED]-suffix".into()),
                ("accept".into(), "application/json".into()),
            ]
        );
    }

    #[test]
    fn formats_compressed_binary_and_truncated_bodies() {
        let secrets = SecretStore::from_pairs([("k", "sk_real_999")]).unwrap();
        assert_eq!(
            format_body_for_log(b"\x1f\x8b...", 1200, Some("gzip"), Some("application/json"), &secrets),
            "[compressed/gzip 1200 bytes]"
        );
        assert_eq!(
            format_body_for_log(b"\x89PNG\r\n\x1a\n", 8, None, Some("image/png"), &secrets),
            "[binary 8 bytes]"
        );
        assert_eq!(
            format_body_for_log(b"token=sk_real_999", 17, None, Some("text/plain"), &secrets),
            "token=[REDACTED]"
        );

        let big = vec![b'a'; MAX_LOGGED_BODY_BYTES + 100];
        let logged = format_body_for_log(&big, big.len(), None, Some("text/plain"), &secrets);
        assert!(logged.ends_with("...[truncated, 65636 bytes total]"));
    }

    #[test]
    fn formats_known_epoch_dates() {
        assert_eq!(utc_date_string(UNIX_EPOCH), "1970-01-01");
        // 2026-01-01T00:00:00Z = 1767225600
        let t = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert_eq!(utc_rfc3339(t), "2026-01-01T00:00:00.000Z");
    }
}
