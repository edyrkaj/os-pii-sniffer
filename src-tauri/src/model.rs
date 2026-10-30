use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::pii::{Finding, FindingAction, PiiType};

/// Hosts that commonly break under local MITM (cert pinning / browser suites).
pub const DEFAULT_BYPASS_HOSTS: &[&str] = &[
    "*.google.com",
    "*.googleapis.com",
    "*.gstatic.com",
    "*.googleusercontent.com",
    "*.youtube.com",
    "*.ytimg.com",
    "*.ggpht.com",
    "*.apple.com",
    "*.icloud.com",
    "*.icloud-content.com",
    "*.mzstatic.com",
    "*.cdn-apple.com",
    "*.microsoft.com",
    "*.live.com",
    "*.office.com",
    "*.office.net",
    "*.windowsupdate.com",
    "*.mozilla.com",
    "*.mozilla.net",
    "*.firefox.com",
    "*.brave.com",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingView {
    pub pii_type: String,
    pub field_path: String,
    pub action: String,
    pub token: String,
}

impl FindingView {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            pii_type: finding.pii_type.as_str().to_string(),
            field_path: finding.field_path.clone(),
            action: match finding.action {
                FindingAction::Masked | FindingAction::AlertedOnly => "detected",
                FindingAction::Allowed => "allowed",
            }
            .to_string(),
            token: match finding.action {
                FindingAction::Masked | FindingAction::AlertedOnly => {
                    "sent unchanged".to_string()
                }
                FindingAction::Allowed => "already-masked".to_string(),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActivityDraft {
    pub process_name: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub action: String,
    pub alert: bool,
    pub detail: Option<String>,
    pub findings: Vec<FindingView>,
}

#[derive(Clone, Debug)]
pub struct ServiceSighting {
    pub process_name: String,
    pub host: String,
    /// `inspected` when MITM'd, `tunneled` when CONNECT is passed through.
    pub mode: String,
    pub scanned: bool,
    pub pii: bool,
}

#[derive(Clone, Debug)]
pub enum SnifferEvent {
    Activity(ActivityDraft),
    Service(ServiceSighting),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEvent {
    pub id: String,
    pub timestamp: String,
    pub process_name: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub action: String,
    pub alert: bool,
    pub seen: bool,
    pub detail: Option<String>,
    pub findings: Vec<FindingView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEvent {
    pub host: String,
    pub process_name: String,
    pub first_seen: String,
    pub last_seen: String,
    pub connect_count: i64,
    pub scanned_count: i64,
    pub pii_count: i64,
    pub last_mode: String,
}

/// Exact host, without scheme, path, or port.
pub fn normalize_host(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut value = trimmed.to_ascii_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            value = rest.to_string();
        }
    }
    if let Some((host, _)) = value.split_once('/') {
        value = host.to_string();
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            value = host.to_string();
        }
    }
    if value.is_empty() || value.contains(' ') || value.contains('*') || value.contains('@') {
        return None;
    }
    Some(value)
}

/// Exact host or a single `*.domain.tld` wildcard for bypass lists.
pub fn normalize_bypass(input: &str) -> Option<String> {
    let trimmed = input.trim().to_ascii_lowercase();
    if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.is_empty()
            || rest.contains('*')
            || rest.contains(' ')
            || rest.contains('/')
            || rest.contains('@')
            || rest.contains(':')
        {
            return None;
        }
        return Some(format!("*.{rest}"));
    }
    normalize_host(input)
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

pub fn host_is_bypassed(host: &str, patterns: &HashSet<String>) -> bool {
    patterns.iter().any(|pattern| host_matches(pattern, host))
}

#[cfg(test)]
mod tests {
    use super::{host_is_bypassed, host_matches, normalize_bypass, normalize_host};
    use std::collections::HashSet;

    #[test]
    fn normalizes_exact_hosts() {
        assert_eq!(
            normalize_host(" HTTPS://Api.Example.com:443/v1 ").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(normalize_host("localhost").as_deref(), Some("localhost"));
        assert!(normalize_host("*.example.com").is_none());
        assert!(normalize_host("").is_none());
    }

    #[test]
    fn normalizes_wildcard_bypass() {
        assert_eq!(
            normalize_bypass("*.Google.com").as_deref(),
            Some("*.google.com")
        );
        assert_eq!(
            normalize_bypass("api.example.com").as_deref(),
            Some("api.example.com")
        );
        assert!(normalize_bypass("*.*.com").is_none());
        assert!(normalize_bypass("*").is_none());
    }

    #[test]
    fn matches_wildcard_and_exact_hosts() {
        assert!(host_matches("*.google.com", "www.google.com"));
        assert!(host_matches("*.google.com", "google.com"));
        assert!(!host_matches("*.google.com", "notgoogle.com"));
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(!host_matches("api.example.com", "other.example.com"));
    }

    #[test]
    fn bypass_set_matches_google_hosts() {
        let patterns = HashSet::from(["*.google.com".to_string(), "bank.example".to_string()]);
        assert!(host_is_bypassed("accounts.google.com", &patterns));
        assert!(host_is_bypassed("bank.example", &patterns));
        assert!(!host_is_bypassed("api.example.com", &patterns));
    }
}
