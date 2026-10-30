use serde::{Deserialize, Serialize};

use crate::pii::{Finding, FindingAction, PiiType};

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
                FindingAction::Masked => "masked",
                FindingAction::Allowed => "allowed",
                FindingAction::AlertedOnly => "allowed",
            }
            .to_string(),
            token: match finding.action {
                FindingAction::Masked => PiiType::token(finding.pii_type).to_string(),
                FindingAction::Allowed => "already-masked".to_string(),
                FindingAction::AlertedOnly => "not-masked".to_string(),
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
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        value = host.to_string();
    }
    if value.is_empty() || value.contains(' ') || value.contains('*') || value.contains('@') {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::normalize_host;

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
}
