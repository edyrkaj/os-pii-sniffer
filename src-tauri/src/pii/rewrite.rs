use serde_json::{Map, Value};

use super::detect::analyze_text;
use super::{Finding, FindingAction, PiiType, Rules};

pub const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug)]
pub struct RewriteResult {
    pub body: Vec<u8>,
    pub findings: Vec<Finding>,
    pub alert: bool,
    pub skipped: Option<String>,
}

pub fn rewrite_body(content_type: Option<&str>, body: Vec<u8>, rules: &Rules) -> RewriteResult {
    if body.len() > MAX_BODY {
        return RewriteResult {
            body,
            findings: Vec::new(),
            alert: false,
            skipped: Some("not scanned: too large".to_string()),
        };
    }
    if body.is_empty() {
        return unchanged(body);
    }
    let content_type = content_type.unwrap_or("");
    let media = media_type(content_type);
    if media == "application/json" || media.ends_with("+json") {
        return rewrite_json(body, rules);
    }
    if media == "application/x-www-form-urlencoded" {
        return rewrite_form(body, rules);
    }
    if media == "multipart/form-data" {
        return rewrite_multipart(content_type, body, rules);
    }
    if media.starts_with("text/") || media.is_empty() {
        return rewrite_utf8(body, rules);
    }
    unchanged(body)
}

fn unchanged(body: Vec<u8>) -> RewriteResult {
    RewriteResult {
        body,
        findings: Vec::new(),
        alert: false,
        skipped: None,
    }
}

fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn rewrite_utf8(body: Vec<u8>, rules: &Rules) -> RewriteResult {
    let Ok(text) = String::from_utf8(body.clone()) else {
        return unchanged(body);
    };
    if text.chars().any(|ch| ch == '\u{0}') {
        return unchanged(body);
    }
    let edited = analyze_text(&text, "body", rules);
    RewriteResult {
        body: edited.text.into_bytes(),
        findings: edited.findings,
        alert: edited.alert,
        skipped: None,
    }
}

fn rewrite_json(body: Vec<u8>, rules: &Rules) -> RewriteResult {
    let Ok(text) = std::str::from_utf8(&body) else {
        return unchanged(body);
    };
    let Ok(mut value) = serde_json::from_str::<Value>(text) else {
        return rewrite_utf8(body, rules);
    };
    let mut findings = Vec::new();
    let mut alert = false;
    walk_json(&mut value, "$", rules, &mut findings, &mut alert);
    let rendered = serde_json::to_vec(&value).unwrap_or(body);
    RewriteResult {
        body: rendered,
        findings,
        alert,
        skipped: None,
    }
}

fn walk_json(
    value: &mut Value,
    path: &str,
    rules: &Rules,
    findings: &mut Vec<Finding>,
    alert: &mut bool,
) {
    match value {
        Value::Object(map) => {
            apply_contact(map, path, rules, findings, alert);
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let child = format!("{path}.{key}");
                if let Some(child_value) = map.get_mut(&key) {
                    walk_json(child_value, &child, rules, findings, alert);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let child = format!("{path}[{index}]");
                walk_json(item, &child, rules, findings, alert);
            }
        }
        Value::String(text) => {
            if findings.iter().any(|finding| finding.field_path == path) {
                return;
            }
            let edited = analyze_text(text, path, rules);
            *alert = *alert || edited.alert;
            findings.extend(edited.findings);
            *text = edited.text;
        }
        _ => {}
    }
}

fn apply_contact(
    map: &mut Map<String, Value>,
    path: &str,
    rules: &Rules,
    findings: &mut Vec<Finding>,
    alert: &mut bool,
) {
    let rule = rules.contact;
    if !rule.enabled() || !is_contact_object(map) {
        return;
    }
    let Some(name_key) = map.keys().find(|key| is_name_key(key)).cloned() else {
        return;
    };
    let Some(name) = map
        .get(&name_key)
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    let field_path = format!("{path}.{name_key}");
    if super::detect::is_field_encrypted(&name) || name == PiiType::Contact.token() {
        findings.push(Finding {
            pii_type: PiiType::Contact,
            field_path,
            action: FindingAction::Allowed,
        });
        return;
    }
    if rule.mask {
        map.insert(
            name_key,
            Value::String(PiiType::Contact.token().to_string()),
        );
        findings.push(Finding {
            pii_type: PiiType::Contact,
            field_path,
            action: FindingAction::Masked,
        });
        if rule.alert {
            *alert = true;
        }
    } else if rule.alert {
        findings.push(Finding {
            pii_type: PiiType::Contact,
            field_path,
            action: FindingAction::AlertedOnly,
        });
        *alert = true;
    }
}

fn is_contact_object(map: &Map<String, Value>) -> bool {
    let Some(name_key) = map.keys().find(|key| is_name_key(key)) else {
        return false;
    };
    let Some(name) = map.get(name_key).and_then(Value::as_str) else {
        return false;
    };
    looks_like_person_name(name) && object_has_email_or_phone(map)
}

fn looks_like_person_name(value: &str) -> bool {
    let value = value.trim();
    value.contains(' ')
        && value.chars().count() <= 80
        && !value.contains('@')
        && value
            .chars()
            .all(|ch| ch.is_alphabetic() || ch.is_whitespace() || matches!(ch, '\'' | '-' | '.'))
        && value.chars().filter(|ch| ch.is_alphabetic()).count() >= 2
}

fn is_name_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "name"
            | "full_name"
            | "fullname"
            | "first_name"
            | "firstname"
            | "last_name"
            | "lastname"
            | "given_name"
            | "family_name"
    )
}

fn object_has_email_or_phone(map: &Map<String, Value>) -> bool {
    map.values().any(value_has_email_or_phone)
}

fn value_has_email_or_phone(value: &Value) -> bool {
    match value {
        Value::String(text) => analyze_text(text, "", &Rules::default())
            .findings
            .iter()
            .any(|finding| matches!(finding.pii_type, PiiType::Email | PiiType::Phone)),
        Value::Array(items) => items.iter().any(value_has_email_or_phone),
        Value::Object(map) => map.values().any(value_has_email_or_phone),
        _ => false,
    }
}

fn rewrite_form(body: Vec<u8>, rules: &Rules) -> RewriteResult {
    let pairs: Vec<(String, String)> = form_urlencoded::parse(&body).into_owned().collect();
    if pairs.is_empty() && !body.is_empty() {
        return rewrite_utf8(body, rules);
    }
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let mut findings = Vec::new();
    let mut alert = false;
    for (key, value) in pairs {
        let path = format!("$.{key}");
        let edited = analyze_text(&value, &path, rules);
        alert = alert || edited.alert;
        findings.extend(edited.findings);
        serializer.append_pair(&key, &edited.text);
    }
    RewriteResult {
        body: serializer.finish().into_bytes(),
        findings,
        alert,
        skipped: None,
    }
}

fn rewrite_multipart(content_type: &str, body: Vec<u8>, rules: &Rules) -> RewriteResult {
    let Some(boundary) = boundary(content_type) else {
        return unchanged(body);
    };
    let marker = format!("--{boundary}");
    let raw = match String::from_utf8(body.clone()) {
        Ok(text) => text,
        Err(_) => return unchanged(body),
    };
    if !raw.contains(&marker) {
        return unchanged(body);
    }
    let mut findings = Vec::new();
    let mut alert = false;
    let mut rebuilt = String::new();
    let parts: Vec<&str> = raw.split(&marker).collect();
    for (index, part) in parts.iter().enumerate() {
        if index == 0 {
            rebuilt.push_str(part);
            continue;
        }
        rebuilt.push_str(&marker);
        if part.starts_with("--") {
            rebuilt.push_str(part);
            continue;
        }
        let Some((headers, content)) = split_part(part) else {
            rebuilt.push_str(part);
            continue;
        };
        if !part_is_text(headers) {
            rebuilt.push_str(part);
            continue;
        }
        let name = field_name(headers).unwrap_or_else(|| "part".to_string());
        let path = format!("$.{name}");
        let edited = analyze_text(content, &path, rules);
        alert = alert || edited.alert;
        findings.extend(edited.findings);
        rebuilt.push_str(headers);
        rebuilt.push_str("\r\n\r\n");
        rebuilt.push_str(&edited.text);
    }
    RewriteResult {
        body: rebuilt.into_bytes(),
        findings,
        alert,
        skipped: None,
    }
}

fn boundary(content_type: &str) -> Option<String> {
    for piece in content_type.split(';').skip(1) {
        let piece = piece.trim();
        let value = piece.strip_prefix("boundary=")?.trim();
        let value = value.trim_matches('"');
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn split_part(part: &str) -> Option<(&str, &str)> {
    let part = part.strip_prefix("\r\n").unwrap_or(part);
    if let Some((headers, content)) = part.split_once("\r\n\r\n") {
        return Some((headers, content));
    }
    part.split_once("\n\n")
}

fn part_is_text(headers: &str) -> bool {
    let lower = headers.to_ascii_lowercase();
    if lower.contains("content-type:") {
        let is_text = lower.contains("text/")
            || lower.contains("application/json")
            || lower.contains("application/x-www-form-urlencoded");
        return is_text;
    }
    !lower.contains("filename=")
}

fn field_name(headers: &str) -> Option<String> {
    let lower = headers.to_ascii_lowercase();
    let start = lower.find("name=\"")? + 6;
    let rest = headers.get(start..)?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules() -> Rules {
        Rules::default()
    }

    #[test]
    fn rewrites_json_form_and_leaves_safe_values() {
        let json_body = br#"{"email":"ada@example.com","note":"hello world"}"#.to_vec();
        let rewritten = rewrite_body(Some("application/json"), json_body, &rules());
        let value: Value = serde_json::from_slice(&rewritten.body).unwrap();
        assert_eq!(value["email"], "[redacted-email]");
        assert_eq!(value["note"], "hello world");
        assert!(rewritten.alert);
        assert!(rewritten.skipped.is_none());

        let masked = br#"{"email":"a***@example.com"}"#.to_vec();
        let rewritten = rewrite_body(Some("application/json; charset=utf-8"), masked, &rules());
        let value: Value = serde_json::from_slice(&rewritten.body).unwrap();
        assert_eq!(value["email"], "a***@example.com");
        assert!(!rewritten.alert);
        assert_eq!(rewritten.findings[0].action, FindingAction::Allowed);

        let encrypted = br#"{"email":"enc:abcdefghijklmnopqrstuvwxyz0123456789ABCD"}"#.to_vec();
        let rewritten = rewrite_body(Some("application/json"), encrypted, &rules());
        let value: Value = serde_json::from_slice(&rewritten.body).unwrap();
        assert_eq!(
            value["email"],
            "enc:abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        );
        assert!(rewritten.findings.is_empty());

        let form = b"email=ada%40example.com&note=hello".to_vec();
        let rewritten = rewrite_body(Some("application/x-www-form-urlencoded"), form, &rules());
        let parsed: Vec<(String, String)> = form_urlencoded::parse(&rewritten.body)
            .into_owned()
            .collect();
        assert_eq!(parsed[0].1, "[redacted-email]");
        assert_eq!(parsed[1].1, "hello");
    }

    #[test]
    fn masks_a_contact_object_and_nested_email() {
        let body = serde_json::to_vec(&json!({
            "name": "Ada Lovelace",
            "email": "ada@example.com"
        }))
        .unwrap();
        let rewritten = rewrite_body(Some("application/json"), body, &rules());
        let value: Value = serde_json::from_slice(&rewritten.body).unwrap();
        assert_eq!(value["name"], "[redacted-contact]");
        assert_eq!(value["email"], "[redacted-email]");
        assert!(
            rewritten
                .findings
                .iter()
                .any(|finding| finding.pii_type == PiiType::Contact)
        );
    }

    #[test]
    fn skips_bodies_over_one_mebibyte_without_a_finding_payload() {
        let body = vec![b'a'; MAX_BODY + 1];
        let rewritten = rewrite_body(Some("text/plain"), body.clone(), &rules());
        assert_eq!(rewritten.skipped.as_deref(), Some("not scanned: too large"));
        assert!(rewritten.findings.is_empty());
        assert_eq!(rewritten.body.len(), body.len());
    }

    #[test]
    fn rewrites_text_parts_of_multipart_forms() {
        let raw = "\
--bnd\r\n\
Content-Disposition: form-data; name=\"email\"\r\n\
\r\n\
ada@example.com\r\n\
--bnd\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\
Content-Type: image/png\r\n\
\r\n\
\u{0}png\r\n\
--bnd--\r\n";
        let rewritten = rewrite_body(
            Some("multipart/form-data; boundary=bnd"),
            raw.as_bytes().to_vec(),
            &rules(),
        );
        let text = String::from_utf8(rewritten.body).unwrap();
        assert!(text.contains("[redacted-email]"));
        assert!(!text.contains("ada@example.com"));
        assert!(text.contains("filename=\"a.png\""));
    }
}
