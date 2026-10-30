use std::sync::LazyLock;

use regex::Regex;

use super::{Finding, FindingAction, PiiType, Rules};

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").expect("email regex")
});

static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        (?:
            \+\d{10,15}
            |
            \+\d{1,3}[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}
            |
            \(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}
        )
        ",
    )
    .expect("phone regex")
});

static CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d(?:[ -]?\d){12,18}").expect("card regex"));

static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b\d{1,6}\s+(?:[A-Za-z][A-Za-z0-9.'\-]*\s+){1,5}(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?",
    )
    .expect("address regex")
});

static VCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)BEGIN:VCARD\b.*?END:VCARD").expect("vcard regex"));

#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    kind: PiiType,
    safe: bool,
}

pub fn token_for(kind: PiiType) -> &'static str {
    kind.token()
}

pub fn is_field_encrypted(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 12 {
        return false;
    }
    if value.len() >= 12 && value[..4].eq_ignore_ascii_case("enc:") && is_opaque_token(&value[4..])
    {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 5
        && parts
            .iter()
            .all(|part| part.len() >= 8 && is_base64url(part))
        && (value.starts_with("eyJ") || value.starts_with("eyj"))
    {
        return true;
    }
    value.len() >= 40 && is_opaque_token(value) && !value.contains('@') && digit_ratio(value) < 0.8
}

pub struct TextEdit {
    pub text: String,
    pub findings: Vec<Finding>,
    pub alert: bool,
}

pub fn analyze_text(text: &str, path: &str, rules: &Rules) -> TextEdit {
    if is_field_encrypted(text) {
        return TextEdit {
            text: text.to_string(),
            findings: Vec::new(),
            alert: false,
        };
    }
    if let Some(kind) = whole_value_safe(text.trim()) {
        return safe_whole_value(text, path, kind, rules);
    }

    let spans = find_spans(text);
    if spans.is_empty() {
        return TextEdit {
            text: text.to_string(),
            findings: Vec::new(),
            alert: false,
        };
    }

    let mut output = String::new();
    let mut findings = Vec::new();
    let mut alert = false;
    let mut cursor = 0;
    for span in spans {
        if span.start < cursor {
            continue;
        }
        output.push_str(&text[cursor..span.start]);
        let slice = &text[span.start..span.end];
        let rule = rules.rule(span.kind);
        if span.safe || is_safe_slice(span.kind, slice) {
            output.push_str(slice);
            if rule.enabled() {
                findings.push(Finding {
                    pii_type: span.kind,
                    field_path: path.to_string(),
                    action: FindingAction::Allowed,
                });
            }
        } else if !rule.enabled() {
            output.push_str(slice);
        } else if rule.mask {
            output.push_str(span.kind.token());
            findings.push(Finding {
                pii_type: span.kind,
                field_path: path.to_string(),
                action: FindingAction::Masked,
            });
            if rule.alert {
                alert = true;
            }
        } else if rule.alert {
            output.push_str(slice);
            findings.push(Finding {
                pii_type: span.kind,
                field_path: path.to_string(),
                action: FindingAction::AlertedOnly,
            });
            alert = true;
        } else {
            output.push_str(slice);
        }
        cursor = span.end;
    }
    output.push_str(&text[cursor..]);
    TextEdit {
        text: output,
        findings,
        alert,
    }
}

fn safe_whole_value(text: &str, path: &str, kind: PiiType, rules: &Rules) -> TextEdit {
    let mut findings = Vec::new();
    if rules.rule(kind).enabled() {
        findings.push(Finding {
            pii_type: kind,
            field_path: path.to_string(),
            action: FindingAction::Allowed,
        });
    }
    TextEdit {
        text: text.to_string(),
        findings,
        alert: false,
    }
}

fn find_spans(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for matched in VCARD.find_iter(text) {
        push_span(
            &mut spans,
            matched.start(),
            matched.end(),
            PiiType::Contact,
            false,
        );
    }
    for matched in CARD.find_iter(text) {
        if !digit_bounded(text, matched.start(), matched.end()) {
            continue;
        }
        let raw = matched.as_str();
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if (13..=19).contains(&digits.len()) && luhn(&digits) {
            push_span(
                &mut spans,
                matched.start(),
                matched.end(),
                PiiType::Card,
                false,
            );
        }
    }
    for matched in EMAIL.find_iter(text) {
        push_span(
            &mut spans,
            matched.start(),
            matched.end(),
            PiiType::Email,
            is_masked_email(matched.as_str()),
        );
    }
    for matched in PHONE.find_iter(text) {
        if !digit_bounded(text, matched.start(), matched.end()) {
            continue;
        }
        let digits = matched
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_digit())
            .count();
        if (10..=15).contains(&digits) {
            push_span(
                &mut spans,
                matched.start(),
                matched.end(),
                PiiType::Phone,
                is_masked_phone(matched.as_str()),
            );
        }
    }
    for matched in ADDRESS.find_iter(text) {
        push_span(
            &mut spans,
            matched.start(),
            matched.end(),
            PiiType::Address,
            is_masked_address(matched.as_str()),
        );
    }
    spans
}

fn push_span(spans: &mut Vec<Span>, start: usize, end: usize, kind: PiiType, safe: bool) {
    if spans
        .iter()
        .any(|span| start < span.end && end > span.start)
    {
        return;
    }
    spans.push(Span {
        start,
        end,
        kind,
        safe,
    });
    spans.sort_by_key(|span| span.start);
}

fn whole_value_safe(value: &str) -> Option<PiiType> {
    if value == PiiType::Email.token() || is_masked_email(value) {
        return Some(PiiType::Email);
    }
    if value == PiiType::Card.token() || is_masked_card(value) {
        return Some(PiiType::Card);
    }
    if value == PiiType::Phone.token() || is_masked_phone(value) {
        return Some(PiiType::Phone);
    }
    if value == PiiType::Address.token() || (value.contains("***") && looks_like_address(value)) {
        return Some(PiiType::Address);
    }
    if value == PiiType::Contact.token() {
        return Some(PiiType::Contact);
    }
    None
}

fn is_safe_slice(kind: PiiType, slice: &str) -> bool {
    match kind {
        PiiType::Email => is_masked_email(slice) || slice == PiiType::Email.token(),
        PiiType::Phone => is_masked_phone(slice) || slice == PiiType::Phone.token(),
        PiiType::Card => is_masked_card(slice) || slice == PiiType::Card.token(),
        PiiType::Address => is_masked_address(slice) || slice == PiiType::Address.token(),
        PiiType::Contact => slice == PiiType::Contact.token(),
    }
}

fn is_masked_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || !domain.contains('.') {
        return false;
    }
    let mask_chars = local
        .chars()
        .filter(|c| matches!(c, '*' | '•' | '#'))
        .count();
    mask_chars > 0 && mask_chars * 2 >= local.chars().count()
}

fn digit_bounded(text: &str, start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !text.as_bytes()[start - 1].is_ascii_digit();
    let after_ok = end >= text.len() || !text.as_bytes()[end].is_ascii_digit();
    before_ok && after_ok
}

fn is_masked_phone(value: &str) -> bool {
    if is_masked_card(value) {
        return false;
    }
    let digits = value.chars().filter(|c| c.is_ascii_digit()).count();
    let masks = value
        .chars()
        .filter(|c| matches!(c, '*' | '•' | '#' | 'x' | 'X'))
        .count();
    digits <= 4 && masks >= 4
}

fn is_masked_card(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if luhn(&digits) && (13..=19).contains(&digits.len()) {
        return false;
    }
    let masks = value
        .chars()
        .filter(|c| matches!(c, '*' | '•' | '#' | 'x' | 'X'))
        .count();
    digits.len() <= 4 && masks >= 8
}

fn is_masked_address(value: &str) -> bool {
    value == PiiType::Address.token() || value.contains("***") || value.contains('•')
}

fn looks_like_address(value: &str) -> bool {
    ADDRESS.is_match(value) || value.to_ascii_lowercase().contains("street")
}

pub fn luhn(digits: &str) -> bool {
    if digits.len() < 13 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0;
    let mut alternate = false;
    for ch in digits.chars().rev() {
        let mut n = ch.to_digit(10).expect("digit");
        if alternate {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alternate = !alternate;
    }
    sum % 10 == 0
}

fn is_opaque_token(value: &str) -> bool {
    value.len() >= 8 && value.bytes().all(is_base64url_byte) && entropy(value) >= 3.5
}

fn is_base64url(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_base64url_byte)
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}

fn digit_ratio(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let digits = value.chars().filter(|c| c.is_ascii_digit()).count();
    digits as f64 / value.chars().count() as f64
}

fn entropy(value: &str) -> f64 {
    let mut counts = [0u32; 128];
    let mut total = 0u32;
    for b in value.bytes() {
        if b >= 128 {
            return 0.0;
        }
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(total);
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = f64::from(count) / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::Rules;

    fn rules() -> Rules {
        Rules::default()
    }

    #[test]
    fn masks_cleartext_email_phone_card_and_address() {
        let email = analyze_text("ada@example.com", "$.email", &rules());
        assert_eq!(email.text, "[redacted-email]");
        assert!(email.alert);
        assert_eq!(email.findings[0].action, FindingAction::Masked);

        let phone = analyze_text("+1 (415) 555-2671", "$.phone", &rules());
        assert_eq!(phone.text, "[redacted-phone]");

        let card = analyze_text("4111 1111 1111 1111", "$.card", &rules());
        assert_eq!(card.text, "[redacted-card]");
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));

        let address = analyze_text("10 Downing Street", "$.address", &rules());
        assert_eq!(address.text, "[redacted-address]");
    }

    #[test]
    fn leaves_masked_encrypted_and_ordinary_text() {
        let masked = analyze_text("a***@example.com", "$.email", &rules());
        assert_eq!(masked.text, "a***@example.com");
        assert!(!masked.alert);
        assert_eq!(masked.findings[0].action, FindingAction::Allowed);

        let token = analyze_text("[redacted-phone]", "$.phone", &rules());
        assert_eq!(token.text, "[redacted-phone]");
        assert_eq!(token.findings[0].action, FindingAction::Allowed);

        let card = analyze_text("************4242", "$.card", &rules());
        assert_eq!(card.text, "************4242");
        assert_eq!(card.findings[0].pii_type, PiiType::Card);

        assert!(is_field_encrypted(
            "enc:abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        ));
        let encrypted = analyze_text(
            "enc:abcdefghijklmnopqrstuvwxyz0123456789ABCD",
            "$.email",
            &rules(),
        );
        assert!(encrypted.findings.is_empty());
        assert_eq!(
            encrypted.text,
            "enc:abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        );

        let jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.qqqqqqqqqqqqqqqq.qqqqqqqqqqqqqqqq.qqqqqqqqqqqqqqqq.qqqqqqqqqqqqqqqq";
        assert!(is_field_encrypted(jwe));
        let opaque = analyze_text(jwe, "$.secret", &rules());
        assert_eq!(opaque.text, jwe);
        assert!(opaque.findings.is_empty());

        let note = analyze_text("hello world", "$.note", &rules());
        assert_eq!(note.text, "hello world");
        assert!(note.findings.is_empty());
    }

    #[test]
    fn replaces_a_vcard_as_a_contact() {
        let raw = "BEGIN:VCARD\nFN:Ada Lovelace\nEMAIL:ada@example.com\nEND:VCARD";
        let edited = analyze_text(raw, "body", &rules());
        assert_eq!(edited.text, "[redacted-contact]");
        assert_eq!(edited.findings[0].pii_type, PiiType::Contact);
    }

    #[test]
    fn alert_without_mask_keeps_the_body_out_of_the_finding() {
        let mut rules = rules();
        rules.email.mask = false;
        rules.email.alert = true;
        let edited = analyze_text("ada@example.com", "$.email", &rules);
        assert_eq!(edited.text, "ada@example.com");
        assert!(edited.alert);
        assert_eq!(edited.findings[0].action, FindingAction::AlertedOnly);
    }

    #[test]
    fn disabled_rule_does_not_record_or_change_text() {
        let mut rules = rules();
        rules.email.mask = false;
        rules.email.alert = false;
        let edited = analyze_text("ada@example.com", "$.email", &rules);
        assert_eq!(edited.text, "ada@example.com");
        assert!(edited.findings.is_empty());
        assert!(!edited.alert);
    }
}
