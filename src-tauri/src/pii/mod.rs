mod detect;
mod rewrite;
mod rules;

pub use detect::{is_field_encrypted, token_for};
pub use rewrite::{MAX_BODY, RewriteResult, rewrite_body};
pub use rules::{Rules, TypeRule};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiiType {
    Email,
    Phone,
    Card,
    Address,
    Contact,
}

impl PiiType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Card => "card",
            Self::Address => "address",
            Self::Contact => "contact",
        }
    }

    pub fn token(self) -> &'static str {
        match self {
            Self::Email => "[redacted-email]",
            Self::Phone => "[redacted-phone]",
            Self::Card => "[redacted-card]",
            Self::Address => "[redacted-address]",
            Self::Contact => "[redacted-contact]",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "card" => Some(Self::Card),
            "address" => Some(Self::Address),
            "contact" => Some(Self::Contact),
            _ => None,
        }
    }

    pub const ALL: [PiiType; 5] = [
        Self::Email,
        Self::Phone,
        Self::Card,
        Self::Address,
        Self::Contact,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingAction {
    Masked,
    Allowed,
    AlertedOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub pii_type: PiiType,
    pub field_path: String,
    pub action: FindingAction,
}
