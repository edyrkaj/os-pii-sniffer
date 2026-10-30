use serde::{Deserialize, Serialize};

use super::PiiType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeRule {
    pub mask: bool,
    pub alert: bool,
}

impl TypeRule {
    pub fn enabled(self) -> bool {
        self.mask || self.alert
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rules {
    pub email: TypeRule,
    pub phone: TypeRule,
    pub card: TypeRule,
    pub address: TypeRule,
    pub contact: TypeRule,
}

impl Default for Rules {
    fn default() -> Self {
        let on = TypeRule {
            mask: true,
            alert: true,
        };
        Self {
            email: on,
            phone: on,
            card: on,
            address: on,
            contact: on,
        }
    }
}

impl Rules {
    pub fn rule(&self, kind: PiiType) -> TypeRule {
        match kind {
            PiiType::Email => self.email,
            PiiType::Phone => self.phone,
            PiiType::Card => self.card,
            PiiType::Address => self.address,
            PiiType::Contact => self.contact,
        }
    }

    pub fn set(&mut self, kind: PiiType, rule: TypeRule) {
        match kind {
            PiiType::Email => self.email = rule,
            PiiType::Phone => self.phone = rule,
            PiiType::Card => self.card = rule,
            PiiType::Address => self.address = rule,
            PiiType::Contact => self.contact = rule,
        }
    }
}
