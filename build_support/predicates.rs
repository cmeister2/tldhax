//! Typed authoring predicates; arbitrary expressions and regexes are excluded.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Ascii,
    Unicode,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    Prefix,
    Suffix,
    Contains,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Value {
    Boolean(bool),
    String(String),
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    String,
    Boolean,
    StringSet,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactStringFormat {
    UppercaseAlpha2,
}

impl FactStringFormat {
    pub fn matches(self, value: &str) -> bool {
        match self {
            Self::UppercaseAlpha2 => {
                value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub field: String,
    pub kind: FactKind,
    #[serde(default)]
    pub allowed_values: Vec<String>,
    #[serde(default)]
    pub string_format: Option<FactStringFormat>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    Constant {
        value: bool,
    },
    All {
        predicates: Vec<Predicate>,
    },
    Any {
        predicates: Vec<Predicate>,
    },
    Not {
        predicate: Box<Predicate>,
    },
    LabelLength {
        component: u8,
        min: u16,
        max: u16,
        basis: Basis,
    },
    LabelMinimum {
        component: u8,
        min: u16,
        basis: Basis,
    },
    LabelMaximum {
        component: u8,
        max: u16,
        basis: Basis,
    },
    LabelInSet {
        component: u8,
        set_id: String,
    },
    AsciiOnly {
        component: u8,
    },
    LabelPattern {
        component: u8,
        pattern: Pattern,
        value: String,
        basis: Basis,
    },
    LabelPositions {
        component: u8,
        positions: Vec<u16>,
        value: String,
        basis: Basis,
    },
    Idn {
        component: u8,
        profile_id: String,
    },
    FieldEquals {
        field: String,
        value: Value,
    },
    FieldIn {
        field: String,
        values: Vec<Value>,
    },
    NameEqualsField {
        component: u8,
        field: String,
    },
    Unsupported {
        feature: String,
    },
}

impl Predicate {
    pub fn component(&self) -> Option<u8> {
        match self {
            Self::LabelLength { component, .. }
            | Self::LabelMinimum { component, .. }
            | Self::LabelMaximum { component, .. }
            | Self::LabelInSet { component, .. }
            | Self::AsciiOnly { component }
            | Self::LabelPattern { component, .. }
            | Self::LabelPositions { component, .. }
            | Self::Idn { component, .. }
            | Self::NameEqualsField { component, .. } => Some(*component),
            _ => None,
        }
    }

    pub fn children(&self) -> &[Predicate] {
        match self {
            Self::All { predicates } | Self::Any { predicates } => predicates,
            Self::Not { predicate } => std::slice::from_ref(predicate),
            _ => &[],
        }
    }

    pub fn unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. }) || self.children().iter().any(Self::unsupported)
    }
}
