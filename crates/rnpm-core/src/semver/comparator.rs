use super::version::Version;
use crate::error::SemverError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Op {
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Gt => ">",
            Op::Gte => ">=",
            Op::Lt => "<",
            Op::Lte => "<=",
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Comparator {
    pub op: Op,
    pub version: Version,
}

impl Comparator {
    #[inline]
    pub fn new(op: Op, version: Version) -> Self {
        Self { op, version }
    }

    #[inline]
    pub fn matches(&self, version: &Version) -> bool {
        match self.op {
            Op::Eq => version == &self.version,
            Op::Gt => version > &self.version,
            Op::Gte => version >= &self.version,
            Op::Lt => version < &self.version,
            Op::Lte => version <= &self.version,
        }
    }

    #[inline]
    pub fn parse(input: &str) -> Result<Self, SemverError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(SemverError::InvalidComparator(input.to_string()));
        }

        let (op, ver_str) = if let Some(rest) = s.strip_prefix(">=") {
            (Op::Gte, rest)
        } else if let Some(rest) = s.strip_prefix("<=") {
            (Op::Lte, rest)
        } else if let Some(rest) = s.strip_prefix('>') {
            (Op::Gt, rest)
        } else if let Some(rest) = s.strip_prefix('<') {
            (Op::Lt, rest)
        } else if let Some(rest) = s.strip_prefix('=') {
            (Op::Eq, rest)
        } else {
            (Op::Eq, s)
        };

        let version = Version::parse_loose(ver_str.trim())
            .map_err(|_| SemverError::InvalidComparator(input.to_string()))?;
        Ok(Self { op, version })
    }
}

impl fmt::Display for Comparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.op, self.version)
    }
}

impl FromStr for Comparator {
    type Err = SemverError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Comparator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Comparator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ComparatorVisitor;

        impl<'de> serde::de::Visitor<'de> for ComparatorVisitor {
            type Value = Comparator;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a semver comparator string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Comparator::parse(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(ComparatorVisitor)
    }
}
