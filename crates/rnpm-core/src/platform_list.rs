use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, ops::Deref};

/// A platform constraint whose original string or array form is retained.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformList {
    values: Vec<String>,
    scalar: bool,
}

impl PlatformList {
    pub fn as_slice(&self) -> &[String] {
        &self.values
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn into_vec(self) -> Vec<String> {
        self.values
    }
}

impl Deref for PlatformList {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl From<Vec<String>> for PlatformList {
    fn from(values: Vec<String>) -> Self {
        Self {
            values,
            scalar: false,
        }
    }
}

impl From<String> for PlatformList {
    fn from(value: String) -> Self {
        Self {
            values: vec![value],
            scalar: true,
        }
    }
}

impl Serialize for PlatformList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.scalar {
            self.values[0].serialize(serializer)
        } else {
            self.values.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PlatformList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlatformVisitor;
        impl<'de> Visitor<'de> for PlatformVisitor {
            type Value = PlatformList;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or an array of strings")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(value.to_owned().into())
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<String>()? {
                    values.push(value);
                }
                Ok(values.into())
            }
        }
        deserializer.deserialize_any(PlatformVisitor)
    }
}
