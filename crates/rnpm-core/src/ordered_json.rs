use indexmap::IndexMap;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

pub type OrderedJsonMap = IndexMap<String, OrderedJsonValue>;

/// A JSON value that preserves object key insertion order, backed by `IndexMap`.
/// This is used exclusively for package.json manifests and manipulation tools
/// (`npm pkg`, `npm version`) to avoid altering key ordering while keeping
/// the rest of the workspace on fast `BTreeMap`/`serde_json::Value`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OrderedJsonValue {
    #[default]
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedJsonValue>),
    Object(OrderedJsonMap),
}

impl OrderedJsonValue {
    pub fn as_object(&self) -> Option<&OrderedJsonMap> {
        match self {
            OrderedJsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut OrderedJsonMap> {
        match self {
            OrderedJsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<OrderedJsonValue>> {
        match self {
            OrderedJsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<OrderedJsonValue>> {
        match self {
            OrderedJsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            OrderedJsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            OrderedJsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, OrderedJsonValue::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, OrderedJsonValue::Array(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, OrderedJsonValue::Null)
    }

    pub fn get(&self, key: &str) -> Option<&OrderedJsonValue> {
        match self {
            OrderedJsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut OrderedJsonValue> {
        match self {
            OrderedJsonValue::Object(map) => map.get_mut(key),
            _ => None,
        }
    }
}

impl Serialize for OrderedJsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OrderedJsonValue::Null => serializer.serialize_unit(),
            OrderedJsonValue::Bool(b) => serializer.serialize_bool(*b),
            OrderedJsonValue::Number(n) => n.serialize(serializer),
            OrderedJsonValue::String(s) => serializer.serialize_str(s),
            OrderedJsonValue::Array(arr) => {
                let mut seq = serializer.serialize_seq(Some(arr.len()))?;
                for elem in arr {
                    seq.serialize_element(elem)?;
                }
                seq.end()
            }
            OrderedJsonValue::Object(map) => {
                let mut s_map = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    s_map.serialize_entry(k, v)?;
                }
                s_map.end()
            }
        }
    }
}

struct OrderedJsonVisitor;

impl<'de> Visitor<'de> for OrderedJsonVisitor {
    type Value = OrderedJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(OrderedJsonValue::Number)
            .ok_or_else(|| de::Error::custom("invalid float value"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OrderedJsonValue::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::new();
        while let Some(elem) = seq.next_element()? {
            vec.push(elem);
        }
        Ok(OrderedJsonValue::Array(vec))
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut index_map = IndexMap::new();
        while let Some((k, v)) = map.next_entry()? {
            index_map.insert(k, v);
        }
        Ok(OrderedJsonValue::Object(index_map))
    }
}

impl<'de> Deserialize<'de> for OrderedJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OrderedJsonVisitor)
    }
}

impl From<serde_json::Value> for OrderedJsonValue {
    fn from(val: serde_json::Value) -> Self {
        match val {
            serde_json::Value::Null => OrderedJsonValue::Null,
            serde_json::Value::Bool(b) => OrderedJsonValue::Bool(b),
            serde_json::Value::Number(n) => OrderedJsonValue::Number(n),
            serde_json::Value::String(s) => OrderedJsonValue::String(s),
            serde_json::Value::Array(arr) => {
                OrderedJsonValue::Array(arr.into_iter().map(Into::into).collect())
            }
            serde_json::Value::Object(map) => {
                let mut m = IndexMap::new();
                for (k, v) in map {
                    m.insert(k, v.into());
                }
                OrderedJsonValue::Object(m)
            }
        }
    }
}

impl From<OrderedJsonValue> for serde_json::Value {
    fn from(val: OrderedJsonValue) -> Self {
        match val {
            OrderedJsonValue::Null => serde_json::Value::Null,
            OrderedJsonValue::Bool(b) => serde_json::Value::Bool(b),
            OrderedJsonValue::Number(n) => serde_json::Value::Number(n),
            OrderedJsonValue::String(s) => serde_json::Value::String(s),
            OrderedJsonValue::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(Into::into).collect())
            }
            OrderedJsonValue::Object(map) => {
                let mut m = serde_json::Map::new();
                for (k, v) in map {
                    m.insert(k, v.into());
                }
                serde_json::Value::Object(m)
            }
        }
    }
}
