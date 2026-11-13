//! Attribute matching from Arborist's query-selector-all.js and @npmcli/query.
use super::{parse_attribute_selector, split_top_level_commas, AttrOp, SimpleSelector};
use serde_json::Value;
use std::borrow::Cow;

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::String(text) => !text.is_empty(),
        Value::Number(number) => number.as_f64() != Some(0.0),
        _ => true,
    }
}

pub(super) fn matches(
    actual: Option<&Value>,
    op: Option<&AttrOp>,
    expected: Option<&str>,
    insensitive: bool,
) -> bool {
    let Some(op) = op else {
        return actual.is_some_and(truthy);
    };
    let expected = expected.unwrap_or_default();
    let expected = if insensitive {
        Cow::Owned(expected.to_lowercase())
    } else {
        Cow::Borrowed(expected)
    };
    let one = |value: Option<&Value>| {
        // JavaScript uses `obj[attribute] || ''`, then converts numbers only.
        // Booleans and objects are not strings and cannot match an operator.
        let value = value.filter(|value| truthy(value));
        let text = match value {
            None => Cow::Borrowed(""),
            Some(Value::String(text)) => Cow::Borrowed(text.as_str()),
            Some(Value::Number(number)) => Cow::Owned(number.to_string()),
            _ => return false,
        };
        let text = if insensitive {
            Cow::Owned(text.to_lowercase())
        } else {
            text
        };
        match op {
            AttrOp::Exact => text == expected,
            AttrOp::Prefix => text.starts_with(expected.as_ref()),
            AttrOp::Suffix => text.ends_with(expected.as_ref()),
            AttrOp::Substring => text.contains(expected.as_ref()),
            AttrOp::Tilde => text
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .any(|part| !part.is_empty() && part == expected),
            AttrOp::Dash => text.starts_with(&format!("{expected}-")),
        }
    };
    match actual {
        Some(Value::Array(items)) => items.iter().any(|item| one(Some(item))),
        other => one(other),
    }
}

pub(super) fn pseudo(arg: &str, package: &Value) -> bool {
    let Ok(mut parts) = split_top_level_commas(arg) else {
        return false;
    };
    let Some(last) = parts.pop() else {
        return false;
    };
    let mut objects = vec![package];
    for property in parts {
        objects = objects
            .into_iter()
            .flat_map(|object| match object.get(property.trim()) {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter(|value| truthy(value))
                    .collect::<Vec<_>>(),
                Some(value) if truthy(value) => vec![value],
                _ => Vec::new(),
            })
            .collect();
    }
    let last = last.trim();
    if let Some(inner) = last
        .strip_prefix(":attr(")
        .and_then(|arg| arg.strip_suffix(')'))
    {
        return objects.into_iter().any(|object| match object {
            Value::Array(items) => items.iter().any(|item| pseudo(inner, item)),
            value => pseudo(inner, value),
        });
    }
    let Some(inner) = last.strip_prefix('[').and_then(|arg| arg.strip_suffix(']')) else {
        return false;
    };
    let Ok(SimpleSelector::Attribute {
        name,
        op,
        val,
        insensitive,
    }) = parse_attribute_selector(inner)
    else {
        return false;
    };
    objects
        .into_iter()
        .any(|object| matches(object.get(&name), op.as_ref(), val.as_deref(), insensitive))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operator_types_follow_javascript_instead_of_json_serialization() {
        assert!(!matches(
            Some(&json!(true)),
            Some(&AttrOp::Exact),
            Some("true"),
            false
        ));
        assert!(matches(
            Some(&json!(18)),
            Some(&AttrOp::Exact),
            Some("18"),
            false
        ));
        assert!(matches(
            Some(&json!("DEP")),
            Some(&AttrOp::Exact),
            Some("dep"),
            true
        ));
        assert!(matches(Some(&json!([])), None, None, false));
        assert!(!matches(Some(&json!(false)), None, None, false));
    }

    #[test]
    fn attr_traverses_objects_and_arrays_without_stringifying_them() {
        let package = json!({"engines":{"node":">=18"},"funding":[{"type":"individual","url":"https://example.invalid"}]});
        assert!(pseudo("engines,[node^=\">=\"]", &package));
        assert!(pseudo("funding,[url*=\"example.invalid\"]", &package));
        assert!(pseudo("funding,:attr([type=individual])", &package));
        assert!(!pseudo("funding,:attr([type=corporate])", &package));
    }
}
