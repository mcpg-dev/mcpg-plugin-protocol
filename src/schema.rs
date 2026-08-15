//! JSON Schema composition helpers shared between host and plugins.
//!
//! Host-side tool composition layers operator-supplied schema onto
//! plugin-derived schema. Both sides need the same merge semantics —
//! this module owns them.

use serde_json::Value;

/// Deep-merge an operator-supplied `overlay` object onto a `base`
/// JSON Schema.
///
/// - Object values merge key-by-key, recursively.
/// - Any non-object value in `overlay` replaces the `base` value
///   wholesale (arrays included — `required: [...]` is atomic,
///   not mergeable).
///
/// Used when a binding plugin derived a schema (types, formats) and
/// the operator supplied a richer one (descriptions, enums, custom
/// constraints): operator fields win at every key.
#[must_use]
pub fn merge_schema(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let existing = b.remove(&k).unwrap_or(Value::Null);
                let merged = match (existing, v) {
                    (Value::Null, v) => v,
                    (existing, v) => merge_schema(existing, v),
                };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        (_base, overlay) => overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overlay_wins_for_scalars() {
        let base = json!({"type": "string", "description": "from derivation"});
        let overlay = json!({"description": "operator override"});
        let merged = merge_schema(base, overlay);
        assert_eq!(merged["type"], "string");
        assert_eq!(merged["description"], "operator override");
    }

    #[test]
    fn recurses_into_properties() {
        let base = json!({
            "type": "object",
            "properties": { "a": {"type": "integer"} }
        });
        let overlay = json!({
            "properties": { "a": {"description": "row id"} }
        });
        let merged = merge_schema(base, overlay);
        assert_eq!(merged["properties"]["a"]["type"], "integer");
        assert_eq!(merged["properties"]["a"]["description"], "row id");
    }

    #[test]
    fn replaces_arrays_wholesale() {
        // `required: [...]` is an atomic list — overlay replaces, not merges.
        let base = json!({"required": ["a", "b"]});
        let overlay = json!({"required": ["b"]});
        let merged = merge_schema(base, overlay);
        assert_eq!(merged["required"], json!(["b"]));
    }

    #[test]
    fn absent_overlay_keys_leave_base_intact() {
        let base = json!({"type": "string", "format": "uuid"});
        let overlay = json!({});
        let merged = merge_schema(base, overlay);
        assert_eq!(merged["type"], "string");
        assert_eq!(merged["format"], "uuid");
    }
}
