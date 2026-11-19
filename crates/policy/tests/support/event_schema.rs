//! Check each reserved history field against its declared event type.

use dogwood_language::{Event, EventFieldType, EventSignature, Value};

pub(crate) fn assert_reserved_fields(
    event: &Event,
    signature: &EventSignature,
    allow_qualified_entities: bool,
) {
    // Derive the reserved fields so a new declaration requires producer coverage.
    for declared in signature
        .fields()
        .filter(|field| !matches!(field.path()[0].as_str(), "input" | "output"))
    {
        let field = declared.path();
        let ty = declared.field_type();
        let value = event.field_path(field).unwrap_or_else(|| {
            panic!(
                "{}::{} lacks declared reserved field {}",
                event.action(),
                event.kind(),
                field.join(".")
            )
        });
        let conforms = match (ty, value) {
            (EventFieldType::Cedar(ty), Value::String(_)) => ty == "String",
            (EventFieldType::Cedar(ty), Value::Int(_)) => ty == "Long",
            (EventFieldType::Cedar(ty), Value::Bool(_)) => ty == "Boolean",
            (EventFieldType::EntityTypes(types), Value::Entity { ty, .. }) => {
                let namespace = &signature.namespace()[..signature.namespace().len() - 1];
                types.iter().any(|declared| {
                    declared == ty
                        || (allow_qualified_entities
                            && format!("{}::{declared}", namespace.join("::")) == *ty)
                })
            }
            _ => false,
        };
        assert!(
            conforms,
            "{}::{} field {} must match {ty:?}, got {value:?}",
            event.action(),
            event.kind(),
            field.join(".")
        );
    }
}
