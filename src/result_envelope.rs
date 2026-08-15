//! Wire envelope shared by every fallible JSON-RString FFI slot.
//!
//! This envelope standardises the wire shape for any vtable slot
//! that returns an `RString` encoding a `Result<T, E>`. The slot's
//! plugin-side encoder writes either `{"ok": <T>}` on success or
//! `{"err": <E>}` on failure; the host decodes that envelope back
//! into a `Result<T, E>`. Pre-v28 the convention was applied
//! piecemeal — a few slots used the envelope (`BackendVTable::execute`,
//! `HostServicesVTable` returns), others used ad-hoc encodings (e.g.
//! `BackendVTable::register_profile` overloaded the empty-string
//! return as `Ok(())`). v28 collapses all fallible slots onto this
//! one shape so host adapters share decoder code and the panic
//! sentinel is uniform.
//!
//! ## Encoding
//!
//! - `Ok(T)` → `{"ok": <serde-T>}`
//! - `Err(E)` → `{"err": <serde-E>}`
//! - `Ok(())` (void-success) → `{"ok": null}` (since `()` serialises
//!   to `null`).
//!
//! ## Why a struct rather than `serde(rename = ...)` on `Result`
//!
//! `serde::Result<T, E>` defaults to `{"Ok": ...}` / `{"Err": ...}`
//! (capitalised). The MCPG protocol predates this module and the
//! existing slots, panic sentinels, and operator-facing docs all use
//! lowercase `"ok"` / `"err"`. Rather than churn every existing
//! sentinel and operator doc, we own the wire shape with a typed
//! `ResultEnvelope` so the encoder can't drift.

use abi_stable::std_types::RString;
use serde::de::{self, DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Wire envelope for `Result<T, E>` over an FFI `RString`. See
/// module-level docs for the JSON shape and rationale.
///
/// `Serialize` stays `#[serde(untagged)]` so success/failure encode as
/// the bare `{"ok": <T>}` / `{"err": <E>}` objects the protocol mandates.
/// `Deserialize`, however, is **hand-written to dispatch on the present
/// key** rather than the derive's untagged "try each variant in order".
/// The untagged decoder is unsound whenever `T` is an `Option<_>` (e.g.
/// `get` → `Option<ResourceContent>`, `signed_url` → `Option<String>`):
/// it would match `Ok { ok: T }` first against an `{"err": ...}` payload
/// because the *missing* `ok` field collapses to `None`, silently
/// swallowing a plugin error as `Ok(None)`. Keying on `ok` vs `err`
/// removes that ambiguity for every payload type.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResultEnvelope<T, E> {
    Ok { ok: T },
    Err { err: E },
}

impl<'de, T, E> Deserialize<'de> for ResultEnvelope<T, E>
where
    T: Deserialize<'de>,
    E: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnvelopeVisitor<T, E>(std::marker::PhantomData<(T, E)>);

        impl<'de, T, E> Visitor<'de> for EnvelopeVisitor<T, E>
        where
            T: Deserialize<'de>,
            E: Deserialize<'de>,
        {
            type Value = ResultEnvelope<T, E>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(r#"a result envelope: {"ok": <T>} or {"err": <E>}"#)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                // Dispatch on the present key, not on variant-shape
                // guessing. Unknown keys are ignored; if both appear
                // (encoders never emit that) the last wins.
                let mut out: Option<ResultEnvelope<T, E>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ok" => {
                            out = Some(ResultEnvelope::Ok {
                                ok: map.next_value()?,
                            })
                        }
                        "err" => {
                            out = Some(ResultEnvelope::Err {
                                err: map.next_value()?,
                            })
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                out.ok_or_else(|| de::Error::custom("result envelope missing both `ok` and `err`"))
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor(std::marker::PhantomData))
    }
}

impl<T, E> ResultEnvelope<T, E> {
    pub fn into_result(self) -> Result<T, E> {
        match self {
            Self::Ok { ok } => Ok(ok),
            Self::Err { err } => Err(err),
        }
    }
}

impl<T, E> From<Result<T, E>> for ResultEnvelope<T, E> {
    fn from(r: Result<T, E>) -> Self {
        match r {
            Ok(ok) => Self::Ok { ok },
            Err(err) => Self::Err { err },
        }
    }
}

/// Plugin-side helper: serialise `Ok(T)` into the wire envelope.
///
/// Used by SDK macros + plugin authors writing fallible vtable slots.
/// On JSON encoding failure (which is essentially impossible for
/// well-formed `Serialize` impls) returns an empty `RString`; the
/// host's decoder treats undecodable returns as transport errors.
pub fn respond_ok_rstring<T: Serialize>(value: &T) -> RString {
    RString::from(serde_json::to_string(&serde_json::json!({ "ok": value })).unwrap_or_default())
}

/// Plugin-side helper: serialise `Err(E)` into the wire envelope.
pub fn respond_err_rstring<E: Serialize>(err: &E) -> RString {
    RString::from(serde_json::to_string(&serde_json::json!({ "err": err })).unwrap_or_default())
}

/// Plugin-side helper: serialise a `Result<T, E>` into the wire
/// envelope. Convenience over the two single-arm helpers when the
/// caller already has a `Result`.
pub fn respond_result_rstring<T: Serialize, E: Serialize>(r: &Result<T, E>) -> RString {
    match r {
        Ok(ok) => respond_ok_rstring(ok),
        Err(err) => respond_err_rstring(err),
    }
}

/// Host-side helper: parse a wire envelope back into a `Result<T, E>`.
/// Forwarded as `Result<Result<T, E>, serde_json::Error>` so the host
/// can distinguish "plugin returned an error" (inner `Err`) from
/// "plugin returned an undecodable string" (outer `Err`); host
/// adapters typically map the outer error to a transport-class error
/// (`BackendError::Transport`, `StoreError::Transport`, etc.).
pub fn decode_result_envelope<T, E>(s: &str) -> Result<Result<T, E>, serde_json::Error>
where
    T: DeserializeOwned,
    E: DeserializeOwned,
{
    let env: ResultEnvelope<T, E> = serde_json::from_str(s)?;
    Ok(env.into_result())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Payload {
        n: u32,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    enum MyError {
        Bad { reason: String },
    }

    #[test]
    fn ok_encodes_lowercase_envelope() {
        let r: Result<Payload, MyError> = Ok(Payload { n: 7 });
        let s = respond_result_rstring(&r);
        assert_eq!(s.as_str(), r#"{"ok":{"n":7}}"#);
    }

    #[test]
    fn err_encodes_lowercase_envelope() {
        let r: Result<Payload, MyError> = Err(MyError::Bad {
            reason: "nope".into(),
        });
        let s = respond_result_rstring(&r);
        assert_eq!(s.as_str(), r#"{"err":{"Bad":{"reason":"nope"}}}"#);
    }

    #[test]
    fn round_trip_ok() {
        let r: Result<Payload, MyError> = Ok(Payload { n: 7 });
        let wire = respond_result_rstring(&r);
        let decoded = decode_result_envelope::<Payload, MyError>(wire.as_str()).expect("decode");
        assert_eq!(decoded, Ok(Payload { n: 7 }));
    }

    #[test]
    fn round_trip_err() {
        let r: Result<Payload, MyError> = Err(MyError::Bad {
            reason: "boom".into(),
        });
        let wire = respond_result_rstring(&r);
        let decoded = decode_result_envelope::<Payload, MyError>(wire.as_str()).expect("decode");
        assert_eq!(
            decoded,
            Err(MyError::Bad {
                reason: "boom".into()
            })
        );
    }

    #[test]
    fn void_ok_encodes_as_ok_null() {
        let r: Result<(), MyError> = Ok(());
        let wire = respond_result_rstring(&r);
        assert_eq!(wire.as_str(), r#"{"ok":null}"#);
        let decoded = decode_result_envelope::<(), MyError>(wire.as_str()).expect("decode");
        assert_eq!(decoded, Ok(()));
    }

    #[test]
    fn malformed_input_propagates_as_outer_err() {
        let bad = "{ not valid json";
        let r = decode_result_envelope::<Payload, MyError>(bad);
        assert!(r.is_err());
    }

    #[test]
    fn err_decodes_when_ok_payload_is_option() {
        // Regression: with an `Option<T>` success payload, an `{"err": E}`
        // envelope must decode as `Err(E)` — NOT `Ok(None)`. The old
        // `#[serde(untagged)]` decoder matched `Ok { ok: Option<_> }`
        // first (missing field → None) and swallowed the error.
        let r: Result<Option<Payload>, MyError> = Err(MyError::Bad {
            reason: "swallowed?".into(),
        });
        let wire = respond_result_rstring(&r);
        let decoded =
            decode_result_envelope::<Option<Payload>, MyError>(wire.as_str()).expect("decode");
        assert_eq!(
            decoded,
            Err(MyError::Bad {
                reason: "swallowed?".into()
            })
        );
    }

    #[test]
    fn ok_none_decodes_as_ok_none_with_option_payload() {
        let r: Result<Option<Payload>, MyError> = Ok(None);
        let wire = respond_result_rstring(&r);
        let decoded =
            decode_result_envelope::<Option<Payload>, MyError>(wire.as_str()).expect("decode");
        assert_eq!(decoded, Ok(None));
    }
}
