//! Typed capability enum. Replaces the
//! stringly-typed `CAP_HOST_*` constants the v24 protocol used.
//!
//! Operator grants and plugin requirements both serialise to the
//! same wire shape, so the same [`Capability`] value can come from
//! a cdylib's typed declaration OR from operator YAML.
//!
//! # Wire shape
//!
//! Two equivalent forms accepted on the operator-config / manifest
//! side; the typed enum normalises both into one Rust value:
//!
//! ```yaml
//! granted_capabilities:
//!   - "network_outbound"                                # bare string (no-args variants only)
//!   - { type: "audit_write" }                           # object form, no args
//!   - { type: "filesystem_read", paths: ["/etc/myapp"] }
//!   - { type: "secrets_read", schemes: ["vault", "env"] }
//! ```
//!
//! No-args variants accept either the bare-string or the object
//! form. Variant-args variants (`filesystem_read`, `filesystem_write`,
//! `secrets_read`, `credential_issue`, `config_read`) require the
//! object form — a bare string for them is a parse error.
//!
//! # Subset semantics
//!
//! Boot validation calls [`Capability::covers`]: a granted
//! capability covers a required one when their kinds match and, for
//! variant-args kinds, the granted set is a superset of the
//! required set. Path globbing is intentionally NOT implemented in
//! v25 — `paths` entries are compared by string equality. Plugins
//! that read truly arbitrary paths can declare `paths: ["/"]` as a
//! v25 "any path" convention.
//!
//! # Forward-compat
//!
//! A future cdylib might serialise a capability kind this host
//! doesn't know. Such values deserialise to [`Capability::Unknown`]
//! (rather than failing decode). Boot validation rejects them with
//! a clear "unknown capability" error pointing at the plugin id —
//! the operator sees the rejection at startup, not as a silent
//! deserialisation drop.

use serde::{Deserialize, Serialize};

/// A single typed capability declaration. Used both by plugins (to
/// say "I require X") and by operators (to say "I grant X").
///
/// The wire encoding uses serde's tagged form with a snake_case
/// discriminator in `type`. No-args variants serialise to the
/// shortest possible JSON (`{"type":"network_outbound"}`); variant-
/// args variants flatten their args into the same object
/// (`{"type":"filesystem_read","paths":["/etc/myapp"]}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Capability {
    /// Outbound network access (HTTP and raw TCP both). Default-deny.
    /// Replaces the v24 `CAP_HOST_OUTBOUND_HTTP` / `CAP_HOST_OUTBOUND_NETWORK`
    /// pair — the two are collapsed because the policy distinction was
    /// rarely useful in practice. The transport-level host/port allowlist
    /// still applies.
    NetworkOutbound,

    /// Read-only filesystem access to specific paths. Operator
    /// grant's `paths` must be a superset of the plugin's required
    /// `paths` (string equality, no glob expansion in v25). Declare
    /// `paths: ["/"]` for "any path".
    FilesystemRead { paths: Vec<String> },

    /// Read-write filesystem access to specific paths. Subset-checked.
    FilesystemWrite { paths: Vec<String> },

    /// Resolve secret URIs of specific schemes (`vault`, `aws-sm`,
    /// `env`, `file`, …). The granted scheme list must be a superset
    /// of the required list.
    SecretsRead { schemes: Vec<String> },

    /// Issue credentials of specific kinds (`oauth_client_credentials`,
    /// `vault_dynamic_db`, …). Granted kinds superset required.
    CredentialIssue { kinds: Vec<String> },

    /// Resolve config URIs of specific schemes. Granted schemes
    /// superset required.
    ConfigRead { schemes: Vec<String> },

    /// Emit audit events to the host's audit pipeline.
    AuditWrite,

    /// Emit metric points beyond the per-plugin observability triad
    /// (counters / gauges / histograms via the host's metrics facade).
    MetricEmit,

    /// Read peer state from the cluster coordinator.
    ClusterPeerRead,

    /// Acquire cluster leadership (implies `ClusterPeerRead`).
    ClusterLeadershipAcquire,

    /// Acquire cluster locks (implies `ClusterPeerRead`).
    ClusterLockAcquire,

    /// Serve HTTP routes (implicit for `class: http_route` plugins —
    /// the boot loop adds it automatically; operators declaring it
    /// explicitly is fine).
    HttpRouteServe,

    /// Run a long-lived listener thread (implicit for `class: transport`
    /// plugins; consolidates the v24 `CAP_HOST_TLS_ACCEPT` and
    /// `CAP_HOST_CLIENT_CERT_ACCEPTOR` capabilities — TLS termination
    /// and mTLS handshake metadata go with the listener).
    TransportListen,

    /// Lift the per-plugin subscription cap (default cap is operator-set).
    UnboundedSubscriptions,

    /// Forward-compat sink — a v1.x plugin declaring a capability
    /// the host doesn't yet know about deserialises to `Unknown`;
    /// boot validation rejects it with a clear "unknown capability"
    /// error so the operator hears about it at startup rather than
    /// silently losing the declaration.
    #[serde(other)]
    Unknown,
}

/// Errors produced by [`Capability::parse_value`] when normalising a
/// loose YAML / JSON entry into a typed `Capability`.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityParseError {
    /// The value was syntactically valid but named a capability kind
    /// this host version doesn't know.
    #[error("unknown capability kind {0:?}")]
    UnknownKind(String),
    /// A variant-args kind was provided in bare-string form (which
    /// only no-args variants accept) or with a missing args field.
    #[error("capability {kind:?} requires args: {missing}")]
    MissingArgs { kind: String, missing: String },
    /// The args sub-object failed to deserialise (wrong type / shape).
    #[error("invalid args for capability {kind:?}: {source}")]
    InvalidArgs {
        kind: String,
        #[source]
        source: serde_json::Error,
    },
    /// The entry was neither a string nor an object — e.g. a YAML
    /// number where a capability identifier was expected.
    #[error("capability entry must be a string or object, got {0}")]
    InvalidEntry(String),
}

impl Capability {
    /// snake_case discriminator string. [`Capability::Unknown`] returns
    /// `"unknown"`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Capability::NetworkOutbound => "network_outbound",
            Capability::FilesystemRead { .. } => "filesystem_read",
            Capability::FilesystemWrite { .. } => "filesystem_write",
            Capability::SecretsRead { .. } => "secrets_read",
            Capability::CredentialIssue { .. } => "credential_issue",
            Capability::ConfigRead { .. } => "config_read",
            Capability::AuditWrite => "audit_write",
            Capability::MetricEmit => "metric_emit",
            Capability::ClusterPeerRead => "cluster_peer_read",
            Capability::ClusterLeadershipAcquire => "cluster_leadership_acquire",
            Capability::ClusterLockAcquire => "cluster_lock_acquire",
            Capability::HttpRouteServe => "http_route_serve",
            Capability::TransportListen => "transport_listen",
            Capability::UnboundedSubscriptions => "unbounded_subscriptions",
            Capability::Unknown => "unknown",
        }
    }

    /// All known discriminator strings (excludes `"unknown"`).
    ///
    /// Stable alphabetical order — used by validators, CLI doc
    /// generators, and the JSON-schema emitter. The order is part of
    /// the public surface; tests pin it.
    #[must_use]
    pub fn known_names() -> &'static [&'static str] {
        // Alphabetical (the `known_names_count_is_14_alphabetical` test
        // pins both order and count); add new variants in sorted position
        // and bump that count.
        &[
            "audit_write",
            "cluster_leadership_acquire",
            "cluster_lock_acquire",
            "cluster_peer_read",
            "config_read",
            "credential_issue",
            "filesystem_read",
            "filesystem_write",
            "http_route_serve",
            "metric_emit",
            "network_outbound",
            "secrets_read",
            "transport_listen",
            "unbounded_subscriptions",
        ]
    }

    /// Whether this variant carries args (and therefore requires the
    /// object form in YAML / JSON).
    #[must_use]
    pub fn has_args(kind: &str) -> bool {
        matches!(
            kind,
            "filesystem_read"
                | "filesystem_write"
                | "secrets_read"
                | "credential_issue"
                | "config_read"
        )
    }

    /// The JSON field name carrying a variant-args kind's argument list
    /// (`paths` / `schemes` / `kinds`), or `None` for no-args variants.
    /// Single source of the kind→arg-field mapping `parse_value` and the
    /// JSON-schema generator both consume — they cannot disagree.
    /// (`has_args(k) == arg_field_for_kind(k).is_some()` is asserted in
    /// tests.)
    #[must_use]
    pub fn arg_field_for_kind(kind: &str) -> Option<&'static str> {
        match kind {
            "filesystem_read" | "filesystem_write" => Some("paths"),
            "secrets_read" | "config_read" => Some("schemes"),
            "credential_issue" => Some("kinds"),
            _ => None,
        }
    }

    /// Generate the JSON-Schema fragment for one `required_capabilities`
    /// item, **from** the typed enum's own metadata
    /// ([`known_names`](Self::known_names) + [`arg_field_for_kind`](Self::arg_field_for_kind)).
    /// This is the authoritative source for the `plugin.v1.json`
    /// descriptor schema's capability shape; a drift test asserts the
    /// committed schema equals this output, so the two can never diverge
    /// (the schema is generated from Rust for exactly this reason).
    ///
    /// The shape is fully discriminated: a no-args variant may appear
    /// as a bare string OR an
    /// object `{type}`; a variant-args variant must be an object
    /// `{type, <arg-field>: [..]}` with its field required. Every object
    /// branch sets `additionalProperties: false`, so a typo in an arg
    /// field name (or a misplaced arg on a no-args kind) is rejected.
    #[must_use]
    pub fn items_json_schema() -> serde_json::Value {
        use serde_json::json;
        let no_arg_kinds: Vec<&'static str> = Self::known_names()
            .iter()
            .copied()
            .filter(|k| !Self::has_args(k))
            .collect();
        // Branch 1: bare-string form, no-args variants only.
        let mut one_of = vec![json!({ "type": "string", "enum": no_arg_kinds })];
        // Branches 2..: one discriminated object per known variant.
        for &kind in Self::known_names() {
            let mut properties = serde_json::Map::new();
            properties.insert("type".into(), json!({ "type": "string", "const": kind }));
            let mut required = vec![json!("type")];
            if let Some(field) = Self::arg_field_for_kind(kind) {
                properties.insert(
                    field.into(),
                    json!({ "type": "array", "items": { "type": "string" } }),
                );
                required.push(json!(field));
            }
            one_of.push(json!({
                "type": "object",
                "required": required,
                "properties": properties,
                "additionalProperties": false,
            }));
        }
        json!({ "oneOf": one_of })
    }

    /// Parse a single loose YAML / JSON value into a typed `Capability`.
    ///
    /// Accepts:
    ///
    /// * A bare string like `"network_outbound"` — no-args variants
    ///   only. Variant-args variants in bare-string form return
    ///   [`CapabilityParseError::MissingArgs`].
    /// * An object `{"type": "...", ...args}` — works for every
    ///   variant.
    ///
    /// Unknown kinds yield [`CapabilityParseError::UnknownKind`].
    /// This is the **eager** check used by the operator-config
    /// deserialiser: the operator sees the typo at config load time.
    /// (Deserialising directly through serde would yield
    /// [`Capability::Unknown`] instead and defer the error to boot
    /// validation; both paths reject, but `parse_value` produces a
    /// better error site.)
    pub fn parse_value(v: &serde_json::Value) -> Result<Capability, CapabilityParseError> {
        match v {
            serde_json::Value::String(s) => {
                if !Self::known_names().contains(&s.as_str()) {
                    return Err(CapabilityParseError::UnknownKind(s.clone()));
                }
                if Self::has_args(s) {
                    return Err(CapabilityParseError::MissingArgs {
                        kind: s.clone(),
                        missing: match s.as_str() {
                            "filesystem_read" | "filesystem_write" => "paths".into(),
                            "secrets_read" | "config_read" => "schemes".into(),
                            "credential_issue" => "kinds".into(),
                            _ => "args".into(),
                        },
                    });
                }
                // No-args variant: deserialize from the equivalent
                // object form. `serde_json::from_value` on a tagged
                // enum with a "type" field requires the object shape.
                let obj = serde_json::json!({ "type": s });
                serde_json::from_value(obj).map_err(|source| CapabilityParseError::InvalidArgs {
                    kind: s.clone(),
                    source,
                })
            }
            serde_json::Value::Object(map) => {
                let kind = map
                    .get("type")
                    .and_then(|t| t.as_str())
                    .ok_or_else(|| {
                        CapabilityParseError::InvalidEntry(
                            "object capability entry is missing string \"type\" field".into(),
                        )
                    })?
                    .to_owned();
                if !Self::known_names().contains(&kind.as_str()) {
                    return Err(CapabilityParseError::UnknownKind(kind));
                }
                serde_json::from_value(v.clone())
                    .map_err(|source| CapabilityParseError::InvalidArgs { kind, source })
            }
            other => Err(CapabilityParseError::InvalidEntry(format!(
                "expected string or object, got {}",
                match other {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::Array(_) => "array",
                    _ => "unknown",
                }
            ))),
        }
    }

    /// True iff `self` (granted) covers `required`. No-args variants
    /// match on kind equality. Variant-args kinds match when the
    /// granted args are a superset of the required args (string
    /// equality on each entry; no glob expansion in v25).
    ///
    /// [`Capability::Unknown`] never covers anything and is never
    /// covered by anything — boot validation catches it as a
    /// separate error class first.
    #[must_use]
    pub fn covers(&self, required: &Capability) -> bool {
        match (self, required) {
            (Capability::Unknown, _) | (_, Capability::Unknown) => false,
            (Capability::NetworkOutbound, Capability::NetworkOutbound)
            | (Capability::AuditWrite, Capability::AuditWrite)
            | (Capability::MetricEmit, Capability::MetricEmit)
            | (Capability::ClusterPeerRead, Capability::ClusterPeerRead)
            | (Capability::ClusterLeadershipAcquire, Capability::ClusterLeadershipAcquire)
            | (Capability::ClusterLockAcquire, Capability::ClusterLockAcquire)
            | (Capability::HttpRouteServe, Capability::HttpRouteServe)
            | (Capability::TransportListen, Capability::TransportListen)
            | (Capability::UnboundedSubscriptions, Capability::UnboundedSubscriptions) => true,
            (Capability::FilesystemRead { paths: g }, Capability::FilesystemRead { paths: r })
            | (
                Capability::FilesystemWrite { paths: g },
                Capability::FilesystemWrite { paths: r },
            ) => is_superset(g, r),
            (Capability::SecretsRead { schemes: g }, Capability::SecretsRead { schemes: r })
            | (Capability::ConfigRead { schemes: g }, Capability::ConfigRead { schemes: r }) => {
                is_superset(g, r)
            }
            (
                Capability::CredentialIssue { kinds: g },
                Capability::CredentialIssue { kinds: r },
            ) => is_superset(g, r),
            _ => false,
        }
    }
}

fn is_superset(granted: &[String], required: &[String]) -> bool {
    required.iter().all(|r| granted.iter().any(|g| g == r))
}

/// Outcome of [`validate_typed_capabilities`].
///
/// Three failure modes are distinguished so operators get a useful
/// error message: a stale-cdylib mismatch ("plugin declared X, host
/// doesn't know X"), a config-side typo (caught upstream at config
/// parse, but returned here for symmetry), and the common case
/// ("plugin needs X, operator didn't grant X").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCheck {
    /// Every required capability is recognised and granted. Proceed.
    Satisfied,
    /// One or more required capabilities deserialised to
    /// [`Capability::Unknown`] — the cdylib targets a future host.
    UnknownRequiredCapabilities(Vec<String>),
    /// One or more granted capabilities deserialised to
    /// [`Capability::Unknown`] — operator config typo. Normally
    /// caught at config parse via [`Capability::parse_value`], but
    /// returned here for code paths that bypass the eager parser.
    UnknownGrantedCapabilities(Vec<String>),
    /// One or more required capabilities are recognised but not
    /// covered by the granted set. Each entry is the kind string
    /// (variant args omitted for the error message — the operator
    /// looks up the plugin's manifest for the full shape).
    UngrantedCapabilities(Vec<String>),
}

impl CapabilityCheck {
    /// Whether registration should proceed.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// Validate a plugin's typed required capabilities against the
/// operator's typed grant set.
///
/// Three-stage check:
///
/// 1. Reject any required capability that is [`Capability::Unknown`]
///    (the cdylib declared a future-version capability) →
///    [`CapabilityCheck::UnknownRequiredCapabilities`].
/// 2. Reject any granted capability that is `Unknown` (config typo) →
///    [`CapabilityCheck::UnknownGrantedCapabilities`].
/// 3. For each required, find a granted that [`Capability::covers`] it.
///    If none, return [`CapabilityCheck::UngrantedCapabilities`].
///
/// `plugin_id` is currently unused in the return value but kept in
/// the signature so callers can log a per-plugin error message
/// without an extra arg threading.
#[must_use]
pub fn validate_typed_capabilities(
    _plugin_id: &str,
    required: &[Capability],
    granted: &[Capability],
) -> CapabilityCheck {
    let unknown_required: Vec<String> = required
        .iter()
        .filter(|&c| matches!(c, Capability::Unknown))
        .map(|c| c.kind().to_owned())
        .collect();
    if !unknown_required.is_empty() {
        return CapabilityCheck::UnknownRequiredCapabilities(unknown_required);
    }
    let unknown_granted: Vec<String> = granted
        .iter()
        .filter(|&c| matches!(c, Capability::Unknown))
        .map(|c| c.kind().to_owned())
        .collect();
    if !unknown_granted.is_empty() {
        return CapabilityCheck::UnknownGrantedCapabilities(unknown_granted);
    }
    let ungranted: Vec<String> = required
        .iter()
        .filter(|r| !granted.iter().any(|g| g.covers(r)))
        .map(|c| c.kind().to_owned())
        .collect();
    if !ungranted.is_empty() {
        return CapabilityCheck::UngrantedCapabilities(ungranted);
    }
    CapabilityCheck::Satisfied
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn kind_returns_snake_case_discriminator() {
        assert_eq!(Capability::NetworkOutbound.kind(), "network_outbound");
        assert_eq!(
            Capability::FilesystemRead { paths: vec![] }.kind(),
            "filesystem_read"
        );
        assert_eq!(Capability::AuditWrite.kind(), "audit_write");
        assert_eq!(Capability::Unknown.kind(), "unknown");
    }

    #[test]
    fn has_args_and_arg_field_agree_for_every_known_kind() {
        // The two mappings the schema generator + parser both consume must
        // never disagree, else `items_json_schema` would emit a branch that
        // `parse_value` can't satisfy (or vice versa).
        for &kind in Capability::known_names() {
            assert_eq!(
                Capability::has_args(kind),
                Capability::arg_field_for_kind(kind).is_some(),
                "has_args / arg_field_for_kind disagree for {kind:?}"
            );
        }
    }

    #[test]
    fn items_json_schema_is_discriminated_and_closed() {
        let schema = Capability::items_json_schema();
        let branches = schema["oneOf"].as_array().expect("oneOf");
        // 1 bare-string branch + one object branch per known variant.
        assert_eq!(branches.len(), 1 + Capability::known_names().len());
        // Every object branch closes additionalProperties + requires `type`.
        for b in branches.iter().filter(|b| b["type"] == "object") {
            assert_eq!(b["additionalProperties"], serde_json::json!(false));
            assert!(
                b["required"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("type"))
            );
        }
    }

    #[test]
    fn known_names_count_is_14_alphabetical() {
        let names = Capability::known_names();
        assert_eq!(names.len(), 14, "expected 14 known capability variants");
        let mut sorted = names.to_vec();
        sorted.sort();
        assert_eq!(sorted, names.to_vec(), "known_names must be alphabetical");
    }

    #[test]
    fn roundtrip_no_args_variants() {
        for cap in [
            Capability::NetworkOutbound,
            Capability::AuditWrite,
            Capability::MetricEmit,
            Capability::ClusterPeerRead,
            Capability::ClusterLeadershipAcquire,
            Capability::ClusterLockAcquire,
            Capability::HttpRouteServe,
            Capability::TransportListen,
            Capability::UnboundedSubscriptions,
        ] {
            let s = serde_json::to_string(&cap).unwrap();
            let back: Capability = serde_json::from_str(&s).unwrap();
            assert_eq!(cap, back, "roundtrip failed for {}", cap.kind());
        }
    }

    #[test]
    fn roundtrip_args_variants() {
        let cap = Capability::FilesystemRead {
            paths: vec!["/a".into(), "/b".into()],
        };
        let s = serde_json::to_string(&cap).unwrap();
        assert!(s.contains("\"paths\""));
        let back: Capability = serde_json::from_str(&s).unwrap();
        assert_eq!(cap, back);

        let cap = Capability::SecretsRead {
            schemes: vec!["vault".into(), "env".into()],
        };
        let s = serde_json::to_string(&cap).unwrap();
        let back: Capability = serde_json::from_str(&s).unwrap();
        assert_eq!(cap, back);

        let cap = Capability::CredentialIssue {
            kinds: vec!["oauth_client_credentials".into()],
        };
        let s = serde_json::to_string(&cap).unwrap();
        let back: Capability = serde_json::from_str(&s).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    fn parse_value_accepts_bare_string_for_no_args() {
        let v = json!("network_outbound");
        assert_eq!(
            Capability::parse_value(&v).unwrap(),
            Capability::NetworkOutbound
        );

        let v = json!("audit_write");
        assert_eq!(Capability::parse_value(&v).unwrap(), Capability::AuditWrite);
    }

    #[test]
    fn parse_value_accepts_object_form_for_no_args() {
        let v = json!({ "type": "network_outbound" });
        assert_eq!(
            Capability::parse_value(&v).unwrap(),
            Capability::NetworkOutbound
        );
    }

    #[test]
    fn parse_value_accepts_object_form_for_args() {
        let v = json!({ "type": "filesystem_read", "paths": ["/a", "/b"] });
        assert_eq!(
            Capability::parse_value(&v).unwrap(),
            Capability::FilesystemRead {
                paths: vec!["/a".into(), "/b".into()]
            }
        );

        let v = json!({ "type": "secrets_read", "schemes": ["vault"] });
        assert_eq!(
            Capability::parse_value(&v).unwrap(),
            Capability::SecretsRead {
                schemes: vec!["vault".into()]
            }
        );
    }

    #[test]
    fn parse_value_rejects_bare_string_for_args_variants() {
        let v = json!("filesystem_read");
        match Capability::parse_value(&v) {
            Err(CapabilityParseError::MissingArgs { kind, missing }) => {
                assert_eq!(kind, "filesystem_read");
                assert_eq!(missing, "paths");
            }
            other => panic!("expected MissingArgs, got {other:?}"),
        }

        let v = json!("secrets_read");
        match Capability::parse_value(&v) {
            Err(CapabilityParseError::MissingArgs { kind, missing }) => {
                assert_eq!(kind, "secrets_read");
                assert_eq!(missing, "schemes");
            }
            other => panic!("expected MissingArgs, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_rejects_unknown_kind() {
        let v = json!("totally_made_up");
        match Capability::parse_value(&v) {
            Err(CapabilityParseError::UnknownKind(k)) => assert_eq!(k, "totally_made_up"),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
        let v = json!({ "type": "future_capability" });
        match Capability::parse_value(&v) {
            Err(CapabilityParseError::UnknownKind(k)) => assert_eq!(k, "future_capability"),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_rejects_non_string_non_object() {
        let v = json!(42);
        match Capability::parse_value(&v) {
            Err(CapabilityParseError::InvalidEntry(msg)) => {
                assert!(msg.contains("number"), "got: {msg}");
            }
            other => panic!("expected InvalidEntry, got {other:?}"),
        }
    }

    #[test]
    fn covers_no_args_kind_equality() {
        assert!(Capability::NetworkOutbound.covers(&Capability::NetworkOutbound));
        assert!(!Capability::NetworkOutbound.covers(&Capability::AuditWrite));
    }

    #[test]
    fn covers_filesystem_read_superset() {
        let granted = Capability::FilesystemRead {
            paths: vec!["/a".into(), "/b".into()],
        };
        let req = Capability::FilesystemRead {
            paths: vec!["/a".into()],
        };
        assert!(granted.covers(&req), "superset should cover subset");
        assert!(!req.covers(&granted), "subset must not cover superset");
    }

    #[test]
    fn covers_filesystem_read_disjoint() {
        let granted = Capability::FilesystemRead {
            paths: vec!["/a".into()],
        };
        let req = Capability::FilesystemRead {
            paths: vec!["/b".into()],
        };
        assert!(!granted.covers(&req));
    }

    #[test]
    fn covers_secrets_read_superset() {
        let granted = Capability::SecretsRead {
            schemes: vec!["vault".into(), "env".into(), "file".into()],
        };
        let req = Capability::SecretsRead {
            schemes: vec!["vault".into()],
        };
        assert!(granted.covers(&req));
        let req2 = Capability::SecretsRead {
            schemes: vec!["aws-sm".into()],
        };
        assert!(!granted.covers(&req2));
    }

    #[test]
    fn covers_mismatched_kind_returns_false() {
        let a = Capability::FilesystemRead {
            paths: vec!["/a".into()],
        };
        let b = Capability::FilesystemWrite {
            paths: vec!["/a".into()],
        };
        assert!(!a.covers(&b));
        assert!(!b.covers(&a));
    }

    #[test]
    fn unknown_deserialises_from_future_kind() {
        let v = json!({ "type": "totally_future_capability" });
        let cap: Capability = serde_json::from_value(v).unwrap();
        assert_eq!(cap, Capability::Unknown);
    }

    #[test]
    fn unknown_never_covers_anything() {
        assert!(!Capability::Unknown.covers(&Capability::NetworkOutbound));
        assert!(!Capability::NetworkOutbound.covers(&Capability::Unknown));
        assert!(!Capability::Unknown.covers(&Capability::Unknown));
    }

    #[test]
    fn validate_satisfied_simple() {
        let required = vec![Capability::NetworkOutbound];
        let granted = vec![Capability::NetworkOutbound];
        assert_eq!(
            validate_typed_capabilities("p", &required, &granted),
            CapabilityCheck::Satisfied
        );
    }

    #[test]
    fn validate_satisfied_with_superset_paths() {
        let required = vec![Capability::FilesystemRead {
            paths: vec!["/etc/myapp/config.yaml".into()],
        }];
        let granted = vec![Capability::FilesystemRead {
            paths: vec!["/etc/myapp/config.yaml".into(), "/etc/myapp/keys".into()],
        }];
        assert_eq!(
            validate_typed_capabilities("p", &required, &granted),
            CapabilityCheck::Satisfied
        );
    }

    #[test]
    fn validate_ungranted_paths_disjoint() {
        let required = vec![Capability::FilesystemRead {
            paths: vec!["/a".into()],
        }];
        let granted = vec![Capability::FilesystemRead {
            paths: vec!["/b".into()],
        }];
        match validate_typed_capabilities("p", &required, &granted) {
            CapabilityCheck::UngrantedCapabilities(v) => assert_eq!(v, vec!["filesystem_read"]),
            other => panic!("expected UngrantedCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_unknown_required() {
        let required = vec![Capability::Unknown];
        let granted = vec![Capability::NetworkOutbound];
        match validate_typed_capabilities("p", &required, &granted) {
            CapabilityCheck::UnknownRequiredCapabilities(v) => assert_eq!(v, vec!["unknown"]),
            other => panic!("expected UnknownRequiredCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_unknown_granted() {
        let required = vec![Capability::NetworkOutbound];
        let granted = vec![Capability::Unknown];
        match validate_typed_capabilities("p", &required, &granted) {
            CapabilityCheck::UnknownGrantedCapabilities(v) => assert_eq!(v, vec!["unknown"]),
            other => panic!("expected UnknownGrantedCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn check_is_satisfied_helper() {
        assert!(CapabilityCheck::Satisfied.is_satisfied());
        assert!(!CapabilityCheck::UnknownRequiredCapabilities(vec!["x".into()]).is_satisfied());
        assert!(!CapabilityCheck::UnknownGrantedCapabilities(vec!["x".into()]).is_satisfied());
        assert!(!CapabilityCheck::UngrantedCapabilities(vec!["x".into()]).is_satisfied());
    }
}
