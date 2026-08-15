//! `config_provider` entity kind — dynamic configuration sources
//! (spec §9.16).
//!
//! Canonical backends: HashiCorp Consul, Kubernetes ConfigMaps, AWS
//! AppConfig, local YAML files with reload-on-change. Plugins expose
//! a URI-addressable snapshot and (optionally) a delta watch stream.
//!
//! # Composition
//!
//! Keyed by scheme. A provider declares the URI schemes it resolves
//! (`file://`, `consul://`, `k8s-cm://`, `aws-appconfig://`, ...);
//! consumers reference config by URI; the gateway routes the lookup
//! to the matching provider. One scheme = one active plugin.
//!
//! # URI reference format
//!
//! `scheme://opaque-backend-path[#fragment]`
//!
//! Examples:
//!   - `file:///etc/mcpg/config.yaml`
//!   - `consul://kv/mcpg/prod/config`
//!   - `k8s-cm://mcpg-system/gateway-config`
//!   - `aws-appconfig://mcpg/prod/gateway`
//!
//! The fragment is provider-specific — a provider MAY use it to pick
//! a subkey out of a larger document; the built-in `file://` reader
//! ignores it.
//!
//! # Relationship to `secret_provider`
//!
//! Both entities are keyed-by-scheme URI-addressable resources.
//! `config_provider` ships the full document tree (non-secret
//! operational settings) whereas `secret_provider` ships a single
//! opaque value (credential material). A typical gateway uses both:
//! `config_provider` for feature flags, routing tables, plugin
//! allow-lists; `secret_provider` for the credentials those
//! features need.

use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;

/// One config document snapshot. `values` is the full JSON tree the
/// backend returned; `version` is backend-assigned (Consul's
/// `ModifyIndex`, K8s `resourceVersion`, a file's mtime hash, ...)
/// and is the authoritative identifier used by the delta stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigSnapshot {
    /// Backend-assigned version string. Opaque to the consumer; the
    /// only contract is that the watch stream emits monotonically
    /// from `from_version` to `to_version`.
    pub version: String,
    /// The full config tree. Consumers deserialize subtrees into
    /// their own structs via `serde_json::from_value`.
    pub values: Value,
    /// Wall-clock timestamp the gateway received the snapshot.
    /// RFC3339-UTC string (kept dep-free; consumers parse with
    /// `chrono` / `time` as needed).
    pub fetched_at: String,
    /// Echoes the reference URI that produced this snapshot; useful
    /// for audit log lines + multi-source debugging.
    pub source: String,
}

/// Per-change delta emitted by `watch`. `changed_paths` is a list of
/// JSON pointers into `snapshot.values` for the subtrees the
/// provider detected as changed; consumers use them to skip
/// no-ops when only an unrelated section of config changed.
///
/// Providers that cannot compute changed paths at the backend MUST
/// still return a delta with `changed_paths: vec!["/".into()]` —
/// i.e. "the whole tree may have changed". Consumers always re-read
/// from the new snapshot; `changed_paths` is an optimisation hint,
/// not a correctness gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigDelta {
    pub from_version: String,
    pub to_version: String,
    /// JSON Pointer (RFC 6901) paths into `snapshot.values`. The
    /// root pointer is `"/"`.
    pub changed_paths: Vec<String>,
    /// Full snapshot at `to_version`. Consumers do not need to hold
    /// on to the previous snapshot — the delta carries the new
    /// full state.
    pub snapshot: ConfigSnapshot,
}

/// Failure modes. Shaped to mirror `SecretError` so operator tools
/// can treat the two kinds uniformly at the metrics + alert level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigError {
    /// Referenced config document does not exist. Consumers MAY
    /// fall back to defaults.
    NotFound,
    /// Authenticated backend refused the request.
    PermissionDenied,
    /// Backend I/O failed. Carries a short human reason.
    Backend { reason: String },
    /// The URI form is malformed (wrong scheme, provider-specific
    /// fragment missing, etc.). Usually a config-authoring bug.
    InvalidReference { message: String },
    /// No provider is bound to the URI's scheme.
    UnsupportedScheme { scheme: String },
    /// Backend returned bytes that do not parse as the expected
    /// document shape (malformed YAML, non-object top-level, ...).
    /// Distinct from `Backend` because the error is in the data,
    /// not the transport — different alert runbook.
    ParseError { reason: String },
}

impl ConfigError {
    /// Bounded metrics label — free-form fields (`reason`,
    /// `message`, `scheme`) never hit Prometheus.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::Backend { .. } => "backend",
            Self::InvalidReference { .. } => "invalid_reference",
            Self::UnsupportedScheme { .. } => "unsupported_scheme",
            Self::ParseError { .. } => "parse_error",
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "config not found"),
            Self::PermissionDenied => write!(f, "config backend denied access"),
            Self::Backend { reason } => write!(f, "config backend: {reason}"),
            Self::InvalidReference { message } => {
                write!(f, "invalid config reference: {message}")
            }
            Self::UnsupportedScheme { scheme } => {
                write!(f, "no config provider bound to scheme '{scheme}'")
            }
            Self::ParseError { reason } => write!(f, "config parse error: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Watch-stream alias — shorter than the raw `Pin<Box<…>>` and
/// consistent with `BoxSecretRotationStream`.
pub type BoxConfigDeltaStream =
    Pin<Box<dyn futures_core::Stream<Item = ConfigDelta> + Send + 'static>>;

/// The `config_provider` entity trait. Dispatched per-scheme by
/// the gateway's registry.
#[crate::async_trait]
pub trait ConfigProvider: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// URI schemes this provider resolves. The registry auto-binds
    /// each advertised scheme to this provider at boot — the schemes
    /// returned here are the source of truth — and refuses startup
    /// if two providers claim the same scheme.
    fn supported_schemes(&self) -> Vec<String>;

    /// Fetch the current snapshot. Returns the full `ConfigSnapshot`
    /// on success. `ConfigError::NotFound` on a missing document
    /// (consumers MAY treat as Ok(None) and fall back); anything
    /// else is an actionable failure.
    async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError>;

    /// Stream deltas for the referenced config document. Default
    /// impl returns `UnsupportedScheme` so plugins without watch
    /// support just don't advertise it; consumers poll via
    /// `snapshot` on a timer instead. Backends with native change
    /// notification (Consul blocking queries, K8s informers,
    /// inotify/kqueue, ...) override.
    async fn watch(&self, reference: &str) -> Result<BoxConfigDeltaStream, ConfigError> {
        let _ = reference;
        Err(ConfigError::UnsupportedScheme {
            scheme: "watch".into(),
        })
    }

    /// Called on gateway shutdown. Default is a no-op.
    async fn shutdown(&self) {}
}

/// Parse a config reference URI into `(scheme, rest)`.
///
/// `rest` includes everything after `scheme://` — providers may
/// parse it further (extract path segments, fragment, etc.).
/// Returns `None` when the input isn't shaped like a URI.
#[must_use]
pub fn parse_config_ref(reference: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = reference.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    Some((scheme, rest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_kind_label_bounded() {
        assert_eq!(ConfigError::NotFound.kind_label(), "not_found");
        assert_eq!(
            ConfigError::PermissionDenied.kind_label(),
            "permission_denied"
        );
        assert_eq!(
            ConfigError::Backend {
                reason: "EIO".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(
            ConfigError::InvalidReference {
                message: "no scheme".into()
            }
            .kind_label(),
            "invalid_reference"
        );
        assert_eq!(
            ConfigError::UnsupportedScheme {
                scheme: "consul".into()
            }
            .kind_label(),
            "unsupported_scheme"
        );
        assert_eq!(
            ConfigError::ParseError {
                reason: "not YAML".into()
            }
            .kind_label(),
            "parse_error"
        );
    }

    #[test]
    fn config_error_display_includes_detail() {
        let e = ConfigError::Backend {
            reason: "connection refused".into(),
        };
        assert!(e.to_string().contains("connection refused"));

        let e = ConfigError::ParseError {
            reason: "expected map at top level".into(),
        };
        assert!(e.to_string().contains("expected map"));
    }

    #[test]
    fn parse_config_ref_splits_canonical_forms() {
        assert_eq!(
            parse_config_ref("file:///etc/mcpg/config.yaml"),
            Some(("file", "/etc/mcpg/config.yaml"))
        );
        assert_eq!(
            parse_config_ref("consul://kv/mcpg/prod/config"),
            Some(("consul", "kv/mcpg/prod/config"))
        );
        assert_eq!(
            parse_config_ref("k8s-cm://mcpg-system/gateway-config#routes"),
            Some(("k8s-cm", "mcpg-system/gateway-config#routes"))
        );
    }

    #[test]
    fn parse_config_ref_rejects_malformed() {
        assert!(parse_config_ref("not-a-uri").is_none());
        assert!(parse_config_ref("://missing-scheme").is_none());
        assert!(parse_config_ref("no-colon-just-text").is_none());
    }

    #[test]
    fn config_error_json_roundtrip() {
        let e = ConfigError::ParseError {
            reason: "invalid YAML".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: ConfigError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn config_snapshot_round_trips_values() {
        let snap = ConfigSnapshot {
            version: "v42".into(),
            values: serde_json::json!({"feature_x": true, "rpm_cap": 60}),
            fetched_at: "2026-04-23T10:00:00Z".into(),
            source: "file:///etc/mcpg/config.yaml".into(),
        };
        assert_eq!(snap.values["feature_x"], true);
        assert_eq!(snap.values["rpm_cap"], 60);
    }

    #[test]
    fn config_delta_root_path_is_fallback() {
        // Providers that can't compute precise paths use "/"; spec
        // contract: consumers always re-read from snapshot, so "/"
        // is the safe "whole tree" hint.
        let snap = ConfigSnapshot {
            version: "v2".into(),
            values: serde_json::json!({}),
            fetched_at: "2026-04-23T10:00:00Z".into(),
            source: "file:///x".into(),
        };
        let delta = ConfigDelta {
            from_version: "v1".into(),
            to_version: "v2".into(),
            changed_paths: vec!["/".into()],
            snapshot: snap,
        };
        assert_eq!(delta.changed_paths, vec!["/".to_owned()]);
    }
}
