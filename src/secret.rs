//! `secret_provider` entity kind — fetch and watch secrets
//! (spec §9.15).
//!
//! Canonical backends: HashiCorp Vault, AWS Secrets Manager, GCP
//! Secret Manager, Kubernetes Secrets, `sops`-encrypted files,
//! environment variables, files on disk.
//!
//! Replaces the placeholder `cap.host.secret_store` capability —
//! secrets are not a host capability, they are an entity dependency
//! with a URI-addressable backing store.
//!
//! # Composition
//!
//! Keyed by scheme. A provider declares the URI schemes it resolves
//! (`vault://`, `aws-sm://`, `env://`, `file://`, etc.); consumers
//! reference secrets by URI; the gateway routes the lookup to the
//! matching provider. One scheme = one active plugin.
//!
//! # URI reference format
//!
//! `scheme://opaque-backend-path[#field]`
//!
//! Examples:
//!   - `env://DATABASE_PASSWORD`
//!   - `file:///etc/mcpg/jwt-signing-key`
//!   - `vault://secret/data/db#password`
//!   - `aws-sm://us-east-1/mcpg/prod/api-key#current`
//!
//! The `#field` anchor is provider-specific — Vault uses it to pick
//! a key out of a JSON secret; env/file providers ignore it.

use std::collections::BTreeMap;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;

/// One secret value. `bytes` is opaque; consumers that expect a
/// string call `std::str::from_utf8(&bytes)`. `version` +
/// `expires_at` are advisory — consumers MAY trigger a refresh
/// when they see an expired value, but the watch API is the
/// canonical rotation signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretValue {
    pub bytes: bytes::Bytes,
    /// Provider-assigned version / generation identifier
    /// (Vault's `metadata.version`, AWS-SM's `VersionId`, ...).
    pub version: Option<String>,
    /// Wall-clock expiry if the backend exposes one. RFC3339-UTC
    /// string (kept dep-free; consumers parse with `chrono` /
    /// `time` as needed).
    pub expires_at: Option<String>,
    /// Provider-specific metadata (Vault's `custom_metadata`,
    /// AWS-SM's tags, ...). Consumers MAY read but MUST NOT rely
    /// on any specific key.
    pub metadata: BTreeMap<String, String>,
}

impl SecretValue {
    /// Build a simple value with no version / expiry / metadata.
    /// Shortest path for callers that just need the bytes.
    pub fn new(bytes: impl Into<bytes::Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            version: None,
            expires_at: None,
            metadata: BTreeMap::new(),
        }
    }
}

/// Rotation event — emitted by `watch` when the backend rotates
/// the secret. `reason` is a short human-readable string the
/// provider attaches for audit logs (`"scheduled"`, `"leak-
/// revoked"`, `"admin-triggered"`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRotation {
    pub new_value: SecretValue,
    pub reason: String,
}

/// Failure modes. Consumers that need to distinguish "secret is
/// missing" (expected for optional config) from "backend failed"
/// (actionable incident) match on variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretError {
    /// Secret does not exist. Consumers MAY fall back to defaults.
    NotFound,
    /// Authenticated backend refused the request.
    PermissionDenied,
    /// Backend I/O failed. Carries a short human reason.
    Backend { reason: String },
    /// The URI form is malformed (wrong scheme, missing anchor a
    /// provider requires, etc.). This variant is usually a
    /// config-authoring bug, not a runtime concern.
    InvalidReference { message: String },
    /// No provider is bound to the URI's scheme. Startup
    /// validation catches most of these, but admin-triggered
    /// rebinding can surface it at runtime too.
    UnsupportedScheme { scheme: String },
}

impl SecretError {
    /// Bounded metrics label — `reason` / `message` / `scheme`
    /// never hit Prometheus.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::Backend { .. } => "backend",
            Self::InvalidReference { .. } => "invalid_reference",
            Self::UnsupportedScheme { .. } => "unsupported_scheme",
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "secret not found"),
            Self::PermissionDenied => write!(f, "secret backend denied access"),
            Self::Backend { reason } => write!(f, "secret backend: {reason}"),
            Self::InvalidReference { message } => {
                write!(f, "invalid secret reference: {message}")
            }
            Self::UnsupportedScheme { scheme } => {
                write!(f, "no secret provider bound to scheme '{scheme}'")
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Watch-stream alias — shorter than the raw `Pin<Box<…>>` and
/// consistent with the `store` entity's `BoxStoreEventStream`.
pub type BoxSecretRotationStream =
    Pin<Box<dyn futures_core::Stream<Item = SecretRotation> + Send + 'static>>;

/// Serde-derivable mirror of [`SecretValue`] for FFI transport.
/// `bytes` travels as a JSON array of bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretValueWire {
    pub bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl From<SecretValue> for SecretValueWire {
    fn from(v: SecretValue) -> Self {
        Self {
            bytes: v.bytes.to_vec(),
            version: v.version,
            expires_at: v.expires_at,
            metadata: v.metadata,
        }
    }
}

impl From<SecretValueWire> for SecretValue {
    fn from(v: SecretValueWire) -> Self {
        Self {
            bytes: bytes::Bytes::from(v.bytes),
            version: v.version,
            expires_at: v.expires_at,
            metadata: v.metadata,
        }
    }
}

/// Serde-derivable mirror of [`SecretRotation`]. The streaming-FFI
/// path uses this as the JSON payload plugins push
/// through the `EventSinkRef` callback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRotationWire {
    pub new_value: SecretValueWire,
    pub reason: String,
}

impl From<SecretRotation> for SecretRotationWire {
    fn from(r: SecretRotation) -> Self {
        Self {
            new_value: r.new_value.into(),
            reason: r.reason,
        }
    }
}

impl From<SecretRotationWire> for SecretRotation {
    fn from(r: SecretRotationWire) -> Self {
        Self {
            new_value: r.new_value.into(),
            reason: r.reason,
        }
    }
}

/// The `secret_provider` entity trait. Dispatched per-scheme by
/// the gateway's registry.
#[crate::async_trait]
pub trait SecretProvider: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// URI schemes this provider resolves. The registry auto-binds
    /// each advertised scheme to this provider at boot — the schemes
    /// returned here are the source of truth — and refuses startup
    /// if two providers claim the same scheme.
    fn supported_schemes(&self) -> Vec<String>;

    /// Fetch the secret. Returns the full `SecretValue` on
    /// success. `SecretError::NotFound` on a missing secret
    /// (consumers MAY treat as Ok(None) and fall back);
    /// anything else is an actionable failure.
    async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError>;

    /// Whether the referenced secret exists. Default impl calls
    /// `get` and maps Ok / NotFound / Err. Backends that have a
    /// cheap existence-check (Vault's `LIST` for example) should
    /// override.
    async fn has(&self, secret_ref: &str) -> bool {
        self.get(secret_ref).await.is_ok()
    }

    /// Stream rotation events for the referenced secret. Default
    /// impl returns `UnsupportedScheme` so plugins without watch
    /// support just don't advertise it; consumers poll on
    /// `expires_at` instead. Backends with native watch (Vault
    /// leases, K8s Secret informers, ...) override.
    async fn watch(&self, secret_ref: &str) -> Result<BoxSecretRotationStream, SecretError> {
        let _ = secret_ref;
        Err(SecretError::UnsupportedScheme {
            scheme: "watch".into(),
        })
    }

    /// Called on gateway shutdown. Default is a no-op.
    async fn shutdown(&self) {}
}

/// Parse a secret reference URI into `(scheme, rest)`.
///
/// `rest` includes everything after `scheme://` — providers may
/// parse it further (extract anchor, path segments, etc.).
/// Returns `None` when the input isn't shaped like a URI.
#[must_use]
pub fn parse_secret_ref(reference: &str) -> Option<(&str, &str)> {
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
    fn secret_value_builder_sets_bytes() {
        let v = SecretValue::new(b"hunter2".to_vec());
        assert_eq!(v.bytes.as_ref(), b"hunter2");
        assert!(v.version.is_none());
        assert!(v.metadata.is_empty());
    }

    #[test]
    fn secret_error_kind_label_bounded() {
        assert_eq!(SecretError::NotFound.kind_label(), "not_found");
        assert_eq!(
            SecretError::PermissionDenied.kind_label(),
            "permission_denied"
        );
        assert_eq!(
            SecretError::Backend {
                reason: "EIO".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(
            SecretError::InvalidReference {
                message: "no scheme".into()
            }
            .kind_label(),
            "invalid_reference"
        );
        assert_eq!(
            SecretError::UnsupportedScheme {
                scheme: "vault".into()
            }
            .kind_label(),
            "unsupported_scheme"
        );
    }

    #[test]
    fn secret_error_display_includes_detail() {
        let e = SecretError::Backend {
            reason: "connection refused".into(),
        };
        assert!(e.to_string().contains("connection refused"));
    }

    #[test]
    fn parse_secret_ref_splits_canonical_forms() {
        assert_eq!(parse_secret_ref("env://DB_PASS"), Some(("env", "DB_PASS")));
        assert_eq!(
            parse_secret_ref("file:///etc/mcpg/key"),
            Some(("file", "/etc/mcpg/key"))
        );
        assert_eq!(
            parse_secret_ref("vault://secret/data/db#password"),
            Some(("vault", "secret/data/db#password"))
        );
    }

    #[test]
    fn parse_secret_ref_rejects_malformed() {
        assert!(parse_secret_ref("not-a-uri").is_none());
        assert!(parse_secret_ref("://missing-scheme").is_none());
        assert!(parse_secret_ref("no-colon-just-text").is_none());
    }

    #[test]
    fn secret_error_json_roundtrip() {
        let e = SecretError::Backend {
            reason: "EIO".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: SecretError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
