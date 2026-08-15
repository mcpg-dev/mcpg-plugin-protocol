//! `store` entity kind — durable keyed state (spec §9.8).
//!
//! One generic entity kind parameterised by role: session, task,
//! pipeline, subscription, replay, plus operator-defined custom
//! roles. A single plugin instance MAY serve multiple roles
//! (typical for backends like NATS KV, Redis, Postgres) or exactly
//! one.
//!
//! # Composition
//!
//! Keyed by role. Per-role, exactly one active `store` entity.
//! Operators pick per-role via the capability's
//! `mcp.configurations.<capability>.store: { kind: <plugin_id> }`.
//! The gateway maintains a role → plugin dispatch table and
//! refuses startup if a required role has no matching plugin.
//!
//! # Per-role semantics (from the spec)
//!
//! - **Session** — read-heavy, short-lived keys, TTL'd.
//! - **Task** — linearizable updates (CAS required), state machines
//!   (pending → running → completed|failed).
//! - **Pipeline** — linearizable, sequence-counted step records.
//! - **Subscription** — KV mapping `(session_id, resource_uri) →
//!   subscriber`. Watched for fan-out.
//! - **Replay** — append-only, sequence-numbered, high-volume. A
//!   plugin that cannot serve Replay MUST omit it from
//!   `supported_roles()`.
//!
//! A plugin advertises which roles it can serve via
//! `supported_roles()`; the gateway's registry refuses a binding
//! that names a role the plugin doesn't support.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;

/// Role a store serves. Every key the gateway writes is scoped to
/// one role — the same key in two roles is two distinct values.
///
/// `Custom` escape hatch lets operators define roles beyond the
/// five canonical ones; plugin vendors implement `supported_roles`
/// defensively to accommodate custom role requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StoreRole {
    Session,
    Task,
    Pipeline,
    Subscription,
    Replay,
    /// Operator-defined role, e.g. `StoreRole::Custom("tenant-
    /// profile".into())`. Wire format serialises as the raw
    /// identifier string, so a custom role looks like any other on
    /// the wire.
    #[serde(untagged)]
    Custom(String),
}

impl std::fmt::Display for StoreRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Task => write!(f, "task"),
            Self::Pipeline => write!(f, "pipeline"),
            Self::Subscription => write!(f, "subscription"),
            Self::Replay => write!(f, "replay"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl StoreRole {
    /// Parse a canonical role string ("session" / "task" / ...).
    /// Anything else is treated as `Custom` — the spec's §9.8
    /// escape hatch.
    pub fn parse(s: &str) -> Self {
        match s {
            "session" => Self::Session,
            "task" => Self::Task,
            "pipeline" => Self::Pipeline,
            "subscription" => Self::Subscription,
            "replay" => Self::Replay,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Metrics-label form. Avoids quoting the `Custom` variant
    /// differently than the canonical ones.
    #[must_use]
    pub fn as_label(&self) -> String {
        self.to_string()
    }
}

/// One value in a store. `bytes` is the opaque payload the caller
/// gave us; `ttl` is advisory (backends MUST honour it when they
/// can, MAY ignore when they can't); `metadata` is caller-attached
/// structured data the backend MUST round-trip alongside the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreValue {
    pub bytes: bytes::Bytes,
    pub ttl: Option<Duration>,
    pub metadata: BTreeMap<String, String>,
}

impl StoreValue {
    /// Build a value with no TTL and no metadata. Shortest path for
    /// callers who just need durable bytes.
    pub fn new(bytes: impl Into<bytes::Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            ttl: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Attach a TTL. The backend MAY ignore (e.g. append-only
    /// stores) — plugin authors MUST advertise their TTL support
    /// in the plugin's documentation.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Attach a `(key, value)` metadata pair.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// One page of a `list` result. `next_cursor = None` signals the
/// final page. Backends that can't paginate MAY return every item
/// at once with `next_cursor = None` — the gateway treats that as
/// one page of N.
#[derive(Debug, Clone)]
pub struct StorePage {
    pub items: Vec<(String, StoreValue)>,
    pub next_cursor: Option<String>,
}

/// Event emitted by a `watch` subscription. The stream terminates
/// when the watched key or the backend connection closes.
#[derive(Debug, Clone)]
pub enum StoreEvent {
    Put { key: String, value: StoreValue },
    Delete { key: String },
}

/// Serde-derivable mirror of [`StoreEvent`] for FFI transport.
/// The streaming-FFI path uses this as the JSON payload plugins
/// push back through the `EventSinkRef` callback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreEventWire {
    Put { key: String, value: StoreValueWire },
    Delete { key: String },
}

impl From<StoreEvent> for StoreEventWire {
    fn from(e: StoreEvent) -> Self {
        match e {
            StoreEvent::Put { key, value } => Self::Put {
                key,
                value: value.into(),
            },
            StoreEvent::Delete { key } => Self::Delete { key },
        }
    }
}

impl From<StoreEventWire> for StoreEvent {
    fn from(e: StoreEventWire) -> Self {
        match e {
            StoreEventWire::Put { key, value } => Self::Put {
                key,
                value: value.into(),
            },
            StoreEventWire::Delete { key } => Self::Delete { key },
        }
    }
}

/// Receipt returned by `append`. `sequence` is monotonically
/// increasing per (role, key) pair — auditors replay the sequence
/// to detect gaps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppendResult {
    pub sequence: u64,
}

/// Failure modes. Backends translate their native errors into
/// one of these variants so gateway policy (retry / fail-open /
/// fail-closed) is uniform across plugins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreError {
    /// Backend I/O failed. Short human-readable `reason` for logs;
    /// the wire form is stable so auditors can index on `kind`.
    Backend { reason: String },
    /// CAS pre-condition failed — `expected` didn't match the
    /// current value. Distinct from `Backend` because the gateway
    /// translates CAS mismatches into task-state conflicts, not
    /// server errors.
    CasMismatch,
    /// Role is not served by this plugin (operator config and
    /// plugin support disagreed). Usually a configuration bug
    /// caught by the startup validation, but shippable as a
    /// runtime error too.
    UnsupportedRole,
    /// Operation not supported on this backend (e.g. `watch` on a
    /// filesystem store).
    Unsupported { op: String },
    /// Backend rejected the request as rate-limited / over-quota.
    Throttled,
    /// Value not found for `get` — distinct from `Backend` because
    /// missing keys are a normal return, not an error to page on.
    /// Note: `get` returns `Ok(None)` for missing keys; this
    /// variant is reserved for operations where the caller's
    /// intent requires the key to exist (CAS with explicit
    /// expected-Some, for instance).
    NotFound,
}

impl StoreError {
    /// Bounded metrics label — mirrors the `AuditError::kind_label`
    /// convention (free-form `reason` strings never hit Prometheus
    /// labels).
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::CasMismatch => "cas_mismatch",
            Self::UnsupportedRole => "unsupported_role",
            Self::Unsupported { .. } => "unsupported_op",
            Self::Throttled => "throttled",
            Self::NotFound => "not_found",
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "store backend: {reason}"),
            Self::CasMismatch => write!(f, "store CAS pre-condition failed"),
            Self::UnsupportedRole => write!(f, "store role unsupported by this plugin"),
            Self::Unsupported { op } => write!(f, "store op unsupported: {op}"),
            Self::Throttled => write!(f, "store backend throttled"),
            Self::NotFound => write!(f, "store key not found"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Type-alias for the watch stream — shorter than the raw
/// `Pin<Box<…>>` in trait signatures without committing to any
/// particular future crate's `BoxStream`.
pub type BoxStoreEventStream =
    Pin<Box<dyn futures_core::Stream<Item = StoreEvent> + Send + 'static>>;

// ---------------------------------------------------------------------------
// Wire types for FFI
// ---------------------------------------------------------------------------

/// Serde-derivable mirror of [`StoreValue`]. `bytes` travels as a
/// `Vec<u8>` (JSON array of bytes, matching `BackendRequest.payload`);
/// `ttl_ms` is milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreValueWire {
    pub bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl From<StoreValue> for StoreValueWire {
    fn from(v: StoreValue) -> Self {
        Self {
            bytes: v.bytes.to_vec(),
            ttl_ms: v.ttl.map(|d| d.as_millis().min(u64::MAX as u128) as u64),
            metadata: v.metadata,
        }
    }
}

impl From<StoreValueWire> for StoreValue {
    fn from(v: StoreValueWire) -> Self {
        Self {
            bytes: bytes::Bytes::from(v.bytes),
            ttl: v.ttl_ms.map(Duration::from_millis),
            metadata: v.metadata,
        }
    }
}

/// Serde-derivable mirror of [`StorePage`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorePageWire {
    pub items: Vec<(String, StoreValueWire)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl From<StorePage> for StorePageWire {
    fn from(p: StorePage) -> Self {
        Self {
            items: p.items.into_iter().map(|(k, v)| (k, v.into())).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

impl From<StorePageWire> for StorePage {
    fn from(p: StorePageWire) -> Self {
        Self {
            items: p.items.into_iter().map(|(k, v)| (k, v.into())).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

/// The `store` entity trait. Durable keyed state, dispatched
/// per-role by the gateway's registry.
#[crate::async_trait]
pub trait Store: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Roles this entity can serve. Binding a role the plugin does
    /// not advertise is refused at registry-build time.
    fn supported_roles(&self) -> Vec<StoreRole>;

    /// Fetch `key` from `role`. `Ok(None)` for missing keys;
    /// `Err(_)` only for backend failures.
    async fn get(&self, role: StoreRole, key: &str) -> Result<Option<StoreValue>, StoreError>;

    /// Insert or overwrite `key` in `role` with `value`. Backends
    /// MUST honour the value's `ttl` + `metadata` fields when they
    /// can; backends that can't MUST document the limitation.
    async fn put(&self, role: StoreRole, key: &str, value: StoreValue) -> Result<(), StoreError>;

    /// Remove `key` from `role`. Idempotent — removing a missing
    /// key returns `Ok(())`, not `Err(NotFound)`.
    async fn delete(&self, role: StoreRole, key: &str) -> Result<(), StoreError>;

    /// List keys matching `prefix` from `role`. Backends that
    /// cannot paginate return every match in one page with
    /// `next_cursor = None`. `cursor` of `None` starts from the
    /// beginning.
    async fn list(
        &self,
        role: StoreRole,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<StorePage, StoreError>;

    /// Atomic compare-and-swap. `expected = None` means "insert
    /// only if missing"; `expected = Some(v)` means "replace only
    /// if current exactly matches `v`". Returns `Ok(true)` on
    /// success, `Ok(false)` on pre-condition miss, `Err(_)` on
    /// backend failure.
    async fn compare_and_swap(
        &self,
        role: StoreRole,
        key: &str,
        expected: Option<StoreValue>,
        new: StoreValue,
    ) -> Result<bool, StoreError>;

    /// Append-only write. Required for the Replay role; optional
    /// for others. Default implementation calls `put`; backends
    /// that distinguish (e.g. append-only Kafka / object storage)
    /// override to use their native append path + assign a proper
    /// sequence.
    async fn append(
        &self,
        role: StoreRole,
        key: &str,
        value: StoreValue,
    ) -> Result<AppendResult, StoreError> {
        self.put(role, key, value).await?;
        Ok(AppendResult { sequence: 0 })
    }

    /// Stream `StoreEvent`s for `key` in `role`. The stream
    /// terminates when the key or the backend connection closes.
    /// Backends that don't support watching return
    /// `Err(StoreError::Unsupported { op: "watch".into() })`.
    async fn watch(&self, role: StoreRole, key: &str) -> Result<BoxStoreEventStream, StoreError>;

    /// Called on gateway shutdown. Default is a no-op; backends
    /// with connections or buffered state SHOULD override.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_role_parse_canonical_names() {
        assert_eq!(StoreRole::parse("session"), StoreRole::Session);
        assert_eq!(StoreRole::parse("task"), StoreRole::Task);
        assert_eq!(StoreRole::parse("pipeline"), StoreRole::Pipeline);
        assert_eq!(StoreRole::parse("subscription"), StoreRole::Subscription);
        assert_eq!(StoreRole::parse("replay"), StoreRole::Replay);
    }

    #[test]
    fn store_role_parse_custom_falls_through() {
        assert_eq!(
            StoreRole::parse("tenant-profile"),
            StoreRole::Custom("tenant-profile".into())
        );
        assert_eq!(StoreRole::parse("").to_string(), "");
    }

    #[test]
    fn store_role_display_matches_wire() {
        assert_eq!(StoreRole::Session.to_string(), "session");
        assert_eq!(
            StoreRole::Custom("tenant-profile".into()).to_string(),
            "tenant-profile"
        );
    }

    #[test]
    fn store_role_roundtrips_canonical() {
        let s = serde_json::to_string(&StoreRole::Task).unwrap();
        assert_eq!(s, "\"task\"");
        let parsed: StoreRole = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, StoreRole::Task);
    }

    #[test]
    fn store_value_builder_preserves_chain() {
        let v = StoreValue::new(b"hi".to_vec())
            .with_ttl(Duration::from_secs(60))
            .with_metadata("node", "test")
            .with_metadata("shard", "1");
        assert_eq!(v.bytes.as_ref(), b"hi");
        assert_eq!(v.ttl, Some(Duration::from_secs(60)));
        assert_eq!(v.metadata.get("node").map(String::as_str), Some("test"));
        assert_eq!(v.metadata.get("shard").map(String::as_str), Some("1"));
    }

    #[test]
    fn store_error_kind_label_bounded() {
        assert_eq!(
            StoreError::Backend {
                reason: "EIO".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(StoreError::CasMismatch.kind_label(), "cas_mismatch");
        assert_eq!(StoreError::UnsupportedRole.kind_label(), "unsupported_role");
        assert_eq!(
            StoreError::Unsupported { op: "watch".into() }.kind_label(),
            "unsupported_op"
        );
        assert_eq!(StoreError::Throttled.kind_label(), "throttled");
        assert_eq!(StoreError::NotFound.kind_label(), "not_found");
    }

    #[test]
    fn store_error_display_includes_reason() {
        let e = StoreError::Backend {
            reason: "disk full".into(),
        };
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn append_result_roundtrips_json() {
        let r = AppendResult { sequence: 42 };
        let s = serde_json::to_string(&r).unwrap();
        let parsed: AppendResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r, parsed);
    }
}
