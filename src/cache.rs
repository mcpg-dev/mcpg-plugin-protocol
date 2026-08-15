//! `cache` entity kind — ephemeral TTL'd KV (spec §9.9).
//!
//! Distinct from `store` because cache loss is always safe — a
//! missed `get` falls back to "ask the source again". Canonical
//! use cases: MCP response caching, JWKS / OIDC discovery caching,
//! rate-limit counters (`incr` is the key primitive), per-request
//! memoisation.
//!
//! # Best-effort semantics
//!
//! `get` MAY return `None` for a key that was just `put` — eviction,
//! TTL, cross-node inconsistency, and backend throttling all
//! legitimately produce misses. Callers MUST treat `None` as
//! "recompute from source", never as an error signal.
//!
//! # `incr` atomicity
//!
//! `incr` MUST be atomic — rate-limit entities rely on this for
//! quota correctness. A racy increment breaks the contract and is
//! a plugin bug. Backends that cannot provide atomic increment
//! (e.g., a dumb filesystem cache) MUST return
//! `CacheError::Unsupported { op: "incr" }` rather than silently
//! falling back to a non-atomic load-then-store.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;

/// Failure modes. Backends translate native errors into one of
/// these so gateway policy (retry / fail-open) is uniform across
/// plugins. Note: a missing key is NOT an error — `get` returns
/// `None`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheError {
    /// Backend I/O failed — network, disk, quota, etc. Carries a
    /// short human-readable reason for logs; the wire form is
    /// stable so auditors can index on `kind`.
    Backend { reason: String },
    /// Operation not supported on this backend. Canonical use:
    /// `incr` on a read-through cache that can't serialise writes.
    Unsupported { op: String },
    /// Backend rejected the request as rate-limited / over-quota.
    Throttled,
    /// Namespace isn't served by this plugin (operator config +
    /// plugin support disagreed). Usually a startup-validation
    /// error; kept as a runtime variant so the dispatcher can
    /// surface clean 5xx messages.
    UnsupportedNamespace,
}

impl CacheError {
    /// Bounded metrics label — matches the `StoreError::kind_label`
    /// pattern (free-form `reason` never hits Prometheus).
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::Unsupported { .. } => "unsupported_op",
            Self::Throttled => "throttled",
            Self::UnsupportedNamespace => "unsupported_namespace",
        }
    }
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "cache backend: {reason}"),
            Self::Unsupported { op } => write!(f, "cache op unsupported: {op}"),
            Self::Throttled => write!(f, "cache backend throttled"),
            Self::UnsupportedNamespace => {
                write!(f, "cache namespace unsupported by this plugin")
            }
        }
    }
}

impl std::error::Error for CacheError {}

/// The `cache` entity trait. Selected per-binding via the
/// binding's `cache: { kind: <plugin_id> }` block.
#[crate::async_trait]
pub trait Cache: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Namespaces this plugin is willing to serve. The gateway's
    /// registry refuses a binding that names a namespace absent
    /// from this list.
    ///
    /// Plugins that can serve ANY namespace (typical for generic
    /// KV backends like Redis) advertise an empty list AND
    /// override [`Self::serves_any_namespace`] to return `true`
    /// — the registry treats that pair as "accept any binding".
    fn supported_namespaces(&self) -> Vec<String>;

    /// Whether this plugin serves any namespace the operator
    /// asks for (generic KV backend pattern). Default `false` —
    /// plugins advertise specific namespaces via
    /// `supported_namespaces()` unless they override.
    fn serves_any_namespace(&self) -> bool {
        false
    }

    /// Fetch `key` from namespace `ns`. `None` for a miss
    /// (including evicted or TTL-expired entries). Backend failures
    /// are swallowed as a miss — callers MUST treat miss as
    /// "recompute from source", so surfacing a backend error as
    /// `Err` would force every caller into retry logic they don't
    /// need.
    async fn get(&self, ns: &str, key: &str) -> Option<bytes::Bytes>;

    /// Insert `key` into namespace `ns` with `value` and a TTL.
    /// `ttl = Duration::ZERO` means "expire on next read" — not
    /// "no TTL"; there's no infinite-TTL form by design, because
    /// a cache that never expires is a store in disguise.
    async fn put(
        &self,
        ns: &str,
        key: &str,
        value: bytes::Bytes,
        ttl: Duration,
    ) -> Result<(), CacheError>;

    /// Remove `key` from namespace `ns`. Idempotent — deleting a
    /// missing key is `Ok(())`.
    async fn delete(&self, ns: &str, key: &str);

    /// Remove every key from namespace `ns`. Used sparingly (key-
    /// rotation, JWKS refresh storms, test cleanup).
    async fn clear(&self, ns: &str) -> Result<(), CacheError>;

    /// Atomic increment. `by` MAY be negative. Returns the value
    /// AFTER the increment. On first access (key missing), the
    /// key is initialised to `by` and `ttl` sets the new entry's
    /// expiry. On existing keys the `ttl` MAY refresh the entry's
    /// expiry — backends document the semantics they implement.
    /// Backends without atomic increment return
    /// `Err(CacheError::Unsupported { op: "incr" })`.
    async fn incr(&self, ns: &str, key: &str, by: i64, ttl: Duration) -> Result<i64, CacheError>;

    /// Called on gateway shutdown. Default is a no-op.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_error_kind_label_bounded() {
        assert_eq!(
            CacheError::Backend {
                reason: "disk full".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(
            CacheError::Unsupported { op: "incr".into() }.kind_label(),
            "unsupported_op"
        );
        assert_eq!(CacheError::Throttled.kind_label(), "throttled");
        assert_eq!(
            CacheError::UnsupportedNamespace.kind_label(),
            "unsupported_namespace"
        );
    }

    #[test]
    fn cache_error_display_includes_reason() {
        let e = CacheError::Backend {
            reason: "EIO".into(),
        };
        assert!(e.to_string().contains("EIO"));
    }

    #[test]
    fn cache_error_json_roundtrip() {
        let e = CacheError::Throttled;
        let s = serde_json::to_string(&e).unwrap();
        let parsed: CacheError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, parsed);
    }
}
