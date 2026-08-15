//! `content_store` entity kind — gateway-managed binary blob storage
//! (the 21st plugin entity class; spec §9.20).
//!
//! Solves "where do generated images / audio / large tool outputs go?"
//! without forcing every binding to inline binary content in its JSON
//! response. A `ContentStore` is the in-process Rust surface a storage
//! backend implements; the gateway routes blob put/get/delete through it.
//!
//! This trait is the canonical, PROTOCOL-CRATE home for the content_store
//! entity (mirroring [`crate::catalog::CatalogProvider`] et al.) — the
//! host-side trait the FFI `ContentStoreVTable` (see
//! [`crate::abi::ContentStoreVTable`]) adapts to. `mcpg-backend-llm-shared`
//! re-exports these for source compatibility.
//!
//! The FFI vtable encodes the same operations as a JSON `{"ok"|"err"}`
//! envelope; a host adapter maps the vtable calls onto this trait. The
//! method names (`kind`, `build_profile` / `register_profile`, `put`,
//! `get`, `delete`, `signed_url`, `stats`, `sweep_expired`) deliberately
//! mirror the vtable's vocabulary so the in-tree trait and the plugin ABI
//! stay aligned.
//!
//! ## Resource URI scheme
//!
//! A returned `ResourceHandle.uri` is `mcpg-resource://<id>` where `<id>`
//! is `hash:<blake3-256-hex>` (anonymous, content-addressed) or
//! `alias:<session-id>:<operator-name>` (operator-aliased within a
//! session). The `<id>` is opaque to clients — they pass it to
//! `resources/read`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PluginManifest;

/// Content + metadata handed to [`ContentStore::put`].
///
/// `Serialize`/`Deserialize` are derived so the value crosses the
/// content_store FFI vtable's JSON `put` envelope directly. NOTE: `bytes`
/// serializes as a JSON byte array — fine for correctness, but a base64
/// wire encoding is a follow-up for large-blob cdylib stores (the common
/// path is the in-process/static store, which never crosses the FFI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentToStore {
    pub bytes: bytes::Bytes,
    pub mime_type: String,
    /// Operator-supplied alias (optional). When set, the public URI
    /// suffix is `alias:<session-id>:<alias>`. The content is still
    /// BLAKE3-hashed for dedup-on-content; both the alias and the hash
    /// resolve to the same blob via [`ContentStore::get`].
    pub alias: Option<String>,
    /// Tag the resource with the session it belongs to. `None` means a
    /// cross-session resource (typically only accessible via signed
    /// URLs). When set, `resources/read` refuses reads from a different
    /// session.
    pub session_id: Option<String>,
    /// Tenant tag for multi-tenant isolation. When set, [`ContentStore::get`]
    /// returns `NotFound` for callers from a different tenant (does not
    /// leak existence). `None` = single-tenant deployments.
    pub tenant_id: Option<String>,
    /// Time-to-live. `None` = infinite (until manual delete or LRU
    /// eviction).
    pub ttl: Option<Duration>,
}

/// Public handle returned by [`ContentStore::put`]. Bindings include this
/// in their JSON response and clients reference the `uri` via
/// `resources/read`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceHandle {
    /// Either `hash:<blake3-hex>` or `alias:<session-id>:<name>`.
    pub id: String,
    /// `mcpg-resource://<id>`.
    pub uri: String,
    pub size_bytes: usize,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Always `blake3:<hex>` — the content hash (unique per blob,
    /// independent of `alias`). Useful for cross-store dedup + audit.
    pub content_hash: String,
}

/// Returned by [`ContentStore::get`].
///
/// `Serialize`/`Deserialize` are derived so the value crosses the
/// content_store FFI vtable's JSON `get` envelope directly (same
/// big-blob-as-JSON-array caveat as [`ContentToStore`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContent {
    pub bytes: bytes::Bytes,
    pub mime_type: String,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub stored_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Per-store usage statistics. Surfaced as Prometheus gauges by the
/// gateway runtime. Counts are best-effort snapshots.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ContentStoreStats {
    pub item_count: u64,
    pub byte_count: u64,
    pub max_bytes: u64,
}

/// All errors a [`ContentStore`] implementation may surface.
///
/// `Serialize`/`Deserialize` are derived so the typed error round-trips
/// across the content_store FFI vtable's `{"err": ...}` envelope — the
/// host adapter reconstructs the exact variant (notably
/// [`Self::SignedUrlNotSupported`], which callers branch on) rather than
/// flattening every failure to an opaque string.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ContentStoreError {
    /// The submitted content exceeds the store's per-call size limit.
    #[error("content too large: {actual_bytes} bytes exceeds limit of {limit_bytes}")]
    SizeLimit {
        limit_bytes: usize,
        actual_bytes: usize,
    },
    /// Backend storage failed (I/O, network).
    #[error("storage error: {message}")]
    Storage { message: String },
    /// The implementation has no signed-URL surface (e.g. the in-process
    /// store). Callers fall back to `resources/read`.
    #[error("signed urls are not supported by this store")]
    SignedUrlNotSupported,
    /// Session/tenant ACL violation. The gateway translates this into a
    /// generic "not found" so existence isn't leaked.
    #[error("forbidden")]
    Forbidden,
    /// The id was not found, has expired, or has been evicted.
    #[error("not found")]
    NotFound,
}

impl ContentStoreError {
    /// Bounded metrics label — mirrors the sibling error types
    /// (`CacheError::kind_label` etc.) so free-form `message` fields never
    /// reach Prometheus.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::SizeLimit { .. } => "size_limit",
            Self::Storage { .. } => "storage",
            Self::SignedUrlNotSupported => "signed_url_not_supported",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
        }
    }
}

/// Gateway-side content store contract — the in-process surface a storage
/// backend implements. The host's content_store FFI adapter implements
/// this by marshalling each call onto [`crate::abi::ContentStoreVTable`].
#[async_trait]
pub trait ContentStore: Send + Sync + std::fmt::Debug {
    /// Store bytes; return a stable handle. Implementations choose a
    /// random-UUID id (no dedup) or a content-addressed BLAKE3 hash id
    /// (automatic dedup).
    async fn put(&self, content: ContentToStore) -> Result<ResourceHandle, ContentStoreError>;

    /// Fetch by id. `Ok(None)` if not found / expired / evicted.
    /// `Err(Forbidden)` for ACL violations (the gateway maps that to
    /// `NotFound` on the public surface to avoid leaking existence).
    async fn get(&self, id: &str) -> Result<Option<ResourceContent>, ContentStoreError>;

    /// Best-effort, idempotent delete (removing a non-existent id is
    /// `Ok(())`).
    async fn delete(&self, id: &str) -> Result<(), ContentStoreError>;

    /// Pre-signed URL for direct client fetch (bypassing `resources/read`
    /// for large blobs). `Ok(None)` = the store has a presigner but this
    /// id has no public-URL access; `Err(SignedUrlNotSupported)` = the
    /// store exposes no presigner at all.
    async fn signed_url(
        &self,
        id: &str,
        ttl: Duration,
    ) -> Result<Option<String>, ContentStoreError>;

    /// Snapshot of storage utilisation (Prometheus gauges).
    fn stats(&self) -> ContentStoreStats;

    /// Sweep expired entries; return the count removed. Default no-op for
    /// stores that expire lazily on read; out-of-band stores (filesystem,
    /// S3) override.
    async fn sweep_expired(&self) -> usize {
        0
    }

    /// Optional graceful shutdown hook (flush, close connections).
    async fn shutdown(&self) {}
}

/// Factory that builds configured [`ContentStore`] instances from
/// operator config. Each storage backend (in-process, file-system, S3,
/// …) ships as a plugin implementing this trait. The gateway iterates the
/// operator's `storage.providers:` list, looks up the matching plugin by
/// [`Self::kind`], calls [`Self::build_profile`], and registers the
/// returned `Arc<dyn ContentStore>` under the profile id.
#[async_trait]
pub trait ContentStorePlugin: Send + Sync + std::fmt::Debug {
    /// Plugin manifest — stable id, version, classification.
    fn manifest(&self) -> &PluginManifest;

    /// Operator-facing kind discriminator (the string operators write in
    /// `storage.providers: [{kind: ...}]`). Must be unique within the
    /// gateway's storage-plugin registry.
    fn kind(&self) -> &str;

    /// Build a configured `ContentStore` profile from operator config.
    /// `profile_name` is the operator-chosen id; `spec` is the raw JSON
    /// under the `config:` key. Errors abort gateway boot.
    async fn build_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<Arc<dyn ContentStore>, ContentStoreError>;
}

#[cfg(test)]
mod wire_tests {
    //! The content_store FFI vtable carries these value types as JSON
    //! `{"ok"|"err"}` envelopes. The SDK `declare_plugin!` arm encodes,
    //! the host `NativeContentStoreAdapter` decodes — both depend on the
    //! serde round-trip below holding. These tests lock that contract
    //! without a live cdylib.
    use super::*;
    use crate::result_envelope::{decode_result_envelope, respond_result_rstring};

    #[test]
    fn content_to_store_round_trips_put_input() {
        let v = ContentToStore {
            bytes: bytes::Bytes::from_static(b"\x00\x01\xff blob"),
            mime_type: "image/png".to_owned(),
            alias: Some("avatar".to_owned()),
            session_id: Some("sess-1".to_owned()),
            tenant_id: None,
            ttl: Some(Duration::from_secs(3600)),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ContentToStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bytes, v.bytes);
        assert_eq!(back.mime_type, v.mime_type);
        assert_eq!(back.alias, v.alias);
        assert_eq!(back.ttl, v.ttl);
    }

    #[test]
    fn resource_content_round_trips_get_output() {
        let v = ResourceContent {
            bytes: bytes::Bytes::from_static(b"hello"),
            mime_type: "text/plain".to_owned(),
            session_id: None,
            tenant_id: Some("t1".to_owned()),
            stored_at: chrono::Utc::now(),
            expires_at: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ResourceContent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bytes, v.bytes);
        assert_eq!(back.tenant_id, v.tenant_id);
    }

    #[test]
    fn put_ok_envelope_decodes_to_resource_handle() {
        // SDK side: a ResourceHandle wrapped in the {"ok": ...} envelope.
        let handle = ResourceHandle {
            id: "hash:abc".to_owned(),
            uri: "mcpg-resource://hash:abc".to_owned(),
            size_bytes: 5,
            mime_type: "text/plain".to_owned(),
            expires_at: None,
            content_hash: "blake3:abc".to_owned(),
        };
        let wire = respond_result_rstring::<ResourceHandle, ContentStoreError>(&Ok(handle.clone()));
        // Host side: decode the same envelope.
        let decoded =
            decode_result_envelope::<ResourceHandle, ContentStoreError>(wire.as_str()).unwrap();
        assert_eq!(decoded.unwrap(), handle);
    }

    #[test]
    fn signed_url_unsupported_error_round_trips_as_typed_variant() {
        // The one error variant callers branch on must survive the wire so
        // the host reconstructs it precisely (not as an opaque string).
        let wire = respond_result_rstring::<Option<String>, ContentStoreError>(&Err(
            ContentStoreError::SignedUrlNotSupported,
        ));
        let decoded =
            decode_result_envelope::<Option<String>, ContentStoreError>(wire.as_str()).unwrap();
        match decoded {
            Err(ContentStoreError::SignedUrlNotSupported) => {}
            other => panic!("expected SignedUrlNotSupported, got {other:?}"),
        }
    }

    #[test]
    fn get_miss_round_trips_as_ok_none() {
        let wire = respond_result_rstring::<Option<ResourceContent>, ContentStoreError>(&Ok(None));
        let decoded =
            decode_result_envelope::<Option<ResourceContent>, ContentStoreError>(wire.as_str())
                .unwrap();
        assert!(decoded.unwrap().is_none());
    }

    #[test]
    fn stats_round_trips_bare() {
        // `stats` / `sweep_expired` are bare (un-enveloped) on the wire.
        let s = ContentStoreStats {
            item_count: 7,
            byte_count: 4096,
            max_bytes: 1 << 20,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ContentStoreStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.item_count, 7);
        assert_eq!(back.byte_count, 4096);
        assert_eq!(back.max_bytes, 1 << 20);
    }
}
