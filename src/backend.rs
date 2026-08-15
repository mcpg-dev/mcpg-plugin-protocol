//! Backend and watch-strategy plugins — transport-level extension points.
//!
//! While `ToolGatePlugin`, `TransformPlugin`, and `IdentityProviderPlugin` attach
//! policy/shape-shifting to existing dispatch, **backend plugins** extend the
//! set of transports MCPG can dispatch to (NATS, Kafka, MQTT, …) and
//! **watch-strategy plugins** extend the set of change-detection sources
//! behind `resources/subscribe`. Operators address backend plugins by `kind`
//! in their YAML (`kind: nats` on a flattened backend spec) and watch plugins
//! by strategy discriminator (`watch.strategy.type: nats_topic`).
//!
//! Each plugin declares the kind(s) it handles via [`BackendPlugin::kind`] /
//! [`WatchStrategyPlugin::kind`]; the host routes dispatch/subscription to
//! the plugin whose kind matches the config.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

// ---------------------------------------------------------------------------
// BackendHost — capability passed to backend plugins at registration time
// ---------------------------------------------------------------------------

/// Host capability handed to a [`BackendPlugin`] at `register_profile` time.
///
/// Most bindings (Kafka, NATS, SQL, HTTP, Command — anything that only
/// talks to its own external transport) receive the host and discard it.
/// Bindings that need to dispatch *back* through the gateway during their
/// own execution — the LLM generator binding's agentic tool-calling loop is
/// the motivating case — call [`BackendHost::invoke_tool`] to invoke other
/// bindings registered in the same gateway. The host re-enters the
/// gateway's standard dispatch path: same policy gates, audit log, depth
/// counter, cycle detection, metrics. From the gateway's perspective a
/// child invocation is indistinguishable from a direct MCP `tools/call`.
///
/// The host also exposes two content capabilities: [`store_content`] /
/// [`fetch_content`]. Bindings that produce large binary outputs
/// (image generation, TTS, document tool returns) push bytes through
/// `store_content` and receive an [`BackendResource`] whose
/// `mcpg-resource://<id>` URI clients dereference via standard MCP
/// `resources/read`. `fetch_content` is the inverse: when an LLM
/// receives a multi-modal input that's already a stored resource,
/// the binding pulls the bytes through the host rather than touching
/// the storage backend directly.
///
/// The host is wrapped in [`Arc`] so plugins may clone and outlive a single
/// `register_profile` call (in practice, a long-lived binding holds the
/// `Arc` for as long as the gateway runs and uses it across many `execute`
/// calls).
///
/// Bindings that never call back into the host receive a
/// `NoOpBackendHost`, so the host arg is wired through every call site
/// without functional change; the first real implementation lands
/// alongside the LLM binding.
#[async_trait]
pub trait BackendHost: Send + Sync {
    /// Invoke another binding registered in this gateway.
    ///
    /// The named tool resolves through the same registry the gateway uses
    /// for direct MCP `tools/call` requests. Argument validation, policy
    /// evaluation, audit, metrics, and depth/cycle bookkeeping are all
    /// applied — the calling binding does not re-implement any of them.
    ///
    /// `args` are passed verbatim to the target binding after standard
    /// validation; on success, `Ok(value)` is the structured tool result.
    /// On failure, [`BackendHostError`] distinguishes "not found" (likely
    /// a config drift between binding registration and the call) from
    /// policy denial, depth-cap, cycle, transport, and timeout.
    async fn invoke_tool(
        &self,
        ctx: &BackendInvocationContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError>;

    /// Store binary content in the gateway-managed content store.
    ///
    /// Returns a [`BackendResource`] whose `uri` (always
    /// `mcpg-resource://<id>`) bindings include in their JSON tool
    /// response. Clients fetch the bytes via standard MCP
    /// `resources/read` against that URI — no need to embed the
    /// blob inline.
    ///
    /// `ttl` is a hint: the store may evict earlier under memory
    /// pressure (LRU) and may keep entries longer when content is
    /// hash-deduplicated and another caller stored the same bytes
    /// with a longer TTL. Pass `None` for "until evicted".
    ///
    /// Default impl returns [`BackendHostError::NotImplemented`] so
    /// existing bindings (Kafka, NATS, SQL) compile unchanged. The
    /// real impl ships in `GatewayBackendHost`.
    async fn store_content(
        &self,
        _ctx: &BackendInvocationContext,
        _bytes: bytes::Bytes,
        _mime_type: String,
        _ttl: Option<std::time::Duration>,
    ) -> Result<BackendResource, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    /// Fetch previously stored content by its resource URI.
    ///
    /// Accepts either the full `mcpg-resource://<id>` URI or the
    /// bare id (`hash:abc…` / `alias:sess:name`). Returns
    /// `Ok(None)` when the id is unknown / expired / evicted, and
    /// [`BackendHostError::PolicyDenied`] for cross-session or
    /// cross-tenant violations (the host has translated the
    /// gateway-side `Forbidden` into the public-facing `PolicyDenied`).
    ///
    /// Default impl returns [`BackendHostError::NotImplemented`].
    async fn fetch_content(
        &self,
        _ctx: &BackendInvocationContext,
        _uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    /// Look up a previously cached response by hash key. Returns
    /// `Ok(None)` on miss / expiry / cache-disabled — callers re-run
    /// upstream and (typically) call [`cache_put`] with the result.
    ///
    /// `key` is an opaque hash string composed by the engine — the
    /// host treats it as a content-addressed lookup and never inspects
    /// its structure. The default no-op returns `Ok(None)` so bindings
    /// running without a cache simply experience a permanent cold
    /// path (no error).
    async fn cache_get(
        &self,
        _ctx: &BackendInvocationContext,
        _key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        Ok(None)
    }

    /// Store a response under `key`. `ttl` is a hint: the
    /// implementation may evict earlier under memory pressure (LRU).
    /// `Duration::ZERO` means "no expiry" (still bounded by LRU).
    ///
    /// The default no-op silently drops the value — bindings running
    /// without a cache see no error, just no acceleration.
    async fn cache_put(
        &self,
        _ctx: &BackendInvocationContext,
        _key: String,
        _value: bytes::Bytes,
        _ttl: std::time::Duration,
    ) -> Result<(), BackendHostError> {
        Ok(())
    }

    /// Best-effort cache invalidation. Idempotent. Default no-op.
    async fn cache_invalidate(
        &self,
        _ctx: &BackendInvocationContext,
        _key: &str,
    ) -> Result<(), BackendHostError> {
        Ok(())
    }

    /// Resolve `cred://<plugin_id>/<target>[#<part>]` URIs anywhere
    /// inside `value` against the gateway's credential cache. Mutates
    /// strings in place; returns the count of substitutions.
    ///
    /// Backend adapters with per-caller dynamic credentials (SQL,
    /// NATS, Kafka) call this on a per-request snapshot of the
    /// connection-relevant config slice (URL, session vars, auth
    /// fields) before opening / reusing a per-credential pool.
    ///
    /// `identity` MUST be the caller identity from
    /// `BackendRequest.identity` — passing `None` (system call) but
    /// finding a `cred://` URI is an error condition the host
    /// surfaces with a `NotImplemented`-flavoured `BackendHostError`.
    /// Adapters should refuse cred:// resolution when identity is
    /// absent rather than fall back to an arbitrary identity.
    ///
    /// On any resolution failure the call returns
    /// `BackendHostError::Backend { cause: BackendError::Transport
    /// { message } }` carrying the operator-visible message
    /// (`CredentialResolverError::operator_message`); the caller-
    /// visible message + audit event are emitted by the host before
    /// returning. The plugin should propagate the error verbatim —
    /// the gateway has already redacted topology.
    ///
    /// Default impl returns `NotImplemented`; impls in
    /// `NoOpBackendHost` test stubs and operator-disabled gateway
    /// modes return success when `value` carries no `cred://`
    /// references at all.
    async fn resolve_credentials(
        &self,
        _ctx: &BackendInvocationContext,
        _value: &mut serde_json::Value,
    ) -> Result<usize, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    /// Subscribe to credential-revocation events. The callback
    /// fires with `(plugin_id, target)` whenever the gateway's
    /// credential cache invalidates a matching entry — both for
    /// local invalidate calls and (in clustered mode) for
    /// peer-published `Revoked` events.
    ///
    /// Backends with per-credential connection state subscribe
    /// at `register_profile` time and use the callback to evict
    /// the matching pool / client. The returned subscription
    /// guard MUST be retained for the lifetime of the consumer
    /// — dropping it unsubscribes.
    ///
    /// Default impl returns a guard whose drop is a no-op.
    /// Adapters that don't get a real impl simply don't receive
    /// revocation events; static-cred profiles (which never
    /// build per-cred pools anyway) are unaffected.
    fn subscribe_credential_revoked(
        &self,
        _cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        CredentialRevocationSubscription::noop()
    }

    /// Subscribe to secret-rotation events. The callback fires with
    /// `(secret_ref, version)` whenever a `SecretProvider` plugin
    /// observes that an upstream secret has rotated — Vault's
    /// `sys/events/subscribe` for KV writes, AWS Secrets Manager
    /// rotation hooks, etc.
    ///
    /// Backends with per-credential connection state subscribe at
    /// `register_profile` time and use the callback to evict any
    /// pool / client whose resolved bundle was derived from the
    /// rotated `secret_ref`. The returned subscription guard MUST be
    /// retained for the lifetime of the consumer — dropping it
    /// unsubscribes.
    ///
    /// **Different from `subscribe_credential_revoked`.** Revocation
    /// is identity-scoped: a specific `(plugin_id, target)` cred is
    /// invalid. Rotation is URI-scoped: the bytes behind a
    /// `vault://...` URI changed; multiple identities may share the
    /// same secret. Don't substitute one for the other.
    ///
    /// Default impl returns a guard whose drop is a no-op. Adapters
    /// that don't wire a real impl simply don't receive rotation
    /// events; static-cred profiles (which never resolved a
    /// `vault://` URI) are unaffected.
    fn subscribe_secret_rotation(&self, _cb: SecretRotationCallback) -> SecretRotationSubscription {
        SecretRotationSubscription::noop()
    }
}

/// Callback type for [`BackendHost::subscribe_credential_revoked`].
/// Receives `(plugin_id, target)` whenever the gateway's credential
/// cache invalidates a matching entry.
pub type CredentialRevocationCallback = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Opaque guard returned by [`BackendHost::subscribe_credential_revoked`].
/// Holds the host-side subscription state; dropping the guard
/// unsubscribes. Plugins typically store one in their per-binding
/// `ProfileRuntime` and let it drop when the binding tears down.
///
/// The guard is intentionally opaque — the host-side concrete type
/// (e.g. `mcpg_plugin_host::credential_cache::RevocationSubscription`)
/// is wrapped behind a `Box<dyn Drop + Send>` so the plugin-protocol
/// crate stays free of credential-cache implementation details.
pub struct CredentialRevocationSubscription {
    _inner: Box<dyn std::any::Any + Send + Sync>,
}

impl CredentialRevocationSubscription {
    /// Wrap a host-side guard. The host's drop runs when this
    /// wrapper drops — the host-side guard's `Drop` impl handles
    /// the actual unsubscribe.
    #[must_use]
    pub fn new<T: std::any::Any + Send + Sync>(inner: T) -> Self {
        Self {
            _inner: Box::new(inner),
        }
    }

    /// No-op subscription — used by hosts that don't support
    /// credential revocation events. Dropping is a no-op.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            _inner: Box::new(()),
        }
    }
}

impl std::fmt::Debug for CredentialRevocationSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRevocationSubscription").finish()
    }
}

/// Callback type for [`BackendHost::subscribe_secret_rotation`].
/// Receives `(secret_ref, version)` whenever a `SecretProvider`
/// observes an upstream rotation of the secret at `secret_ref`.
///
/// `secret_ref` is the full URI the operator's config carried (e.g.
/// `vault://kv/data/db#password`), preserved verbatim from
/// `secret_resolver` so subscribers can match it against the refs
/// recorded at `register_profile` time.
///
/// `version` is the provider-reported version counter — Vault's
/// KV-v2 `metadata.version`, Secrets Manager's `VersionId` hash
/// reduced to a `u64`, etc. Hosts use it for de-duplication; a
/// callback that has already evicted for this `(secret_ref, version)`
/// can short-circuit.
///
/// The closure runs synchronously on the host's broadcast thread.
/// Keep it short — long work belongs in a spawned task driven by a
/// channel the closure pushes to.
pub type SecretRotationCallback = std::sync::Arc<dyn Fn(&str, u64) + Send + Sync>;

/// Opaque guard returned by [`BackendHost::subscribe_secret_rotation`].
/// Holds the host-side subscription state; dropping the guard
/// unsubscribes. Plugins typically store one in their per-binding
/// `ProfileRuntime` and let it drop when the binding tears down.
///
/// The guard is intentionally opaque — the host-side concrete type
/// is wrapped behind a `Box<dyn Any + Send + Sync>` so the
/// plugin-protocol crate stays free of host implementation details.
pub struct SecretRotationSubscription {
    _inner: Box<dyn std::any::Any + Send + Sync>,
}

impl SecretRotationSubscription {
    /// Wrap a host-side guard. The host's drop runs when this
    /// wrapper drops — the host-side guard's `Drop` impl handles
    /// the actual unsubscribe.
    #[must_use]
    pub fn new<T: std::any::Any + Send + Sync>(inner: T) -> Self {
        Self {
            _inner: Box::new(inner),
        }
    }

    /// No-op subscription — used by hosts that don't support
    /// secret rotation events. Dropping is a no-op.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            _inner: Box::new(()),
        }
    }
}

impl std::fmt::Debug for SecretRotationSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRotationSubscription").finish()
    }
}

/// Public handle returned by [`BackendHost::store_content`]. Mirrors
/// the gateway-internal `ResourceHandle` defined in the LLM-binding
/// shared crate, but trimmed to what bindings actually need on the
/// plugin-protocol surface — no chrono / blake3 deps land in this
/// crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendResource {
    /// Either `hash:<blake3-hex>` or `alias:<session-id>:<name>`.
    pub id: String,
    /// `mcpg-resource://<id>`. The string clients dereference via
    /// standard MCP `resources/read`.
    pub uri: String,
    pub size_bytes: usize,
    pub mime_type: String,
    /// Always `blake3:<hex>` — the content hash. Useful for caches /
    /// audit trails / cross-store deduplication.
    pub content_hash: String,
    /// Unix epoch seconds at which the entry is scheduled to expire
    /// (TTL eviction). `None` = no expiry. Approximate — eviction
    /// under memory pressure may happen earlier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

/// Per-call context the host uses to scope a re-entrant tool invocation.
///
/// Carries the parent request_id, session_id, depth counter, and the name
/// of the binding initiating the child call. The gateway's dispatch path
/// uses these to (a) link audit/metric records back to the parent call,
/// (b) enforce the depth cap, (c) detect cycles in the child-tool graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInvocationContext {
    /// Gateway-assigned identifier for the originating tool call.
    /// Propagated unchanged across the chain so all child events share it.
    pub parent_request_id: String,
    /// Session identifier when the originating call is session-bound.
    pub session_id: Option<String>,
    /// Name of the binding initiating this child invocation.
    /// Used for audit attribution and cycle detection.
    pub initiating_backend: String,
    /// 0 for the root invocation; the host increments on each re-entry.
    /// Bindings should not modify this — it's host bookkeeping.
    pub depth: u32,
    /// Caller identity for the chain. Propagated to child invocations so
    /// per-caller credential resolution stays consistent across the
    /// dispatch graph (`cred://` resolution on the child uses the same
    /// identity that gated the parent). `None` for system-initiated
    /// invocations. Added in PROTOCOL_VERSION 1.8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PluginIdentity>,
}

impl BackendInvocationContext {
    /// Construct a depth-0 context. Bindings that call the host pass this
    /// through unchanged; the host will populate depth itself when it
    /// re-enters its own dispatch path.
    pub fn root(
        parent_request_id: impl Into<String>,
        session_id: Option<String>,
        initiating_backend: impl Into<String>,
    ) -> Self {
        Self {
            parent_request_id: parent_request_id.into(),
            session_id,
            initiating_backend: initiating_backend.into(),
            depth: 0,
            identity: None,
        }
    }
}

/// Errors returned by [`BackendHost::invoke_tool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum BackendHostError {
    /// No binding registered under that name. Usually a config drift —
    /// the binding name was valid at the calling binding's
    /// `register_profile` time but has since been removed.
    NotFound { tool_name: String },
    /// Gateway policy refused the call. Cause is intentionally opaque —
    /// the policy layer's reason text goes to audit, not to the caller.
    PolicyDenied { tool_name: String },
    /// Maximum dispatch depth exceeded. The gateway-wide cap is the
    /// circuit breaker against accidentally-recursive binding graphs.
    DepthExceeded { tool_name: String, depth: u32 },
    /// A cycle was detected in the child-tool graph
    /// (`A` calls `B` which calls `A`). Refused before transport.
    Cycle {
        tool_name: String,
        path: Vec<String>,
    },
    /// Standard backend-side error. Mirror of [`BackendError`] — the
    /// gateway transparently re-wraps whatever the target backend raised.
    Backend {
        tool_name: String,
        cause: BackendError,
    },
    /// Host implementation has no dispatcher wired (e.g. the
    /// `NoOpBackendHost` shipped for tests and for bindings that never
    /// call the host). A binding that relies on `invoke_tool` should
    /// fail-fast at `register_profile` rather than reaching this at
    /// execute time.
    NotImplemented,
}

impl BackendHostError {
    /// Bounded metrics label (mirrors the sibling error types).
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::PolicyDenied { .. } => "policy_denied",
            Self::DepthExceeded { .. } => "depth_exceeded",
            Self::Cycle { .. } => "cycle",
            Self::Backend { .. } => "backend",
            Self::NotImplemented => "not_implemented",
        }
    }

    /// HTTP status the gateway surfaces for a cross-binding dispatch error.
    /// `Backend` defers to the wrapped [`BackendError`].
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotFound { .. } => 404,
            Self::PolicyDenied { .. } => 403,
            // 508 Loop Detected — the recursion/cycle circuit breakers.
            Self::DepthExceeded { .. } | Self::Cycle { .. } => 508,
            Self::Backend { cause, .. } => cause.http_status(),
            Self::NotImplemented => 501,
        }
    }
}

impl std::fmt::Display for BackendHostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { tool_name } => {
                write!(f, "child tool '{tool_name}' not registered in this gateway")
            }
            Self::PolicyDenied { tool_name } => {
                write!(f, "child tool '{tool_name}' denied by policy")
            }
            Self::DepthExceeded { tool_name, depth } => {
                write!(
                    f,
                    "child tool '{tool_name}' refused: dispatch depth {depth} exceeds cap"
                )
            }
            Self::Cycle { tool_name, path } => {
                write!(
                    f,
                    "child tool '{tool_name}' refused: cycle in dispatch graph ({})",
                    path.join(" → ")
                )
            }
            Self::Backend { tool_name, cause } => {
                write!(f, "child tool '{tool_name}' failed: {cause}")
            }
            Self::NotImplemented => write!(f, "backend host has no dispatcher wired"),
        }
    }
}

impl std::error::Error for BackendHostError {}

/// No-op host used by the gateway during the trait-extension phase and
/// by tests / benches that don't need cross-binding dispatch.
///
/// All `invoke_tool` calls return [`BackendHostError::NotImplemented`].
/// Bindings that genuinely need the host (the LLM Generator binding) check
/// this at `register_profile` time by attempting a sentinel call and
/// fail-fast with `BackendError::InvalidSpec` if the host is a no-op.
#[derive(Debug, Default, Clone)]
pub struct NoOpBackendHost;

#[async_trait]
impl BackendHost for NoOpBackendHost {
    async fn invoke_tool(
        &self,
        _ctx: &BackendInvocationContext,
        _tool_name: &str,
        _args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }
}

/// Convenience: an `Arc<NoOpBackendHost>` upcast to `Arc<dyn BackendHost>`.
/// The two-line idiom for tests and for call sites that intentionally
/// disable host capability.
pub fn noop_backend_host() -> Arc<dyn BackendHost> {
    Arc::new(NoOpBackendHost)
}

/// A [`BackendHost`] whose inner implementation is set later.
///
/// ## Why this exists
///
/// Some hosts can only be constructed *after* the runtime has been
/// assembled — the gateway's [`BackendHost`] needs the dispatcher and
/// plugin registry, which don't exist when binding plugins'
/// `register_profile` is called. The chicken-and-egg solution: pass a
/// `LateBoundBackendHost` at registration time, and call
/// [`LateBoundBackendHost::set`] once the real host is available.
///
/// All `invoke_tool` calls before [`set`] return
/// [`BackendHostError::NotImplemented`]; once `set` runs, calls
/// transparently forward to the inner host.
///
/// `set` may be called more than once — the most recent host wins.
/// This makes test fixtures simple (swap a fake host between tests
/// without re-registering the binding) and is a natural place to
/// hot-swap during config reload, should that become a feature.
///
/// Thread-safe: the inner uses an [`std::sync::RwLock`], and reads are
/// the hot path (one per child tool dispatch).
///
/// ## Subscription replay
///
/// `subscribe_credential_revoked` and `subscribe_secret_rotation` are
/// called by binding plugins from inside `register_profile` — i.e.
/// before [`set`] runs. A naive forwarding impl would lose those
/// subscriptions: pre-`set` the no-op default trait body returns a
/// dead guard, and post-`set` the plugin has no way to retry.
///
/// `LateBoundBackendHost` instead **buffers** every pre-`set`
/// subscription and **replays** the buffered callbacks against the
/// real host the moment `set` lands. Plugins always see a live
/// subscription for the lifetime of the guard they hold; they don't
/// need to know `set` happened.
///
/// Replay also runs on every subsequent `set` (host swap) — the old
/// real subscriptions drop with the previous inner host, and the
/// buffered callbacks re-subscribe against the new one. This mirrors
/// the hot-reload contract: surviving plugin profiles keep receiving
/// events across a host swap.
pub struct LateBoundBackendHost {
    inner: std::sync::RwLock<Option<Arc<dyn BackendHost>>>,
    subscriptions: Arc<std::sync::Mutex<LateBoundSubscriptions>>,
}

#[derive(Default)]
struct LateBoundSubscriptions {
    next_id: u64,
    revocation: Vec<RevocationSlot>,
    rotation: Vec<RotationSlot>,
}

struct RevocationSlot {
    id: u64,
    callback: CredentialRevocationCallback,
    /// Real subscription installed once [`LateBoundBackendHost::set`]
    /// runs. Dropping this field unsubscribes from the inner host.
    real: Option<CredentialRevocationSubscription>,
}

struct RotationSlot {
    id: u64,
    callback: SecretRotationCallback,
    /// Real subscription installed once [`LateBoundBackendHost::set`]
    /// runs. Dropping this field unsubscribes from the inner host.
    real: Option<SecretRotationSubscription>,
}

impl Default for LateBoundBackendHost {
    fn default() -> Self {
        Self {
            inner: std::sync::RwLock::new(None),
            subscriptions: Arc::new(std::sync::Mutex::new(LateBoundSubscriptions::default())),
        }
    }
}

impl std::fmt::Debug for LateBoundBackendHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LateBoundBackendHost")
            .field("bound", &self.is_bound())
            .finish()
    }
}

impl LateBoundBackendHost {
    /// Construct a new unbound host.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Install (or replace) the inner host. Subsequent `invoke_tool`
    /// calls forward to `host`. Any subscriptions registered before
    /// (or during a previous `set`) are re-issued against the new
    /// inner host so callbacks installed at `register_profile` time
    /// keep firing across host swaps.
    pub fn set(&self, host: Arc<dyn BackendHost>) {
        *self.inner.write().expect("late-bound host poisoned") = Some(Arc::clone(&host));
        let mut subs = self
            .subscriptions
            .lock()
            .expect("late-bound subscriptions poisoned");
        // Replay buffered subscriptions against the new inner host.
        // Drop any prior real subscription first (its Drop
        // unsubscribes from the previous host) so the new one
        // cleanly replaces it.
        for slot in subs.revocation.iter_mut() {
            slot.real = None;
            slot.real = Some(host.subscribe_credential_revoked(Arc::clone(&slot.callback)));
        }
        for slot in subs.rotation.iter_mut() {
            slot.real = None;
            slot.real = Some(host.subscribe_secret_rotation(Arc::clone(&slot.callback)));
        }
    }

    /// Returns whether an inner host has been installed.
    pub fn is_bound(&self) -> bool {
        self.inner
            .read()
            .expect("late-bound host poisoned")
            .is_some()
    }
}

/// Drop guard returned from [`LateBoundBackendHost::subscribe_credential_revoked`].
///
/// Holds an `Arc` to the shared subscription registry so dropping the
/// guard removes the buffered slot (and, transitively, drops any real
/// inner subscription installed by [`LateBoundBackendHost::set`]).
/// Boxed inside [`CredentialRevocationSubscription`].
struct LateBoundRevocationGuard {
    subs: Arc<std::sync::Mutex<LateBoundSubscriptions>>,
    id: u64,
}

impl Drop for LateBoundRevocationGuard {
    fn drop(&mut self) {
        if let Ok(mut subs) = self.subs.lock() {
            subs.revocation.retain(|slot| slot.id != self.id);
        }
    }
}

/// Drop guard returned from [`LateBoundBackendHost::subscribe_secret_rotation`].
///
/// Holds an `Arc` to the shared subscription registry so dropping the
/// guard removes the buffered slot (and, transitively, drops any real
/// inner subscription installed by [`LateBoundBackendHost::set`]).
/// Boxed inside [`SecretRotationSubscription`].
struct LateBoundRotationGuard {
    subs: Arc<std::sync::Mutex<LateBoundSubscriptions>>,
    id: u64,
}

impl Drop for LateBoundRotationGuard {
    fn drop(&mut self) {
        if let Ok(mut subs) = self.subs.lock() {
            subs.rotation.retain(|slot| slot.id != self.id);
        }
    }
}

#[async_trait]
impl BackendHost for LateBoundBackendHost {
    async fn invoke_tool(
        &self,
        ctx: &BackendInvocationContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.invoke_tool(ctx, tool_name, args).await,
            None => Err(BackendHostError::NotImplemented),
        }
    }

    async fn store_content(
        &self,
        ctx: &BackendInvocationContext,
        bytes: bytes::Bytes,
        mime_type: String,
        ttl: Option<std::time::Duration>,
    ) -> Result<BackendResource, BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.store_content(ctx, bytes, mime_type, ttl).await,
            None => Err(BackendHostError::NotImplemented),
        }
    }

    async fn fetch_content(
        &self,
        ctx: &BackendInvocationContext,
        uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.fetch_content(ctx, uri).await,
            None => Err(BackendHostError::NotImplemented),
        }
    }

    async fn cache_get(
        &self,
        ctx: &BackendInvocationContext,
        key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.cache_get(ctx, key).await,
            // Pre-bind: caller treats it as a permanent miss
            // (matches the default no-op host behaviour).
            None => Ok(None),
        }
    }

    async fn cache_put(
        &self,
        ctx: &BackendInvocationContext,
        key: String,
        value: bytes::Bytes,
        ttl: std::time::Duration,
    ) -> Result<(), BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.cache_put(ctx, key, value, ttl).await,
            None => Ok(()),
        }
    }

    async fn cache_invalidate(
        &self,
        ctx: &BackendInvocationContext,
        key: &str,
    ) -> Result<(), BackendHostError> {
        let inner_opt = self.inner.read().expect("late-bound host poisoned").clone();
        match inner_opt {
            Some(host) => host.cache_invalidate(ctx, key).await,
            None => Ok(()),
        }
    }

    fn subscribe_credential_revoked(
        &self,
        cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        // Buffer the callback in the subscription registry so a later
        // `set()` can replay it. If `set()` has already run, install
        // the real subscription right now too — the buffered slot
        // owns it and drops it when the slot drops.
        let mut subs = self
            .subscriptions
            .lock()
            .expect("late-bound subscriptions poisoned");
        subs.next_id = subs.next_id.wrapping_add(1);
        let id = subs.next_id;
        let real = self
            .inner
            .read()
            .expect("late-bound host poisoned")
            .as_ref()
            .map(|host| host.subscribe_credential_revoked(Arc::clone(&cb)));
        subs.revocation.push(RevocationSlot {
            id,
            callback: cb,
            real,
        });
        drop(subs);
        CredentialRevocationSubscription::new(LateBoundRevocationGuard {
            subs: Arc::clone(&self.subscriptions),
            id,
        })
    }

    fn subscribe_secret_rotation(&self, cb: SecretRotationCallback) -> SecretRotationSubscription {
        let mut subs = self
            .subscriptions
            .lock()
            .expect("late-bound subscriptions poisoned");
        subs.next_id = subs.next_id.wrapping_add(1);
        let id = subs.next_id;
        let real = self
            .inner
            .read()
            .expect("late-bound host poisoned")
            .as_ref()
            .map(|host| host.subscribe_secret_rotation(Arc::clone(&cb)));
        subs.rotation.push(RotationSlot {
            id,
            callback: cb,
            real,
        });
        drop(subs);
        SecretRotationSubscription::new(LateBoundRotationGuard {
            subs: Arc::clone(&self.subscriptions),
            id,
        })
    }
}

// ---------------------------------------------------------------------------
// BackendPlugin — tool dispatch over pluggable transports
// ---------------------------------------------------------------------------

/// A plugin that executes tool calls over a custom transport.
///
/// The host deserializes the per-backend config fragment (e.g. the contents
/// of `type: nats` + `nats: { subject: ..., timeout_ms: ... }`) into a
/// `serde_json::Value` and passes it as `spec` to `register_profile`. The
/// plugin validates the spec, stores any per-backend state, and returns.
///
/// At dispatch time the host calls `execute(backend_name, request)`. The
/// plugin looks up its registered profile, performs the request/reply, and
/// returns the raw response bytes (or an error).
///
/// ## The `host` argument
///
/// `register_profile` receives an [`Arc<dyn BackendHost>`](BackendHost) at
/// registration time. Most backends (Kafka, NATS, SQL, HTTP, Command) ignore
/// it — they only talk to their own external transport. Backends that need
/// to dispatch *back* through the gateway during their own execution
/// (e.g. the LLM generator backend's tool-calling loop) clone and store the
/// `Arc` and call [`BackendHost::invoke_tool`] from inside their own
/// `execute`. Adding the arg uniformly to every backend (vs. a separate
/// `HostedBackendPlugin` trait) keeps the registration path single-track in
/// the plugin loader and lets any future backend adopt host capability
/// without trait surgery.
#[async_trait]
pub trait BackendPlugin: Send + Sync {
    /// Returns the plugin manifest.
    fn manifest(&self) -> &PluginManifest;

    /// The binding `kind` this plugin handles (e.g. `"nats"`, `"kafka"`).
    /// The host uses this to route `BackendTypeConfig::Nats` → plugin
    /// whose `kind() == "nats"`.
    fn kind(&self) -> &str;

    /// Register a per-binding execution profile. Called once per binding
    /// at startup with the binding's name and its typed config serialized
    /// as `serde_json::Value`, plus an [`Arc<dyn BackendHost>`](BackendHost)
    /// the binding may keep for re-entrant tool dispatch (see trait docs).
    ///
    /// Plugins should validate the spec here and return an error synchronously
    /// so misconfigurations fail fast at startup rather than on first dispatch.
    /// Bindings that depend on `host` (e.g. the LLM binding when
    /// `tools.allowed` is non-empty) MUST verify host capability at this
    /// point — the gateway hands a [`NoOpBackendHost`] before the dispatcher
    /// is wired.
    async fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError>;

    /// Execute a tool call through this binding.
    async fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError>;

    /// Return a JSON Schema the plugin derived for this binding's
    /// tool input. Default `None` — plugins that don't introspect
    /// their transport (HTTP, Command, Mock, …) skip this.
    ///
    /// When both a derived and an operator-supplied schema exist,
    /// the host merges them via
    /// [`crate::schema::merge_schema`] — operator fields win at
    /// every key. A `None` here falls through to operator schema
    /// (or the default `{type: object, additionalProperties: true}`).
    fn input_schema(&self, _profile_name: &str) -> Option<serde_json::Value> {
        None
    }

    /// Return a JSON Schema the plugin derived for this binding's
    /// tool output. Default `None` — same fallback semantics as
    /// [`input_schema`]: the host merges with operator-supplied
    /// schema via [`crate::schema::merge_schema`] and operator
    /// fields win. Plugins that can introspect their result shape
    /// (SQL column metadata, gRPC return types, …) override.
    fn output_schema(&self, _profile_name: &str) -> Option<serde_json::Value> {
        None
    }

    /// Enumerate dynamic resources this binding advertises for
    /// `resources/list` (P2.3 — SQL binding `kind: resource_template`
    /// with a `list_query`). The host merges the returned page into
    /// the static registry and threads `next_cursor` through the
    /// protocol-level pagination cursor.
    ///
    /// Default `Ok(ResourcePage::empty())` — bindings that don't
    /// back resource listings (NATS / Kafka / HTTP / Command) inherit
    /// the empty page and fall through to the static registry.
    async fn list_resources(
        &self,
        _profile_name: &str,
        _cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        Ok(ResourcePage::empty())
    }

    /// Capabilities this backend elects to auto-register from its own
    /// config (e.g. OpenAPI `sources` with `expose:`).
    /// Called once at boot/reload, NOT per request. The gateway
    /// synthesizes one ordinary binding per returned capability before
    /// building the capability registry; it stays agnostic to the
    /// backend's domain by reconstructing the binding from
    /// [`ExpandedTool::backend_kind`] + [`ExpandedTool::backend_spec`].
    ///
    /// Default `Ok(CapabilitySet::default())` — every backend that doesn't
    /// produce capabilities inherits the empty set, so the new ABI slot is
    /// inert for them.
    async fn expand_capabilities(&self) -> Result<CapabilitySet, BackendError> {
        Ok(CapabilitySet::default())
    }

    /// Streaming variant of [`execute`].
    ///
    /// Returns a stream of [`BackendChunk`]s the gateway can forward
    /// to the MCP client as `progress` notifications, terminated by
    /// [`BackendChunk::Done`] carrying the same [`BackendResponse`]
    /// non-streaming `execute` would have returned.
    ///
    /// **The default implementation calls `execute` and emits a
    /// single [`BackendChunk::Done`].** Bindings that have nothing to
    /// stream (Kafka request/reply, SQL queries, NATS request/reply)
    /// inherit it for free. Bindings whose upstream emits incremental
    /// data (the LLM Generator binding's token stream) override this
    /// to forward chunks as they arrive.
    ///
    /// The gateway transport (HTTP / WebSocket / stdio) is responsible
    /// for translating chunks into the wire-level streaming primitive
    /// — typically MCP `notifications/progress` events. Until a
    /// transport adopts this surface, end-to-end token streaming
    /// degrades to "wait for Done": the binding still streams
    /// internally, but the client only sees the final response.
    async fn execute_streaming(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendChunkStream, BackendError> {
        let response = self.execute(profile_name, request).await?;
        let stream = futures::stream::once(async move { Ok(BackendChunk::Done(response)) });
        Ok(Box::pin(stream))
    }

    /// Execute a multi-statement transaction group atomically — the
    /// `sql_tx` pipeline step. `tx_group` is an opaque JSON object the
    /// backend interprets: for SQL it is
    /// `{"steps": [{"id", "sql", "params", "row_mode"}], "step_input": <json>}`.
    /// The backend opens ONE transaction on `backend_name`'s connection,
    /// runs every step (each binding against `step_input` — the steps
    /// are independent, no inter-step data flow), rolls back on any
    /// error, else commits, and returns
    /// `{"steps": {<id>: <shaped-result>}}`.
    ///
    /// Default: unsupported (only SQL-shaped backends implement it; the
    /// gateway routes `sql_tx` steps to the `sql` backend). v35
    /// (backend-plugin-migration) — lets the SQL transaction
    /// orchestration cross the cdylib FFI as a single round-trip
    /// instead of a stateful tx handle.
    async fn execute_transaction(
        &self,
        _backend_name: &str,
        _tx_group: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendError> {
        Err(BackendError::Transport {
            message: "execute_transaction is not supported by this backend".to_owned(),
        })
    }

    /// Active health probe for a registered binding profile, honoured
    /// only when the plugin's
    /// [`BackendProfile::health_probe`](crate::manifest::BackendProfile::health_probe)
    /// declares [`HealthProbeDecl::Plugin`](crate::manifest::HealthProbeDecl::Plugin).
    /// The gateway's generic prober calls this instead of doing a
    /// transport-level TCP/HTTP probe; the result is advisory.
    ///
    /// Default [`BackendHealth::Unknown`] — health is advisory, so a
    /// plugin that declares no probe (or declares `Tcp`/`Http`/`Skip`)
    /// never reaches this method, and a plugin that forgets to override
    /// it reports "unknown" rather than failing the binding. This is a
    /// Rust trait default, not an FFI vtable slot, so it does not change
    /// the ABI dispatch surface.
    async fn health(&self, _profile_name: &str) -> BackendHealth {
        BackendHealth::Unknown
    }

    /// Drain and release plugin-owned background resources (connections,
    /// consumers). Called once at gateway shutdown. Default no-op.
    async fn shutdown(&self) {}

    /// Domain-specific audit fields the gateway merges into the
    /// `mcpg.backend.executed` / `mcpg.backend.failed` audit event's
    /// `details` block (P6.3). Default empty map — plugins that have
    /// nothing extra to surface inherit the baseline schema (`kind` /
    /// `profile` / `session_id` / `duration_ms` / byte counts).
    ///
    /// SQL bindings return `{"db.driver": "<postgres|mysql|sqlite>",
    /// "db.query_ref": "<backend_name>"}` so auditors can filter on
    /// the underlying engine and the stable query identifier without
    /// guessing from the resource URI. Other bindings can do the
    /// same for their own audit context (e.g. an HTTP binding could
    /// surface the upstream host).
    ///
    /// Keys with `.` in them are accepted; the gateway preserves the
    /// dot-namespaced shape so search rules over JSON paths can
    /// match cleanly. Operator-controlled fields (caller-supplied
    /// strings) MUST NOT appear here — the audit lane is for
    /// system-derived, redaction-safe metadata only.
    fn audit_metadata(&self, _profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    /// Return completion candidates for a resource template variable
    /// given the partially-typed prefix. Default returns an empty list
    /// — bindings without dynamic completion inherit no-op behavior.
    ///
    /// Called by the gateway's `completion/complete` handler after the
    /// static `variable_completions` registry returns no match. Auth
    /// gate has already run; rate limit has already been consumed.
    /// The gateway clamps results to 100 with `has_more` semantics.
    ///
    /// `config` is the operator-declared opaque blob from the binding's
    /// `variable_completions` map (e.g. `{ query, max_results? }` for
    /// the SQL backend). Plugins parse it inline — the gateway is
    /// stateless with respect to per-(binding, variable) wiring.
    ///
    /// `context` carries the MCP `completion/complete` request's
    /// `context.arguments` — values the user has already filled for
    /// other template variables in the same URI. Backends use it for
    /// owner-scoped lookups (`SELECT … WHERE owner = :ctx_owner AND
    /// repo LIKE :prefix || '%'`); pass it as named parameters (SQL)
    /// or substitute into the URL/query via CEL (HTTP). An empty map
    /// means the client sent no prior arguments.
    ///
    /// Backends MUST return only values matching `prefix` (case-
    /// sensitive starts-with is the convention; the SQL backend uses
    /// `LIKE :prefix || '%'`). The gateway does not re-filter; what
    /// the backend returns is what the MCP client sees.
    async fn complete_template_variable(
        &self,
        _profile_name: &str,
        _variable_name: &str,
        _prefix: &str,
        _config: &serde_json::Value,
        _context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// BackendChunk — streaming-output protocol surface
// ---------------------------------------------------------------------------

/// One unit of streamed output from a [`BackendPlugin::execute_streaming`]
/// call.
///
/// The stream conventionally ends with [`BackendChunk::Done`], which
/// carries the same [`BackendResponse`] a non-streaming `execute`
/// would have returned. Earlier chunks are *advisory* — they describe
/// what the binding is doing in flight (text token deltas, child tool
/// dispatches) so the client can render progress, but they are not
/// the contract. Validation, metrics, and audit happen at `Done` time
/// and are encoded in `Done.payload` per the existing
/// [`BackendResponse`] semantics.
///
/// Initial chunk surface. Future variants (e.g. structured
/// elicitation chunks, multi-modal segment markers) can land
/// additively without breaking older consumers — the gateway
/// transport ignores variants it doesn't recognize.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendChunk {
    /// A text-content delta. For LLM bindings, this is one or more
    /// streamed tokens. The accumulating concatenation up to (but
    /// not including) the matching `Done.payload` should match the
    /// `text` field of the structured response, when present. For
    /// non-LLM bindings that never invoke this variant, semantics
    /// don't apply.
    TextDelta { delta: String },
    /// A child tool call has been requested by the upstream model
    /// (LLM bindings only). Surfaced as a discrete event so the
    /// client can display "calling X…" UI before the result lands.
    /// The binding still dispatches the call internally — clients
    /// don't act on this; it's informational.
    ToolCall {
        id: String,
        name: String,
        arguments: serde_json::Value,
    },
    /// The corresponding child tool call returned. Same advisory
    /// semantics as [`ToolCall`].
    ToolResult {
        id: String,
        /// Truncated to the binding's `tool_result_max_bytes`; the
        /// untruncated value is what the model sees.
        result: serde_json::Value,
    },
    /// Token usage update from the upstream provider. Most providers
    /// emit one usage update at the end of a call; some (Anthropic
    /// `usage_delta` events) emit multiple. The values are
    /// cumulative-per-iteration: a `Usage` chunk reports the total
    /// for the iteration in progress, not deltas.
    Usage {
        input_tokens: u32,
        output_tokens: u32,
        #[serde(default)]
        cached_input_tokens: u32,
    },
    /// Boundary marker between agentic-loop iterations. Useful for
    /// clients that want to render iteration breaks distinctly. The
    /// `iteration` index is 0-based.
    IterationBoundary { iteration: u32 },
    /// Intermediate progress event emitted by a backend during request
    /// execution. Surfaces as `notifications/progress` to the MCP
    /// client when the caller supplied a `progressToken`. `total` is
    /// `None` for indeterminate progress (e.g. chunked HTTP without
    /// `Content-Length`).
    ///
    /// Plugins SHOULD emit increasing `progress` values within a
    /// single request — the gateway emits a `progress` field on every
    /// chunk frame keyed off its own monotonic counter, but the
    /// per-chunk `progress` value here flows through `_meta` so rich
    /// clients can render plugin-native progress (bytes received,
    /// step index in a multi-step external operation).
    Progress {
        /// Monotonic per-request progress counter. The gateway
        /// enforces monotonicity per (session_id, progress_token);
        /// plugins should emit increasing values within a single
        /// request.
        progress: u32,
        /// Total expected progress, when known. `None` is spec-valid
        /// for indeterminate progress.
        total: Option<u32>,
        /// Short human-readable description for the chunk
        /// (e.g. "received 16 KiB", "stream chunk 3").
        message: String,
    },
    /// Terminal chunk. Carries the same [`BackendResponse`] a non-
    /// streaming `execute` would have returned: payload bytes,
    /// truncation flag. After this chunk the stream MUST end.
    Done(BackendResponse),
}

/// Convenient stream alias for binding chunks.
pub type BackendChunkStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<BackendChunk, BackendError>> + Send>>;

/// One resource descriptor returned by [`BackendPlugin::list_resources`].
///
/// Shape follows the MCP `Resource` descriptor per spec; the host
/// projects this into the protocol response without further
/// transformation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListedResource {
    /// Opaque resource URI — must be unique and stable across pages.
    pub uri: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional IANA media type.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// One page of resources plus a cursor for the next page.
///
/// `next_cursor == None` signals the listing is exhausted. Cursors
/// are opaque strings — the binding plugin defines the format and
/// parses them back on the next call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePage {
    /// Resources in this page, in iteration order.
    #[serde(default)]
    pub resources: Vec<ListedResource>,
    /// Opaque continuation cursor. `None` when no more pages exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl ResourcePage {
    /// Empty page with no continuation — the default for bindings
    /// that don't back dynamic listings.
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Capabilities a backend auto-registers from its own config, returned by
/// [`BackendPlugin::expand_capabilities`].
///
/// `#[serde(default)]` on each field keeps the wire form backward-compatible
/// as surfaces are added (`resources` / `prompts` remain future work).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CapabilitySet {
    #[serde(default)]
    pub tools: Vec<ExpandedTool>,
    #[serde(default)]
    pub resource_templates: Vec<ExpandedResourceTemplate>,
}

/// One tool a backend elects to expose. The gateway turns this into an
/// ordinary tool binding: it rebuilds the backend impl by deserializing
/// `{ "kind": backend_kind, ...backend_spec }` into its binding enum, so it
/// never needs to understand the backend's domain (OpenAPI, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandedTool {
    /// MCP tool name (already prefixed/filtered by the backend).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub description: String,
    /// Derived MCP input schema.
    pub input_schema: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    /// Backend `kind()` to dispatch to (e.g. `"openapi"`).
    pub backend_kind: String,
    /// Per-binding spec the gateway forwards to `register_profile`, minus
    /// the `kind` tag (the gateway re-attaches `backend_kind`).
    pub backend_spec: serde_json::Value,
    /// Operator-authored governance for this capability's source, relayed
    /// verbatim (the backend invents nothing; the gateway enforces). Shaped
    /// like the binding `governance:` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<serde_json::Value>,
    /// Operator-authored retry for this capability's source, relayed
    /// verbatim. Shaped like the binding `retry:` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<serde_json::Value>,
}

/// One resource template a backend elects to expose (e.g. an OpenAPI
/// read-by-id `GET`). The gateway turns this into an
/// ordinary `resource_template` binding, rebuilding the backend impl from
/// `backend_kind` + `backend_spec` exactly like [`ExpandedTool`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpandedResourceTemplate {
    /// Binding name (already prefixed/filtered by the backend).
    pub name: String,
    /// RFC 6570 level-1 URI template, e.g. `petstore://pets/{petId}`.
    pub uri_template: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    pub backend_kind: String,
    pub backend_spec: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<serde_json::Value>,
}

/// Input to a binding execution.
/// Serde codec for the `payload` byte fields that cross the plugin FFI
/// boundary. JSON has no byte-string type, so a bare `Vec<u8>` serialises as a
/// number-array — one decimal token per byte, which the `ffi_matrix` payload
/// benchmark clocked at ~15 MiB/s because serde visits every element. Base64
/// collapses that to a single string token plus a tight encode/decode loop
/// (orders of magnitude faster, ~1.33× the raw size — a non-issue under the
/// 256 KiB FFI payload cap). The bytes still arrive as `Vec<u8>` on both sides;
/// only the wire form changes, so plugin authors and the trait API are
/// unaffected. This is a wire-incompatible change gated by the ABI version bump
/// to v37 (a stale number-array plugin is rejected at load, never misread).
mod payload_b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRequest {
    /// The tool arguments serialized as a JSON payload. The plugin forwards
    /// these bytes verbatim to the remote peer. Base64 on the FFI wire (see
    /// [`payload_b64`]).
    #[serde(with = "payload_b64")]
    pub payload: Vec<u8>,

    /// Out-of-band headers the plugin SHOULD propagate to the remote peer
    /// when the transport supports headers (e.g. NATS message headers,
    /// Kafka record headers). Currently used for W3C `traceparent` /
    /// `tracestate`.
    pub headers: Vec<(String, String)>,

    /// Gateway-assigned request identifier — useful for correlation logs.
    pub request_id: String,

    /// Session identifier if the request is session-bound.
    pub session_id: Option<String>,

    /// Caller identity at the time of dispatch. Threaded so adapters that
    /// resolve `cred://<plugin_id>/<target>` URIs can scope credential
    /// issuance per-caller. `None` for system-initiated calls (await
    /// runtime, watch-engine fetch path) — adapters MUST treat absence
    /// as "no caller, static-cred only" and refuse `cred://` resolution
    /// rather than fall back to an arbitrary identity. Added in
    /// PROTOCOL_VERSION 1.8 (additive — older plugins absorb the field
    /// at JSON deserialise time and ignore it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PluginIdentity>,

    /// Idempotency hint carried through from the gateway when the
    /// owning tool-call rode a `dev.mcpg/idempotency-key`. Backends that
    /// propagate to upstreams (HTTP / SQL / NATS / Kafka) consume this
    /// to dedupe at the upstream layer; backends that don't propagate
    /// ignore it. Added in PROTOCOL_VERSION 1.16 (additive — older
    /// plugins absorb the field at JSON deserialise time and ignore
    /// it).
    ///
    /// Per design doc §5: pipeline sub-steps inherit the SAME hint as
    /// the parent tool-call — no per-hop derivation. The key carried
    /// here is the operator/caller-supplied key verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<IdempotencyHint>,
}

/// Hint carried on `BackendRequest` when the owning tool-call rode a
/// `dev.mcpg/idempotency-key`. Backends that propagate to upstreams
/// (HTTP / SQL / NATS / Kafka) consume this; backends that don't
/// ignore it.
///
/// Added in PROTOCOL_VERSION 1.16.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdempotencyHint {
    /// Operator/caller-supplied key (≤255 ASCII bytes after the
    /// gateway's `validate_request_key` check). Backends MUST pass
    /// this verbatim to the upstream — preserve the key the gateway
    /// saw, do not derive sub-keys per hop.
    pub key: String,

    /// Hex-encoded BLAKE3 hash (truncated to 16 bytes / 32 hex chars)
    /// of the gateway-side dedupe scope (tenant + identity + method +
    /// tool_name). Backends maintaining their OWN per-call cache
    /// (e.g. response cache) can include this in their cache key to
    /// avoid cross-scope reuse. NOT a security boundary — the
    /// gateway already validates scope inside `IdempotencyRecord`.
    pub scope_hash: String,
}

/// Output of a binding execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendResponse {
    /// Raw response bytes from the remote peer (opaque to the host). Base64 on
    /// the FFI wire (see [`payload_b64`]).
    #[serde(with = "payload_b64")]
    pub payload: Vec<u8>,

    /// True if the response was truncated to the configured byte limit.
    /// The host surfaces this in `_meta` on the tool result.
    pub truncated: bool,
}

/// Advisory health verdict a backend reports from
/// [`BackendPlugin::health`] when it declares
/// [`HealthProbeDecl::Plugin`](crate::manifest::HealthProbeDecl::Plugin).
/// Health is advisory: the gateway surfaces it but never fails a binding
/// on an `Unhealthy`/`Unknown` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackendHealth {
    /// The backend confirmed it can serve traffic.
    Healthy,
    /// The backend reports it cannot currently serve traffic, with an
    /// optional human-readable reason.
    Unhealthy {
        /// Human-readable reason, surfaced in advisory health output.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The backend did not determine its health (the default — a plugin
    /// that declares no `Plugin` probe never reaches this method).
    #[default]
    Unknown,
}

/// Errors raised by a `BackendPlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum BackendError {
    /// The plugin was asked to dispatch for a name it never registered.
    ProfileNotFound { backend_name: String },
    /// The spec passed to `register_profile` failed validation.
    InvalidSpec { message: String },
    /// The request did not complete within the configured timeout.
    Timeout { timeout_ms: u64 },
    /// A transport-level failure (connection closed, broker refused, …).
    Transport { message: String },
}

impl BackendError {
    /// Bounded metrics label — mirrors `CacheError::kind_label` /
    /// `CredentialError::kind_label` so the free-form `message` fields never
    /// reach Prometheus as unbounded label cardinality.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::ProfileNotFound { .. } => "profile_not_found",
            Self::InvalidSpec { .. } => "invalid_spec",
            Self::Timeout { .. } => "timeout",
            Self::Transport { .. } => "transport",
        }
    }

    /// HTTP status the gateway surfaces when this backend error escapes to a
    /// request boundary (Timeout → 504, Transport → 502 upstream, the rest
    /// → 500 operator/internal).
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::ProfileNotFound { .. } | Self::InvalidSpec { .. } => 500,
            Self::Timeout { .. } => 504,
            Self::Transport { .. } => 502,
        }
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileNotFound { backend_name } => {
                write!(f, "no execution profile registered for '{backend_name}'")
            }
            Self::InvalidSpec { message } => write!(f, "invalid binding spec: {message}"),
            Self::Timeout { timeout_ms } => write!(f, "binding timed out after {timeout_ms}ms"),
            Self::Transport { message } => write!(f, "binding transport error: {message}"),
        }
    }
}

impl std::error::Error for BackendError {}

// ---------------------------------------------------------------------------
// WatchStrategyPlugin — pluggable change-detection sources for resources
// ---------------------------------------------------------------------------

/// A plugin that detects resource changes and emits `resources/updated` events.
///
/// Given a serialized strategy spec (e.g. `{ "subject": "orders.changed",
/// "url": "nats://..." }`), the plugin spawns background tasks that watch
/// the external source. Whenever a change is observed, it calls
/// `sink.emit(event)` so the host can fan out `notifications/resources/updated`
/// to subscribed MCP sessions, honoring subject-scoped filters via
/// `WatchEvent::user_id` / `session_id`.
///
/// The plugin returns a `WatchHandle` the host uses to cancel the watcher
/// (e.g. when the last subscriber disconnects or on shutdown).
#[async_trait]
pub trait WatchStrategyPlugin: Send + Sync {
    /// Returns the plugin manifest.
    fn manifest(&self) -> &PluginManifest;

    /// The strategy discriminator this plugin handles (e.g. `"nats_topic"`,
    /// `"kafka_topic"`). Matched against the `WatchStrategy` variant name
    /// in the host config.
    fn kind(&self) -> &str;

    /// Start a watcher. The plugin takes ownership of the background task(s)
    /// and calls `sink.emit(event)` on every detected change until the
    /// returned `WatchHandle` is cancelled.
    async fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        sink: std::sync::Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError>;

    /// Shutdown hook — default no-op. Most plugins close resources when
    /// individual handles are cancelled; this is for global teardown.
    async fn shutdown(&self) {}
}

/// Sink the host provides to a watch plugin for publishing change events.
///
/// The host's implementation consults the subscription store and filter
/// config to fan out `notifications/resources/updated` to the right sessions.
#[async_trait]
pub trait WatchEventSink: Send + Sync {
    async fn emit(&self, event: WatchEvent);
}

/// A resource-change event emitted by a watch plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchEvent {
    /// Principal/user the event belongs to, when the plugin can extract it
    /// from the event payload. Consumed by subject-scoped notification
    /// filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Originating MCP session when the change was triggered by a known
    /// session. Consumed by session-scoped notification filters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Handle returned by `WatchStrategyPlugin::watch`. Dropping the handle
/// MUST NOT implicitly cancel the watcher — the host calls `cancel()`
/// explicitly so error paths are visible.
#[async_trait]
pub trait WatchHandle: Send + Sync {
    /// Stop the watcher's background tasks. After this returns, the sink
    /// will receive no further events for this handle.
    async fn cancel(&self);
}

/// Errors raised by a `WatchStrategyPlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum WatchError {
    /// The strategy spec failed validation.
    InvalidSpec { message: String },
    /// The plugin could not establish its subscription (connect failed,
    /// topic missing, …).
    Subscribe { message: String },
}

impl WatchError {
    /// Bounded metrics label (mirrors the sibling error types).
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::InvalidSpec { .. } => "invalid_spec",
            Self::Subscribe { .. } => "subscribe",
        }
    }
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSpec { message } => write!(f, "invalid watch spec: {message}"),
            Self::Subscribe { message } => write!(f, "watch subscribe failed: {message}"),
        }
    }
}

impl std::error::Error for WatchError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginClass, PluginManifest};

    fn manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "0.1.0".into(),
            name: "test".into(),
            plugin_class: PluginClass::ToolGate, // reused; binding/watch are additive
            protocol_version: "1.0".to_owned(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    struct EchoBinding {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl BackendPlugin for EchoBinding {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            "echo"
        }
        async fn register_profile(
            &self,
            _name: &str,
            _spec: &serde_json::Value,
            _host: Arc<dyn BackendHost>,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        async fn execute(
            &self,
            _name: &str,
            req: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            Ok(BackendResponse {
                payload: req.payload,
                truncated: false,
            })
        }
    }

    #[tokio::test]
    async fn backend_plugin_echo() {
        let plugin = EchoBinding {
            manifest: manifest("test.echo"),
        };
        assert_eq!(plugin.kind(), "echo");
        plugin
            .register_profile("t1", &serde_json::json!({}), noop_backend_host())
            .await
            .unwrap();
        let resp = plugin
            .execute(
                "t1",
                BackendRequest {
                    payload: b"hello".to_vec(),
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.payload, b"hello");
        assert!(!resp.truncated);
    }

    #[tokio::test]
    async fn complete_template_variable_default_returns_empty() {
        let plugin = EchoBinding {
            manifest: manifest("test.echo.completion"),
        };
        let out = plugin
            .complete_template_variable(
                "b",
                "v",
                "p",
                &serde_json::Value::Null,
                &std::collections::BTreeMap::new(),
            )
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn backend_error_display_and_serde() {
        let err = BackendError::Timeout { timeout_ms: 500 };
        assert!(format!("{err}").contains("500"));
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("timeout"));
        let parsed: BackendError = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BackendError::Timeout { timeout_ms: 500 }));
    }

    #[tokio::test]
    async fn noop_backend_host_returns_not_implemented() {
        let host = noop_backend_host();
        let ctx = BackendInvocationContext::root("req-1", None, "echo");
        let err = host
            .invoke_tool(&ctx, "other.tool", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
        assert!(format!("{err}").contains("no dispatcher"));
    }

    /// A host that records its invocations into a shared list, used
    /// to prove the [`LateBoundBackendHost`] forwards correctly.
    struct RecordingHost {
        log: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    }
    #[async_trait]
    impl BackendHost for RecordingHost {
        async fn invoke_tool(
            &self,
            _ctx: &BackendInvocationContext,
            tool_name: &str,
            args: &serde_json::Value,
        ) -> Result<serde_json::Value, BackendHostError> {
            self.log
                .lock()
                .unwrap()
                .push((tool_name.to_owned(), args.clone()));
            Ok(serde_json::json!({"ok": true}))
        }
    }

    #[tokio::test]
    async fn late_bound_host_returns_not_implemented_until_set() {
        let host = LateBoundBackendHost::new();
        assert!(!host.is_bound());
        let ctx = BackendInvocationContext::root("r1", None, "init");
        let err = host
            .invoke_tool(&ctx, "child.tool", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
    }

    #[tokio::test]
    async fn late_bound_host_forwards_after_set() {
        let host = LateBoundBackendHost::new();
        let inner = Arc::new(RecordingHost {
            log: std::sync::Mutex::new(Vec::new()),
        });
        host.set(inner.clone());
        assert!(host.is_bound());

        let ctx = BackendInvocationContext::root("r1", None, "init");
        let result = host
            .invoke_tool(&ctx, "linear.fetch_issue", &serde_json::json!({"id": 42}))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"ok": true}));

        let log = inner.log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, "linear.fetch_issue");
        assert_eq!(log[0].1, serde_json::json!({"id": 42}));
    }

    #[tokio::test]
    async fn late_bound_host_swap_replaces_inner() {
        let host = LateBoundBackendHost::new();
        let first = Arc::new(RecordingHost {
            log: std::sync::Mutex::new(Vec::new()),
        });
        let second = Arc::new(RecordingHost {
            log: std::sync::Mutex::new(Vec::new()),
        });
        host.set(first.clone());

        let ctx = BackendInvocationContext::root("r1", None, "init");
        host.invoke_tool(&ctx, "a", &serde_json::json!({}))
            .await
            .unwrap();
        host.set(second.clone());
        host.invoke_tool(&ctx, "b", &serde_json::json!({}))
            .await
            .unwrap();

        // Each inner host saw exactly one call.
        assert_eq!(first.log.lock().unwrap().len(), 1);
        assert_eq!(first.log.lock().unwrap()[0].0, "a");
        assert_eq!(second.log.lock().unwrap().len(), 1);
        assert_eq!(second.log.lock().unwrap()[0].0, "b");
    }

    #[tokio::test]
    async fn late_bound_host_can_be_passed_as_arc_dyn_backend_host() {
        // The whole point of this type: `Arc<LateBoundBackendHost>`
        // upcasts cleanly to `Arc<dyn BackendHost>` so it can be
        // passed to BackendPlugin::register_profile without ceremony.
        let host: Arc<dyn BackendHost> = LateBoundBackendHost::new();
        let ctx = BackendInvocationContext::root("r1", None, "x");
        let err = host
            .invoke_tool(&ctx, "y", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
    }

    /// A host that records every revocation and rotation event into a
    /// shared `Vec`. Used to prove the late-bound host replays
    /// pre-`set` subscriptions onto the inner host. Subscription
    /// guards remove the corresponding callback on drop, mirroring
    /// the production `GatewayBackendHost` contract.
    struct BroadcastingHost {
        revocation: Arc<std::sync::Mutex<Vec<(u64, CredentialRevocationCallback)>>>,
        rotation: Arc<std::sync::Mutex<Vec<(u64, SecretRotationCallback)>>>,
        next_id: std::sync::atomic::AtomicU64,
    }
    impl BroadcastingHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                revocation: Arc::new(std::sync::Mutex::new(Vec::new())),
                rotation: Arc::new(std::sync::Mutex::new(Vec::new())),
                next_id: std::sync::atomic::AtomicU64::new(0),
            })
        }
        fn fire_revoked(&self, plugin_id: &str, target: &str) {
            for (_, cb) in self.revocation.lock().unwrap().iter() {
                cb(plugin_id, target);
            }
        }
        fn fire_rotation(&self, secret_ref: &str, version: u64) {
            for (_, cb) in self.rotation.lock().unwrap().iter() {
                cb(secret_ref, version);
            }
        }
    }
    struct BroadcastRevocGuard {
        list: Arc<std::sync::Mutex<Vec<(u64, CredentialRevocationCallback)>>>,
        id: u64,
    }
    impl Drop for BroadcastRevocGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.list.lock() {
                g.retain(|(i, _)| *i != self.id);
            }
        }
    }
    struct BroadcastRotGuard {
        list: Arc<std::sync::Mutex<Vec<(u64, SecretRotationCallback)>>>,
        id: u64,
    }
    impl Drop for BroadcastRotGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.list.lock() {
                g.retain(|(i, _)| *i != self.id);
            }
        }
    }
    #[async_trait]
    impl BackendHost for BroadcastingHost {
        async fn invoke_tool(
            &self,
            _ctx: &BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, BackendHostError> {
            Err(BackendHostError::NotImplemented)
        }
        fn subscribe_credential_revoked(
            &self,
            cb: CredentialRevocationCallback,
        ) -> CredentialRevocationSubscription {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.revocation.lock().unwrap().push((id, cb));
            CredentialRevocationSubscription::new(BroadcastRevocGuard {
                list: Arc::clone(&self.revocation),
                id,
            })
        }
        fn subscribe_secret_rotation(
            &self,
            cb: SecretRotationCallback,
        ) -> SecretRotationSubscription {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.rotation.lock().unwrap().push((id, cb));
            SecretRotationSubscription::new(BroadcastRotGuard {
                list: Arc::clone(&self.rotation),
                id,
            })
        }
    }

    /// Subscribing to revocation events *before* `set()` runs must
    /// still deliver events fired *after* `set()`. The buffered
    /// callback is replayed onto the inner host.
    #[tokio::test]
    async fn late_bound_host_replays_buffered_revocation_subscription() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = LateBoundBackendHost::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        // Subscribe BEFORE set() — mirrors plugin register_profile.
        let _guard =
            host.subscribe_credential_revoked(Arc::new(move |_plugin_id: &str, _target: &str| {
                counter_cb.fetch_add(1, Ordering::SeqCst);
            }));

        let inner = BroadcastingHost::new();
        host.set(inner.clone());

        // Fire after set() — callback registered via the buffered
        // slot's replay must observe this.
        inner.fire_revoked("plugin.x", "target.y");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Same shape as the revocation case — pre-`set` rotation
    /// subscriptions must fire on post-`set` events.
    #[tokio::test]
    async fn late_bound_host_replays_buffered_rotation_subscription() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = LateBoundBackendHost::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let _guard =
            host.subscribe_secret_rotation(Arc::new(move |_secret_ref: &str, _version: u64| {
                counter_cb.fetch_add(1, Ordering::SeqCst);
            }));

        let inner = BroadcastingHost::new();
        host.set(inner.clone());

        inner.fire_rotation("vault://kv/db#pw", 7);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Dropping the subscription guard removes the buffered slot —
    /// subsequent events must NOT fire the callback.
    #[tokio::test]
    async fn late_bound_host_drop_unsubscribes_buffered_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = LateBoundBackendHost::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let guard = host.subscribe_secret_rotation(Arc::new(move |_s: &str, _v: u64| {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        }));

        let inner = BroadcastingHost::new();
        host.set(inner.clone());
        drop(guard);

        inner.fire_rotation("vault://x", 1);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "dropped guard should remove its callback before set()'s replayed sub fires"
        );
    }

    /// Calling `subscribe_*` *after* `set()` must wire the callback
    /// straight into the inner host (no buffering needed) and the
    /// guard must still unsubscribe on drop.
    #[tokio::test]
    async fn late_bound_host_subscribe_after_set_fires_immediately() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = LateBoundBackendHost::new();
        let inner = BroadcastingHost::new();
        host.set(inner.clone());

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let _guard = host.subscribe_credential_revoked(Arc::new(move |_p: &str, _t: &str| {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        }));

        inner.fire_revoked("p", "t");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// A second `set()` (host swap during reload) must also re-issue
    /// every buffered subscription — events on the new inner host
    /// must reach the original callback.
    #[tokio::test]
    async fn late_bound_host_replay_runs_on_host_swap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let host = LateBoundBackendHost::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        let _guard = host.subscribe_secret_rotation(Arc::new(move |_s: &str, _v: u64| {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        }));

        let first = BroadcastingHost::new();
        host.set(first.clone());
        first.fire_rotation("vault://a", 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Hot-swap. The buffered callback must be re-registered
        // against the new host AND removed from the old host (so
        // events fired on `first` no longer bump the counter).
        let second = BroadcastingHost::new();
        host.set(second.clone());
        second.fire_rotation("vault://a", 2);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "buffered subscription should replay onto the new host on swap"
        );
        // The old host's subscription was dropped during replay, so
        // firing on it must not reach the callback any more.
        first.fire_rotation("vault://a", 3);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "old host's subscription should be dropped during replay"
        );
    }

    #[tokio::test]
    async fn noop_host_store_and_fetch_content_return_not_implemented() {
        let host = noop_backend_host();
        let ctx = BackendInvocationContext::root("r1", None, "x");
        let err = host
            .store_content(
                &ctx,
                bytes::Bytes::from_static(b"x"),
                "text/plain".into(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
        let err = host
            .fetch_content(&ctx, "mcpg-resource://hash:abc")
            .await
            .unwrap_err();
        assert!(matches!(err, BackendHostError::NotImplemented));
    }

    #[tokio::test]
    async fn late_bound_host_forwards_store_and_fetch_after_set() {
        struct StoreHost;
        #[async_trait]
        impl BackendHost for StoreHost {
            async fn invoke_tool(
                &self,
                _ctx: &BackendInvocationContext,
                _tool_name: &str,
                _args: &serde_json::Value,
            ) -> Result<serde_json::Value, BackendHostError> {
                unreachable!("not used in this test")
            }
            async fn store_content(
                &self,
                _ctx: &BackendInvocationContext,
                bytes: bytes::Bytes,
                mime_type: String,
                _ttl: Option<std::time::Duration>,
            ) -> Result<BackendResource, BackendHostError> {
                Ok(BackendResource {
                    id: "hash:test".into(),
                    uri: "mcpg-resource://hash:test".into(),
                    size_bytes: bytes.len(),
                    mime_type,
                    content_hash: "blake3:test".into(),
                    expires_at_unix: None,
                })
            }
            async fn fetch_content(
                &self,
                _ctx: &BackendInvocationContext,
                _uri: &str,
            ) -> Result<Option<bytes::Bytes>, BackendHostError> {
                Ok(Some(bytes::Bytes::from_static(b"fetched")))
            }
        }

        let host = LateBoundBackendHost::new();
        host.set(Arc::new(StoreHost));

        let ctx = BackendInvocationContext::root("r1", None, "x");
        let resource = host
            .store_content(
                &ctx,
                bytes::Bytes::from_static(b"hello"),
                "text/plain".into(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(resource.id, "hash:test");
        assert_eq!(resource.size_bytes, 5);

        let bytes = host
            .fetch_content(&ctx, "mcpg-resource://hash:test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_ref(), b"fetched");
    }

    #[test]
    fn backend_resource_serde_round_trip() {
        let r = BackendResource {
            id: "hash:abc".into(),
            uri: "mcpg-resource://hash:abc".into(),
            size_bytes: 11,
            mime_type: "image/png".into(),
            content_hash: "blake3:abc".into(),
            expires_at_unix: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: BackendResource = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, r);

        // Without expires, the field is omitted from JSON.
        let r2 = BackendResource {
            expires_at_unix: None,
            ..r
        };
        let json = serde_json::to_string(&r2).unwrap();
        assert!(!json.contains("expires_at_unix"));
    }

    #[test]
    fn backend_invocation_context_root_zero_depth() {
        let ctx = BackendInvocationContext::root("req-1", Some("sess-2".into()), "incident.triage");
        assert_eq!(ctx.depth, 0);
        assert_eq!(ctx.parent_request_id, "req-1");
        assert_eq!(ctx.session_id.as_deref(), Some("sess-2"));
        assert_eq!(ctx.initiating_backend, "incident.triage");
    }

    #[test]
    fn backend_host_error_display_and_serde() {
        for err in [
            BackendHostError::NotFound {
                tool_name: "t".into(),
            },
            BackendHostError::PolicyDenied {
                tool_name: "t".into(),
            },
            BackendHostError::DepthExceeded {
                tool_name: "t".into(),
                depth: 9,
            },
            BackendHostError::Cycle {
                tool_name: "t".into(),
                path: vec!["a".into(), "b".into()],
            },
            BackendHostError::Backend {
                tool_name: "t".into(),
                cause: BackendError::Timeout { timeout_ms: 100 },
            },
            BackendHostError::NotImplemented,
        ] {
            // Display works
            let _ = format!("{err}");
            // Round-trip serde
            let json = serde_json::to_string(&err).unwrap();
            let _: BackendHostError = serde_json::from_str(&json).unwrap();
        }
    }

    /// A binding that captures the host it was given so we can prove the
    /// new arg threads through and is callable. Uses [`NoOpBackendHost`]
    /// as the stand-in dispatcher; a real gateway-side host will be
    /// exercised in apps/gateway integration tests.
    ///
    /// Uses `std::sync::Mutex` rather than `tokio::sync::Mutex` because
    /// plugin-protocol does not enable any tokio features beyond
    /// `tokio-test`/`macros` for the test build, and these critical
    /// sections are trivial.
    struct HostUsingBinding {
        manifest: PluginManifest,
        captured_host: std::sync::Mutex<Option<Arc<dyn BackendHost>>>,
    }

    #[async_trait]
    impl BackendPlugin for HostUsingBinding {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            "host_using"
        }
        async fn register_profile(
            &self,
            _name: &str,
            _spec: &serde_json::Value,
            host: Arc<dyn BackendHost>,
        ) -> Result<(), BackendError> {
            *self.captured_host.lock().expect("mutex") = Some(host);
            Ok(())
        }
        async fn execute(
            &self,
            _name: &str,
            _req: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            let host_opt = self.captured_host.lock().expect("mutex").clone();
            let host = host_opt.ok_or_else(|| BackendError::Transport {
                message: "host not captured".into(),
            })?;
            let ctx = BackendInvocationContext::root("r1", None, "host_using");
            let res = host
                .invoke_tool(&ctx, "child.tool", &serde_json::json!({}))
                .await;
            // NoOpBackendHost returns NotImplemented — surface that as
            // a Transport error so the test sees the host was reached.
            match res {
                Err(BackendHostError::NotImplemented) => Err(BackendError::Transport {
                    message: "noop_host".into(),
                }),
                _ => unreachable!("NoOpBackendHost should always return NotImplemented"),
            }
        }
    }

    #[tokio::test]
    async fn execute_streaming_default_wraps_execute_with_single_done_chunk() {
        use futures::StreamExt;

        let plugin = EchoBinding {
            manifest: manifest("test.echo"),
        };
        plugin
            .register_profile("p", &serde_json::json!({}), noop_backend_host())
            .await
            .unwrap();
        let mut stream = plugin
            .execute_streaming(
                "p",
                BackendRequest {
                    payload: b"hello".to_vec(),
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap();

        let chunk = stream.next().await.expect("at least one chunk").unwrap();
        match chunk {
            BackendChunk::Done(BackendResponse { payload, truncated }) => {
                assert_eq!(payload, b"hello");
                assert!(!truncated);
            }
            other => panic!("expected Done, got {other:?}"),
        }
        // Stream must end after Done.
        assert!(
            stream.next().await.is_none(),
            "stream should end after Done"
        );
    }

    #[tokio::test]
    async fn backend_chunk_serde_round_trip() {
        for chunk in [
            BackendChunk::TextDelta {
                delta: "hello".into(),
            },
            BackendChunk::ToolCall {
                id: "c1".into(),
                name: "fetch".into(),
                arguments: serde_json::json!({"q": "x"}),
            },
            BackendChunk::ToolResult {
                id: "c1".into(),
                result: serde_json::json!({"data": 42}),
            },
            BackendChunk::Usage {
                input_tokens: 10,
                output_tokens: 5,
                cached_input_tokens: 0,
            },
            BackendChunk::IterationBoundary { iteration: 1 },
            BackendChunk::Progress {
                progress: 3,
                total: Some(10),
                message: "received 16 KiB".into(),
            },
            BackendChunk::Progress {
                progress: 7,
                total: None,
                message: "stream chunk 7".into(),
            },
            BackendChunk::Done(BackendResponse {
                payload: b"final".to_vec(),
                truncated: false,
            }),
        ] {
            let json = serde_json::to_string(&chunk).unwrap();
            // Each variant tags via `type` discriminator.
            assert!(json.contains("\"type\":"), "missing type tag in {json}");
            let _: BackendChunk = serde_json::from_str(&json).unwrap();
        }
    }

    /// Confirms the `Progress` variant uses the snake_case discriminator
    /// (`"type":"progress"`) and that `total: None` round-trips cleanly.
    /// Indeterminate-progress emission is the primary HTTP use case
    /// (chunked transfer encoding, no `Content-Length`).
    #[test]
    fn backend_chunk_progress_serde_shape() {
        let chunk = BackendChunk::Progress {
            progress: 1,
            total: None,
            message: "received 1024 bytes".into(),
        };
        let json = serde_json::to_string(&chunk).unwrap();
        assert!(
            json.contains("\"type\":\"progress\""),
            "wrong tag in {json}"
        );
        assert!(json.contains("\"total\":null"), "missing total: null");
        let parsed: BackendChunk = serde_json::from_str(&json).unwrap();
        match parsed {
            BackendChunk::Progress {
                progress,
                total,
                message,
            } => {
                assert_eq!(progress, 1);
                assert!(total.is_none());
                assert_eq!(message, "received 1024 bytes");
            }
            other => panic!("expected Progress, got {other:?}"),
        }
    }

    /// A binding that overrides `execute_streaming` to actually emit
    /// multiple chunks before Done. Proves the override path works
    /// without affecting the default impl.
    struct StreamingDemoBinding {
        manifest: PluginManifest,
    }
    #[async_trait]
    impl BackendPlugin for StreamingDemoBinding {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            "demo_streaming"
        }
        async fn register_profile(
            &self,
            _name: &str,
            _spec: &serde_json::Value,
            _host: Arc<dyn BackendHost>,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        async fn execute(
            &self,
            _name: &str,
            _req: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            // Executed only if a caller bypasses execute_streaming.
            Ok(BackendResponse {
                payload: b"final".to_vec(),
                truncated: false,
            })
        }
        async fn execute_streaming(
            &self,
            _name: &str,
            _req: BackendRequest,
        ) -> Result<BackendChunkStream, BackendError> {
            let chunks: Vec<Result<BackendChunk, BackendError>> = vec![
                Ok(BackendChunk::TextDelta {
                    delta: "hel".into(),
                }),
                Ok(BackendChunk::TextDelta { delta: "lo".into() }),
                Ok(BackendChunk::Usage {
                    input_tokens: 5,
                    output_tokens: 2,
                    cached_input_tokens: 0,
                }),
                Ok(BackendChunk::Done(BackendResponse {
                    payload: b"hello".to_vec(),
                    truncated: false,
                })),
            ];
            Ok(Box::pin(futures::stream::iter(chunks)))
        }
    }

    #[tokio::test]
    async fn execute_streaming_override_emits_multiple_chunks() {
        use futures::StreamExt;

        let plugin = StreamingDemoBinding {
            manifest: manifest("test.streaming_demo"),
        };
        let mut stream = plugin
            .execute_streaming(
                "p",
                BackendRequest {
                    payload: vec![],
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap();

        let mut text_deltas = String::new();
        let mut saw_usage = false;
        let mut done_payload = None;
        while let Some(chunk) = stream.next().await {
            match chunk.unwrap() {
                BackendChunk::TextDelta { delta } => text_deltas.push_str(&delta),
                BackendChunk::Usage {
                    input_tokens,
                    output_tokens,
                    ..
                } => {
                    assert_eq!(input_tokens, 5);
                    assert_eq!(output_tokens, 2);
                    saw_usage = true;
                }
                BackendChunk::Done(resp) => {
                    done_payload = Some(resp.payload);
                }
                other => panic!("unexpected chunk {other:?}"),
            }
        }
        assert_eq!(text_deltas, "hello");
        assert!(saw_usage);
        assert_eq!(done_payload.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn host_arg_threads_through_register_profile_and_execute() {
        let plugin = HostUsingBinding {
            manifest: manifest("test.host_using"),
            captured_host: std::sync::Mutex::new(None),
        };
        plugin
            .register_profile("p1", &serde_json::json!({}), noop_backend_host())
            .await
            .unwrap();
        let err = plugin
            .execute(
                "p1",
                BackendRequest {
                    payload: vec![],
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::Transport { ref message } if message == "noop_host"));
    }

    #[test]
    fn watch_error_display_and_serde() {
        let err = WatchError::Subscribe {
            message: "broker refused".into(),
        };
        assert!(format!("{err}").contains("broker refused"));
        let json = serde_json::to_string(&err).unwrap();
        let parsed: WatchError = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, WatchError::Subscribe { .. }));
    }

    struct NoopHandle;
    #[async_trait]
    impl WatchHandle for NoopHandle {
        async fn cancel(&self) {}
    }

    struct CountingSink {
        count: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl WatchEventSink for CountingSink {
        async fn emit(&self, _event: WatchEvent) {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    struct FakeWatch {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl WatchStrategyPlugin for FakeWatch {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            "fake"
        }
        async fn watch(
            &self,
            _uri: &str,
            _spec: &serde_json::Value,
            sink: std::sync::Arc<dyn WatchEventSink>,
        ) -> Result<Box<dyn WatchHandle>, WatchError> {
            sink.emit(WatchEvent {
                user_id: Some("u-1".into()),
                session_id: None,
            })
            .await;
            Ok(Box::new(NoopHandle))
        }
    }

    #[tokio::test]
    async fn watch_plugin_emits_event_to_sink() {
        let plugin = FakeWatch {
            manifest: manifest("test.fake_watch"),
        };
        let sink = std::sync::Arc::new(CountingSink {
            count: std::sync::atomic::AtomicUsize::new(0),
        });
        let handle = plugin
            .watch("mem://res", &serde_json::json!({}), sink.clone())
            .await
            .unwrap();
        assert_eq!(sink.count.load(std::sync::atomic::Ordering::Relaxed), 1);
        handle.cancel().await;
    }

    #[test]
    fn resource_page_default_is_empty() {
        let p = ResourcePage::empty();
        assert!(p.resources.is_empty());
        assert!(p.next_cursor.is_none());
    }

    #[test]
    fn listed_resource_mime_type_uses_camel_case() {
        let r = ListedResource {
            uri: "mem://1".into(),
            name: Some("n".into()),
            description: None,
            mime_type: Some("text/plain".into()),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["uri"], "mem://1");
        assert_eq!(json["name"], "n");
        assert!(json.get("description").is_none(), "None fields skipped");
        assert_eq!(
            json["mimeType"], "text/plain",
            "MCP spec uses mimeType, not mime_type"
        );
    }

    #[tokio::test]
    async fn default_backend_list_resources_returns_empty_page() {
        let plugin = EchoBinding {
            manifest: manifest("test.echo"),
        };
        let page = plugin.list_resources("t1", None).await.unwrap();
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn watch_event_default_round_trip() {
        let e = WatchEvent::default();
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "{}");
        let parsed: WatchEvent = serde_json::from_str(&json).unwrap();
        assert!(parsed.user_id.is_none());
        assert!(parsed.session_id.is_none());
    }

    // ----- IdempotencyHint serde + back-compat ------

    #[test]
    fn idempotency_hint_round_trip_with_hint() {
        // Round-trip a populated hint through JSON to verify both
        // fields survive serde and the field names match the plugin
        // contract (snake_case Rust idents, no rename).
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "r1".into(),
            session_id: None,
            identity: None,
            idempotency: Some(IdempotencyHint {
                key: "01J9X8N3QKHA0V9C4D8TYR2ABC".to_owned(),
                scope_hash: "0123456789abcdef0123456789abcdef".to_owned(),
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"idempotency\""));
        assert!(json.contains("\"key\":\"01J9X8N3QKHA0V9C4D8TYR2ABC\""));
        assert!(json.contains("\"scope_hash\":\"0123456789abcdef0123456789abcdef\""));
        let parsed: BackendRequest = serde_json::from_str(&json).unwrap();
        let hint = parsed.idempotency.expect("hint preserved");
        assert_eq!(hint.key, "01J9X8N3QKHA0V9C4D8TYR2ABC");
        assert_eq!(hint.scope_hash, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn idempotency_hint_round_trip_without_hint_omits_field() {
        // `skip_serializing_if = "Option::is_none"` keeps the wire
        // clean for the dominant path (no key supplied).
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "r1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            !json.contains("idempotency"),
            "absent hint must not emit the field; got: {json}"
        );
    }

    #[test]
    fn idempotency_hint_back_compat_pre_1_16_payload_deserialises_to_none() {
        // Older plugins built against PROTOCOL_VERSION ≤ 1.15 emit
        // BackendRequest payloads without the `idempotency` field.
        // `#[serde(default)]` MUST absorb the absence as `None` —
        // this is the additive-field contract for ABI v24.
        let pre_1_16 = serde_json::json!({
            "payload": "aGk=", // base64 of "hi" (ABI v37 wire form)
            "headers": [],
            "request_id": "r1",
            "session_id": null,
        });
        let parsed: BackendRequest = serde_json::from_value(pre_1_16).unwrap();
        assert!(
            parsed.idempotency.is_none(),
            "missing field must default to None"
        );
        assert!(parsed.identity.is_none());
        assert_eq!(parsed.payload, b"hi".to_vec());
    }

    #[test]
    fn payload_crosses_wire_as_base64_string_not_number_array() {
        // ABI v37: payload bytes serialise as base64 (one string token + a
        // tight loop) instead of a JSON number-array (one decimal token per
        // byte, ~15 MiB/s). Lock the wire form for both request and response,
        // and confirm a non-UTF-8 / non-printable payload round-trips.
        let req = BackendRequest {
            payload: b"hi".to_vec(),
            headers: vec![],
            request_id: "r".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["payload"], "aGk=", "request payload must be base64");
        assert_eq!(
            serde_json::from_value::<BackendRequest>(v).unwrap().payload,
            b"hi".to_vec()
        );

        let resp = BackendResponse {
            payload: vec![0u8, 255, 16, b'{'],
            truncated: false,
        };
        let rv = serde_json::to_value(&resp).unwrap();
        assert!(
            rv["payload"].is_string(),
            "response payload must be a base64 string, got {}",
            rv["payload"]
        );
        assert_eq!(
            serde_json::from_value::<BackendResponse>(rv)
                .unwrap()
                .payload,
            vec![0u8, 255, 16, b'{']
        );
    }

    #[test]
    fn idempotency_hint_eq_clone_debug_derives() {
        // The plugin contract derives Clone+Debug+PartialEq+Eq so
        // backends can compare hints (e.g. cache-key derivation) and
        // record them in trace spans without manually formatting.
        let h1 = IdempotencyHint {
            key: "k".into(),
            scope_hash: "s".into(),
        };
        let h2 = h1.clone();
        assert_eq!(h1, h2);
        let dbg = format!("{h1:?}");
        assert!(dbg.contains("IdempotencyHint"));
        assert!(dbg.contains("\"k\""));
    }

    #[test]
    fn backend_error_kind_labels_and_http_status() {
        assert_eq!(
            BackendError::Timeout { timeout_ms: 1 }.kind_label(),
            "timeout"
        );
        assert_eq!(BackendError::Timeout { timeout_ms: 1 }.http_status(), 504);
        assert_eq!(
            BackendError::Transport {
                message: "x".into()
            }
            .http_status(),
            502
        );
        assert_eq!(
            BackendError::InvalidSpec {
                message: "x".into()
            }
            .http_status(),
            500
        );
    }

    #[test]
    fn backend_host_error_labels_and_status() {
        assert_eq!(
            BackendHostError::NotFound {
                tool_name: "t".into()
            }
            .http_status(),
            404
        );
        assert_eq!(
            BackendHostError::PolicyDenied {
                tool_name: "t".into()
            }
            .http_status(),
            403
        );
        // Backend cause is forwarded through.
        let wrapped = BackendHostError::Backend {
            tool_name: "t".into(),
            cause: BackendError::Timeout { timeout_ms: 1 },
        };
        assert_eq!(wrapped.kind_label(), "backend");
        assert_eq!(wrapped.http_status(), 504);
    }

    #[test]
    fn watch_error_kind_labels() {
        assert_eq!(
            WatchError::Subscribe {
                message: "x".into()
            }
            .kind_label(),
            "subscribe"
        );
        assert_eq!(
            WatchError::InvalidSpec {
                message: "x".into()
            }
            .kind_label(),
            "invalid_spec"
        );
    }
}
