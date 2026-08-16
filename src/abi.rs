//! FFI-stable ABI for dynamic native plugins.
//!
//! Dynamic `.so` / `.dylib` plugins cannot rely on Rust's internal ABI —
//! the compiler does not promise layout stability across versions, and
//! `async_trait`'s boxed futures are not FFI-safe. This module exposes a
//! layout-pinned mirror of the plugin types using `abi_stable`, plus an
//! FFI-safe vtable so the host can dispatch into a loaded cdylib without
//! round-tripping through JSON.
//!
//! ## Contract
//!
//! A dynamic plugin cdylib MUST export:
//!
//! ```text
//! #[no_mangle]
//! pub extern "C" fn mcpg_plugin_register() -> PluginRegistration;
//! ```
//!
//! where the returned [`PluginRegistration`] carries an
//! [`MCPG_PLUGIN_ABI_VERSION`] sentinel and one vtable per class the
//! plugin implements. The loader refuses to bind a plugin whose version
//! sentinel does not match the host's compiled-in value.
//!
//! ## Async bridge
//!
//! The in-tree async trait contracts (`ToolGatePlugin`, `TransformPlugin`,
//! `IdentityProviderPlugin`) continue to work for statically-linked plugins. For
//! dynamically-loaded plugins the host wraps each ABI-stable vtable in a
//! small adapter that runs the synchronous FFI call on a blocking-friendly
//! executor — plugin authors who need long I/O are expected to return a
//! deferred result or to rely on the gateway's timeout. This matches the
//! mediation-chain semantics, which already bound every plugin call with a
//! per-step timeout.

use abi_stable::std_types::Tuple2;
use abi_stable::{
    StableAbi,
    std_types::{ROption, RStr, RString, RVec},
};

use crate::types::{
    GateDecision, IdentityResolution, PluginContext, PluginIdentity, TransformResult,
};

/// Version sentinel returned by every dynamic plugin. The host refuses
/// to bind a plugin whose version does not match its own compiled-in
/// value. Bump on any layout change to the types in this module.
///
/// History:
/// - v1: initial three-vtable surface (tool_gate / transform / identity).
/// - v2: panic-sentinel constants + FFI capability refinements.
/// - v3: adds `BackendVTable` + `WatchStrategyVTable` to
///   `PluginRegistration`. Adding vtable fields changes the struct's
///   layout; any v2 plugin reads a v3 host's expected layout
///   incorrectly, hence the bump.
/// - v4: adds `HttpRouteVTable` to `PluginRegistration`.
///   Same layout-change reasoning as v3 applies.
/// - v5: adds `AuditSinkVTable` + `LogSinkVTable` to
///   `PluginRegistration`. Same layout-change reasoning.
/// - v6: adds `TelemetrySinkVTable` to
///   `PluginRegistration`.
/// - v7: adds `StoreVTable` + `CacheVTable`. `watch` on
///   store is not wired into the vtable (stream-callback deferred).
/// - v8: adds `SecretProviderVTable` +
///   `ConfigProviderVTable`. `watch` on either is not wired
///   (stream-callback deferred, same as `store.watch`).
/// - v9: adds `PolicyEngineVTable`. `Transport` was
///   planned to pair here but deferred entirely (requires
///   `MessageDispatcher` callback + `TransportHandle` trait
///   object across FFI, both blocked on the callback-channel
///   infrastructure common to every streaming kind).
/// - v10: adds `ClusterBackendVTable` (read-only
///   and publish surface). Leases and subscriptions deferred
///   (need stream-across-FFI infrastructure, same as store.watch).
/// - v11: adds `watch` + `cancel_watch` slots to
///   `StoreVTable`, `SecretProviderVTable`, and
///   `ConfigProviderVTable`. Introduces the canonical
///   `StreamStartResult` return shape (later consolidated into
///   [`StreamHandle`] in v27) for
///   stream-subscription setup. Generalises the original
///   `WatchEventSinkRef` primitive into `EventSinkRef` (alias
///   preserved for backward compat).
/// - v12: adds `subscribe` + `watch_peers` +
///   `cancel_stream` slots to `ClusterBackendVTable`.
/// - v13: adds `handle_streaming` + `cancel_stream`
///   slots to `HttpRouteVTable` for chunked response bodies.
/// - v14: adds `acquire_leadership` + `acquire_lock`
///   plus lease-ops slots (`lease_renew` / `lease_release` /
///   `lease_drop`) to `ClusterBackendVTable`, and introduces
///   the `LeaseAcquireResult` struct (later renamed to
///   [`LeaseHandle`] in v27).
/// - v15: adds `TransportVTable` to
///   `PluginRegistration`, plus `DispatcherCallbackRef` +
///   `TransportStartResult` primitives (later consolidated into
///   [`StreamHandle`] in v27 with the listen
///   address moved to `metadata_json`). Bidirectional
///   host→plugin→host dispatch callback; plugin-returned
///   transport handle with close/drop operations. SDK macro
///   ergonomics deferred (same as the chunked-body slots in v13).
///
/// (Wire-version negotiation note: `PROTOCOL_VERSION` and the ABI
/// version are independent. The ABI sentinel gates whether a cdylib's
/// binary layout matches the host; `PROTOCOL_VERSION` gates wire-format
/// semantics. A change can bump one, the other, or both — each entry
/// below records which.)
///
/// - v16: adds `CatalogProviderVTable` to
///   `PluginRegistration`. New 17th `PluginClass` variant
///   (`CatalogProvider`). Chain-composed; gateway invokes the
///   chain on every `tools/list` request to filter + enrich
///   tool descriptors with operator-curated metadata.
/// - v17: adds `CredentialIssuerVTable` to
///   `PluginRegistration`. New 18th `PluginClass` variant
///   (`CredentialIssuer`). Per-request issuance keyed by
///   `cred://<plugin_id>/<target>` URI; gateway-side cache.
/// - v18: Protocol 1.1 — adds `metadata_json` parameter to
///   `IdentityVTable::resolve_identity`. Pairs with the
///   `RequestMetadata` + `TlsInfo` types. Identity
///   plugins migrate to take `&RequestMetadata` in their async
///   trait + sync FFI shim. Header-only plugins that ignore the
///   new parameter remain functionally protocol-1.0-equivalent.
/// - v19: Protocol 1.2 — human-approval workflow.
///   Adds `RGateDecision::PendingApproval` variant + new 19th
///   `PluginClass::ApprovalNotifier` entity kind +
///   `ApprovalNotifierVTable` on `PluginRegistration`. Tool-gate
///   consumers gain a "pause for human approval" decision
///   surface; the gateway pauses the in-flight request, fans out
///   to bound notifiers, and resumes on approve / denies on deny.
/// - v20: Protocol 1.4 — cluster opt-in for identity / policy
///   plugins. Adds [`ClusterClientRef`] and changes the `make`
///   slot of [`IdentityVTable`] and [`PolicyEngineVTable`] to take
///   a second argument `cluster: ROption<ClusterClientRef>`. The
///   host fills in the active `cluster_backend`'s handle +
///   vtable when one is registered (single-node deploys see
///   `RNone`). Pairs with a new [`crate::cluster::ClusterClient`]
///   helper in the SDK so plugin authors call coordinator slots
///   through a Rust async surface instead of touching the vtable
///   directly. Also derives `Copy` on
///   `ClusterBackendVTable` so the host can hand a copy to
///   each consumer without lifetime ceremony.
///   PROTOCOL_VERSION jumps 1.3 → 1.4 to record the breaking
///   make-signature change; older plugins will trip the
///   ABI-sentinel check at load.
/// - v21: Protocol 1.5 — non-blocking acquire variants. Adds
///   `try_acquire_leadership` + `try_acquire_lock` slots to
///   [`ClusterBackendVTable`]. Backed by matching default-
///   impl trait methods on [`crate::cluster::ClusterBackend`];
///   backends with native CAS / put-if-absent (Consul, etcd,
///   JetStream KV) override for true non-blocking semantics.
///   Return convention: `LeaseHandle.handle != 0` →
///   acquired; `handle == 0 && error_json.is_empty()` → declined
///   (peer holds the lease); `handle == 0 && !error_json.is_empty()`
///   → backend error. PROTOCOL_VERSION jumps 1.4 → 1.5 to record
///   the additive vtable slots; bumping (rather than treating it
///   as additive-with-default) is intentional — the new slots
///   are now part of the wire contract every host expects, and
///   plugins that ship a v20 vtable layout would have garbage
///   memory in the new slot positions.
/// - v22: adds [`MetricsSinkVTable`] to
///   [`PluginRegistration`] for the new `metrics_sink` entity-kind
///   (the in-tree trait [`crate::metrics::MetricsSink`] landed first).
///   Distinct from `telemetry_sink`
///   because metrics flow through `metrics-rs` recorder cadence;
///   pure-metrics plugins (Prometheus exporter, OTLP metrics-only
///   shippers) implement just this trait without no-op span methods.
///   ROption-defaulting means v21 plugins remain wire-compatible —
///   they just deserialize with `metrics_sink: RNone`. PROTOCOL_VERSION
///   stays at 1.7 (the trait surface was the protocol-level addition;
///   this is the FFI implementation).
/// - v23: adds `render_text_exposition` slot to
///   [`MetricsSinkVTable`] so a `MetricsSink` plugin can publish
///   a textual snapshot (e.g. Prometheus exposition v0.0.4) the
///   gateway's `/metrics` route hands back to scrapers without
///   owning the recorder itself. Optional (returns empty `RString`
///   when the sink is push-only); `register_metrics_sink_filtered`
///   now invokes it through the registry's lookup helper. New
///   crate-side trait method `MetricsSink::render_text_exposition`
///   carries a default `None` so non-Prometheus sinks stay free of
///   the concept. PROTOCOL_VERSION stays at 1.7 (no on-the-wire
///   surface change beyond the FFI vtable).
/// - v24: adds `module_path_prefix: ROption<RString>`
///   to [`PluginRegistration`] so the gateway can attribute every
///   tracing event / span / metric emit back to the originating
///   plugin id (via `metadata.module_path()` lookup at the
///   bridges). Per-plugin observability override (logs / metrics /
///   traces with `inherit` / `replace` / `tee` semantics) drives
///   off this. Optional — empty / `RNone` means the plugin's
///   events all attribute to the `core` pseudo-id. Set by the
///   `declare_plugin!` macro via `module_path!()`. PROTOCOL_VERSION
///   stays at 1.7.
/// - v24 (PROTOCOL_VERSION 1.7 → 1.8 only) — Per-backend `cred://`
///   resolution. Adds `identity: Option<PluginIdentity>` to the
///   JSON-encoded `BackendRequest` payload so backend adapters can
///   resolve `cred://<plugin_id>/<target>` URIs against per-caller
///   credential issuers. Wire-format-only change — vtable layout is
///   unchanged, ABI version stays at v24. Older plugins receiving a
///   request with the new field absorb it via serde's default-ignore
///   behaviour; newer plugins receiving a request from an older host
///   see `identity: None` and fall back to the static-cred path.
/// - v24 (PROTOCOL_VERSION 1.8 → 1.9 → 1.10) — HTTP backend
///   extraction. 1.9 added `spec_overrides: Option<Vec<u8>>` as
///   a transitional bridge so the gateway could pre-resolve operator
///   CEL templates and ship the resolved url/headers to the HTTP
///   plugin per-call. 1.10 removes that field again — the HTTP
///   plugin now carries its own CEL evaluator (via the shared
///   `mcpg-expr` crate), evaluating compiled `${arguments.X}` /
///   `${context.X}` expressions inline against `BackendRequest`
///   args + identity. Wire-format-only changes — vtable layout is
///   unchanged, ABI version stays at v24.
/// - v24 (PROTOCOL_VERSION 1.10 → 1.11) — Backend-driven progress.
///   Adds [`crate::backend::BackendChunk::Progress`] variant carrying
///   `progress: u32 + total: Option<u32> + message: String` so non-LLM
///   backends (HTTP first; SQL / NATS / Kafka can follow) can emit
///   intermediate `notifications/progress` events between request
///   start and completion. `BackendChunk` is JSON-encoded over the
///   `BackendChunkStream` (not vtable-discriminated), so vtable
///   layout is unchanged and ABI stays at v24. Older plugins that
///   never emit `Progress` continue to work; older hosts receiving
///   a `Progress` chunk from a newer plugin would fail serde —
///   that's the protocol-version negotiation's job.
/// - v24 (PROTOCOL_VERSION 1.11 → 1.12) — Dynamic resource template
///   completion. Adds the optional default-impl trait method
///   [`crate::backend::BackendPlugin::complete_template_variable`]
///   with signature `(backend_name, variable_name, prefix, config)
///   -> Result<Vec<String>, BackendError>`. Plugins consumed in-
///   process by the gateway (static-firstparty plugins) inherit the
///   default empty-list impl for free; SQL overrides to run a
///   prepared statement against `:prefix`. Adding a default-impl
///   method to a Rust trait is not a public-binary-ABI change —
///   the trait is dispatched in-process, not over the FFI vtable —
///   so ABI stays at v24.
/// - v25: registry-style `PluginRegistration`.
///   The 21-`ROption<*VTable>` shape is replaced by a single
///   `entities: RVec<EntityRegistration>` field carrying one
///   tagged-union variant per declared entity. This is a layout
///   break (every plugin must rebuild) that makes the
///   retrospective §15.1 "boot loop skips a vtable kind" bug
///   structurally impossible — adding a new entity kind is now an
///   `EntityRegistration` enum variant, not a struct field, and the
///   gateway boot loop matches exhaustively. Same change makes
///   `module_path_prefix: RString` (was `ROption<RString>`, but
///   was already de-facto required since v24 for non-builtin
///   plugins) and embeds an `inner_name: RString` on every
///   variant for first-class multi-entity-same-kind support
///   (e.g. one cdylib registering two `tool_gate` entities with
///   `inner_name: "rate-limit-public"` and `"rate-limit-internal"`).
///   PROTOCOL_VERSION jumps 1.16 → 1.17.
/// - v26: `HostHandle` on every `make` slot. Every
///   `<Kind>VTable.make` now takes `host: HostHandleRef` first and
///   `inner_name: RString` last. The v20
///   `cluster: ROption<ClusterClientRef>` arg on `IdentityVTable` and
///   `PolicyEngineVTable` is **dropped** — subsumed by
///   [`HostServicesVTable::cluster`]. `IdentityVTable` gains a
///   `shutdown` slot (retrospective §15.7 — pre-v26 the only kind
///   without one). [`HostServicesVTable`] is the bidirectional API:
///   `resolve_secret`, `issue_credential`, `config_snapshot`,
///   `audit_event`, `metric_emit`, `cluster`, `span_start` /
///   `span_end` / `span_event`, `alias`. The host bridge struct
///   (referenced via `HostHandleRef.ctx`) lives for the entire plugin
///   handle lifetime and is freed only after `drop_instance()`
///   returns. PROTOCOL_VERSION jumps 1.17 → 1.18.
/// - v27: ContentStore vocab sweep + Backend
///   `complete_template_variable` real vtable slot. Three changes:
///   (1) `ContentStoreVTable` renames `type_name → kind`,
///   `register_instance → register_profile`; per-call JSON args use
///   `profile_name` instead of `instance_name` so the vtable matches
///   the rest of the workspace (Backend, Transport, etc. all use
///   `register_profile` + `profile_name`). (2) `BackendPlugin` trait
///   renames the `_backend_name` arg to `_profile_name` on
///   `register_profile`, `execute`, `input_schema`, `output_schema`,
///   `list_resources`, `audit_metadata`, `complete_template_variable`
///   — Rust-only rename, no FFI impact since these all go through
///   the JSON-marshalled `BackendVTable.execute` slot. (3) Adds
///   `complete_template_variable` as a real
///   `BackendVTable.complete_template_variable` slot (was a default-
///   impl trait method on `BackendPlugin` so native cdylib backends
///   couldn't override it). PROTOCOL_VERSION jumps 1.18 → 1.19.
/// - v28: ABI sweep — four interlocking breaking
///   changes consolidating the vtable surface for v1.0.
///   (1) Uniform error envelope:
///   every fallible `RString`-return slot now uses the uniform
///   `{"ok": ..., "err": ...}` envelope (12 slots migrated:
///   `BackendVTable::register_profile`, the four sink `flush` slots,
///   `Store::{put,delete}`, `Cache::{put,clear}`,
///   `CredentialIssuer::revoke`, `ClusterBackend::{publish,
///   lease_release}`). Helpers in [`crate::result_envelope`]
///   (`respond_result_rstring` / `decode_result_envelope`) own the
///   wire shape so SDK macros + host adapters can't drift.
///   (2) Watch handles:
///   `WatchStrategyVTable::watch` returns
///   [`StreamHandle`](crate::abi::StreamHandle) instead of the legacy
///   `RWatchHandle` raw pointer; the `cancel` slot takes
///   `cancel_token: usize` rather than `*mut ()`.
///   (3) Handle consolidation:
///   `StreamStartResult`, `TransportStartResult`, and
///   `LeaseAcquireResult` are deleted and replaced by `StreamHandle`
///   plus [`LeaseHandle`](crate::abi::LeaseHandle). `StreamHandle`
///   adds a `metadata_json` field carrying kind-specific success
///   metadata
///   (Transport's `listen_address` rides here as
///   `{"listen_address": "..."}`). `HttpHandleResult` is left as-is
///   because its `handle == 0 ⇒ buffered bytes response` semantic
///   doesn't fold cleanly.
///   (4) Binary stream sink: new
///   [`BytesSinkRef`](crate::abi::BytesSinkRef) primitive for
///   high-volume binary streams (parallel to `EventSinkRef`); the
///   HTTP route streaming path now offers a bytes mode in addition
///   to the existing JSON `HttpChunkWire` SSE mode, avoiding the
///   JSON encode/decode tax per chunk. PROTOCOL_VERSION jumps 1.19 →
///   1.20.
/// - v29: naming sweep — two struct renames on the
///   FFI surface, plus an `EntityRegistration` variant rename.
///   (1) `ClusterBackendVTable → ClusterVTable` (15-slot
///   function-pointer struct embedded by value in `ClusterClientRef`
///   and in `EntityRegistration::Cluster`); the matching variant
///   `EntityRegistration::ClusterBackend → ::Cluster` and its
///   `kind()` discriminator string `"cluster_backend" → "cluster"`
///   land together (completes the 2026-05-02 cluster refactor's
///   crate/id/operator-config rename across the FFI surface).
///   (2) `IdentityVTable → IdentityProviderVTable` (5-slot
///   function-pointer struct on `EntityRegistration::IdentityProvider`);
///   realigns the vtable + trait + adapter naming to match the
///   already-correct `PluginClass::IdentityProvider` and
///   operator-config `class: identity_provider`. (3) residual
///   v24-`binding` doc-comment / JSON-Schema-enum sweep — code-only
///   cleanup, no FFI surface change on its own.
///
///   Why a bump: the two struct renames change `abi_stable`'s
///   `StableAbi` type UIDs. Even though the slot layouts are identical
///   bit-for-bit, the type-identity check at plugin load (the host's
///   `MCPG_PLUGIN_ABI_VERSION` sentinel + the per-vtable type tag
///   `abi_stable` derives from the type name) refuses to bind a v28
///   plugin against a v29 host or vice-versa. Pre-1.0 we prefer the
///   correct names over backward-binary-compat with the old layouts.
///   PROTOCOL_VERSION jumps 1.20 → 1.21.
///
/// - v30: typed capability declarations. Three
///   FFI surface changes:
///   (1) adds [`TypedCapabilityDecl`] — a new `#[repr(C)] StableAbi`
///   struct carrying `{kind: RString, args_json: RString}`. This
///   struct's `StableAbi` type UID is new, so the abi_stable
///   layout-check would refuse the load regardless of where it's
///   used.
///   (2) adds `capabilities: RVec<TypedCapabilityDecl>` field
///   to `PluginRegistration` — changes the struct's binary layout
///   (one new field after `entities`).
///   (3) deletes the legacy `cap.host.*` const + `Vec<String>`
///   capability surface in operator config + descriptor; the
///   replacement is typed at every surface.
///   Why a bump: the new field on `PluginRegistration` shifts
///   every subsequent field's offset (there are none — `capabilities`
///   is the last field — but adding a new field is still an ABI
///   change), AND every v29 cdylib produces a 5-field
///   `PluginRegistration` that the v30 host reads as missing the
///   capabilities slot. Pre-1.0 we prefer the cleanest typed
///   surface over backward-binary-compat with v29.
///   PROTOCOL_VERSION jumps 1.21 → 1.22.
///
/// - v31–v36: backend-plugin migration — make *every* backend a
///   runtime-loaded cdylib. These add function-pointer slots to existing
///   vtables so a cdylib backend can do mid-`execute` work the static
///   path did in-process. All are **ABI-layout-only — PROTOCOL_VERSION
///   stays 1.22** (additive slots, no wire-semantic change).
///   - v31: `HostServicesVTable` gains `resolve_credentials` (per-caller
///     `cred://<plugin>/<target>` substitution), `cache_get` (response
///     cache), `subscribe_credential_revoked` / `subscribe_secret_rotation`
///     (return an opaque `sub_id: u64`) + `host_unsubscribe`. CONTRACT:
///     these run from inside the cdylib bridge's `Runtime::block_on`, so
///     the host impl must NOT nest `block_on` — it spawns onto the gateway
///     runtime + waits on a channel (`host_bridge::block_on_host_service`).
///   - v32: `HostServicesVTable` gains `fetch_content` + `store_content`
///     (`Option<Bytes>` base64 shape) — LLM multimodal in/out.
///   - v33: `HostServicesVTable::invoke_tool` — an LLM binding with
///     `tools.allowed` calls back into the gateway dispatcher; the plugin
///     threads its own ctx for depth/cycle parity with the static path.
///   - v34: `BackendVTable` gains `execute_streaming`
///     (→ `StreamHandle`, chunks via `EventSinkRef`) + `cancel_stream`.
///     cdylib LLMs/http stream incrementally instead of buffering a single
///     `BackendChunk::Done`. CONTRACT: the host frees the stream bridge the
///     instant `cancel_stream` returns, so the plugin must synchronously
///     stop its drain task before returning (sticky cancel token +
///     completion channel — never a nested `block_on`).
///   - v35: `BackendVTable::execute_transaction` — the `sql_tx` pipeline
///     step; one-shot begin/steps/commit-or-rollback round-trip, no
///     stateful tx handle crosses the FFI.
///   - v36: `BackendVTable::audit_metadata` — domain audit fields merged
///     into the backend audit event (e.g. SQL `db.driver` / `db.query_ref`).
///   - v37: `BackendRequest`/`BackendResponse` `payload` bytes travel as
///     **base64** on the FFI wire instead of a JSON number-array (the
///     `ffi_matrix` payload bench measured the latter at ~15 MiB/s — serde
///     visits every byte). Wire-incompatible but vtable-layout-identical; the
///     ABI bump is what forces a stale plugin to be rejected at load rather
///     than silently misread the encoding. No signature change.
///   - v38: **Tier-1 slots take borrowed `RStr` args**
///     and support two host dispatch policies on the **one** slot:
///     `ToolGateVTable::{evaluate_pre,evaluate_post}_dispatch`,
///     `TransformVTable::{transform_arguments,transform_result}`,
///     `IdentityProviderVTable::resolve_identity`. The host calls each either
///     **ferried** (default — `spawn_blocking` + per-call timeout, strings owned
///     in the closure) or **inline** (operator opt-in `inline_dispatch` —
///     zero-copy, no ferry, ~33× on `tool_gate`). No separate "fast" slot — one
///     clean slot, dispatch is host policy. See `fast-slot-rollout.md`
///     + `benchmarks.md` §19.
///
/// - v2 (first post-release bump; the counter reset to 1 on 2026-06-05):
///   `RIdentityResolution::Invalid` gains
///   `response_headers: RVec<Tuple2<RString, RString>>` — response headers the
///   transport attaches to the authentication-failure response (AAuth's
///   `Signature-Error` / `Accept-Signature-*` diagnostics). Why a bump: the
///   new field changes the variant's binary layout, and a v1 cdylib's
///   two-word `Invalid` must be refused at load rather than misread.
pub const MCPG_PLUGIN_ABI_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// ABI-stable mirrors of the plugin data types
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(StableAbi, Debug, Clone)]
pub struct RPluginIdentity {
    pub kind: RString,
    pub trust_level: RString,
    pub subject_id: ROption<RString>,
    pub auth_provider: ROption<RString>,
    pub issuer: ROption<RString>,
    pub roles: RVec<RString>,
    pub groups: RVec<RString>,
    pub scopes: RVec<RString>,
    /// Attributes as `(key, value)` pairs. `BTreeMap` is not FFI-stable;
    /// the ABI exposes a flat key/value vec so both sides reconstruct
    /// their native map type on the boundary.
    pub attributes: RVec<RKeyValue>,
}

#[repr(C)]
#[derive(StableAbi, Debug, Clone)]
pub struct RKeyValue {
    pub key: RString,
    pub value: RString,
}

#[repr(C)]
#[derive(StableAbi, Debug, Clone)]
pub struct RPluginContext {
    pub request_id: RString,
    pub session_id: ROption<RString>,
    pub tool_name: RString,
    pub surface: RString,
    pub identity: RPluginIdentity,
    pub transport: RString,
}

#[repr(u8)]
#[derive(StableAbi, Debug, Clone)]
pub enum RGateDecision {
    /// JSON payloads travel as `RString` so the host / plugin do not have
    /// to share a `serde_json::Value` layout. They MUST be valid JSON.
    Allow {
        modified_arguments_json: ROption<RString>,
        modified_result_json: ROption<RString>,
        metadata_json: ROption<RString>,
    },
    Deny {
        http_status: u16,
        code: i32,
        message: RString,
        error_data_json: ROption<RString>,
    },
    Challenge {
        http_status: u16,
        code: i32,
        message: RString,
        challenge_data_json: RString,
    },
    /// Pause the request, dispatch to bound
    /// `approval_notifier` plugins, await human resolution.
    /// Fields are JSON-encoded RStrings to avoid dragging
    /// serde_json::Value layouts across the FFI; the host
    /// deserialises into the typed `GateDecision::PendingApproval`
    /// variant.
    PendingApproval {
        approval_id: RString,
        deadline_at: RString,
        summary: RString,
        /// JSON-encoded `Vec<String>`.
        target_notifiers_json: RString,
        /// JSON-encoded `Option<serde_json::Value>` (or
        /// `"null"` when the plugin sets nothing).
        metadata_json: RString,
    },
}

#[repr(u8)]
#[derive(StableAbi, Debug, Clone)]
pub enum RTransformResult {
    Unchanged,
    Modified { value_json: RString },
    Error { message: RString },
}

// `RPluginIdentity` is ~250 B (eight `RString`s + three `RVec<RString>`s
// + a small `RHashMap`). The other variants are ~24 B — so the enum is
// dominated by `Resolved`. We accept the size variance deliberately:
// this is a tagged union on the FFI boundary whose layout is pinned by
// `#[repr(u8)]` and `StableAbi`; boxing the `Resolved` payload would
// require bumping `MCPG_PLUGIN_ABI_VERSION` and complicating the drop
// path (plugin-allocated `Box` crossing the library boundary) for no
// measurable gain — one `RIdentityResolution` is returned per request.
#[repr(u8)]
#[derive(StableAbi, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RIdentityResolution {
    Resolved {
        identity: RPluginIdentity,
    },
    None,
    Invalid {
        reason: RString,
        /// `(name, value)` response headers for the resulting
        /// authentication-failure response, lowercase names.
        response_headers: RVec<Tuple2<RString, RString>>,
    },
}

// ---------------------------------------------------------------------------
// FFI vtables (one per plugin class)
// ---------------------------------------------------------------------------
//
// The host calls `make` once to construct an opaque plugin handle, then
// invokes the per-hook function pointers with that handle. The plugin is
// responsible for dropping the handle when `drop_instance` is called.

/// Opaque plugin instance. Meaning is owned by the plugin; the host only
/// ever receives it back through the same vtable.
pub type RPluginHandle = *mut ();

/// Cluster-coordinator handle handed to identity / policy plugins at
/// `make` time when the operator has registered a `cluster`
/// entity. Carries an opaque plugin instance pointer plus a copy of the
/// coordinator's vtable so the consumer plugin can call publish /
/// subscribe / lease slots without a registry lookup of its own.
///
/// The `handle` is stored as `usize` (rather than `RPluginHandle = *mut
/// ()`) because raw pointers don't satisfy `StableAbi`'s derive in a
/// `#[derive]` struct. Plugins cast it back via `handle as *mut ()`
/// inside the FFI shim.
///
/// Lifetime: the host promises that the coordinator's cdylib stays
/// loaded and the handle stays valid for as long as any consumer plugin
/// holding this `ClusterClientRef` is alive. Concretely, the registry
/// drops consumer plugins (identity / policy) before it drops the
/// coordinator at shutdown.
///
/// Single-node and tests-without-cluster deploys pass `RNone` to the
/// modified `make`; consumer plugins that never need cluster state
/// simply ignore the argument and behave identically to v19.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct ClusterClientRef {
    pub handle: usize,
    pub vtable: ClusterVTable,
}

/// FFI handle to host services, given to every plugin at `make()` time.
/// The universal mechanism for plugin → host calls.
///
/// The `ctx` field is an opaque host-side bridge pointer (cast to
/// `*const HostBridge` inside the host). Plugins never deref it — they
/// pass it back through the vtable. The host's bridge struct is allocated
/// at `make()` time, outlives every method call the plugin makes, and is
/// freed only after `drop_instance()` returns. The plugin MUST NOT call
/// `vtable.<method>(ctx, ...)` after `drop_instance()` returns.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct HostHandleRef {
    pub ctx: usize,
    pub vtable: HostServicesVTable,
}

/// Vtable of host services exposed to plugins via [`HostHandleRef`].
/// All slots receive the bridge `ctx` as the first argument; the host
/// casts it to its bridge struct and dispatches.
///
/// JSON-encoded slots use `Result<T, E>` envelopes serialised as
/// `{"ok": ...}` or `{"err": ...}`.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct HostServicesVTable {
    /// Resolve a `vault://` / `aws-sm://` / `file://` / `env://` /
    /// custom-scheme URI to a SecretValue.
    pub resolve_secret: extern "C" fn(ctx: usize, uri: RString) -> RString,

    /// Resolve a `cred://<plugin_id>/<target>` URI to an IssuedCredential,
    /// given the caller's identity.
    pub issue_credential:
        extern "C" fn(ctx: usize, uri: RString, identity_json: RString) -> RString,

    /// Resolve a config URI to a ConfigSnapshot.
    pub config_snapshot: extern "C" fn(ctx: usize, uri: RString) -> RString,

    /// Emit a typed audit event. Synchronous, durable.
    pub audit_event: extern "C" fn(ctx: usize, event_json: RString) -> RString,

    /// Emit a metric point. Best-effort.
    pub metric_emit: extern "C" fn(ctx: usize, point_json: RString),

    /// Get the active cluster handle, if any. `RNone` in single-node
    /// deployments. Subsumes the v20 `make` arg on `IdentityVTable`
    /// and `PolicyEngineVTable`.
    pub cluster: extern "C" fn(ctx: usize) -> ROption<ClusterClientRef>,

    /// Open a tracing span attributed to this plugin.
    pub span_start: extern "C" fn(ctx: usize, name: RString, attrs_json: RString) -> u64,

    /// Close a span opened with `span_start`.
    pub span_end: extern "C" fn(ctx: usize, span_id: u64),

    /// Record a span event. `span_id == 0` records on the current span.
    pub span_event: extern "C" fn(ctx: usize, span_id: u64, name: RString, attrs_json: RString),

    /// Get the operator alias of the plugin entry this handle belongs to.
    pub alias: extern "C" fn(ctx: usize) -> RString,

    // ── Backend host services (v31, backend-plugin-migration) ──────────
    // Let dynamically-loaded BACKEND plugins (kafka/nats/sql) reach the
    // same host services the statically-linked backends get via the async
    // `BackendHost` trait. The cdylib is dlopen'd into the gateway
    // process, so subscribe_* callbacks pass real in-process function
    // pointers (no serialization): the plugin boxes its `Arc<dyn Fn>` into
    // `cb_ctx` + a trampoline; the host stores them + invokes the
    // trampoline on each event.
    /// Resolve `cred://` URIs inside the JSON value in place. Returns
    /// `{"ok": {"value": <json>, "count": <n>}}` | `{"err": <BackendHostError>}`.
    pub resolve_credentials:
        extern "C" fn(ctx: usize, value_json: RString, identity_json: RString) -> RString,

    /// Look up a cached response by opaque key. Returns
    /// `{"ok": <base64-string-or-null>}` | `{"err": <BackendHostError>}`.
    pub cache_get: extern "C" fn(ctx: usize, key: RString) -> RString,

    /// Fetch host-stored content (multimodal inputs) by `mcpg-resource://`
    /// URI. Returns `{"ok": <base64-string-or-null>}` (null = not found)
    /// | `{"err": <BackendHostError>}`. v32 (backend-plugin-migration,
    /// LLM multimodal). Same Option<Bytes> shape as `cache_get`.
    pub fetch_content: extern "C" fn(ctx: usize, uri: RString) -> RString,

    /// Store content (generated images / audio) in the host's content
    /// store. Input is `{"bytes": <base64>, "mime_type": <str>,
    /// "ttl_ms": <u64-or-null>}`; returns `{"ok": <BackendResource>}` |
    /// `{"err": <BackendHostError>}`. v32 (backend-plugin-migration).
    pub store_content: extern "C" fn(ctx: usize, args_json: RString) -> RString,

    /// Invoke another gateway tool (the agentic child-tool call LLM
    /// backends make when a binding sets `tools.allowed`). `ctx_json` is
    /// the plugin's serialized [`BackendInvocationContext`] (carries
    /// parent_request_id / depth / session for the host's depth-cap +
    /// cycle detection — the plugin owns its depth exactly as the static
    /// path does). Returns `{"ok": <tool-result-json>}` |
    /// `{"err": <BackendHostError>}`. v33 (backend-plugin-migration, LLM
    /// agentic loop).
    pub invoke_tool: extern "C" fn(
        ctx: usize,
        ctx_json: RString,
        tool_name: RString,
        args_json: RString,
    ) -> RString,

    /// Subscribe to credential-revocation events. `cb` is a
    /// [`CredRevokedCallbackFfi`] trampoline cast to `usize` (abi_stable
    /// rejects a fn-pointer-typed parameter inside a fn-pointer field, so
    /// it crosses as `usize` and the host transmutes it back). The host
    /// invokes `cb(cb_ctx, plugin_id, target)` on each event. Returns an
    /// opaque subscription id (`0` = no subscription registered).
    pub subscribe_credential_revoked: extern "C" fn(ctx: usize, cb: usize, cb_ctx: usize) -> u64,

    /// Subscribe to secret-rotation events. `cb` is a
    /// [`SecretRotationCallbackFfi`] trampoline cast to `usize`. The host
    /// invokes `cb(cb_ctx, secret_ref, version)` on each event. Returns an
    /// opaque subscription id (`0` = none).
    pub subscribe_secret_rotation: extern "C" fn(ctx: usize, cb: usize, cb_ctx: usize) -> u64,

    /// Drop the host-side guard for a subscription id returned by either
    /// `subscribe_*` slot. Idempotent; `0` is a no-op.
    pub host_unsubscribe: extern "C" fn(ctx: usize, sub_id: u64),
}

/// Plugin-provided trampoline the host invokes when a subscribed
/// credential is revoked. `cb_ctx` is the plugin's opaque boxed-callback
/// pointer (round-trips untouched through the host). Crosses the vtable
/// as a `usize` (`fn_ptr as usize`); host transmutes back before calling.
pub type CredRevokedCallbackFfi = extern "C" fn(cb_ctx: usize, plugin_id: RString, target: RString);

/// Plugin-provided trampoline the host invokes on secret rotation.
/// Crosses the vtable as a `usize`; host transmutes back before calling.
pub type SecretRotationCallbackFfi =
    extern "C" fn(cb_ctx: usize, secret_ref: RString, version: u64);

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct ToolGateVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Pre-dispatch gate decision. JSON-ish args/meta/config cross as **borrowed
    /// `RStr`** (zero-copy — the cdylib shares the host's address space); `ctx`
    /// and the return are typed. The host calls this either **ferried** (default
    /// — `spawn_blocking` + per-call timeout, the strings owned inside the
    /// closure) or **inline** (operator opt-in `inline_dispatch` — zero-copy, no
    /// ferry, ~33×). One slot, two dispatch policies (v38).
    pub evaluate_pre_dispatch: extern "C" fn(
        handle: RPluginHandle,
        ctx: RPluginContext,
        arguments_json: RStr<'_>,
        meta_json: ROption<RStr<'_>>,
        config_json: RStr<'_>,
    ) -> RGateDecision,
    /// Post-dispatch gate decision. Borrowed `RStr` args/result/config; same
    /// ferried-default / inline-opt-in dispatch as `evaluate_pre_dispatch`.
    pub evaluate_post_dispatch: extern "C" fn(
        handle: RPluginHandle,
        ctx: RPluginContext,
        arguments_json: RStr<'_>,
        result_json: RStr<'_>,
        execution_duration_ms: u64,
        config_json: RStr<'_>,
    ) -> RGateDecision,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct TransformVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Borrowed `RStr` args/config; ferried-default / inline-opt-in dispatch
    /// (one slot, two policies — see `ToolGateVTable::evaluate_pre_dispatch`).
    pub transform_arguments: extern "C" fn(
        handle: RPluginHandle,
        ctx: RPluginContext,
        arguments_json: RStr<'_>,
        config_json: RStr<'_>,
    ) -> RTransformResult,
    pub transform_result: extern "C" fn(
        handle: RPluginHandle,
        ctx: RPluginContext,
        result_json: RStr<'_>,
        config_json: RStr<'_>,
    ) -> RTransformResult,
    /// Called once on gateway shutdown so transform plugins with buffered
    /// sinks can flush before the process exits.
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `identity_provider` plugins. `resolve_identity` takes a
/// `metadata_json` parameter. Identity plugins can opt into
/// cluster-coordinated state via host services (cross-node cache
/// invalidation, coordinated upstream pulls).
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct IdentityProviderVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: serialised headers + serialised `RequestMetadata`
    /// plus serialised plugin config. Output: `RIdentityResolution`.
    /// Borrowed `RStr` headers/metadata/config; ferried-default / inline-opt-in
    /// dispatch (one slot, two policies — see
    /// `ToolGateVTable::evaluate_pre_dispatch`).
    pub resolve_identity: extern "C" fn(
        handle: RPluginHandle,
        headers_json: RStr<'_>,
        metadata_json: RStr<'_>,
        config_json: RStr<'_>,
    ) -> RIdentityResolution,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// Binding + WatchStrategy vtables
// ---------------------------------------------------------------------------
//
// The `Binding` and `WatchStrategy` trait surfaces are richer than the
// Tier-1 trio (ToolGate / Transform / Identity) because they carry
// async state, per-profile configuration, and — for watch — reverse
// callbacks.
//
// The FFI boundary is still synchronous; plugins that need real async
// I/O bundle a private tokio runtime internally and `block_on` at each
// FFI entry point. The wire format is JSON for every non-trivial
// payload (`BackendRequest`, `BackendResponse`, `BackendError`,
// `ResourcePage`, watch spec, `WatchEvent`, `WatchError`). JSON adds a
// serialise round-trip per request but keeps the ABI definition
// narrow, avoids abi_stable enum-layout maintenance for every payload
// variant, and lets plugin authors debug the wire format with any JSON
// tool.

/// Canonical one-way plugin→host event sink for streaming
/// subscriptions. The host hands one of these to every vtable slot
/// that wants the plugin to push events back (watch / subscribe /
/// streaming body / peer-change notifications / …). Bundles the
/// callback function pointer + opaque host-side context together
/// so the vtable slot carries one argument instead of two —
/// high-arity function-pointer fields trip `StableAbi`'s derive
/// inside the vtable struct.
///
/// Plugins call `(sink.callback)(sink.ctx, event_json)` on every
/// emitted event; the host casts `ctx` back to its own bridge
/// struct inside the callback body. `event_json` is owned by the
/// plugin for the duration of the call.
///
/// Why `usize` for `ctx` instead of a raw pointer: abi_stable's
/// `StableAbi` derive does not cover function pointers that take
/// raw pointers; `usize` is the StableAbi-friendly alias. The host
/// casts `sink.ctx as *const HostBridge` inside its callback.
///
/// # History
///
/// Originally named `WatchEventSinkRef` and specific to
/// `WatchStrategy`. Later generalised into the canonical
/// streaming-FFI primitive and renamed to `EventSinkRef`;
/// `WatchEventSinkRef` remains as a type alias so existing
/// plugins compile unchanged.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct EventSinkRef {
    pub ctx: usize,
    pub callback: extern "C" fn(usize, RString),
}

/// Backward-compat alias. Prefer [`EventSinkRef`] in new code.
pub type WatchEventSinkRef = EventSinkRef;

/// Sink for high-volume binary streams. Parallel to [`EventSinkRef`]
/// (which carries JSON-serialised text events) — exists so streaming
/// kinds whose payload is naturally bytes (HTTP response bodies,
/// blob downloads from content-stores, etc.) don't pay the JSON
/// encode/decode tax per chunk.
///
/// The callback's `bytes` argument is an `RVec<u8>` carrying chunk
/// data. An empty `RVec<u8>` MUST be treated as "end of stream"
/// (mirrors the `HttpChunk::End` sentinel from the legacy
/// `HttpChunkWire` text path); the host stops reading the body
/// stream and finalises the response.
///
/// `ctx` is the host's bridge struct cast to `usize`, same
/// convention as [`EventSinkRef`].
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct BytesSinkRef {
    pub ctx: usize,
    pub callback: extern "C" fn(usize, abi_stable::std_types::RVec<u8>),
}

/// Canonical return shape for any FFI slot that hands the host a
/// stream-like handle (subscriptions, transports, watches). Replaces
/// the v27 trio `StreamStartResult` / `TransportStartResult` (and the
/// older `RWatchHandle` raw pointer).
///
/// - `handle != 0` ⇒ success; `error_json == ""`. `metadata_json`
///   carries kind-specific success metadata (transport listen address,
///   …) as JSON, or empty string when the kind has nothing to
///   report.
/// - `handle == 0` ⇒ failure; `error_json` holds the JSON-encoded
///   kind-specific error (`StoreError` / `TransportError` / …).
///
/// Two-slot success/failure design (vs. the earlier "null handle =
/// error, no reason" convention) preserves error structure while
/// staying `StableAbi`-safe.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct StreamHandle {
    /// Opaque plugin-side handle. Zero means "setup failed; see
    /// `error_json`."
    pub handle: usize,
    /// Empty on success; JSON-encoded kind-specific error
    /// otherwise.
    pub error_json: RString,
    /// JSON-encoded kind-specific success metadata
    /// (e.g. `{"listen_address": "0.0.0.0:8080"}` for transports).
    /// Empty string when there's nothing to report — most
    /// subscription kinds use empty here. Only meaningful on the
    /// success path (`handle != 0`).
    pub metadata_json: RString,
}

/// Bidirectional callback handed to a `TransportVTable::start`.
/// The plugin invokes this per incoming MCP message to dispatch
/// into the gateway + get back the reply. Unlike the one-way
/// `EventSinkRef`, this is request/response: the callback
/// SYNCHRONOUSLY returns a `DispatcherCallbackResult`.
///
/// Plugin calls:
///   `(cb.dispatch)(cb.ctx, session_id, message_json)`
/// where `message_json` is a JSON-encoded `{"bytes": Vec<u8>}`
/// object; the return's `reply_json` is JSON-encoded
/// `{"ok": {"bytes": Vec<u8>}}` or `{"err": DispatcherError}`.
///
/// Streaming replies (`DispatchResponse.stream`) are not carried
/// through this callback — the host wraps the
/// streaming dispatcher in a bytes-only façade and returns
/// `{"err": DispatcherError::Internal { reason: "stream reply
/// not supported across FFI" }}` if a stream is produced.
/// Streaming on top of this could later be layered via `EventSinkRef`.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct DispatcherCallbackRef {
    pub ctx: usize,
    pub dispatch: extern "C" fn(
        ctx: usize,
        session_id: RString,
        message_json: RString,
    ) -> DispatcherCallbackResult,
}

/// Return shape for `DispatcherCallbackRef::dispatch`. Holds a
/// JSON-encoded `Result<DispatchReplyWire, DispatcherError>` via
/// the `{"ok", "err"}` convention. Wrapped as a struct (rather
/// than just returning `RString`) to let future revisions add
/// fields (streaming-reply handle, etc.) without breaking the
/// `extern "C"` signature.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct DispatcherCallbackResult {
    pub reply_json: RString,
}

/// Canonical return shape for cluster-lease acquire slots
/// (`acquire_leadership`, `acquire_lock`, plus the `try_*` variants).
///
/// Lease-specific fields (`fencing_token`, `expires_at`) live up front
/// so the host doesn't round-trip back for them on every read.
///
/// - `handle != 0` ⇒ success; `error_json == ""`; lease metadata
///   fields are populated.
/// - `handle == 0` ⇒ failure; `error_json` holds the JSON-encoded
///   `ClusterError`.
///
/// `try_*` variants reuse this shape with one extra state:
/// `handle == 0 && error_json.is_empty()` ⇒ declined (peer holds
/// the lease). See `try_acquire_lease_common` in the host adapter
/// + `decode_try_acquire` in the SDK.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct LeaseHandle {
    pub handle: usize,
    pub error_json: RString,
    pub fencing_token: u64,
    pub expires_at: RString,
}

/// Return shape for `HttpRouteVTable::handle_streaming`. Two
/// modes depending on `handle`:
///
/// - `handle == 0` ⇒ the plugin produced a bytes response;
///   `head_json` is a full serialised `HttpRouteResponseWire`.
/// - `handle != 0` ⇒ the plugin is streaming chunks through the
///   sink; `head_json` is a serialised `HttpStreamHead` (status +
///   headers). Host wraps the subsequent chunk-events into the
///   response body.
///
/// Distinct from [`StreamHandle`] because HTTP routes have
/// a legitimate "success with bytes" path (not a streaming
/// subscription); a response is always produced — the
/// `handle == 0` arm here means "buffered bytes response", not
/// failure. (Deliberately kept separate from the `StreamHandle`
/// consolidation.)
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct HttpHandleResult {
    pub handle: usize,
    pub head_json: RString,
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct BackendVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Transport kind the plugin handles (`"nats"` / `"kafka"` / ...).
    /// Host routes `BackendTypeConfig::X` to the plugin whose `kind`
    /// matches.
    pub kind: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Register a per-backend profile. Returns JSON-encoded
    /// `Result<(), BackendError>` via the
    /// `{"ok": null}` / `{"err": BackendError}` envelope.
    pub register_profile:
        extern "C" fn(handle: RPluginHandle, backend_name: RString, spec_json: RString) -> RString,
    /// Execute a tool call through this backend. Request + response
    /// are JSON-encoded `BackendRequest` / `Result<BackendResponse,
    /// BackendError>`.
    pub execute: extern "C" fn(
        handle: RPluginHandle,
        backend_name: RString,
        request_json: RString,
    ) -> RString,
    /// Execute a tool call with an incremental response stream (LLM
    /// token streaming, etc.). The plugin drives its async chunk
    /// stream on its own runtime and pushes each item via `sink`
    /// (one result-envelope JSON per chunk: `{"ok": <BackendChunk>}`
    /// | `{"err": <BackendError>}`); the stream conventionally ends
    /// with a `BackendChunk::Done`. Returns a [`StreamHandle`] whose
    /// `handle` is an opaque cancel token (`0` on setup failure, with
    /// `error_json` set). The host wraps `sink` into a
    /// `BackendChunkStream`. Backends that don't stream inherit a
    /// default that emits the buffered `execute` result as one
    /// `Done` chunk. v34 (backend-plugin-migration). Mirrors the
    /// `EventSinkRef` streaming-FFI primitive used by watch/transport.
    pub execute_streaming: extern "C" fn(
        handle: RPluginHandle,
        backend_name: RString,
        request_json: RString,
        sink: EventSinkRef,
    ) -> StreamHandle,
    /// Cancel a stream started by `execute_streaming`. `stream_token`
    /// is the `StreamHandle.handle` returned there. Idempotent; `0`
    /// is a no-op. v34.
    pub cancel_stream: extern "C" fn(handle: RPluginHandle, stream_token: usize),
    /// Execute a multi-statement transaction group atomically (the
    /// `sql_tx` pipeline step). `tx_group_json` is the JSON-encoded
    /// group (`{"steps":[{id,sql,params,row_mode}],"step_input":…}` for
    /// SQL); returns `{"ok": {"steps": {<id>: <result>}}}` |
    /// `{"err": <BackendError>}`. Single round-trip — the plugin owns
    /// the whole transaction lifecycle (begin / per-step / commit /
    /// rollback), so no stateful tx handle crosses the FFI. Backends
    /// that aren't SQL-shaped inherit a default that returns a transport
    /// error. v35 (backend-plugin-migration).
    pub execute_transaction: extern "C" fn(
        handle: RPluginHandle,
        backend_name: RString,
        tx_group_json: RString,
    ) -> RString,
    /// Input schema — `ROption<RString>` holding a JSON Schema blob.
    pub input_schema_json:
        extern "C" fn(handle: RPluginHandle, backend_name: RString) -> ROption<RString>,
    /// Output schema — symmetric with `input_schema_json`.
    pub output_schema_json:
        extern "C" fn(handle: RPluginHandle, backend_name: RString) -> ROption<RString>,
    /// List resources. Returns JSON-encoded `Result<ResourcePage,
    /// BackendError>`.
    /// Return resource-template variable completions. A real vtable
    /// slot so cdylib backends can override resource-template
    /// completion instead of falling through to the static-list
    /// registry.
    ///
    /// Input: JSON-encoded `{profile_name, variable_name, prefix,
    /// config, context}` where `context` is a `BTreeMap<String,
    /// String>` of MCP `completion/complete` `context.arguments`.
    /// Output: `{"ok": Vec<String>}` (empty vec = no candidates) or
    /// `{"err": BackendError}` for backend-side failures (e.g. SQL
    /// query errors). The gateway clamps results to 100 with
    /// `has_more` semantics; backends MUST pre-filter to values
    /// matching `prefix` (case-sensitive starts-with is the
    /// convention).
    pub complete_template_variable:
        extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    pub list_resources: extern "C" fn(
        handle: RPluginHandle,
        backend_name: RString,
        cursor: ROption<RString>,
    ) -> RString,
    /// Domain-specific audit fields the gateway merges into the
    /// `mcpg.backend.executed` / `.failed` audit event details —
    /// e.g. SQL's `{"db.driver": "...", "db.query_ref": "..."}`. Returns
    /// a JSON object (empty `{}` when the backend has nothing to add).
    /// Pure request/response, infallible (a malformed return decodes to
    /// an empty map).
    pub audit_metadata: extern "C" fn(handle: RPluginHandle, backend_name: RString) -> RString,
    /// Capabilities the backend auto-registers from its own config
    /// (e.g. OpenAPI `sources` with `expose:`). Called
    /// once at boot/reload, parameterless (the plugin reads its own config
    /// loaded at `make`). Output: `{"ok": CapabilitySet}` or
    /// `{"err": BackendError}` — same envelope as `list_resources`.
    /// Default-empty for every backend that doesn't produce capabilities.
    pub expand_capabilities: extern "C" fn(handle: RPluginHandle) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct WatchStrategyVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Watch kind (`"nats_topic"` / `"kafka_topic"` / `"sql_polling"`
    /// / ...).
    pub kind: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Start watching. `uri` is the resource URI; `spec_json` is the
    /// operator's watch spec; `sink_ctx` + `sink_callback` let the
    /// plugin push events back to the host.
    ///
    /// Returns a [`StreamHandle`]: `handle != 0` ⇒ success;
    /// `error_json` empty; the plugin stores a handle (connection,
    /// consumer, polling task) it exposes via `cancel`'s argument.
    /// `handle == 0` ⇒ failure; `error_json` holds the JSON-encoded
    /// [`crate::WatchError`]. `metadata_json` is unused (empty
    /// string).
    ///
    /// Returns the canonical `StreamHandle` shape so failures
    /// carry structured error context instead of collapsing to
    /// "null handle".
    pub watch: extern "C" fn(
        handle: RPluginHandle,
        uri: RString,
        spec_json: RString,
        sink: WatchEventSinkRef,
    ) -> StreamHandle,
    /// Cancel a running watch. Plugin tears down the connection
    /// identified by `cancel_token` — the cookie returned in the
    /// matching `watch()`'s `StreamHandle.handle`. Idempotent.
    ///
    /// `cancel_token` is a `usize` to match the other streaming-kind
    /// cancel slots (`StoreVTable::cancel_watch`, etc.) and to
    /// keep raw pointers off the FFI surface.
    pub cancel: extern "C" fn(handle: RPluginHandle, cancel_token: usize),
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// HttpRoute vtable
// ---------------------------------------------------------------------------
//
// `HttpRoute` is a request/response entity (like `Binding`, unlike the
// callback-driven `WatchStrategy`). JSON marshalling handles the
// request/response pair end-to-end, including the identity and
// headers — see `HttpRouteRequestWire` / `HttpRouteResponseWire` in
// `http_route.rs` for the wire schema.
//
// Limitation: streaming response bodies (`HttpBody::Stream`) are
// not supported through the non-streaming `handle` slot across the FFI
// boundary. A plugin that returns a `Stream`-backed body through that
// adapter is rejected by the host with a 500. Streaming bodies instead
// go through the `handle_streaming` slot + `EventSinkRef`/`BytesSinkRef`.

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct HttpRouteVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `Vec<RouteSpec>` — the dispatch table this plugin
    /// contributes to the host.
    pub routes_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Handle a request. Input is JSON-encoded `HttpRouteRequestWire`;
    /// output is JSON-encoded `HttpRouteResponseWire`. The plugin MUST
    /// NOT return `HttpBody::Stream` through this path — stream bodies
    /// cannot be marshalled here and the host rejects attempts with a
    /// 500 at the adapter layer.
    pub handle: extern "C" fn(handle: RPluginHandle, request_json: RString) -> RString,
    /// Streaming variant. Input is the same wire request; plugin
    /// returns `HttpHandleResult`:
    /// - `handle == 0` ⇒ bytes response, `head_json` is
    ///   `HttpRouteResponseWire` (full response).
    /// - `handle != 0` ⇒ streaming, `head_json` is
    ///   `HttpStreamHead` (status + headers); chunks arrive
    ///   through either:
    ///     * `sink` (text/SSE — JSON-encoded `HttpChunkWire`,
    ///       plugin emits `HttpChunkWire::End` to terminate); or
    ///     * `bytes_sink` (binary path — raw `RVec<u8>` per chunk,
    ///       empty `RVec<u8>` to terminate).
    ///
    ///   Plugins choose one path per response and ignore the other
    ///   sink; mixing is undefined behaviour.
    pub handle_streaming: extern "C" fn(
        handle: RPluginHandle,
        request_json: RString,
        sink: EventSinkRef,
        bytes_sink: BytesSinkRef,
    ) -> HttpHandleResult,
    /// Cancel an in-flight streaming response (host closed the
    /// connection). Plugin MUST stop calling `sink.callback`
    /// after this returns. Idempotent.
    pub cancel_stream: extern "C" fn(handle: RPluginHandle, stream_handle: usize),
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// AuditSink + LogSink vtables
// ---------------------------------------------------------------------------
//
// Both sinks are fan-out-shaped (host calls `emit` on every
// registered sink); their trait surfaces are the simplest of any
// kind (manifest + emit + flush + shutdown). Wire format is JSON
// for every payload — the in-tree types (`AuditEvent` / `AuditReceipt`
// / `AuditError` / `LogRecord` / `LogError`) already derive serde,
// so no dedicated wire types are needed.
//
// Design differences from the Tier-1 vtables:
//
// - Audit `emit` returns `RString` encoding `{"ok": AuditReceipt}`
//   or `{"err": AuditError}` — matches the `BackendVTable::execute`
//   wire format for symmetry.
// - Log `emit` is infallible on the in-tree trait (best-effort
//   logging); the FFI slot returns `()` and wraps its body in
//   `catch_panic_silent` so a panicking plugin doesn't UB across
//   the boundary. A silent drop on panic matches the best-effort
//   contract.
// - `flush` returns `RString` with the
//   `{"ok": null}` / `{"err": <Error>}` envelope,
//   matching `BackendVTable::register_profile` and every other
//   fallible `RString` slot.

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct AuditSinkVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Emit an audit event. Input is JSON-encoded `AuditEvent`;
    /// output is JSON-encoded `Result<AuditReceipt, AuditError>` via
    /// the untagged `{"ok": ..., "err": ...}` convention.
    pub emit: extern "C" fn(handle: RPluginHandle, event_json: RString) -> RString,
    /// Force a flush up to `timeout_ms`. Returns JSON-encoded
    /// `Result<(), AuditError>` via the
    /// `{"ok": null}` / `{"err": AuditError}` envelope.
    pub flush: extern "C" fn(handle: RPluginHandle, timeout_ms: u64) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct LogSinkVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Emit a log record. Input is a JSON-encoded `LogRecord` as a **borrowed**
    /// `RStr` (zero-copy; v38); return is `()` — `LogSink::emit` is infallible
    /// on the in-tree trait (best-effort logging). Dispatched ferried-by-default
    /// (`spawn_blocking` + timeout) or inline (operator `inline_dispatch`), like
    /// the Tier-1 slots. The plugin's macro body is wrapped in
    /// `catch_panic_silent` so a panic here silently drops the record rather
    /// than UB-ing across the boundary.
    pub emit: extern "C" fn(handle: RPluginHandle, record_json: RStr<'_>),
    /// Force a flush with a millisecond deadline. Returns JSON-encoded
    /// `Result<(), LogError>` via the
    /// `{"ok": null}` / `{"err": LogError}` envelope.
    pub flush: extern "C" fn(handle: RPluginHandle, timeout_ms: u64) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// TelemetrySink vtable
// ---------------------------------------------------------------------------
//
// Span-lifecycle sink. Four emit surfaces (span start / span end /
// metric / log), all `()`-returning with `catch_panic_silent` on the
// plugin side — same best-effort contract as `log_sink.emit`. Plus
// `flush` with the audit/log wire format (empty = Ok).

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct TelemetrySinkVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `SpanStart`.
    pub span_started: extern "C" fn(handle: RPluginHandle, span_json: RString),
    /// JSON-encoded `SpanEnd`.
    pub span_ended: extern "C" fn(handle: RPluginHandle, span_json: RString),
    /// JSON-encoded `MetricPoint`.
    pub metric_recorded: extern "C" fn(handle: RPluginHandle, metric_json: RString),
    /// JSON-encoded `LogRecord`. Optional passthrough — default
    /// plugin impl ignores.
    pub log_recorded: extern "C" fn(handle: RPluginHandle, record_json: RString),
    /// JSON-encoded `Result<(), TelemetryError>` via the
    /// `{"ok": null}` / `{"err": TelemetryError}` envelope.
    pub flush: extern "C" fn(handle: RPluginHandle, timeout_ms: u64) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// MetricsSink vtable
// ---------------------------------------------------------------------------
//
// Pure-metrics counterpart to TelemetrySink. One emit slot
// (`MetricPoint`-shaped), `()`-returning + panic-silent on the
// plugin side per the best-effort contract. Plus `flush` with
// the audit/log/telemetry wire format (the
// `{"ok": null}` / `{"err": MetricsError}` envelope).

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct MetricsSinkVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `MetricPoint`. No return value — best-effort
    /// delivery. The plugin's macro body is wrapped in
    /// `catch_panic_silent` so a panicking plugin silently drops
    /// the metric rather than UB-ing across the boundary.
    pub emit: extern "C" fn(handle: RPluginHandle, metric_json: RString),
    /// JSON-encoded `Result<(), MetricsError>` via the
    /// `{"ok": null}` / `{"err": MetricsError}` envelope.
    pub flush: extern "C" fn(handle: RPluginHandle, timeout_ms: u64) -> RString,
    /// Optional textual snapshot (Prometheus exposition v0.0.4 for
    /// the canonical Prometheus plugin; empty `RString` for any
    /// push-only sink that has nothing to expose). This lets
    /// the gateway's `/metrics` route render
    /// from the plugin without the gateway owning a metrics
    /// recorder. Best-effort — panics inside the implementation
    /// are caught and surface as an empty payload.
    pub render_text_exposition: extern "C" fn(handle: RPluginHandle) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// Store + Cache vtables
// ---------------------------------------------------------------------------
//
// JSON-over-FFI for the non-streaming surface. The `watch` slots below
// reuse the `EventSinkRef` streaming primitive (originally built for
// `WatchStrategy` as `WatchEventSinkRef`), with store-specific ownership
// semantics.

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct StoreVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `Vec<StoreRole>` — the roles this plugin serves.
    pub supported_roles_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `{role, key}`. Output: JSON-encoded
    /// `Result<Option<StoreValueWire>, StoreError>` via the untagged
    /// `{"ok": ..., "err": ...}` convention.
    pub get: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{role, key, value}`. Output:
    /// `Result<(), StoreError>` via the
    /// `{"ok": null}` / `{"err": StoreError}` envelope.
    pub put: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{role, key}`. Output: same shape as `put`.
    pub delete: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{role, prefix, cursor}`. Output:
    /// `Result<StorePageWire, StoreError>` via `{"ok", "err"}`.
    pub list: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{role, key, expected, new}`. Output:
    /// `Result<bool, StoreError>` via `{"ok", "err"}`.
    pub compare_and_swap: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{role, key, value}`. Output:
    /// `Result<AppendResult, StoreError>` via `{"ok", "err"}`.
    pub append: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Start a `StoreEvent` subscription on `(role, key)`. Input:
    /// JSON-encoded `{role, key}`. Host passes an `EventSinkRef`
    /// the plugin calls with JSON-encoded `StoreEventWire`
    /// payloads on every event. Returns a `StreamHandle`
    /// — `handle != 0` on success, `error_json` on failure.
    /// `metadata_json` is unused (empty). (Consolidated onto
    /// `StreamHandle` in v27.)
    pub watch: extern "C" fn(
        handle: RPluginHandle,
        args_json: RString,
        sink: EventSinkRef,
    ) -> StreamHandle,
    /// Cancel a running watch. `watch_handle` is the opaque
    /// cookie returned in `StreamHandle.handle`. Idempotent.
    pub cancel_watch: extern "C" fn(handle: RPluginHandle, watch_handle: usize),
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// SecretProvider + ConfigProvider vtables
// ---------------------------------------------------------------------------
//
// Both are scheme-keyed URI-addressable resources with near-
// identical shape (manifest + supported_schemes + get/snapshot +
// optional watch). Watch is NOT wired (stream deferral). The `has`
// secret method is omitted — the trait has a default impl built on
// `get`, so consumers see identical semantics via `get` + match on
// NotFound.

// ---------------------------------------------------------------------------
// Transport vtable
// ---------------------------------------------------------------------------
//
// Unlike every earlier kind, transport's `start` takes a
// host-provided callback (the gateway's `MessageDispatcher`)
// AND returns an opaque lifecycle handle: it composes the
// cluster-lease trait-object pattern with a new bidirectional
// callback pattern.
//
// Streaming replies (`DispatchResponse.stream`) are NOT carried
// across FFI here — the dispatcher callback returns bytes-only.
// Plumbing an `EventSinkRef`-style stream channel onto the reply
// is possible but currently driver-blocked.

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct TransportVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Self-declared transport name (`"http-v1"`, `"stdio-v1"`,
    /// …). Host refuses duplicate registrations.
    pub name: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Start accepting sessions. Input: JSON-encoded
    /// `listener_config` + the dispatcher callback ref. Returns
    /// a `StreamHandle`: `handle != 0` ⇒ success, `metadata_json`
    /// carries `{"listen_address": "..."}` (or `""` if the
    /// transport has no listen address); `handle == 0` ⇒
    /// `error_json` holds JSON-encoded `TransportError`.
    /// Plugin MUST call `dispatcher_cb.dispatch(...)` synchronously
    /// per received message and return the reply bytes.
    /// (Consolidated onto `StreamHandle` in v27, from the former
    /// `TransportStartResult` shape.)
    pub start: extern "C" fn(
        handle: RPluginHandle,
        listener_config_json: RString,
        dispatcher_cb: DispatcherCallbackRef,
    ) -> StreamHandle,
    /// Stop accepting new sessions. Idempotent.
    pub transport_handle_close: extern "C" fn(handle: RPluginHandle, transport_handle: usize),
    /// Free plugin-side transport-handle state. Called by the host
    /// after the owner `Box<dyn TransportHandle>` is dropped.
    pub transport_handle_drop: extern "C" fn(handle: RPluginHandle, transport_handle: usize),
    /// Retrieve the transport's current listen address. Empty
    /// string = None.
    pub transport_handle_listen_address:
        extern "C" fn(handle: RPluginHandle, transport_handle: usize) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

// ---------------------------------------------------------------------------
// PolicyEngine vtable
// ---------------------------------------------------------------------------
//
// Transport was originally blocked from landing alongside this kind:
// its `start(config, dispatcher)` signature takes an
// `Arc<dyn MessageDispatcher>` callback (host → transport on every
// received message) AND returns a `Box<dyn TransportHandle>`, both of
// which needed the callback-channel-across-FFI infrastructure that the
// streaming-FFI work later built once and shared across every kind
// that needs it (store.watch, secret.watch, config.watch,
// cluster.subscribe, and transport — see `TransportVTable` above).

// ---------------------------------------------------------------------------
// Cluster vtable
// ---------------------------------------------------------------------------
//
// Slot groups:
//   - node_info / list_peers (read-only, snapshot)
//   - publish (fire-and-forget)
//   - subscribe / watch_peers (streaming via `EventSinkRef` →
//     `StreamHandle`)
//   - acquire_leadership / acquire_lock (+ `try_*` non-blocking
//     variants) and the lease lifecycle ops (`lease_renew` /
//     `lease_release` / `lease_drop`) keyed by an opaque
//     `LeaseHandle` cookie rather than a trait object across FFI.

// `Copy` + `Clone` are derived so the vtable can be embedded by value
// in `ClusterClientRef` and handed to consumer plugins without lifetime
// ceremony. Function pointers are `Copy` and there are no other fields,
// so the bit-copy is trivially correct.
#[repr(C)]
#[derive(StableAbi, Debug, Clone, Copy)]
pub struct ClusterVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `ClusterNodeInfo`.
    pub node_info: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `Vec<ClusterPeer>`.
    pub list_peers: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `{topic, routing_key: Option<String>,
    /// payload: Vec<u8>}`. Output: `Result<(), ClusterError>` via
    /// the `{"ok": null}` / `{"err": ClusterError}` envelope.
    pub publish: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Start a subscription. Input: JSON-encoded
    /// `{topic, group: Option<String>, routing_key:
    /// Option<String>}`. Sink receives JSON-encoded
    /// `PublishedMessage` payloads.
    pub subscribe: extern "C" fn(
        handle: RPluginHandle,
        args_json: RString,
        sink: EventSinkRef,
    ) -> StreamHandle,
    /// Start a peer-lifecycle watch. Sink receives JSON-encoded
    /// `PeerEvent` payloads.
    pub watch_peers: extern "C" fn(handle: RPluginHandle, sink: EventSinkRef) -> StreamHandle,
    /// Cancel a running stream (subscribe or watch_peers).
    /// `stream_handle` is the opaque cookie returned in
    /// `StreamHandle.handle`. Idempotent.
    pub cancel_stream: extern "C" fn(handle: RPluginHandle, stream_handle: usize),
    /// Acquire leadership for a named role. Input: JSON-encoded
    /// `{role, ttl_ms}`. Returns a `LeaseHandle` — on
    /// success carries the opaque lease handle + fencing token +
    /// RFC3339 expiry.
    pub acquire_leadership: extern "C" fn(handle: RPluginHandle, args_json: RString) -> LeaseHandle,
    /// Acquire a distributed lock on `key`. Same shape as
    /// `acquire_leadership`.
    pub acquire_lock: extern "C" fn(handle: RPluginHandle, args_json: RString) -> LeaseHandle,
    /// Non-blocking variant of `acquire_leadership`. Same input
    /// shape. Return convention:
    ///   `handle != 0` → acquired (fencing_token + expires_at populated)
    ///   `handle == 0 && error_json == ""` → declined (peer holds lease)
    ///   `handle == 0 && error_json != ""` → JSON-encoded ClusterError
    /// See [`crate::cluster::ClusterBackend::try_acquire_leadership`].
    pub try_acquire_leadership:
        extern "C" fn(handle: RPluginHandle, args_json: RString) -> LeaseHandle,
    /// Non-blocking variant of `acquire_lock`. Same input shape +
    /// return convention as `try_acquire_leadership`.
    pub try_acquire_lock: extern "C" fn(handle: RPluginHandle, args_json: RString) -> LeaseHandle,
    /// Renew a lease. `lease_handle` is the cookie from the
    /// matching acquire's `LeaseHandle.handle`. Returns
    /// JSON-encoded `Result<expires_at_string, ClusterError>`
    /// via the `{"ok", "err"}` convention so the host updates
    /// its cached expiry.
    pub lease_renew: extern "C" fn(handle: RPluginHandle, lease_handle: usize) -> RString,
    /// Release a lease. Returns JSON-encoded `Result<(),
    /// ClusterError>` via the
    /// `{"ok": null}` / `{"err": ClusterError}` envelope.
    /// Idempotent.
    pub lease_release: extern "C" fn(handle: RPluginHandle, lease_handle: usize) -> RString,
    /// Free plugin-side lease state. Called by the host on
    /// `NativeLeaseHandle::Drop` after `release` returns — the
    /// plugin MUST NOT touch the lease after this. Distinct from
    /// `lease_release` because drop happens even on
    /// double-release / panic paths.
    pub lease_drop: extern "C" fn(handle: RPluginHandle, lease_handle: usize),
    // -- KeyValueStore primitive over FFI --
    //
    // Each slot blocks on the coordinator's own runtime internally, exactly
    // like `publish`. The host marshals the `KeyValueStore` trait across the
    // boundary via the JSON arg/return DTOs in
    // `mcpg_cluster_api::key_value`. A coordinator that does not back a KV
    // (consul / etcd today) returns a `ClusterError` envelope — the host
    // exposes `key_value_store()` as `Some` only for coordinators whose
    // manifest `provides` includes the `kv` role, so these slots are never
    // reached on a non-KV coordinator.
    /// Input: JSON `KvKeyArgs` (`{key}`). Output: envelope
    /// `Result<Option<KvEntryWire>, ClusterError>`.
    pub kv_get: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON `KvPutArgs` (`{key, value, ttl_ms?}`). Output:
    /// envelope `Result<(), ClusterError>`.
    pub kv_put: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON `KvPutArgs`. Output: envelope
    /// `Result<bool, ClusterError>` (`true` == this caller created the
    /// entry; the cross-replica single-winner claim).
    pub kv_put_if_absent: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON `KvKeyArgs`. Output: envelope
    /// `Result<bool, ClusterError>` (`true` == the key existed).
    pub kv_delete: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON `KvListPrefixArgs` (`{prefix, limit}`). Output:
    /// envelope `Result<Vec<KvListEntryWire>, ClusterError>`.
    pub kv_list_prefix: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON `KvExpireArgs` (`{key, ttl_ms?}`). Output: envelope
    /// `Result<bool, ClusterError>` (`true` == the key existed).
    pub kv_expire: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `policy_engine` plugins. Policy engines (Cedar, OPA, …)
/// can opt into cluster-coordinated state via host services —
/// coordinated policy-document reloads, cross-node entity-set sync,
/// fenced refresh locks. Engines that don't need it ignore it.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct PolicyEngineVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Self-declared engine name. `PolicyEngine::name()` returns
    /// `&str`; cached on the adapter at construction time.
    pub name: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `{decision_point, input, context}`.
    /// Output: JSON-encoded `PolicyDecision` (never an error — the
    /// trait's `evaluate` is side-effect-free and encodes failures
    /// as `Deny` / `NotApplicable` per spec §9.14).
    pub evaluate: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// JSON-encoded `PolicyVersion`.
    pub policy_version: extern "C" fn(handle: RPluginHandle) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct SecretProviderVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `Vec<String>`.
    pub supported_schemes_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: secret reference URI (raw string, not JSON). Output:
    /// JSON-encoded `Result<SecretValueWire, SecretError>` via
    /// `{"ok", "err"}`.
    pub get: extern "C" fn(handle: RPluginHandle, reference: RString) -> RString,
    /// Start a rotation-event subscription. Input: secret
    /// reference URI. Sink receives JSON-encoded
    /// `SecretRotationWire` payloads.
    pub watch: extern "C" fn(
        handle: RPluginHandle,
        reference: RString,
        sink: EventSinkRef,
    ) -> StreamHandle,
    /// Cancel a running watch.
    pub cancel_watch: extern "C" fn(handle: RPluginHandle, watch_handle: usize),
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct ConfigProviderVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    pub supported_schemes_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: config reference URI. Output: JSON-encoded
    /// `Result<ConfigSnapshot, ConfigError>` via `{"ok", "err"}`.
    pub snapshot: extern "C" fn(handle: RPluginHandle, reference: RString) -> RString,
    /// Start a delta-event subscription on a config reference.
    /// Sink receives JSON-encoded `ConfigDelta` payloads.
    pub watch: extern "C" fn(
        handle: RPluginHandle,
        reference: RString,
        sink: EventSinkRef,
    ) -> StreamHandle,
    /// Cancel a running watch.
    pub cancel_watch: extern "C" fn(handle: RPluginHandle, watch_handle: usize),
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `approval_notifier` plugins. Posts
/// human-approval requests to a channel (Slack / email /
/// PagerDuty / Teams). Single method: `notify` is async on the
/// host side, sync at the FFI boundary; the SDK macro bridges.
///
/// FFI shape: JSON-encoded args/returns. Plugin host
/// serialises + deserialises across the boundary.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct ApprovalNotifierVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `NotificationRequest`. Output:
    /// JSON-encoded `Result<NotificationResult, NotificationError>`
    /// via `{"ok"}` / `{"err"}`. The gateway routes
    /// `target_notifiers` matches by plugin manifest id, so plugins
    /// don't need to advertise a separate notifier id here.
    pub notify: extern "C" fn(handle: RPluginHandle, request_json: RString) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `credential_issuer` plugins. Issues
/// per-request backend credentials keyed on the caller's
/// `PluginIdentity` + an operator-supplied target string.
///
/// FFI shape: every method takes JSON-encoded inputs and returns
/// a JSON-encoded payload. The plugin host serialises +
/// deserialises across the boundary.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct CredentialIssuerVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `{identity, target, config}`. Output:
    /// JSON-encoded `Result<IssuedCredential, CredentialError>`
    /// via `{"ok": IssuedCredential}` or `{"err": CredentialError}`.
    pub issue: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: lease id (raw string). Output: JSON-encoded
    /// `Result<(), CredentialError>` via the
    /// `{"ok": null}` / `{"err": CredentialError}` envelope.
    pub revoke: extern "C" fn(handle: RPluginHandle, lease_id: RString) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `catalog_provider` plugins. Filters +
/// enriches the tool list returned by `tools/list` with operator-
/// curated metadata (tags, owner, doc URL, trust level, etc.).
///
/// FFI shape: every method takes JSON-encoded inputs and returns a
/// JSON-encoded payload, matching the existing `policy_engine` /
/// `secret_provider` patterns. The plugin host serialises +
/// deserialises across the boundary; no `RVec<Struct>` payloads
/// to keep the ABI footprint small.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct CatalogProviderVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Input: JSON-encoded `{ctx, in_progress}` where
    /// `in_progress: Vec<EnrichedToolDescriptor>`. Output:
    /// JSON-encoded `Vec<EnrichedToolDescriptor>` — the refined
    /// view this provider contributes to the chain. Drops are
    /// represented by omission. Plugins MUST NOT add tools.
    pub filter_and_enrich: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Forward-compat for a future admin API. Input: tool id
    /// (raw string, not JSON). Output: JSON-encoded
    /// `Option<CatalogEntry>` — `null` for "not in scope".
    pub describe: extern "C" fn(handle: RPluginHandle, tool_id: RString) -> RString,
    /// Forward-compat for a future admin API. Output:
    /// JSON-encoded `Vec<CatalogEntry>` — every catalog entry this
    /// provider knows about.
    pub list_catalog: extern "C" fn(handle: RPluginHandle) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct CacheVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// JSON-encoded `Vec<String>` — declared namespaces.
    pub supported_namespaces_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Returns 1 if the plugin serves any namespace, 0 otherwise.
    pub serves_any_namespace: extern "C" fn(handle: RPluginHandle) -> u8,
    /// Input: JSON-encoded `{ns, key}`. Output: JSON-encoded
    /// `Option<Vec<u8>>` — `null` = miss.
    pub get: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{ns, key, value, ttl_ms}`. Output:
    /// `Result<(), CacheError>` via the
    /// `{"ok": null}` / `{"err": CacheError}` envelope.
    pub put: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{ns, key}`. `Cache::delete` is
    /// infallible; return is `()`.
    pub delete: extern "C" fn(handle: RPluginHandle, args_json: RString),
    /// Input: JSON-encoded `{ns}`. Output: `Result<(), CacheError>`
    /// via the `{"ok": null}` / `{"err": CacheError}` envelope.
    pub clear: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{ns, key, by, ttl_ms}`. Output:
    /// `Result<i64, CacheError>` via `{"ok", "err"}`.
    pub incr: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// Vtable for `content_store` plugins. Storage
/// backends — operators declare multiple providers per plugin in
/// their top-level `storage.providers: [...]` list, and bindings
/// reference providers by id.
///
/// FFI shape: this is a 2-level vtable. `make` produces ONE plugin
/// handle. `register_profile(name, spec)` builds a configured
/// profile internally — the plugin caches per-name state (clients,
/// connections) so subsequent calls with the same `profile_name`
/// reuse it. Per-resource methods (`put` / `get` / etc.) take the
/// `profile_name` in their JSON args so the plugin dispatches to
/// the right backend.
///
/// Why not return per-profile handles: keeping all state plugin-
/// side simplifies lifecycle (one `drop_instance` cleans up
/// everything) and avoids two round-trips (vtable.make_profile
/// then vtable.put_via_profile).
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct ContentStoreVTable {
    pub make: extern "C" fn(
        host: HostHandleRef,
        config_json: RString,
        inner_name: RString,
    ) -> RPluginHandle,
    pub manifest_json: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Operator-facing kind discriminator (e.g. `"s3"`, `"gcs"`,
    /// `"azure_blob"`, `"cassandra"`). Operators write this in their
    /// `storage.providers: [{kind: ...}]` config; the gateway looks
    /// up the matching plugin by this string.
    pub kind: extern "C" fn(handle: RPluginHandle) -> RString,
    /// Build a configured profile. Input: JSON-encoded
    /// `{profile_name, spec}`. Output: `{"ok": null}` or
    /// `{"err": "..."}`. The plugin caches the profile internally;
    /// subsequent `put` / `get` / etc. with the same `profile_name`
    /// reuse the cached client/connection.
    pub register_profile: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name, content: ContentToStoreWire}`.
    /// Output: `{"ok": ResourceHandleWire}` or `{"err": "..."}`.
    pub put: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name, id}`. Output:
    /// `{"ok": Option<ResourceContentWire>}` (null = NotFound) or
    /// `{"err": "..."}`.
    pub get: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name, id}`. Output:
    /// `{"ok": null}` or `{"err": "..."}`. Idempotent.
    pub delete: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name, id, ttl_seconds}`.
    /// Output: `{"ok": Option<String>}` (null = supported but no URL
    /// for this id), `{"err": "signed_url_not_supported"}` for
    /// stores that have no presigner, or `{"err": "..."}`.
    pub signed_url: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name}`. Output: JSON-encoded
    /// `ContentStoreStats` `{item_count, byte_count, max_bytes}` —
    /// best-effort, may return zeros when the backend doesn't
    /// surface utilisation cheaply (e.g. S3).
    pub stats: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    /// Input: JSON-encoded `{profile_name}`. Output: JSON-encoded
    /// number of expired entries removed. Plugin decides what
    /// "expired" means (lazy-on-read backends return 0).
    pub sweep_expired: extern "C" fn(handle: RPluginHandle, args_json: RString) -> RString,
    pub shutdown: extern "C" fn(handle: RPluginHandle),
    pub drop_instance: extern "C" fn(handle: RPluginHandle),
}

/// FFI-stable carrier for a single [`Capability`](crate::capability::Capability)
/// declaration. The typed replacement for the legacy
/// `Vec<String>` capability list on `PluginManifest` (which is now
/// derived from the typed declarations).
///
/// One [`TypedCapabilityDecl`] per capability the plugin requires.
/// Both fields are owned `RString`s (allocated inside the cdylib;
/// the host copies them out and reconstructs the typed
/// [`Capability`] enum via
/// [`TypedCapabilityDecl::to_capability`]). The wire shape
/// deliberately keeps no `enum`-style discriminator — the kind
/// string IS the discriminator — so adding new capability variants
/// in the future doesn't change the FFI struct layout.
///
/// # Encoding rules
///
/// * `kind` is the snake_case discriminator returned by
///   [`Capability::kind()`](crate::capability::Capability::kind). It
///   must match one of [`Capability::known_names()`](crate::capability::Capability::known_names)
///   on a current host; an unknown kind deserialises to
///   [`Capability::Unknown`](crate::capability::Capability::Unknown)
///   and boot validation rejects it.
/// * `args_json` is the JSON-encoded args object for variant-args
///   kinds (e.g. `{"paths":["/etc/myapp"]}` for `filesystem_read`).
///   Empty string for no-args variants.
///
/// JSON, rather than a dedicated enum, is used so a v25.0 host can
/// load a v25.1 cdylib that uses additional optional args fields on
/// an existing variant — serde's `#[serde(default)]` on the args
/// struct handles the schema evolution without an ABI bump.
#[repr(C)]
#[derive(StableAbi, Debug, Clone)]
pub struct TypedCapabilityDecl {
    /// Capability variant discriminator (snake_case:
    /// `"network_outbound"`, `"filesystem_read"`, …). Must match a
    /// [`Capability::kind()`](crate::capability::Capability::kind)
    /// value on the loading host.
    pub kind: RString,
    /// JSON-encoded variant args (e.g. `{"paths":["/etc/myapp"]}`).
    /// Empty string for no-args variants — the host's decoder treats
    /// `""` as `"{}"`.
    pub args_json: RString,
}

impl TypedCapabilityDecl {
    /// Encode a typed [`Capability`](crate::capability::Capability) into
    /// the FFI-stable carrier. The args field, for no-args variants,
    /// is the empty string; for variant-args variants it's the JSON
    /// object containing just the variant's args (no `"type"` field —
    /// the `kind` field on the struct carries the discriminator).
    pub fn from_capability(cap: &crate::capability::Capability) -> Self {
        use crate::capability::Capability;
        let kind = RString::from(cap.kind());
        let args_json = match cap {
            // No-args variants → empty string.
            Capability::NetworkOutbound
            | Capability::AuditWrite
            | Capability::MetricEmit
            | Capability::ClusterPeerRead
            | Capability::ClusterLeadershipAcquire
            | Capability::ClusterLockAcquire
            | Capability::HttpRouteServe
            | Capability::TransportListen
            | Capability::UnboundedSubscriptions
            | Capability::Unknown => RString::new(),
            // Variant-args → encode just the args object.
            Capability::FilesystemRead { paths } | Capability::FilesystemWrite { paths } => {
                let v = serde_json::json!({ "paths": paths });
                RString::from(v.to_string())
            }
            Capability::SecretsRead { schemes } | Capability::ConfigRead { schemes } => {
                let v = serde_json::json!({ "schemes": schemes });
                RString::from(v.to_string())
            }
            Capability::CredentialIssue { kinds } => {
                let v = serde_json::json!({ "kinds": kinds });
                RString::from(v.to_string())
            }
        };
        Self { kind, args_json }
    }

    /// Decode the FFI-stable carrier back into a typed
    /// [`Capability`](crate::capability::Capability). The kind
    /// string is checked against the host's known vocabulary — a
    /// future-version cdylib declaring an unknown kind yields
    /// [`CapabilityParseError::UnknownKind`](crate::capability::CapabilityParseError::UnknownKind)
    /// (boot validation surfaces that to the operator).
    pub fn to_capability(
        &self,
    ) -> Result<crate::capability::Capability, crate::capability::CapabilityParseError> {
        use crate::capability::{Capability, CapabilityParseError};
        let kind = self.kind.as_str();
        if !Capability::known_names().contains(&kind) {
            return Err(CapabilityParseError::UnknownKind(kind.to_owned()));
        }
        // Reconstruct the full enum form `{"type": "...", ...args}`
        // and let serde drive the decode.
        let args_raw = self.args_json.as_str();
        let args_value: serde_json::Value = if args_raw.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(args_raw).map_err(|source| CapabilityParseError::InvalidArgs {
                kind: kind.to_owned(),
                source,
            })?
        };
        let mut obj = match args_value {
            serde_json::Value::Object(m) => m,
            _ => {
                return Err(CapabilityParseError::InvalidEntry(format!(
                    "args_json for capability {kind:?} must be a JSON object"
                )));
            }
        };
        obj.insert(
            "type".to_owned(),
            serde_json::Value::String(kind.to_owned()),
        );
        serde_json::from_value(serde_json::Value::Object(obj)).map_err(|source| {
            CapabilityParseError::InvalidArgs {
                kind: kind.to_owned(),
                source,
            }
        })
    }
}

/// Tagged-union of every entity kind a plugin may register. Each
/// variant carries:
///
/// - `inner_name: RString` — within-plugin disambiguator. For the
///   common case (one entity per kind per plugin) it's `""`.
///   Multi-entity-same-kind plugins emit multiple variants of the
///   same kind with distinct inner_names (e.g.
///   `"rate-limit-public"` vs `"rate-limit-internal"`). The
///   registry keys on `(alias, inner_name)` for kinds that support
///   multi-entity-same-kind.
/// - `vtable: <Kind>VTable` — the FFI vtable for this entity's
///   `make` / lifecycle / per-call slots.
///
/// Adding a new entity kind in v1.x is an additive `EntityRegistration`
/// variant; the struct layout doesn't change so the ABI stays at v25.
/// Removing one is a major-bump break.
#[repr(u8)]
#[derive(StableAbi, Debug)]
pub enum EntityRegistration {
    ToolGate {
        inner_name: RString,
        vtable: ToolGateVTable,
    },
    Transform {
        inner_name: RString,
        vtable: TransformVTable,
    },
    IdentityProvider {
        inner_name: RString,
        vtable: IdentityProviderVTable,
    },
    Backend {
        inner_name: RString,
        vtable: BackendVTable,
    },
    WatchStrategy {
        inner_name: RString,
        vtable: WatchStrategyVTable,
    },
    HttpRoute {
        inner_name: RString,
        vtable: HttpRouteVTable,
    },
    AuditSink {
        inner_name: RString,
        vtable: AuditSinkVTable,
    },
    LogSink {
        inner_name: RString,
        vtable: LogSinkVTable,
    },
    TelemetrySink {
        inner_name: RString,
        vtable: TelemetrySinkVTable,
    },
    MetricsSink {
        inner_name: RString,
        vtable: MetricsSinkVTable,
    },
    Store {
        inner_name: RString,
        vtable: StoreVTable,
    },
    Cache {
        inner_name: RString,
        vtable: CacheVTable,
    },
    SecretProvider {
        inner_name: RString,
        vtable: SecretProviderVTable,
    },
    ConfigProvider {
        inner_name: RString,
        vtable: ConfigProviderVTable,
    },
    PolicyEngine {
        inner_name: RString,
        vtable: PolicyEngineVTable,
    },
    Cluster {
        inner_name: RString,
        vtable: ClusterVTable,
    },
    Transport {
        inner_name: RString,
        vtable: TransportVTable,
    },
    CatalogProvider {
        inner_name: RString,
        vtable: CatalogProviderVTable,
    },
    CredentialIssuer {
        inner_name: RString,
        vtable: CredentialIssuerVTable,
    },
    ApprovalNotifier {
        inner_name: RString,
        vtable: ApprovalNotifierVTable,
    },
    ContentStore {
        inner_name: RString,
        vtable: ContentStoreVTable,
    },
}

impl EntityRegistration {
    /// Canonical kind discriminator string. Matches the values
    /// returned from the [`crate::PluginClass`] serde tag and the
    /// `kind:` field on operator config.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ToolGate { .. } => "tool_gate",
            Self::Transform { .. } => "transform",
            Self::IdentityProvider { .. } => "identity_provider",
            Self::Backend { .. } => "backend",
            Self::WatchStrategy { .. } => "watch_strategy",
            Self::HttpRoute { .. } => "http_route",
            Self::AuditSink { .. } => "audit_sink",
            Self::LogSink { .. } => "log_sink",
            Self::TelemetrySink { .. } => "telemetry_sink",
            Self::MetricsSink { .. } => "metrics_sink",
            Self::Store { .. } => "store",
            Self::Cache { .. } => "cache",
            Self::SecretProvider { .. } => "secret_provider",
            Self::ConfigProvider { .. } => "config_provider",
            Self::PolicyEngine { .. } => "policy_engine",
            Self::Cluster { .. } => "cluster",
            Self::Transport { .. } => "transport",
            Self::CatalogProvider { .. } => "catalog_provider",
            Self::CredentialIssuer { .. } => "credential_issuer",
            Self::ApprovalNotifier { .. } => "approval_notifier",
            Self::ContentStore { .. } => "content_store",
        }
    }

    /// Within-plugin disambiguator. Empty string for one-entity-per-kind
    /// plugins (the common case).
    pub fn inner_name(&self) -> &str {
        match self {
            Self::ToolGate { inner_name, .. }
            | Self::Transform { inner_name, .. }
            | Self::IdentityProvider { inner_name, .. }
            | Self::Backend { inner_name, .. }
            | Self::WatchStrategy { inner_name, .. }
            | Self::HttpRoute { inner_name, .. }
            | Self::AuditSink { inner_name, .. }
            | Self::LogSink { inner_name, .. }
            | Self::TelemetrySink { inner_name, .. }
            | Self::MetricsSink { inner_name, .. }
            | Self::Store { inner_name, .. }
            | Self::Cache { inner_name, .. }
            | Self::SecretProvider { inner_name, .. }
            | Self::ConfigProvider { inner_name, .. }
            | Self::PolicyEngine { inner_name, .. }
            | Self::Cluster { inner_name, .. }
            | Self::Transport { inner_name, .. }
            | Self::CatalogProvider { inner_name, .. }
            | Self::CredentialIssuer { inner_name, .. }
            | Self::ApprovalNotifier { inner_name, .. }
            | Self::ContentStore { inner_name, .. } => inner_name.as_str(),
        }
    }
}

/// Value returned from the cdylib's `mcpg_plugin_register` symbol.
/// Registry-style: a single
/// `entities: RVec<EntityRegistration>` field carries one tagged-union
/// variant per declared entity. Multi-vtable plugins (e.g. tool_gate +
/// approval_notifier + http_route) emit three variants;
/// multi-entity-same-kind plugins emit multiple variants of the same
/// kind with distinct `inner_name` fields.
///
/// One enum variant per kind makes the gateway match exhaustively
/// compiler-checked, so a "forgotten kind" is structurally impossible.
#[repr(C)]
#[derive(StableAbi, Debug)]
pub struct PluginRegistration {
    /// ABI version sentinel. Must equal [`MCPG_PLUGIN_ABI_VERSION`].
    /// The host refuses to bind a plugin whose value differs.
    pub abi_version: u32,
    /// Plugin manifest id. Cross-checked against the operator
    /// config entry's `ref:` (or `id:` if `ref:` is absent).
    pub plugin_id: RString,
    /// Plugin version (semver). Operator-visible.
    pub plugin_version: RString,
    /// The `module_path!()` of the declaring crate, captured at the
    /// cdylib's `mcpg_plugin_register` symbol. The gateway uses
    /// this as the boot-time `target_prefix → plugin_id` map key —
    /// every tracing event whose target starts with this prefix
    /// attributes to this plugin's id when applying per-plugin
    /// observability override (`inherit` / `replace` / `tee`).
    ///
    /// Required. Empty string is rejected at validate time for
    /// non-`dev.mcpg.builtin.*` plugins.
    pub module_path_prefix: RString,
    /// Entity registrations. One vector entry per provided entity.
    /// Empty vec is rejected at validate time.
    pub entities: RVec<EntityRegistration>,
    /// Typed capability declarations.
    /// Empty vec means "plugin requires no host capabilities". The
    /// list is per-cdylib (not per-entity), reflecting the operating-
    /// system model: a plugin process / library either has a
    /// capability or it doesn't. Boot validation rejects the plugin
    /// if any declared capability decodes to
    /// [`Capability::Unknown`](crate::capability::Capability::Unknown)
    /// (cdylib targets a future host) or is not covered by the
    /// operator's `granted_capabilities` grant set.
    pub capabilities: RVec<TypedCapabilityDecl>,
    /// Backend-class declaration, JSON-encoded
    /// [`BackendProfile`](crate::manifest::BackendProfile). `RNone`
    /// (the default for every non-backend plugin and for backend
    /// plugins that declare nothing) reproduces today's behaviour.
    ///
    /// Carried as a JSON `RString` rather than a dedicated `StableAbi`
    /// struct so additional optional `BackendProfile` fields evolve via
    /// `#[serde(default)]` without an ABI bump — the same schema-
    /// evolution rule [`TypedCapabilityDecl::args_json`] uses. The host
    /// decodes it and copies the result onto
    /// [`PluginManifest::backend_profile`](crate::manifest::PluginManifest::backend_profile)
    /// at registration, exactly like the capability decls.
    pub backend_profile_json: ROption<RString>,
    /// The plugin's own `plugin.yaml`, compiled in by
    /// `declare_plugin! { descriptor_yaml: ... }`.
    ///
    /// Carries the manifest across the boundary as data, so the host can
    /// read a plugin's identity without constructing an instance to ask.
    /// That matters because construction needs the operator's config, which
    /// the host does not have at manifest time — a plugin that fails closed
    /// on an empty config would otherwise be unloadable.
    ///
    /// Empty for hand-built registrations (built-ins, test fixtures); the
    /// host falls back to probing in that case.
    pub descriptor_yaml: RString,
}

/// Canonical, semver-stable list of every plugin kind the v1.x ABI
/// supports — the same snake_case strings [`EntityRegistration::kind`]
/// emits and that operator config writes under `plugins[].class`.
/// One-stop source of truth for validators, CLI tools, doc generators,
/// and the gateway boot's allowlist.
///
/// Adding a new entity kind in v1.x is an additive [`EntityRegistration`]
/// variant + a new entry here + a new `first_<kind>()` accessor in the
/// `first_vtable_accessors!` invocation below. The compiler enforces
/// exhaustiveness on every match against `EntityRegistration`; this
/// const enforces the same on every string-keyed iteration site that
/// otherwise has no compile-time safety net.
///
/// The order mirrors the `EntityRegistration` variant declaration order
/// for readability — callers that need a specific ordering must sort.
pub const ALL_KINDS: &[&str] = &[
    "tool_gate",
    "transform",
    "identity_provider",
    "backend",
    "watch_strategy",
    "http_route",
    "audit_sink",
    "log_sink",
    "telemetry_sink",
    "metrics_sink",
    "store",
    "cache",
    "secret_provider",
    "config_provider",
    "policy_engine",
    "cluster",
    "transport",
    "catalog_provider",
    "credential_issuer",
    "approval_notifier",
    "content_store",
];

/// Default wall-clock budgets per FFI slot class.
///
/// A single cap for every native FFI call would let a hung
/// *control-plane* slot (e.g. config-set on a misbehaving plugin)
/// stall boot or admin endpoints. The budget is split by
/// **what the slot is doing**:
///
/// - **Lifecycle** (`make`, `manifest`, `shutdown`, `drop_instance`,
///   health probes): must complete near-instantly. A 1 s cap means a
///   hung lifecycle slot fails boot in seconds, not minutes.
/// - **Control** (config-set, snapshot, version-query, register-
///   profile, refresh, describe, list-peers, list-catalog, …):
///   admin operations issued by operators or the gateway's reload
///   path. 5 s tolerates a slow database round-trip but not a hang.
/// - **Data** (execute, evaluate, transform, dispatch, http_route,
///   sink-emit, lease-acquire, …): in-flight request path; matches
///   typical upstream RPC budgets. 30 s preserves the historical cap.
///
/// Operators may override per-plugin via the gateway config field
/// `plugins[].ffi_limits.{lifecycle,control,data}_timeout_ms`.
/// Whether a given vtable slot is Lifecycle / Control / Data is
/// tracked statically in the host adapter; see
/// [`mcpg_plugin_host::native_loader`](../mcpg_plugin_host/native_loader/index.html)
/// for the per-call-site classification.
pub const FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS: u64 = 1_000;
/// Default budget for control-plane FFI slots — see
/// [`FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS`] doc.
pub const FFI_CONTROL_TIMEOUT_DEFAULT_MS: u64 = 5_000;
/// Default budget for data-plane FFI slots — see
/// [`FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS`] doc.
pub const FFI_DATA_TIMEOUT_DEFAULT_MS: u64 = 30_000;

/// Coarse classification of every native FFI slot for per-tier
/// timeout budgeting. See
/// [`FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS`] for the per-tier rationale.
///
/// Hosts pick the appropriate variant per call-site; the variant
/// indexes into the `FFI_*_TIMEOUT_DEFAULT_MS` constants (or the
/// per-plugin override). Plugins do **not** observe this enum
/// directly — it is a host-side dispatch concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiSlotClass {
    /// Boot / shutdown / health-probe slots — must complete in
    /// [`FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS`].
    Lifecycle,
    /// Admin / config / introspection slots — must complete in
    /// [`FFI_CONTROL_TIMEOUT_DEFAULT_MS`].
    Control,
    /// In-flight request / sink-emit / hot-path slots — must
    /// complete in [`FFI_DATA_TIMEOUT_DEFAULT_MS`].
    Data,
}

impl FfiSlotClass {
    /// Default ms budget for this slot class. Per-plugin overrides
    /// are applied by the host before invoking the vtable; this
    /// returns the spec-level default unconditionally.
    pub const fn default_timeout_ms(self) -> u64 {
        match self {
            Self::Lifecycle => FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS,
            Self::Control => FFI_CONTROL_TIMEOUT_DEFAULT_MS,
            Self::Data => FFI_DATA_TIMEOUT_DEFAULT_MS,
        }
    }
}

/// Default cap on the byte-length of a single `RString` returned to
/// the host by a native cdylib plugin.
///
/// Native plugins return JSON-encoded payloads (responses, schemas,
/// resource pages, …) as `abi_stable::std_types::RString`. Without a
/// cap a plugin can allocate arbitrarily large strings in the host
/// process — either by accident (runaway resource page) or by
/// exfiltration / DoS. 256 KiB covers every legitimate slot today
/// (the largest first-party schema is ~28 KiB; the largest
/// list_resources page is bounded by the catalog page-size config)
/// while still serving as a hard ceiling against pathological output.
///
/// Operators may override per-plugin via the gateway config field
/// `plugins[].ffi_limits.max_payload_bytes`. When the cap is hit
/// the host emits `mcpg_plugin_payload_oversize_total{plugin_alias,
/// slot}` and returns a transport-error / empty-result fallback to
/// the caller (slot-specific, never a process abort).
pub const FFI_MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Entry-point symbol the host looks up via `libloading`. Declared here
/// so both sides of the boundary agree on the exported name.
pub const MCPG_PLUGIN_REGISTER_SYMBOL: &[u8] = b"mcpg_plugin_register";

/// Convenience signature for the exported entry point.
pub type PluginRegisterFn = extern "C" fn() -> PluginRegistration;

/// Second entry-point symbol: exports the cdylib's
/// `abi_stable` *type layout* for [`PluginRegistration`].
///
/// The numeric [`MCPG_PLUGIN_ABI_VERSION`] sentinel is checked only
/// *after* `mcpg_plugin_register` returns its `PluginRegistration` by
/// value — so a cdylib built against a different *layout* of that struct
/// (different field order / nested vtable shape / `abi_stable` type
/// identity) is materialised with the host's layout before any field is
/// validated. This is acute under the frozen-ABI policy, where breaking
/// layout changes are applied in place *without* bumping the version, so
/// two builds with different layouts both report version `1`.
///
/// The host looks up this symbol and runs `abi_stable`'s structural
/// `check_layout_compatibility` against its own
/// [`plugin_registration_layout`] *before* calling
/// `mcpg_plugin_register`, refusing on any mismatch — so a
/// layout-incompatible struct is never read.
pub const MCPG_PLUGIN_ABI_LAYOUT_SYMBOL: &[u8] = b"mcpg_plugin_abi_layout";

/// FFI-safe return type of [`MCPG_PLUGIN_ABI_LAYOUT_SYMBOL`]: a raw
/// pointer to the cdylib's `'static` [`TypeLayout`] for
/// [`PluginRegistration`]. A raw pointer (rather than
/// `&'static TypeLayout`) keeps the export `improper_ctypes`-clean; it
/// points into the cdylib's static data and stays valid for the loaded
/// library's lifetime.
pub type AbiLayoutPtr = *const ::abi_stable::type_layout::TypeLayout;

/// Signature of [`MCPG_PLUGIN_ABI_LAYOUT_SYMBOL`].
pub type PluginAbiLayoutFn = extern "C" fn() -> AbiLayoutPtr;

/// The `PluginRegistration` `abi_stable` type layout. Both the host and
/// every cdylib compute this from the *same* `mcpg_plugin_protocol`
/// build, so the host can `check_layout_compatibility` the value a
/// cdylib returns against its own. Used by the host loader and by the
/// `declare_plugin!`-generated `mcpg_plugin_abi_layout` export.
#[must_use]
pub fn plugin_registration_layout() -> AbiLayoutPtr {
    <PluginRegistration as StableAbi>::LAYOUT as AbiLayoutPtr
}

impl PluginRegistration {
    /// Return the first `EntityRegistration` whose [`EntityRegistration::kind`]
    /// matches `kind`, or `None`. Multi-entity-same-kind plugins
    /// have multiple variants of the same kind; use
    /// [`Self::find_entity`] with `inner_name` to disambiguate.
    pub fn first_entity_of_kind(&self, kind: &str) -> Option<&EntityRegistration> {
        self.entities.iter().find(|e| e.kind() == kind)
    }

    /// Return the entity matching both `kind` and `inner_name`,
    /// or `None`. Empty `inner_name` matches the first entity of
    /// that kind whose stored `inner_name` is also empty (the
    /// one-entity-per-kind common case).
    pub fn find_entity(&self, kind: &str, inner_name: &str) -> Option<&EntityRegistration> {
        self.entities
            .iter()
            .find(|e| e.kind() == kind && e.inner_name() == inner_name)
    }
}

/// Generates `first_<kind>()` accessors on [`PluginRegistration`].
/// Each returns `Option<&<Kind>VTable>` for the first matching
/// entity registration. Adapter constructors call these to bind to
/// the cdylib's vtable without reaching through the full
/// [`EntityRegistration`] enum each time.
macro_rules! first_vtable_accessors {
    ( $( ($variant:ident, $vt_ty:ident, $fn_name:ident) ),+ $(,)? ) => {
        impl PluginRegistration {
            $(
                #[doc = concat!(
                    "First [`",
                    stringify!($vt_ty),
                    "`] in [`Self::entities`], or `None`."
                )]
                pub fn $fn_name(&self) -> Option<&$vt_ty> {
                    self.entities.iter().find_map(|e| match e {
                        EntityRegistration::$variant { vtable, .. } => Some(vtable),
                        _ => None,
                    })
                }
            )+
        }
    };
}

first_vtable_accessors! {
    (ToolGate, ToolGateVTable, first_tool_gate),
    (Transform, TransformVTable, first_transform),
    (IdentityProvider, IdentityProviderVTable, first_identity_provider),
    (Backend, BackendVTable, first_backend),
    (WatchStrategy, WatchStrategyVTable, first_watch_strategy),
    (HttpRoute, HttpRouteVTable, first_http_route),
    (AuditSink, AuditSinkVTable, first_audit_sink),
    (LogSink, LogSinkVTable, first_log_sink),
    (TelemetrySink, TelemetrySinkVTable, first_telemetry_sink),
    (MetricsSink, MetricsSinkVTable, first_metrics_sink),
    (Store, StoreVTable, first_store),
    (Cache, CacheVTable, first_cache),
    (SecretProvider, SecretProviderVTable, first_secret_provider),
    (ConfigProvider, ConfigProviderVTable, first_config_provider),
    (PolicyEngine, PolicyEngineVTable, first_policy_engine),
    (Cluster, ClusterVTable, first_cluster),
    (Transport, TransportVTable, first_transport),
    (CatalogProvider, CatalogProviderVTable, first_catalog_provider),
    (CredentialIssuer, CredentialIssuerVTable, first_credential_issuer),
    (ApprovalNotifier, ApprovalNotifierVTable, first_approval_notifier),
    (ContentStore, ContentStoreVTable, first_content_store),
}

// ---------------------------------------------------------------------------
// Conversions: host-native <-> FFI-stable
// ---------------------------------------------------------------------------

impl From<&PluginIdentity> for RPluginIdentity {
    fn from(src: &PluginIdentity) -> Self {
        Self {
            kind: RString::from(src.kind.as_str()),
            trust_level: RString::from(src.trust_level.as_str()),
            subject_id: src.subject_id.clone().map(RString::from).into(),
            auth_provider: src.auth_provider.clone().map(RString::from).into(),
            issuer: src.issuer.clone().map(RString::from).into(),
            roles: src
                .roles
                .iter()
                .map(|s| RString::from(s.as_str()))
                .collect(),
            groups: src
                .groups
                .iter()
                .map(|s| RString::from(s.as_str()))
                .collect(),
            scopes: src
                .scopes
                .iter()
                .map(|s| RString::from(s.as_str()))
                .collect(),
            attributes: src
                .attributes
                .iter()
                .map(|(k, v)| RKeyValue {
                    key: RString::from(k.as_str()),
                    value: RString::from(v.as_str()),
                })
                .collect(),
        }
    }
}

impl From<RPluginIdentity> for PluginIdentity {
    fn from(src: RPluginIdentity) -> Self {
        Self {
            kind: src.kind.into_string(),
            trust_level: src.trust_level.into_string(),
            subject_id: src.subject_id.into_option().map(RString::into_string),
            auth_provider: src.auth_provider.into_option().map(RString::into_string),
            issuer: src.issuer.into_option().map(RString::into_string),
            roles: src.roles.into_iter().map(RString::into_string).collect(),
            groups: src.groups.into_iter().map(RString::into_string).collect(),
            scopes: src.scopes.into_iter().map(RString::into_string).collect(),
            attributes: src
                .attributes
                .into_iter()
                .map(|kv| (kv.key.into_string(), kv.value.into_string()))
                .collect(),
        }
    }
}

impl From<&PluginContext> for RPluginContext {
    fn from(src: &PluginContext) -> Self {
        Self {
            request_id: RString::from(src.request_id.as_str()),
            session_id: src.session_id.clone().map(RString::from).into(),
            tool_name: RString::from(src.tool_name.as_str()),
            surface: RString::from(src.surface.as_str()),
            identity: (&src.identity).into(),
            transport: RString::from(src.transport.as_str()),
        }
    }
}

impl From<RPluginContext> for PluginContext {
    fn from(src: RPluginContext) -> Self {
        Self {
            request_id: src.request_id.into_string(),
            session_id: src.session_id.into_option().map(RString::into_string),
            tool_name: src.tool_name.into_string(),
            surface: src.surface.into_string(),
            identity: src.identity.into(),
            transport: src.transport.into_string(),
        }
    }
}

impl From<RGateDecision> for GateDecision {
    fn from(src: RGateDecision) -> Self {
        fn parse(s: Option<String>) -> Option<serde_json::Value> {
            s.and_then(|raw| serde_json::from_str(&raw).ok())
        }
        match src {
            RGateDecision::Allow {
                modified_arguments_json,
                modified_result_json,
                metadata_json,
            } => GateDecision::Allow {
                modified_arguments: parse(
                    modified_arguments_json
                        .into_option()
                        .map(RString::into_string),
                ),
                modified_result: parse(
                    modified_result_json.into_option().map(RString::into_string),
                ),
                metadata: parse(metadata_json.into_option().map(RString::into_string)),
            },
            RGateDecision::Deny {
                http_status,
                code,
                message,
                error_data_json,
            } => GateDecision::Deny {
                http_status,
                code,
                message: message.into_string(),
                error_data: parse(error_data_json.into_option().map(RString::into_string)),
            },
            RGateDecision::Challenge {
                http_status,
                code,
                message,
                challenge_data_json,
            } => GateDecision::Challenge {
                http_status,
                code,
                message: message.into_string(),
                challenge_data: serde_json::from_str(challenge_data_json.as_str())
                    .unwrap_or(serde_json::Value::Null),
            },
            RGateDecision::PendingApproval {
                approval_id,
                deadline_at,
                summary,
                target_notifiers_json,
                metadata_json,
            } => GateDecision::PendingApproval {
                approval_id: approval_id.into_string(),
                deadline_at: deadline_at.into_string(),
                summary: summary.into_string(),
                target_notifiers: serde_json::from_str(target_notifiers_json.as_str())
                    .unwrap_or_default(),
                metadata: parse(Some(metadata_json.into_string())),
            },
        }
    }
}

impl From<GateDecision> for RGateDecision {
    fn from(src: GateDecision) -> Self {
        fn enc(v: Option<serde_json::Value>) -> ROption<RString> {
            v.and_then(|val| serde_json::to_string(&val).ok())
                .map(RString::from)
                .into()
        }
        match src {
            GateDecision::Allow {
                modified_arguments,
                modified_result,
                metadata,
            } => RGateDecision::Allow {
                modified_arguments_json: enc(modified_arguments),
                modified_result_json: enc(modified_result),
                metadata_json: enc(metadata),
            },
            GateDecision::Deny {
                http_status,
                code,
                message,
                error_data,
            } => RGateDecision::Deny {
                http_status,
                code,
                message: RString::from(message),
                error_data_json: enc(error_data),
            },
            GateDecision::Challenge {
                http_status,
                code,
                message,
                challenge_data,
            } => RGateDecision::Challenge {
                http_status,
                code,
                message: RString::from(message),
                challenge_data_json: RString::from(
                    serde_json::to_string(&challenge_data).unwrap_or_else(|_| "null".into()),
                ),
            },
            GateDecision::PendingApproval {
                approval_id,
                deadline_at,
                summary,
                target_notifiers,
                metadata,
            } => RGateDecision::PendingApproval {
                approval_id: RString::from(approval_id),
                deadline_at: RString::from(deadline_at),
                summary: RString::from(summary),
                target_notifiers_json: RString::from(
                    serde_json::to_string(&target_notifiers).unwrap_or_else(|_| "[]".into()),
                ),
                metadata_json: RString::from(
                    serde_json::to_string(&metadata).unwrap_or_else(|_| "null".into()),
                ),
            },
        }
    }
}

impl From<RTransformResult> for TransformResult {
    fn from(src: RTransformResult) -> Self {
        match src {
            RTransformResult::Unchanged => TransformResult::Unchanged,
            RTransformResult::Modified { value_json } => TransformResult::Modified {
                value: serde_json::from_str(value_json.as_str()).unwrap_or(serde_json::Value::Null),
            },
            RTransformResult::Error { message } => TransformResult::Error {
                message: message.into_string(),
            },
        }
    }
}

impl From<TransformResult> for RTransformResult {
    fn from(src: TransformResult) -> Self {
        match src {
            TransformResult::Unchanged => RTransformResult::Unchanged,
            TransformResult::Modified { value } => RTransformResult::Modified {
                value_json: RString::from(
                    serde_json::to_string(&value).unwrap_or_else(|_| "null".into()),
                ),
            },
            TransformResult::Error { message } => RTransformResult::Error {
                message: RString::from(message),
            },
        }
    }
}

impl From<RIdentityResolution> for IdentityResolution {
    fn from(src: RIdentityResolution) -> Self {
        match src {
            RIdentityResolution::Resolved { identity } => IdentityResolution::Resolved {
                identity: identity.into(),
            },
            RIdentityResolution::None => IdentityResolution::None,
            RIdentityResolution::Invalid {
                reason,
                response_headers,
            } => IdentityResolution::Invalid {
                reason: reason.into_string(),
                response_headers: response_headers
                    .into_iter()
                    .map(|t| (t.0.into_string(), t.1.into_string()))
                    .collect(),
            },
        }
    }
}

impl From<IdentityResolution> for RIdentityResolution {
    fn from(src: IdentityResolution) -> Self {
        match src {
            IdentityResolution::Resolved { identity } => RIdentityResolution::Resolved {
                identity: (&identity).into(),
            },
            IdentityResolution::None => RIdentityResolution::None,
            IdentityResolution::Invalid {
                reason,
                response_headers,
            } => RIdentityResolution::Invalid {
                reason: RString::from(reason),
                response_headers: response_headers
                    .into_iter()
                    .map(|(n, v)| Tuple2(RString::from(n), RString::from(v)))
                    .collect(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Panic-across-FFI guards
// ---------------------------------------------------------------------------
//
// Rust's `extern "C"` contract says a panic must not unwind across the
// foreign function boundary. On modern Rust (≥ 1.81) a panic that
// reaches the boundary aborts the process; on older versions it is
// undefined behaviour. Either way, a misbehaving plugin taking the
// whole gateway with it is unacceptable.
//
// Plugin authors implementing a vtable function MUST wrap their user
// code in `catch_unwind` before the panic can reach the FFI boundary.
// The helpers below give each per-request vtable slot a ready-made
// wrapper that converts a caught panic into a well-formed Deny /
// TransformResult::Error / IdentityResolution::Invalid — the gateway
// then records the failure and moves on.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Sentinel `code` value returned inside a panic-guarded `Deny`. A
/// `GateDecision::Deny { code: PANIC_DENY_CODE, .. }` is the host's
/// signal that the plugin panicked inside its FFI boundary — the
/// health prober and admin surfaces use this to distinguish a real
/// deny (plugin doing its job) from a crashing plugin.
///
/// Chosen to fall inside the MCP-reserved JSON-RPC range (-32099 is
/// `-32099` itself, the lowest end) so clients don't mistake a panic
/// for an application-level deny.
pub const PANIC_DENY_CODE: i32 = -32099;

const PANIC_DENY_STATUS: u16 = 500;
const PANIC_DENY_MSG: &str = "plugin panicked during evaluate_pre/post_dispatch";

/// Sentinel `message` substring inside a panic-guarded
/// `TransformResult::Error`.
pub const PANIC_TRANSFORM_MSG: &str = "plugin panicked during transform";

/// Sentinel `reason` substring inside a panic-guarded
/// `IdentityResolution::Invalid`.
pub const PANIC_IDENTITY_MSG: &str = "plugin panicked during resolve_identity";

/// Run `f` inside `catch_unwind`; on panic return an internal-error
/// `Deny`. Intended for the body of `evaluate_pre_dispatch` and
/// `evaluate_post_dispatch` vtable slots.
///
/// ```ignore
/// extern "C" fn my_evaluate_pre(...) -> RGateDecision {
///     mcpg_plugin_protocol::abi::catch_panic_to_deny(|| {
///         // author code here — free to panic
///         RGateDecision::Allow { .. }
///     })
/// }
/// ```
pub fn catch_panic_to_deny<F>(f: F) -> RGateDecision
where
    F: FnOnce() -> RGateDecision,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => RGateDecision::Deny {
            http_status: PANIC_DENY_STATUS,
            code: PANIC_DENY_CODE,
            message: RString::from(PANIC_DENY_MSG),
            error_data_json: ROption::RNone,
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return
/// `RTransformResult::Error`.
pub fn catch_panic_to_transform_error<F>(f: F) -> RTransformResult
where
    F: FnOnce() -> RTransformResult,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => RTransformResult::Error {
            message: RString::from(PANIC_TRANSFORM_MSG),
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return
/// `RIdentityResolution::Invalid`.
pub fn catch_panic_to_identity_invalid<F>(f: F) -> RIdentityResolution
where
    F: FnOnce() -> RIdentityResolution,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => RIdentityResolution::Invalid {
            reason: RString::from(PANIC_IDENTITY_MSG),
            response_headers: RVec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Panic guards for lifecycle vtable slots (make / drop / manifest_json /
// shutdown / mcpg_plugin_register)
//
// Same pattern as the per-request guards above. A panic across an
// `extern "C"` boundary is undefined behaviour; every FFI slot the host
// might invoke MUST wrap its body in `catch_unwind`. The three
// per-request slots (evaluate_*, transform_*, resolve_identity) have
// value-carrying return types and get per-variant "failure" decisions
// above. The lifecycle slots return handles, strings, or nothing, so
// they need their own per-return-shape guards.
// ---------------------------------------------------------------------------

/// Run `f` inside `catch_unwind`; on panic return a null
/// `RPluginHandle`. Intended for the body of the `make` vtable slot
/// (constructor). The host's native loader MUST treat a null handle as
/// "plugin failed to construct" and refuse to register the vtable.
pub fn catch_panic_to_null_handle<F>(f: F) -> RPluginHandle
where
    F: FnOnce() -> RPluginHandle,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(h) => h,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run `f` inside `catch_unwind`; on panic return an empty `RString`.
/// Intended for the body of `manifest_json`. An empty string fails
/// manifest JSON-parse in the host, which is the desired signal ("this
/// plugin cannot be registered").
pub fn catch_panic_to_empty_rstring<F>(f: F) -> RString
where
    F: FnOnce() -> RString,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => RString::new(),
    }
}

/// Run `f` inside `catch_unwind`; on panic swallow it silently.
/// Intended for the body of `drop_instance` and `shutdown` vtable
/// slots — both have a `()` return. A panic in destructor code should
/// not unwind into the host; there is no downstream "failure" the
/// gateway can act on beyond logging-and-continue.
///
/// The caller is expected to already be on a best-effort path (e.g.,
/// shutting the gateway down); we do not re-raise the panic.
pub fn catch_panic_silent<F>(f: F)
where
    F: FnOnce(),
{
    let _ = catch_unwind(AssertUnwindSafe(f));
}

/// Sentinel ABI version returned from `mcpg_plugin_register` when the
/// registration body itself panicked. The native loader checks
/// `abi_version` first; this value is reserved to mean "plugin
/// panicked during registration, refuse to load."
pub const MCPG_PLUGIN_ABI_PANIC_SENTINEL: u32 = u32::MAX;

/// Run `f` inside `catch_unwind`; on panic return a `PluginRegistration`
/// with `abi_version = MCPG_PLUGIN_ABI_PANIC_SENTINEL` and empty / RNone
/// fields. The native loader MUST refuse to register a plugin whose
/// `abi_version` equals the sentinel.
///
/// Intended for the body of the `mcpg_plugin_register` entry point.
pub fn catch_panic_to_panicked_registration<F>(f: F) -> PluginRegistration
where
    F: FnOnce() -> PluginRegistration,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => PluginRegistration {
            abi_version: MCPG_PLUGIN_ABI_PANIC_SENTINEL,
            plugin_id: RString::new(),
            plugin_version: RString::new(),
            module_path_prefix: RString::new(),
            entities: RVec::new(),
            capabilities: RVec::new(),
            backend_profile_json: ROption::RNone,
            descriptor_yaml: RString::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Panic guards for sentinel-struct returns
//
// A sentinel-struct return is a `#[repr(C)]` shape where one field
// distinguishes "success" from "failure" (e.g. `handle != 0`) and a
// sibling field carries the JSON-encoded error on the failure branch.
// These cover the five FFI return shapes that don't fit the simpler
// `null-handle | empty-rstring` panic pattern: `LeaseHandle`,
// `StreamHandle`, `HttpHandleResult`,
// `DispatcherCallbackResult`. (`StreamHandle` covers both
// stream-subscription and transport returns.)
//
// On panic each helper returns a struct that carries the established
// "failure" sentinel value AND an `error_json` (or `reply_json`) field
// containing the panic message. Downstream host adapters already
// surface these failures as `Internal { reason }` errors — the panic
// guard just keeps the FFI boundary safe. Callers who want richer
// reporting can serialise their own error payload before returning
// from the inner `f`.
// ---------------------------------------------------------------------------

/// Sentinel `error_json` substring on a panic-guarded
/// [`LeaseHandle`].
pub const PANIC_LEASE_MSG: &str = "plugin panicked during lease acquire";

/// Sentinel `error_json` substring on a panic-guarded
/// [`StreamHandle`] returned from a stream-subscription slot.
pub const PANIC_STREAM_MSG: &str = "plugin panicked during stream subscription";

/// Sentinel `error_json` substring on a panic-guarded
/// [`StreamHandle`] returned from a transport `start` slot.
pub const PANIC_TRANSPORT_MSG: &str = "plugin panicked during transport start";

/// Sentinel `head_json` substring on a panic-guarded
/// `HttpHandleResult`. The host's HTTP-route adapter detects this and
/// returns a 500 response to the caller.
pub const PANIC_HTTP_MSG: &str = "plugin panicked during http handle";

/// Sentinel `reply_json` substring on a panic-guarded
/// `DispatcherCallbackResult`. The host parses `reply_json` as a
/// `Result<DispatchReplyWire, DispatcherError>` JSON envelope; this
/// constant is encoded into the err arm so the gateway surfaces a
/// clean `DispatcherError::Internal { reason }`.
pub const PANIC_DISPATCHER_MSG: &str = "plugin panicked during dispatcher callback";

/// JSON envelope returned from a panicked dispatcher callback.
/// Matches the shape `{"err": {"Internal": {"reason": ...}}}` the host
/// adapter expects for failed dispatches.
fn panicked_dispatcher_reply() -> RString {
    RString::from(r#"{"err":{"Internal":{"reason":"plugin panicked during dispatcher callback"}}}"#)
}

/// Run `f` inside `catch_unwind`; on panic return a
/// [`LeaseHandle`] with `handle == 0` and `error_json` set to the
/// panic sentinel. Intended for the body of
/// `ClusterVTable::acquire_leadership` /
/// `acquire_lock` / `try_acquire_*` slots.
pub fn catch_panic_to_lease_failure<F>(f: F) -> LeaseHandle
where
    F: FnOnce() -> LeaseHandle,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => LeaseHandle {
            handle: 0,
            error_json: RString::from(PANIC_LEASE_MSG),
            fencing_token: 0,
            expires_at: RString::new(),
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return a
/// [`StreamHandle`] with `handle == 0` and `error_json` set to the
/// panic sentinel. Intended for the body of any vtable slot that
/// returns `StreamHandle` — `subscribe`, `watch_peers`,
/// `watch_*` on cluster coordinators, etc.
pub fn catch_panic_to_stream_failure<F>(f: F) -> StreamHandle
where
    F: FnOnce() -> StreamHandle,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => StreamHandle {
            handle: 0,
            error_json: RString::from(PANIC_STREAM_MSG),
            metadata_json: RString::new(),
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return a
/// [`StreamHandle`] with `handle == 0`, empty `metadata_json`,
/// and `error_json` set to the panic sentinel. Intended for the body
/// of `TransportVTable::start` — transports return the
/// same `StreamHandle` shape as subscriptions, with the listen
/// address (when present) encoded into `metadata_json`.
pub fn catch_panic_to_transport_failure<F>(f: F) -> StreamHandle
where
    F: FnOnce() -> StreamHandle,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => StreamHandle {
            handle: 0,
            error_json: RString::from(PANIC_TRANSPORT_MSG),
            metadata_json: RString::new(),
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return an
/// `HttpHandleResult` with `handle == 0` and `head_json` set to the
/// panic sentinel. Intended for the body of
/// `HttpRouteVTable::handle_streaming`. The host's HTTP-route adapter
/// detects the empty-handle / sentinel `head_json` combination and
/// surfaces a 500 response.
pub fn catch_panic_to_http_failure<F>(f: F) -> HttpHandleResult
where
    F: FnOnce() -> HttpHandleResult,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => HttpHandleResult {
            handle: 0,
            head_json: RString::from(PANIC_HTTP_MSG),
        },
    }
}

/// Run `f` inside `catch_unwind`; on panic return a
/// `DispatcherCallbackResult` whose `reply_json` is a serialised
/// `Result::Err(DispatcherError::Internal { reason: ... })` envelope.
/// Intended for the dispatcher-callback path on
/// `TransportVTable::start`.
pub fn catch_panic_to_dispatcher_failure<F>(f: F) -> DispatcherCallbackResult
where
    F: FnOnce() -> DispatcherCallbackResult,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => DispatcherCallbackResult {
            reply_json: panicked_dispatcher_reply(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("user-1".into()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://idp.example.com".into()),
            roles: vec!["admin".into()],
            groups: vec!["eng".into()],
            scopes: vec!["tools:read".into()],
            attributes: [("tenant".to_owned(), "acme".to_owned())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn plugin_context_roundtrip_preserves_all_fields() {
        let ctx = PluginContext {
            request_id: "r-1".into(),
            session_id: Some("s-1".into()),
            tool_name: "orders.list".into(),
            surface: "tool".into(),
            identity: sample_identity(),
            transport: "http".into(),
        };
        let r: RPluginContext = (&ctx).into();
        let back: PluginContext = r.into();
        assert_eq!(back.request_id, ctx.request_id);
        assert_eq!(back.session_id, ctx.session_id);
        assert_eq!(back.tool_name, ctx.tool_name);
        assert_eq!(back.surface, ctx.surface);
        assert_eq!(back.transport, ctx.transport);
        assert_eq!(back.identity.subject_id, ctx.identity.subject_id);
        assert_eq!(back.identity.roles, ctx.identity.roles);
        assert_eq!(back.identity.attributes, ctx.identity.attributes);
    }

    #[test]
    fn gate_decision_allow_roundtrip_carries_modifications() {
        let d = GateDecision::Allow {
            modified_arguments: Some(serde_json::json!({"a": 1})),
            modified_result: None,
            metadata: Some(serde_json::json!({"plugin": "x"})),
        };
        let r: RGateDecision = d.clone().into();
        let back: GateDecision = r.into();
        match back {
            GateDecision::Allow {
                modified_arguments,
                modified_result,
                metadata,
            } => {
                assert_eq!(modified_arguments, Some(serde_json::json!({"a": 1})));
                assert_eq!(modified_result, None);
                assert_eq!(metadata, Some(serde_json::json!({"plugin": "x"})));
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn gate_decision_deny_roundtrip() {
        let d = GateDecision::Deny {
            http_status: 403,
            code: -32044,
            message: "nope".into(),
            error_data: Some(serde_json::json!({"why": "scope"})),
        };
        let r: RGateDecision = d.into();
        let back: GateDecision = r.into();
        match back {
            GateDecision::Deny {
                http_status,
                code,
                message,
                error_data,
            } => {
                assert_eq!(http_status, 403);
                assert_eq!(code, -32044);
                assert_eq!(message, "nope");
                assert_eq!(error_data, Some(serde_json::json!({"why": "scope"})));
            }
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn gate_decision_pending_approval_roundtrip() {
        let d = GateDecision::PendingApproval {
            approval_id: "appr_01HFXYZ".into(),
            deadline_at: "2026-04-26T10:00:00Z".into(),
            summary: "rm /etc/passwd".into(),
            target_notifiers: vec!["security.tool-gate-slack-approval".into()],
            metadata: Some(serde_json::json!({"risk": "high"})),
        };
        let r: RGateDecision = d.into();
        let back: GateDecision = r.into();
        match back {
            GateDecision::PendingApproval {
                approval_id,
                deadline_at,
                summary,
                target_notifiers,
                metadata,
            } => {
                assert_eq!(approval_id, "appr_01HFXYZ");
                assert_eq!(deadline_at, "2026-04-26T10:00:00Z");
                assert_eq!(summary, "rm /etc/passwd");
                assert_eq!(target_notifiers, vec!["security.tool-gate-slack-approval"]);
                assert_eq!(metadata, Some(serde_json::json!({"risk": "high"})));
            }
            _ => panic!("expected PendingApproval"),
        }
    }

    #[test]
    fn identity_resolution_roundtrip() {
        let r = IdentityResolution::Resolved {
            identity: sample_identity(),
        };
        let ffi: RIdentityResolution = r.into();
        let back: IdentityResolution = ffi.into();
        match back {
            IdentityResolution::Resolved { identity } => {
                assert_eq!(identity.subject_id.as_deref(), Some("user-1"))
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn transform_result_roundtrip() {
        let t = TransformResult::Modified {
            value: serde_json::json!({"redacted": true}),
        };
        let r: RTransformResult = t.into();
        let back: TransformResult = r.into();
        match back {
            TransformResult::Modified { value } => {
                assert_eq!(value, serde_json::json!({"redacted": true}))
            }
            _ => panic!("expected Modified"),
        }
    }

    #[test]
    fn abi_version_is_current() {
        // Pins the constant so a layout change cannot ship without a
        // deliberate bump decision. v2 is the first post-release bump:
        // `RIdentityResolution::Invalid` gained `response_headers` (see the
        // version history above and docs/plugin-protocol/abi-changelog.md);
        // the freeze that held the counter at 1 ended with the first public
        // release.
        assert_eq!(MCPG_PLUGIN_ABI_VERSION, 2);
    }

    /// Catch ALL_KINDS drift the moment a new `EntityRegistration`
    /// variant lands without a matching const entry. Constructing one
    /// representative variant per kind and asserting `kind()` is in
    /// `ALL_KINDS` would require building a dummy vtable for each kind
    /// (a lot of boilerplate); instead this test just checks the
    /// length matches the known v27 entity count. Update both numbers
    /// when adding a kind.
    #[test]
    fn all_kinds_matches_entity_count() {
        // Sanity: v27 has 21 entity kinds. Update this number AND
        // ALL_KINDS in lockstep when a new kind ships in a future ABI.
        assert_eq!(
            ALL_KINDS.len(),
            21,
            "ALL_KINDS const out of sync with EntityRegistration variant count"
        );
        // Verify no accidental duplicate / typo by collecting through
        // a HashSet.
        let unique: std::collections::HashSet<&&str> = ALL_KINDS.iter().collect();
        assert_eq!(
            unique.len(),
            ALL_KINDS.len(),
            "ALL_KINDS contains duplicate kind strings"
        );
    }

    /// Pin the FFI payload cap so that downstream
    /// adapters (the host's `enforce_ffi_payload_cap` helper, the
    /// gateway's per-plugin override schema, the K8s admission
    /// validator) all see the same baseline. Bumping the constant
    /// requires updating this assertion + the operator-facing docs.
    #[test]
    fn ffi_max_payload_bytes_is_256kib() {
        assert_eq!(FFI_MAX_PAYLOAD_BYTES, 256 * 1024);
    }

    /// Pin the per-tier FFI timeout defaults so
    /// that Lifecycle stays in the sub-second band, Control fails
    /// fast on admin paths, and Data keeps the 30-second budget for
    /// hot-path RPC-equivalent calls.
    #[test]
    fn ffi_timeout_defaults_are_tiered() {
        assert_eq!(FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS, 1_000);
        assert_eq!(FFI_CONTROL_TIMEOUT_DEFAULT_MS, 5_000);
        assert_eq!(FFI_DATA_TIMEOUT_DEFAULT_MS, 30_000);
        // Strict ordering: Lifecycle < Control < Data — this is how
        // adapters reason about which class to assign at each
        // call-site. Same-tier ties are not allowed. const block so
        // the comparison is checked at compile time.
        const _: () = {
            assert!(FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS < FFI_CONTROL_TIMEOUT_DEFAULT_MS);
            assert!(FFI_CONTROL_TIMEOUT_DEFAULT_MS < FFI_DATA_TIMEOUT_DEFAULT_MS);
        };
        // The enum lookup must agree with the constants.
        assert_eq!(
            FfiSlotClass::Lifecycle.default_timeout_ms(),
            FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS
        );
        assert_eq!(
            FfiSlotClass::Control.default_timeout_ms(),
            FFI_CONTROL_TIMEOUT_DEFAULT_MS
        );
        assert_eq!(
            FfiSlotClass::Data.default_timeout_ms(),
            FFI_DATA_TIMEOUT_DEFAULT_MS
        );
    }

    #[test]
    fn catch_panic_to_deny_returns_deny_on_panic() {
        let r = catch_panic_to_deny(|| panic!("boom"));
        match r {
            RGateDecision::Deny {
                http_status,
                code,
                message,
                ..
            } => {
                assert_eq!(http_status, PANIC_DENY_STATUS);
                assert_eq!(code, PANIC_DENY_CODE);
                assert!(message.as_str().contains("panicked"), "got: {}", message);
            }
            _ => panic!("expected Deny on caught panic"),
        }
    }

    #[test]
    fn catch_panic_to_deny_passes_through_when_no_panic() {
        let r = catch_panic_to_deny(|| RGateDecision::Allow {
            modified_arguments_json: ROption::RNone,
            modified_result_json: ROption::RNone,
            metadata_json: ROption::RNone,
        });
        assert!(matches!(r, RGateDecision::Allow { .. }));
    }

    #[test]
    fn catch_panic_to_transform_error_returns_error_on_panic() {
        let r = catch_panic_to_transform_error(|| panic!("boom"));
        match r {
            RTransformResult::Error { message } => {
                assert!(message.as_str().contains("panicked"))
            }
            _ => panic!("expected Error on caught panic"),
        }
    }

    #[test]
    fn catch_panic_to_identity_invalid_returns_invalid_on_panic() {
        let r = catch_panic_to_identity_invalid(|| panic!("boom"));
        match r {
            RIdentityResolution::Invalid { reason, .. } => {
                assert!(reason.as_str().contains("panicked"))
            }
            _ => panic!("expected Invalid on caught panic"),
        }
    }

    #[test]
    fn catch_panic_to_null_handle_returns_null_on_panic() {
        let h = catch_panic_to_null_handle(|| panic!("boom"));
        assert!(h.is_null());
    }

    #[test]
    fn catch_panic_to_null_handle_passes_through_when_no_panic() {
        let expected = Box::into_raw(Box::new(42_u32)) as RPluginHandle;
        let h = catch_panic_to_null_handle(|| expected);
        assert_eq!(h, expected);
        // Drop the box we leaked to avoid a test-run leak.
        unsafe { drop(Box::from_raw(h as *mut u32)) };
    }

    #[test]
    fn catch_panic_to_empty_rstring_returns_empty_on_panic() {
        let s = catch_panic_to_empty_rstring(|| panic!("boom"));
        assert!(s.as_str().is_empty());
    }

    #[test]
    fn catch_panic_to_empty_rstring_passes_through_when_no_panic() {
        let s = catch_panic_to_empty_rstring(|| RString::from("hello"));
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn catch_panic_silent_swallows_panic() {
        // Asserts only that no panic escapes; the return is `()`.
        catch_panic_silent(|| panic!("boom"));
    }

    #[test]
    fn catch_panic_silent_runs_body_on_no_panic() {
        let mut called = false;
        catch_panic_silent(|| {
            called = true;
        });
        assert!(called);
    }

    #[test]
    fn catch_panic_to_panicked_registration_marks_sentinel_on_panic() {
        let r = catch_panic_to_panicked_registration(|| panic!("boom"));
        assert_eq!(r.abi_version, MCPG_PLUGIN_ABI_PANIC_SENTINEL);
        assert!(r.plugin_id.as_str().is_empty());
        assert!(r.plugin_version.as_str().is_empty());
        assert!(r.module_path_prefix.as_str().is_empty());
        assert!(r.entities.is_empty());
    }

    #[test]
    fn catch_panic_to_panicked_registration_passes_through_when_no_panic() {
        let r = catch_panic_to_panicked_registration(|| PluginRegistration {
            abi_version: MCPG_PLUGIN_ABI_VERSION,
            plugin_id: RString::from("dev.mcpg.example"),
            plugin_version: RString::from("1.0.0"),
            module_path_prefix: RString::from("crate::example"),
            entities: RVec::new(),
            capabilities: RVec::new(),
            backend_profile_json: ROption::RNone,
            descriptor_yaml: Default::default(),
        });
        assert_eq!(r.abi_version, MCPG_PLUGIN_ABI_VERSION);
        assert_eq!(r.plugin_id.as_str(), "dev.mcpg.example");
        assert_eq!(r.module_path_prefix.as_str(), "crate::example");
    }

    // Note: `EntityRegistration::kind()` / `inner_name()` are
    // exercised by the conformance tests in plugin-host that load
    // real cdylibs (e.g. `multi_instance_two_aliases_one_library`).
    // No unit-level spot-check here because the FFI vtable structs
    // demand real function pointers and a synthetic constructor
    // would just be ceremony.

    #[test]
    fn catch_panic_to_lease_failure_returns_zero_handle_on_panic() {
        let r = catch_panic_to_lease_failure(|| panic!("boom"));
        assert_eq!(r.handle, 0);
        assert_eq!(r.fencing_token, 0);
        assert!(r.expires_at.as_str().is_empty());
        assert!(
            r.error_json.as_str().contains(PANIC_LEASE_MSG),
            "got: {}",
            r.error_json
        );
    }

    #[test]
    fn catch_panic_to_lease_failure_passes_through_when_no_panic() {
        let r = catch_panic_to_lease_failure(|| LeaseHandle {
            handle: 42,
            error_json: RString::new(),
            fencing_token: 7,
            expires_at: RString::from("2030-01-01T00:00:00Z"),
        });
        assert_eq!(r.handle, 42);
        assert_eq!(r.fencing_token, 7);
    }

    #[test]
    fn catch_panic_to_stream_failure_returns_zero_handle_on_panic() {
        let r = catch_panic_to_stream_failure(|| panic!("boom"));
        assert_eq!(r.handle, 0);
        assert!(
            r.error_json.as_str().contains(PANIC_STREAM_MSG),
            "got: {}",
            r.error_json
        );
    }

    #[test]
    fn catch_panic_to_stream_failure_passes_through_when_no_panic() {
        let r = catch_panic_to_stream_failure(|| StreamHandle {
            handle: 99,
            error_json: RString::new(),
            metadata_json: RString::new(),
        });
        assert_eq!(r.handle, 99);
    }

    #[test]
    fn catch_panic_to_transport_failure_returns_zero_handle_on_panic() {
        let r = catch_panic_to_transport_failure(|| panic!("boom"));
        assert_eq!(r.handle, 0);
        assert!(r.metadata_json.as_str().is_empty());
        assert!(
            r.error_json.as_str().contains(PANIC_TRANSPORT_MSG),
            "got: {}",
            r.error_json
        );
    }

    #[test]
    fn catch_panic_to_http_failure_returns_zero_handle_with_panic_sentinel() {
        let r = catch_panic_to_http_failure(|| panic!("boom"));
        assert_eq!(r.handle, 0);
        assert!(
            r.head_json.as_str().contains(PANIC_HTTP_MSG),
            "got: {}",
            r.head_json
        );
    }

    #[test]
    fn catch_panic_to_dispatcher_failure_returns_internal_err_envelope() {
        let r = catch_panic_to_dispatcher_failure(|| panic!("boom"));
        assert!(
            r.reply_json.as_str().contains(PANIC_DISPATCHER_MSG),
            "got: {}",
            r.reply_json
        );
        // Confirm the wire shape parses as a Result::Err envelope
        // matching what the host's dispatcher adapter expects.
        let parsed: serde_json::Value = serde_json::from_str(r.reply_json.as_str())
            .expect("dispatcher panic reply must be valid JSON");
        assert!(
            parsed.pointer("/err/Internal/reason").is_some(),
            "expected /err/Internal/reason in {parsed}"
        );
    }

    // ---------------------------------------------------------------------------
    // BytesSinkRef
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // TypedCapabilityDecl round-trips
    // ---------------------------------------------------------------------------

    #[test]
    fn typed_capability_decl_roundtrip_no_args() {
        use crate::capability::Capability;
        for cap in [
            Capability::NetworkOutbound,
            Capability::AuditWrite,
            Capability::MetricEmit,
            Capability::HttpRouteServe,
            Capability::TransportListen,
            Capability::ClusterPeerRead,
            Capability::ClusterLeadershipAcquire,
            Capability::ClusterLockAcquire,
            Capability::UnboundedSubscriptions,
        ] {
            let decl = TypedCapabilityDecl::from_capability(&cap);
            assert_eq!(
                decl.args_json.as_str(),
                "",
                "no-args variant {} must serialise to empty args_json",
                cap.kind()
            );
            let back = decl.to_capability().unwrap();
            assert_eq!(cap, back);
        }
    }

    #[test]
    fn typed_capability_decl_roundtrip_args() {
        use crate::capability::Capability;
        let cases = [
            Capability::FilesystemRead {
                paths: vec!["/etc/myapp".into(), "/var/run/x".into()],
            },
            Capability::FilesystemWrite {
                paths: vec!["/tmp/scratch".into()],
            },
            Capability::SecretsRead {
                schemes: vec!["vault".into(), "env".into()],
            },
            Capability::ConfigRead {
                schemes: vec!["file".into()],
            },
            Capability::CredentialIssue {
                kinds: vec!["oauth_client_credentials".into()],
            },
        ];
        for cap in cases {
            let decl = TypedCapabilityDecl::from_capability(&cap);
            assert!(
                !decl.args_json.as_str().is_empty(),
                "args-variant {} must serialise non-empty args_json",
                cap.kind()
            );
            let back = decl.to_capability().unwrap();
            assert_eq!(cap, back);
        }
    }

    #[test]
    fn typed_capability_decl_rejects_unknown_kind() {
        let decl = TypedCapabilityDecl {
            kind: RString::from("totally_made_up"),
            args_json: RString::new(),
        };
        match decl.to_capability() {
            Err(crate::capability::CapabilityParseError::UnknownKind(k)) => {
                assert_eq!(k, "totally_made_up");
            }
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    #[test]
    fn typed_capability_decl_rejects_malformed_args_json() {
        let decl = TypedCapabilityDecl {
            kind: RString::from("filesystem_read"),
            args_json: RString::from("not json at all"),
        };
        match decl.to_capability() {
            Err(crate::capability::CapabilityParseError::InvalidArgs { kind, .. }) => {
                assert_eq!(kind, "filesystem_read");
            }
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[test]
    fn typed_capability_decl_args_shape_pinned() {
        // Pin the on-the-wire JSON shape for variant-args capabilities
        // so a future refactor can't silently change the FFI encoding.
        use crate::capability::Capability;
        let cap = Capability::FilesystemRead {
            paths: vec!["/a".into()],
        };
        let decl = TypedCapabilityDecl::from_capability(&cap);
        assert_eq!(decl.kind.as_str(), "filesystem_read");
        assert_eq!(decl.args_json.as_str(), r#"{"paths":["/a"]}"#);

        let cap = Capability::SecretsRead {
            schemes: vec!["vault".into()],
        };
        let decl = TypedCapabilityDecl::from_capability(&cap);
        assert_eq!(decl.kind.as_str(), "secrets_read");
        assert_eq!(decl.args_json.as_str(), r#"{"schemes":["vault"]}"#);
    }

    #[test]
    fn bytes_sink_ref_round_trips_chunk_and_terminator() {
        use std::sync::Mutex;
        // Static accumulator the C callback writes into. `Mutex<Vec<…>>`
        // because the callback can't capture environment.
        static EVENTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

        extern "C" fn capture(_ctx: usize, chunk: abi_stable::std_types::RVec<u8>) {
            EVENTS.lock().unwrap().push(chunk.into());
        }

        EVENTS.lock().unwrap().clear();
        let sink = BytesSinkRef {
            ctx: 0,
            callback: capture,
        };
        (sink.callback)(sink.ctx, abi_stable::std_types::RVec::from(vec![1, 2, 3]));
        // Empty chunk == end-of-stream sentinel.
        (sink.callback)(sink.ctx, abi_stable::std_types::RVec::<u8>::new());

        let got = EVENTS.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], vec![1, 2, 3]);
        assert!(got[1].is_empty(), "second chunk should be EOS sentinel");
    }
}
