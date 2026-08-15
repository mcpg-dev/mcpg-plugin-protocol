//! Plugin manifest — identity, versioning, and capability declarations.

use serde::{Deserialize, Serialize};

/// Every plugin must supply a manifest that declares its identity,
/// the plugin class it implements, and what host capabilities it requires.
///
/// Field ordering philosophy: **stable identity first, contract/versioning
/// next, capabilities last**. New additive fields go immediately before
/// `required_capabilities` with `#[serde(default)]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    /// Reverse-domain plugin identifier, e.g. `"dev.mcpg.audit"`.
    pub id: String,

    /// Plugin package version (semver), e.g. `"0.1.0"`.
    pub version: String,

    /// Human-readable display name.
    pub name: String,

    /// Which plugin class this plugin implements.
    pub plugin_class: PluginClass,

    /// Plugin protocol version the plugin targets, as a semver
    /// string (e.g. `"1.0"`, `"1.1"`). The authoritative
    /// compatibility identifier — the host loads a plugin only if
    /// its declared protocol version is within the host's
    /// supported range.
    pub protocol_version: String,

    /// SPDX identifier of the plugin's source license (e.g.
    /// `Apache-2.0`), mirroring the descriptor's `license` key.
    /// Informational metadata for catalogs / marketplaces; the host
    /// never acts on it. `None` when the plugin doesn't declare one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    /// Host capabilities the plugin requires, as typed
    /// [`Capability`](crate::capability::Capability) values — the same
    /// type the descriptor (`plugin.yaml`) and the operator's
    /// `granted_capabilities` use, and the in-Rust form the FFI
    /// [`TypedCapabilityDecl`](crate::abi::TypedCapabilityDecl) projects
    /// to/from at the cdylib boundary. There is no longer a stringly
    /// parallel representation.
    ///
    /// **Host-derived, not plugin-authored.** A plugin's `manifest()`
    /// leaves this empty (`Vec::new()`); the single authoring point is
    /// the typed declaration in `declare_plugin! { capabilities: ... }`
    /// (cdylib → `PluginRegistration.capabilities`) or the descriptor
    /// (static-firstparty). The host fills this field from that
    /// authoritative source at registration, so the manifest's caps can
    /// never drift from what's enforced. Consumers (admin inventory,
    /// allowlist docs) read the typed values directly.
    #[serde(default)]
    pub required_capabilities: Vec<crate::capability::Capability>,

    /// Free-form classification tags. Plugin authors declare
    /// labels like `enterprise`, `paid`, `experimental`,
    /// `security-critical`, `vendor:hashicorp`. Operators wire
    /// these into a `policy_engine` chain at the
    /// `plugin.lifecycle.register` decision point so the engine
    /// can deny / allow plugin loading per their org's rules
    /// (e.g. "block all `experimental` in prod", "only load
    /// plugins where `vendor:internal`").
    ///
    /// Tags are normative-free strings — no enum constraint, no
    /// well-known set today; operators define their own scheme.
    /// Empty by default. See spec §9.14.1 for the
    /// `plugin.lifecycle.register` decision-point input shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Cluster slot **roles** the plugin advertises. Used by
    /// `cluster_backend` plugins to declare which gateway slots they
    /// can back — one or more of `cache` / `kv` / `bus`. The gateway's
    /// point-of-use slot resolver (`resolve_kind`) consults this set to
    /// decide whether `kind: cluster` is valid for a given slot. The
    /// gateway cross-checks this list against the descriptor's
    /// `provides` and the runtime `ClusterBackend::cluster_provides()`
    /// at boot and fails-closed on drift.
    ///
    /// This is the slot-*role* vocabulary, distinct from the trait's
    /// primitive *accessor* methods (`key_value_store` / `pub_sub` /
    /// `lease` / `watch`): a coordinator declares the `cache` role only
    /// if it has eviction semantics, the `bus` role only if it ships
    /// `pub_sub`, etc.
    ///
    /// Well-known values: `cache`, `kv`, `bus`. Empty / absent for
    /// non-cluster plugin classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<String>,

    /// URI schemes this plugin claims for auto-routing — the STATIC
    /// descriptor/manifest mirror of the provider's runtime
    /// `supported_schemes()`. `secret_provider` / `config_provider`
    /// classes route purely by URI scheme prefix, with no operator-side
    /// `name → plugin_id` map.
    ///
    /// The AUTHORITATIVE routing surface is the trait method
    /// `supported_schemes()` (FFI-carried): the host walks every loaded
    /// provider at boot and builds the live `scheme → plugin_id` table
    /// from it (`auto_bind_*_provider_schemes`). This field is the
    /// optional static declaration surfaced to catalogs / `mcpg-config`;
    /// when present, the host cross-checks it against
    /// `supported_schemes()` at registration and fails-closed on a
    /// mismatch (so the catalog can't advertise a scheme the runtime
    /// won't serve). An empty value opts out of that cross-check —
    /// `supported_schemes()` remains authoritative regardless.
    ///
    /// Examples: `["vault"]` for the Vault secret provider,
    /// `["aws-sm"]` for AWS Secrets Manager, `["consul"]` for the
    /// Consul config provider. Two providers serving the same scheme
    /// refuse boot, and the built-in `env` / `file` schemes are reserved
    /// (a third-party plugin claiming them is rejected) — both enforced
    /// on the live auto-bind path. Empty / absent on plugin classes that
    /// don't route by URI scheme.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides_schemes: Vec<String>,

    /// Crate-root module path of the plugin (ABI v24).
    /// Plugins set this to `module_path!()` evaluated at any point
    /// in their crate, then take the first `::`-separated segment
    /// — e.g. `"mcpg_plugin_observability_audit"`. The gateway's
    /// observability bridges use the value as the key in a
    /// boot-time `target_prefix → plugin_id` map: every tracing
    /// event whose target starts with this prefix attributes back
    /// to this plugin's id when the bridges apply per-plugin
    /// observability override (`inherit` / `replace` / `tee`).
    /// Empty / absent on plugins that haven't migrated yet —
    /// their events attribute to the `core` pseudo-id and the
    /// operator can't aim a per-plugin override at them. The
    /// `firstparty_manifest!` macro fills this automatically;
    /// plugins constructing the manifest by hand should set it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub module_path_prefix: String,

    /// Backend-class declarations the host reads back by `kind` to
    /// drive the residual per-kind facts a generic dispatch path can't
    /// infer from an opaque spec: active health probing, the metric /
    /// type label, dynamic-tool-list capability, pipeline-step
    /// eligibility, and which spec fields are transport-only (must never
    /// carry a `cred://` ref).
    ///
    /// **Host-derived, not plugin-authored on the FFI path**, exactly
    /// like [`required_capabilities`](Self::required_capabilities): the
    /// authoritative declaration is the cdylib's
    /// [`PluginRegistration::backend_profile`](crate::abi::PluginRegistration::backend_profile)
    /// (authored via `declare_plugin! { backend_profile: ... }`) or the
    /// static first-party manifest; the host copies it onto this field at
    /// registration. `None` for non-backend classes and for backend
    /// plugins that declare nothing — `None` reproduces today's behaviour
    /// (probe `Skip`, label = the kind string, no dynamic list, not
    /// pipeline-capable, no transport-only field policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_profile: Option<BackendProfile>,
}

/// Manifest-declared backend facts the gateway reads back from the
/// registry by `kind` string. Every field defaults to the
/// behaviour-neutral value, so a backend plugin that declares nothing
/// (or declares `BackendProfile::default()`) is indistinguishable from
/// today's hardcoded defaults.
///
/// This is a *declaration* surface, never a dispatch switch: the gateway
/// reads `registry.backend(kind).manifest().backend_profile` and forwards
/// the opaque spec; it never matches on the kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackendProfile {
    /// Active-probe declaration the gateway's health prober honours.
    /// Default [`HealthProbeDecl::Skip`] — health is advisory.
    #[serde(default)]
    pub health_probe: HealthProbeDecl,

    /// Metric / type label for this kind. `None` means "use the kind
    /// string" — a generic label that is correct for free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,

    /// This kind self-configures a dynamic tool list at boot (it produces
    /// tools rather than serving a single static-config tool). Default
    /// `false`.
    #[serde(default)]
    pub dynamic_list: bool,

    /// This kind may appear as a backend pipeline step. Default `false`.
    #[serde(default)]
    pub pipeline_capable: bool,

    /// JSON-pointer paths into the binding spec that name transport-only
    /// fields — host/port/url/path the plugin treats as plaintext connection
    /// facts and that must never carry a `cred://` ref. Advisory metadata: a
    /// plugin declares which of its fields are connection-plaintext; each
    /// plugin's own `register_profile` is responsible for rejecting a
    /// `cred://` ref at these positions. Empty means "no transport-only field
    /// policy". The gateway does not yet run a generic spec-walk over these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_only_fields: Vec<String>,
}

/// Active health-probe strategy a backend kind declares in its
/// [`BackendProfile`]. The gateway's generic prober honours the
/// declaration; it never switches on the kind string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum HealthProbeDecl {
    /// No active probe. Health is reported as advisory-unknown. Default.
    #[default]
    Skip,
    /// The gateway opens a TCP connection to the resolved host/port.
    Tcp,
    /// The gateway issues an HTTP GET against the resolved base URL +
    /// `path` and treats a 2xx/3xx as healthy.
    Http {
        /// Request path appended to the resolved base URL.
        path: String,
    },
    /// The gateway calls the plugin's own
    /// [`BackendPlugin::health`](crate::backend::BackendPlugin::health)
    /// trait method.
    Plugin,
}

/// The class of extension point a plugin implements.
///
/// Mirrors one-to-one with the plugin trait families in
/// [`crate::traits`] and [`crate::backend`]. Every shipped plugin
/// declares exactly one class in its manifest; the host routes it to
/// the matching registry chain or `kind`-keyed map based on that
/// declaration.
///
/// Note: the `Backend` and `WatchStrategy` variants are additive and
/// serialize to new `snake_case` strings, so existing parsers tolerate
/// them.
///
/// [`BackendPlugin`]: crate::backend::BackendPlugin
/// [`WatchStrategyPlugin`]: crate::backend::WatchStrategyPlugin
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginClass {
    /// Pre/post-dispatch gating (payment, rate-limiting, guardrails,
    /// circuit-breaking, IP allowlists, response caching, audit/webhook
    /// observability sinks). Catch-all; see the plugin platform brief
    /// for the category split planned in a later phase.
    ToolGate,
    /// Argument / result rewriting.
    Transform,
    /// Identity resolution from request headers.
    IdentityProvider,
    /// Tool dispatch over a pluggable transport (NATS / Kafka / SQL /
    /// HTTP / Command). Registered by `kind()` in the host registry.
    Backend,
    /// Resource-change detection source for `notifications/resources/
    /// updated` subscriptions (e.g. `nats_topic`, `pg_listen`).
    WatchStrategy,
    /// Custom HTTP handler mounted on the gateway's HTTP listener.
    /// Per spec §9.7: health / metrics / webhook receivers / OAuth
    /// callbacks / elicitation URL handlers, etc.
    HttpRoute,
    /// Tamper-evident audit event sink. Per spec §9.12: every
    /// registered sink receives every event; `emit` is
    /// synchronously-acknowledged (MUST durably persist before
    /// returning Ok). Fan-out composition — not a chain.
    AuditSink,
    /// Durable keyed state. Per spec §9.8: one generic entity
    /// parameterised by role (session / task / pipeline /
    /// subscription / replay / custom). Per-role exactly one
    /// active plugin; operator picks via the capability's
    /// `mcp.configurations.<capability>.store: { kind: <plugin_id> }`.
    Store,
    /// Ephemeral TTL'd KV. Per spec §9.9: best-effort `get`, atomic
    /// `incr` for rate-limit counters. Selected per-binding via the
    /// binding's `cache: { kind: <plugin_id> }` block.
    Cache,
    /// OTLP-shaped traces + metrics export (spec §9.10). Fan-out
    /// — every registered sink receives every event. Canonical
    /// backends: OTel Collector, Datadog, Honeycomb, Grafana Cloud.
    TelemetrySink,
    /// Structured line-shaped log emission (spec §9.11). Fan-out,
    /// best-effort. Distinct from `telemetry_sink` because logs
    /// are line-shaped and have a different durability contract.
    LogSink,
    /// Metric data-point delivery. Fan-out — every
    /// registered sink receives every emit. Distinct from
    /// `telemetry_sink` because metrics flow through the
    /// `metrics-rs` recorder API on a different cadence than
    /// span events; canonical backends: Prometheus
    /// (`dev.mcpg.observability.prometheus`), OTLP metrics
    /// (`dev.mcpg.observability.otlp`).
    MetricsSink,
    /// URI-addressable secret backend (spec §9.15). Keyed by
    /// scheme (`vault://`, `env://`, `file://`, ...); one scheme
    /// is served by exactly one active provider. Auto-bound by the
    /// plugin's advertised `supported_schemes` — operators just add
    /// the entry to `plugins[]`; the scheme it claims is the source
    /// of truth.
    SecretProvider,
    /// URI-addressable config document backend (spec §9.16).
    /// Keyed by scheme (`file://`, `consul://`, `k8s-cm://`,
    /// ...); one scheme is served by exactly one active provider.
    /// Auto-bound by the plugin's advertised `supported_schemes`,
    /// like `secret_provider`.
    ConfigProvider,
    /// MCP wire transport (spec §9.6). Keyed by transport name
    /// (`http-v1`, `stdio-v1`, `websocket-v1`, ...); one name is
    /// served by exactly one active plugin. Operators enable via
    /// `server.transports[]` (`{ kind: <plugin_id> }`). Not
    /// Wasm-reachable.
    Transport,
    /// Centralised authorization engine (spec §9.14). Keyed by
    /// engine name (`opa`, `cedar`, `yaml-rules`, ...). Multiple
    /// engines can coexist; consumers reference one by name.
    /// Returns structured `PolicyDecision` with obligations +
    /// redactions, richer than the binary `tool_gate` allow/deny.
    PolicyEngine,
    /// Cluster-level primitives — peer discovery, leader
    /// election, distributed locks, notification routing
    /// (spec §9.13). Singleton: exactly one `cluster`
    /// is active per gateway. Operators pick it via the top-level
    /// `cluster: { kind: <plugin_id> }` block.
    Cluster,
    /// Operator-curated tool discovery metadata (spec §9.17).
    /// Chain-bound: each provider receives the previous
    /// provider's filtered + enriched output. Consulted on every
    /// `tools/list` request to drop / tag / annotate tool
    /// descriptors before they reach AI clients.
    CatalogProvider,
    /// Per-request backend credential issuance (spec §9.18).
    /// Resolves a credential per-request based on caller
    /// `PluginIdentity` + an operator-supplied target, letting
    /// backend plugins authenticate to upstreams as the actual
    /// caller. Keyed by plugin id (`cred://<plugin_id>/<target>`).
    CredentialIssuer,
    /// Human-approval workflow notification delivery.
    /// Posts approval requests to a human-facing
    /// channel (Slack, email, PagerDuty, Teams) when a `tool_gate`
    /// returns `GateDecision::PendingApproval`. Multiple notifiers
    /// can be bound; each receives a fan-out of every approval
    /// (or only those targeting it via `target_notifiers`).
    ApprovalNotifier,
    /// Binary blob storage backend for the gateway's `content_store`
    /// surface. Plugins of this class produce
    /// configured `ContentStore` instances on demand — operators
    /// declare named providers in the top-level `storage.providers:`
    /// list and reference them by id from backend specs (e.g.
    /// `storage: media`, `cache.storage: hot-cache`).
    /// Examples: `in_process` (built-in), `file_system` (built-in),
    /// `s3` (mcpg-plugin-storage-s3). Trait + factory live in
    /// `mcpg-backend-llm-shared::ContentStorePlugin`.
    ContentStore,
}

impl PluginClass {
    /// Every entity kind, in `plugin.v1.json` schema order. The single
    /// Rust source for the descriptor schema's `class` enum — a drift
    /// test asserts the committed schema lists exactly these (via
    /// [`Display`](std::fmt::Display)). Adding a variant forces a new
    /// `Display` arm (exhaustive match); add it here too so the schema
    /// stays in sync.
    pub const ALL: &'static [PluginClass] = &[
        Self::ToolGate,
        Self::Transform,
        Self::IdentityProvider,
        Self::Backend,
        Self::WatchStrategy,
        Self::HttpRoute,
        Self::AuditSink,
        Self::Store,
        Self::Cache,
        Self::TelemetrySink,
        Self::LogSink,
        Self::MetricsSink,
        Self::SecretProvider,
        Self::ConfigProvider,
        Self::Transport,
        Self::PolicyEngine,
        Self::Cluster,
        Self::CatalogProvider,
        Self::CredentialIssuer,
        Self::ApprovalNotifier,
        Self::ContentStore,
    ];
}

impl std::fmt::Display for PluginClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolGate => write!(f, "tool_gate"),
            Self::Transform => write!(f, "transform"),
            Self::IdentityProvider => write!(f, "identity_provider"),
            Self::Backend => write!(f, "backend"),
            Self::WatchStrategy => write!(f, "watch_strategy"),
            Self::HttpRoute => write!(f, "http_route"),
            Self::AuditSink => write!(f, "audit_sink"),
            Self::Store => write!(f, "store"),
            Self::Cache => write!(f, "cache"),
            Self::TelemetrySink => write!(f, "telemetry_sink"),
            Self::LogSink => write!(f, "log_sink"),
            Self::MetricsSink => write!(f, "metrics_sink"),
            Self::SecretProvider => write!(f, "secret_provider"),
            Self::ConfigProvider => write!(f, "config_provider"),
            Self::Transport => write!(f, "transport"),
            Self::PolicyEngine => write!(f, "policy_engine"),
            Self::Cluster => write!(f, "cluster"),
            Self::CatalogProvider => write!(f, "catalog_provider"),
            Self::CredentialIssuer => write!(f, "credential_issuer"),
            Self::ApprovalNotifier => write!(f, "approval_notifier"),
            Self::ContentStore => write!(f, "content_store"),
        }
    }
}

/// Plugin execution tier — determines trust model and loading mechanism.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginTier {
    /// Wasm/WASI component loaded via Wasmtime. Sandboxed.
    Wasm,
    /// Native Rust dylib loaded via `abi_stable`. Must be cryptographically signed.
    Native,
}

impl std::fmt::Display for PluginTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasm => write!(f, "wasm"),
            Self::Native => write!(f, "native"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_json() {
        let manifest = PluginManifest {
            id: "dev.mcpg.payment".into(),
            version: "0.1.0".into(),
            name: "Machine Payment Protocol".into(),
            plugin_class: PluginClass::ToolGate,
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
        };
        let json = serde_json::to_string(&manifest).expect("serialize");
        let parsed: PluginManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn plugin_class_display() {
        assert_eq!(PluginClass::ToolGate.to_string(), "tool_gate");
        assert_eq!(PluginClass::Transform.to_string(), "transform");
        assert_eq!(
            PluginClass::IdentityProvider.to_string(),
            "identity_provider"
        );
        assert_eq!(PluginClass::Backend.to_string(), "backend");
        assert_eq!(PluginClass::WatchStrategy.to_string(), "watch_strategy");
        assert_eq!(PluginClass::TelemetrySink.to_string(), "telemetry_sink");
        assert_eq!(PluginClass::LogSink.to_string(), "log_sink");
        assert_eq!(PluginClass::MetricsSink.to_string(), "metrics_sink");
    }

    #[test]
    fn plugin_class_metrics_sink_serde_roundtrip() {
        let class = PluginClass::MetricsSink;
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, "\"metrics_sink\"");
        let parsed: PluginClass = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, class);
    }

    #[test]
    fn plugin_tier_display() {
        assert_eq!(PluginTier::Wasm.to_string(), "wasm");
        assert_eq!(PluginTier::Native.to_string(), "native");
    }

    #[test]
    fn plugin_class_serde_roundtrip() {
        let class = PluginClass::ToolGate;
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, "\"tool_gate\"");
        let parsed: PluginClass = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, class);
    }
}
