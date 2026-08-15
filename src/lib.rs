//! # mcpg-plugin-protocol
//!
//! The versioned MCPG plugin protocol: shared types, trait
//! contracts, and the canonical [`PROTOCOL_VERSION`] for the
//! interface between the gateway host and any plugin (Wasm or
//! native).
//!
//! This crate is the single semver-governed contract every MCPG
//! plugin is built against. Both the gateway host and every plugin
//! depend on it — it contains only data types and trait
//! definitions with **no** runtime, networking, or framework
//! dependencies.
//!
//! Compatibility is governed by [`PROTOCOL_VERSION`] (semver
//! string) — the single authoritative identifier. Plugins declare
//! their target protocol in their manifest and the host checks the
//! declared version against its supported range.
//!
//! ## Plugin Classes
//!
//! | Class | Trait | Hook Points |
//! |-------|-------|-------------|
//! | Tool Gate | [`ToolGatePlugin`] | Pre-dispatch / post-dispatch decision |
//! | Transform | [`TransformPlugin`] | Argument / result rewriting |
//! | Identity Provider | [`IdentityProviderPlugin`] | Identity resolution from headers |
//! | Backend | [`BackendPlugin`] | Tool dispatch over a pluggable transport |
//! | Watch Strategy | [`WatchStrategyPlugin`] | Resource-change detection source |
//!
//! ## Plugin Tiers
//!
//! - **Wasm** — sandboxed via Wasmtime Component Model; default customer model
//! - **Native** — zero-overhead `abi_stable` dylib; requires Ed25519 signature

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use async_trait::async_trait;
pub use backend::*;
// Re-exported so the `declare_plugin!` macro (expanded in downstream
// cdylib crates) can JSON-encode a `BackendProfile` without assuming the
// downstream crate has its own `serde_json` dependency in scope.
pub use serde_json;
// Re-export the typed-capability symbols at the crate root for
// ergonomic `mcpg_plugin_protocol::Capability` /
// `mcpg_plugin_protocol::CapabilityCheck` usage.
pub use capability::{
    Capability, CapabilityCheck, CapabilityParseError, validate_typed_capabilities,
};
pub use descriptor::*;
// `http_route::*` is NOT glob-re-exported to keep the crate prelude
// disciplined: the kind ships rare-enough types (`HttpBody`,
// `HttpChunk`, `HttpRoute`, `RouteSpec`) that would muddy autocomplete
// for plugin authors writing the much more common `ToolGatePlugin`.
// Callers use the `http_route::` module path explicitly.
pub use manifest::*;
pub use traits::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

pub mod abi;
pub mod approval_notifier;
pub mod audit;
pub mod backend;
pub mod cache;
pub mod capability;
pub mod catalog;
pub mod config;
pub mod content_store;
pub mod credential;
pub mod descriptor;
pub mod http_route;
pub mod logs;
pub mod macros;
pub mod manifest;
pub mod metrics;
pub mod payment;
pub mod policy;
pub mod redact;
pub mod result_envelope;
pub mod schema;
pub mod secret;
pub mod security;
pub mod store;
pub mod telemetry;
pub mod traits;
pub mod transport;
pub mod types;

/// Current plugin protocol version (semver).
///
/// This is the **authoritative** compatibility identifier for the
/// MCPG plugin platform. Plugins declare their target protocol in
/// their manifest and the host checks the declared version against
/// its supported range. Semver discipline:
///
///   - **Major** bumps are breaking changes (trait-signature removals,
///     type-layout changes on FFI boundary, incompatible manifest
///     field semantics).
///   - **Minor** bumps are additive (new optional trait methods with
///     default impls, new manifest fields with `#[serde(default)]`,
///     new well-known capability identifiers).
///   - **Patch** bumps are documentation or clarification only.
///
/// Compatibility is **major-only**: a plugin is loadable on any host
/// that shares its major version (additive minor bumps stay loadable;
/// only a major mismatch is a hard load error). So a plugin declaring
/// `protocol_version: "1.0"` loads on any `1.x` host (`>=1.0, <2.0`),
/// and a plugin built against a newer `1.y` SDK still loads on a `1.x`
/// host — the host only emits a stale-version WARN. The host enforces
/// this with a `starts_with("1.")` major check in
/// `PluginRegistry::validate_manifest` plus a same-major descriptor↔
/// manifest cross-check in the loader; there is no minor-range gate.
/// (During the pre-1.0-public freeze every in-tree host and plugin
/// declares exactly `"1.0"`, so the stale-minor WARN path is dormant.)
pub const PROTOCOL_VERSION: &str = "1.0";

/// Returns whether a `make`-slot config JSON string is the host's load-time
/// MANIFEST-DERIVATION probe — i.e. an EMPTY config object (`{}`, possibly with
/// whitespace) or empty/absent input. The host's
/// `native_loader::derive_manifest` builds + immediately drops an instance only
/// to read its plugin-wide `manifest()`, passing `{}` because it has no real
/// config at that point. A plugin that eagerly constructs a real connection in
/// `make` / strictly validates its config (the cluster coordinators, the strict
/// identity resolvers) uses this to return a lazy, non-connecting placeholder
/// for the probe while still rejecting a NON-empty-but-invalid REAL config at
/// its real `make`. (A real coordinator/identity config is never empty — it
/// always carries `url`/`servers`/`token_sources`/etc.)
pub fn is_manifest_probe_config(config_json: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(config_json) {
        Ok(serde_json::Value::Object(map)) => map.is_empty(),
        Ok(serde_json::Value::Null) => true,
        Err(_) => config_json.trim().is_empty(),
        _ => false,
    }
}
