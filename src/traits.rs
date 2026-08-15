//! Plugin traits — the contracts that every plugin must implement.
//!
//! All trait methods are async, enabling plugins that need I/O (HTTP callouts,
//! database queries, external PDP calls) while remaining zero-cost for pure
//! compute plugins (the async overhead is negligible for in-process evaluation).
//!
//! For native (Tier 2) plugins, these traits are implemented directly in Rust.
//! For Wasm (Tier 1) plugins, the host auto-implements these traits by bridging
//! to the Wasm component's exported functions.

use async_trait::async_trait;

use crate::manifest::PluginManifest;
use crate::types::{GateDecision, IdentityResolution, PluginContext, TransformResult};

// ---------------------------------------------------------------------------
// ToolGatePlugin — pre/post-dispatch gating
// ---------------------------------------------------------------------------

/// A plugin that makes allow/deny/challenge decisions around tool dispatch.
///
/// Examples: payment gates, rate limiters, external authorization providers,
/// human-approval workflows, budget enforcement.
///
/// The gateway evaluates the tool-gate chain in order. The first non-Allow
/// decision (Deny or Challenge) short-circuits the chain.
#[async_trait]
pub trait ToolGatePlugin: Send + Sync {
    /// Returns the plugin manifest.
    fn manifest(&self) -> &PluginManifest;

    /// Called before the tool is dispatched to the backend.
    ///
    /// The plugin may inspect the tool name, arguments, caller identity,
    /// and optional `_meta` from the client. It returns a decision.
    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        meta: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> GateDecision;

    /// Called after the tool has been dispatched and a result is available.
    ///
    /// The plugin may inspect and optionally modify the result.
    /// Not all tool-gate plugins need post-dispatch logic — the default
    /// implementation returns `Allow`.
    async fn evaluate_post_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
        config: &serde_json::Value,
    ) -> GateDecision {
        let _ = (ctx, arguments, result, execution_duration_ms, config);
        GateDecision::allow()
    }

    /// Drain and release any plugin-owned background resources.
    ///
    /// Called once during gateway shutdown before the process exits.
    /// Plugins with buffered sinks (audit, webhook) use this to flush
    /// in-flight events; plugins that allocate no background state can
    /// accept the default no-op. Implementations SHOULD bound their work
    /// (e.g. a 5-second drain budget) so a slow plugin cannot delay
    /// shutdown indefinitely.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// TransformPlugin — argument / result rewriting
// ---------------------------------------------------------------------------

/// A plugin that transforms tool arguments before dispatch or results after dispatch.
///
/// Examples: PII masking, schema migration, field mapping, response enrichment.
#[async_trait]
pub trait TransformPlugin: Send + Sync {
    /// Returns the plugin manifest.
    fn manifest(&self) -> &PluginManifest;

    /// Transform tool arguments before dispatch.
    async fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult;

    /// Transform the tool result after dispatch.
    async fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult;

    /// Drain and release plugin-owned background resources. Default is
    /// a no-op; override for plugins with buffered sinks.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// IdentityProviderPlugin — identity resolution
// ---------------------------------------------------------------------------

/// A plugin that resolves caller identity from request headers
/// and (since protocol 1.1) per-request `RequestMetadata` —
/// remote address, TLS handshake info, transport label, request
/// path. The metadata is `Default::default()` when the gateway
/// has nothing to populate (stdio transport, plain HTTP, no
/// peer-cert handshake), so plugins that only inspect headers
/// remain protocol-1.0-equivalent.
///
/// Examples: custom JWT claim expansion, enterprise group lookup,
/// workload identity mapping, native mTLS validation, proprietary
/// token verification.
#[async_trait]
pub trait IdentityProviderPlugin: Send + Sync {
    /// Returns the plugin manifest.
    fn manifest(&self) -> &PluginManifest;

    /// Attempt to resolve a caller identity from the provided
    /// HTTP headers + per-request `RequestMetadata`.
    ///
    /// Headers are presented as `(name, value)` pairs. The plugin
    /// should return `IdentityResolution::None` if it does not
    /// recognize any credential, allowing the next identity
    /// resolver to run.
    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &crate::types::RequestMetadata,
        config: &serde_json::Value,
    ) -> IdentityResolution;

    /// Release any background state on gateway shutdown / config reload.
    /// Defaulted no-op so simple resolvers need no change. Mirrors the
    /// chain siblings (`ToolGatePlugin`/`TransformPlugin`); the FFI vtable
    /// already carries an identity shutdown slot (ABI v26), so the host can
    /// drain identity providers uniformly with every other class.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginClass, PluginManifest};

    struct TestGatePlugin {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl ToolGatePlugin for TestGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }

        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _arguments: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Deny {
                http_status: 403,
                code: -32044,
                message: "test deny".into(),
                error_data: None,
            }
        }
    }

    #[tokio::test]
    async fn tool_gate_plugin_default_post_dispatch_allows() {
        let plugin = TestGatePlugin {
            manifest: PluginManifest {
                id: "test.gate".into(),
                version: "0.1.0".into(),
                name: "Test".into(),
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
            },
        };
        let ctx = crate::types::PluginContext {
            surface: "tool".to_owned(),
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test".into(),
            identity: crate::types::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        };
        let result = plugin
            .evaluate_post_dispatch(
                &ctx,
                &serde_json::json!({}),
                &serde_json::json!({}),
                100,
                &serde_json::json!({}),
            )
            .await;
        assert!(result.is_allow());
    }

    #[tokio::test]
    async fn tool_gate_plugin_pre_dispatch_can_deny() {
        let plugin = TestGatePlugin {
            manifest: PluginManifest {
                id: "test.gate".into(),
                version: "0.1.0".into(),
                name: "Test".into(),
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
            },
        };
        let ctx = crate::types::PluginContext {
            surface: "tool".to_owned(),
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test".into(),
            identity: crate::types::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        };
        let result = plugin
            .evaluate_pre_dispatch(&ctx, &serde_json::json!({}), None, &serde_json::json!({}))
            .await;
        assert!(!result.is_allow());
    }
}
