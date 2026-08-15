# mcpg-plugin-protocol

> The versioned, semver-governed contract every MCPG plugin and the gateway host are built against.

This is the single shared interface crate that sits between the MCPG gateway and
any plugin, native cdylib or Wasm. It carries data types, trait contracts, the
`abi_stable` FFI surface, and the compatibility identifiers — and nothing else.
There is no runtime here: no HTTP client, no server, no framework, no plugin
loading. That is deliberate, and it is what lets both sides depend on this crate
without pulling in each other's machinery. If you are writing a plugin you
normally want `mcpg-plugin-sdk` (or the `mcpg-sdk` façade), which re-exports this
crate together with the authoring macros; depend on this one directly when you
need the types and traits without the macros. The gateway-side loader and
registry live in `mcpg-plugin-host`.

## What's here

- **Trait contracts, one family per plugin class.** `ToolGatePlugin`,
  `TransformPlugin`, `IdentityProviderPlugin` (in `traits`), `BackendPlugin` and
  `WatchStrategyPlugin` (in `backend`), plus the host-service and sink families:
  `AuditSink`, `MetricsSink`, `TelemetrySink`, `LogSink`, `Store`, `Cache`,
  `SecretProvider`, `ConfigProvider`, `PolicyEngine`, `CatalogProvider`,
  `CredentialIssuer`, `ContentStore`, `ApprovalNotifier`, `HttpRoute`,
  `Transport`. Every method that can do I/O is `async`; the metadata accessors
  (`manifest()`, `kind()`, `supported_schemes()`, `routes()`, …) are plain
  synchronous methods.
- **Identity and versioning.** `PluginManifest` (`id`, `version`, `name`,
  `plugin_class`, `protocol_version`, `license`, `required_capabilities`, `tags`,
  `provides`, `provides_schemes`, `module_path_prefix`), the `PluginClass` and
  `PluginTier` enums, and the `descriptor` module covering the on-disk
  `plugin.yaml`.
- **Request-path currency.** `PluginContext` (`request_id`, `session_id`,
  `tool_name`, `surface`, `identity`, `transport`), `PluginIdentity`,
  `GateDecision`, `TransformResult`, `IdentityResolution`, and
  `BackendRequest` / `BackendResponse`.
- **The FFI surface.** The `abi` module holds the `abi_stable` vtables used by
  cdylib plugins and `MCPG_PLUGIN_ABI_VERSION`, the numeric sentinel a
  registration must carry. `result_envelope` standardises the
  `{"ok": …}` / `{"err": …}` wire shape every fallible vtable slot returns, so
  host-side decoders and the panic sentinel are uniform.
- **Typed capabilities.** `capability::Capability`, `CapabilityCheck`, and
  `validate_typed_capabilities` — one representation shared by a plugin's
  declaration, its descriptor, and the operator's grants.
- **Shared safety helpers.** `security` classifies private, loopback,
  link-local, CGNAT, ULA, multicast and unspecified IP ranges for DNS-rebinding
  and SSRF guards. `redact` strips `user:pass@` userinfo so a resolved connection
  URL never reaches a log, an audit event, or an error message with its password
  intact. `schema` owns the deep-merge semantics for operator schema overlays, so
  host and plugin compose them identically.
- `PROTOCOL_VERSION` — the authoritative compatibility identifier — and
  `is_manifest_probe_config`, which lets a plugin factory recognise the host's
  load-time manifest-derivation probe (an empty config object) and return a
  non-connecting placeholder instead of dialling a real backend.
- `schema/plugin.v1.json` — the normative JSON Schema for `plugin.yaml`, shipped
  inside the published crate so external tooling can validate a descriptor
  without cloning the workspace.

Compatibility is **major-only**. A plugin declares the protocol version it
targets in its manifest and the host loads it whenever the major matches; an
additive minor difference stays loadable and produces only a stale-version
warning. The FFI has its own independent gate: a cdylib whose registration
reports a different `MCPG_PLUGIN_ABI_VERSION` than the host is refused at load
time, before any vtable slot is called, rather than being allowed to misread the
wire encoding.

## Used by

- Every plugin crate, directly or through `mcpg-plugin-sdk` / `mcpg-sdk`.
- `mcpg-plugin-host` — the gateway-side loader and registry that enforces this
  contract — plus `mcpg-cluster-api`, the shared net and LLM backend cores, and
  the gateway binary itself.
- Third-party tooling that needs the descriptor schema or the type definitions
  without the authoring macros.

## Usage

```toml
[dependencies]
mcpg-plugin-protocol = "<version>"
serde_json = "1"
```

```rust
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, ToolGatePlugin,
    async_trait,
};

struct BlockDebugTools {
    manifest: PluginManifest,
}

#[async_trait]
impl ToolGatePlugin for BlockDebugTools {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        if ctx.tool_name.starts_with("debug_") {
            GateDecision::Deny {
                http_status: 403,
                code: -32030,
                message: "debug tools are not callable through the gateway".to_owned(),
                error_data: None,
            }
        } else {
            GateDecision::allow()
        }
    }
}

// `plugin_class` is the key the host indexes the entry under.
assert_eq!(PluginClass::ToolGate.to_string(), "tool_gate");
```

The gateway evaluates a tool-gate chain in order and the first non-`Allow`
decision short-circuits it, so a `Deny` from any entry ends the dispatch.

## Build / test

```bash
cargo build -p mcpg-plugin-protocol
cargo test  -p mcpg-plugin-protocol
```

## Licence

Apache-2.0.

## See also

- [Plugins and the plugin protocol](https://mcpg.dev/docs/plugins/plugins-and-protocol) — the classes, the tiers, and the ABI.
- [Plugin authoring](https://mcpg.dev/docs/plugins/plugin-authoring) — writing, packaging, and testing a plugin.
- `libs/plugin-sdk` — the authoring macros and mock-gateway harness built on this crate.
- `libs/plugin-host` — the gateway-side runtime that loads, verifies, and dispatches into plugins.
