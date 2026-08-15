//! Plugin descriptor — the on-disk authoritative representation of a
//! plugin's identity and runtime requirements.
//!
//! Every MCPG plugin ships a `plugin.yaml` at its crate root. The
//! descriptor is the **single source of truth** that:
//!
//! * The gateway inspects at load time to decide compatibility.
//! * Packaging tooling (`mcpg-plugin pack` + OCI tagging) reads it to
//!   construct manifest labels.
//! * Admin surfaces return to operators so `what plugins am I
//!   running?` can be answered without running code.
//!
//! The in-code [`PluginManifest`](crate::PluginManifest) remains the
//! runtime-typed value a plugin returns from its `manifest()` hook.
//! At build/load time, the descriptor is cross-checked against that
//! manifest — a mismatch is a packaging bug.
//!
//! # Schema
//!
//! A descriptor is small, flat YAML:
//!
//! ```yaml
//! # plugin.yaml
//! schema: mcpg.dev/plugin/v1
//! id: dev.mcpg.circuit-breaker
//! name: Circuit Breaker
//! description: |
//!   Per-tool circuit breaker that fails fast on unhealthy backends.
//! class: tool_gate
//! runtime: static-firstparty-v1
//! protocol_version: "1.0"
//! required_capabilities: []
//! ```
//!
//! The crate version is **not** duplicated in the descriptor — it
//! comes from `Cargo.toml` at build time so there is exactly one
//! place to bump it.

use crate::PluginClass;
use serde::{Deserialize, Serialize};

/// Untagged Vec<Capability> deserialiser,
/// shared with the operator-config `granted_capabilities` field's
/// deserialiser; both surfaces accept bare-string form for no-args
/// variants and object form for variant-args variants. Eager-errors
/// on unknown kinds so the plugin author / operator sees the typo
/// at config parse time.
fn deserialize_required_capabilities<'de, D>(
    deserializer: D,
) -> Result<Vec<crate::capability::Capability>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let raw: Vec<serde_json::Value> = Vec::deserialize(deserializer)?;
    let mut out = Vec::with_capacity(raw.len());
    for (idx, v) in raw.iter().enumerate() {
        match crate::capability::Capability::parse_value(v) {
            Ok(cap) => out.push(cap),
            Err(e) => {
                return Err(D::Error::custom(format!(
                    "required_capabilities[{idx}]: {e}"
                )));
            }
        }
    }
    Ok(out)
}

/// Current plugin descriptor schema identifier. The gateway refuses
/// to load a plugin whose descriptor declares an unknown schema.
pub const DESCRIPTOR_SCHEMA_V1: &str = "mcpg.dev/plugin/v1";

/// The JSON Schema for `plugin.yaml` descriptors, embedded at
/// compile time from `schema/plugin.v1.json`.
///
/// Consumers (IDE plugins, `mcpg-plugin lint`, CI validators) can
/// parse this as JSON without fetching a schema URL over the network.
/// The same file ships in the crate's sdist via `Cargo.toml`'s
/// `include = [..., "schema/**/*.json", ...]`.
///
/// Load into a validator with e.g.
/// `jsonschema::validator_for(&serde_json::from_str(DESCRIPTOR_SCHEMA_V1_JSON)?)`.
pub const DESCRIPTOR_SCHEMA_V1_JSON: &str = include_str!("../schema/plugin.v1.json");

/// The runtime class tells the host *how* to load the plugin. It
/// selects the code path between static link (first-party plugins
/// compiled into the gateway), dynamic cdylib loading, and
/// Wasmtime Component Model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeClass {
    /// Compiled-in first-party plugin. No artifact file on disk.
    #[serde(rename = "static-firstparty-v1")]
    StaticFirstparty,
    /// Dynamically loaded cdylib with `abi_stable` FFI. Requires
    /// Ed25519 signature + SHA-256 hash pinning.
    #[serde(rename = "native-cdylib-v1")]
    NativeCdylib,
    /// WASI Preview 2 component loaded via Wasmtime. Default
    /// customer model.
    #[serde(rename = "wasi-v1")]
    Wasi,
}

impl RuntimeClass {
    /// Canonical string label matching the serde rename.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuntimeClass::StaticFirstparty => "static-firstparty-v1",
            RuntimeClass::NativeCdylib => "native-cdylib-v1",
            RuntimeClass::Wasi => "wasi-v1",
        }
    }

    /// Every runtime class, in `plugin.v1.json` schema order. The single
    /// Rust source for the descriptor schema's `runtime` enum (drift-tested
    /// via [`as_str`](Self::as_str)). Adding a variant forces a new `as_str`
    /// arm (exhaustive match); add it here too.
    pub const ALL: &'static [RuntimeClass] =
        &[Self::StaticFirstparty, Self::NativeCdylib, Self::Wasi];
}

/// The cluster slot **roles** a `cluster` plugin may advertise in its
/// descriptor's `provides` list (and `PluginManifest.provides`). This is
/// the single Rust source for the `plugin.v1.json` schema's `provides`
/// enum — a drift test asserts the committed schema lists exactly these.
///
/// These are the same role strings the gateway's point-of-use slot
/// resolver consults (`cache` / `kv` / `bus`) and that
/// `mcpg_cluster_api::ClusterBackend::cluster_provides()` returns — the
/// gateway cross-checks all three at boot and fails-closed on
/// drift. Note this is the *slot-role*
/// vocabulary, distinct from the trait's primitive *accessor* methods
/// (`key_value_store` / `pub_sub` / `lease` / `watch`): a coordinator
/// fills the `cache` slot only if it has eviction semantics, the `bus`
/// slot only if it ships `pub_sub`, etc.
pub const CLUSTER_PROVIDES_ROLES: &[&str] = &["cache", "kv", "bus"];

impl std::fmt::Display for RuntimeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical plugin descriptor loaded from `plugin.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginDescriptor {
    /// Descriptor schema version. Currently always
    /// [`DESCRIPTOR_SCHEMA_V1`]. Future schema migrations MUST bump
    /// this string.
    pub schema: String,
    /// Reverse-DNS plugin identifier. MUST match the `id` field of
    /// the plugin's in-code [`PluginManifest`](crate::PluginManifest).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// SPDX identifier of the plugin's source license (e.g.
    /// `Apache-2.0`). Informational — surfaced to catalogs /
    /// marketplaces and admin inventory; the gateway does not act
    /// on it. Mirrors `PluginManifest.license`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Long-form description. Shown in admin surfaces and plugin
    /// catalogues.
    #[serde(default)]
    pub description: String,
    /// Plugin class. Determines which trait the plugin implements
    /// and which chain slot it joins.
    pub class: PluginClass,
    /// How the plugin is loaded at runtime.
    pub runtime: RuntimeClass,
    /// Required protocol version (semver).
    pub protocol_version: String,
    /// Typed capability declarations the plugin needs the gateway
    /// to grant. Empty list means no capabilities beyond the
    /// baseline. [`Capability`] values use the same
    /// `{type: "...", ...args}` wire shape the operator's
    /// `granted_capabilities` uses.
    #[serde(default, deserialize_with = "deserialize_required_capabilities")]
    pub required_capabilities: Vec<crate::capability::Capability>,
    /// Free-form classification tags (e.g. `enterprise`, `paid`,
    /// `experimental`, `vendor:hashicorp`). Operators wire these
    /// into a `policy_engine` chain at the
    /// `plugin.lifecycle.register` decision point so the engine
    /// can deny / allow loading per their org's rules. Pass-
    /// through to `PluginManifest.tags`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Cluster slot **roles** this plugin provides. Used by
    /// `cluster_backend` plugins to declare which gateway slots they
    /// can back — one or more of `cache` / `kv` / `bus`
    /// ([`CLUSTER_PROVIDES_ROLES`]). Empty / absent for non-cluster
    /// classes. Mirrors `PluginManifest.provides` and the runtime
    /// `ClusterBackend::cluster_provides()`; the gateway cross-checks
    /// all three at boot and fails-closed on drift.
    #[serde(default)]
    pub provides: Vec<String>,
    /// URI schemes this plugin claims for auto-routing — the static
    /// declaration for `secret_provider` / `config_provider` classes
    /// (which route by URI scheme prefix). Mirrors
    /// `PluginManifest.provides_schemes`; the authoritative routing
    /// surface is the runtime `supported_schemes()`, which the host
    /// cross-checks this field against at registration (fail-closed on
    /// mismatch). Empty / absent on classes that don't claim a scheme.
    #[serde(default)]
    pub provides_schemes: Vec<String>,
}

impl PluginDescriptor {
    /// Whether this descriptor declares the current schema version.
    /// A future gateway reading an older plugin should call this to
    /// decide whether to attempt compat shimming.
    #[must_use]
    pub fn is_current_schema(&self) -> bool {
        self.schema == DESCRIPTOR_SCHEMA_V1
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed `plugin.v1.json` descriptor schema must mirror the
    /// Rust types it claims to describe — the JSON schema is generated
    /// from Rust so they cannot drift. This is the drift guard:
    /// the capability `items` schema is produced *by* the `Capability`
    /// enum, and the `class` / `runtime` / `provides` enum lists are
    /// sourced from `PluginClass::ALL` / `RuntimeClass::ALL` /
    /// `CLUSTER_PROVIDES_ROLES`. Add a variant to any of those
    /// without updating the schema and this fails at boot of the test
    /// suite (always-on; no feature flag).
    #[test]
    fn plugin_v1_schema_enums_match_rust_types() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schema/plugin.v1.json"))
                .expect("plugin.v1.json parses");
        let props = &schema["properties"];

        // capability items — fully generated from the typed Capability enum.
        assert_eq!(
            props["required_capabilities"]["items"],
            crate::capability::Capability::items_json_schema(),
            "plugin.v1.json required_capabilities.items drifted from \
             Capability::items_json_schema()"
        );

        let str_list = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .expect("enum array")
                .iter()
                .map(|e| e.as_str().expect("enum string").to_owned())
                .collect()
        };

        // class enum == PluginClass::ALL (via Display / serde names).
        assert_eq!(
            str_list(&props["class"]["enum"]),
            PluginClass::ALL
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "plugin.v1.json class enum drifted from PluginClass::ALL"
        );

        // runtime enum == RuntimeClass::ALL.
        assert_eq!(
            str_list(&props["runtime"]["enum"]),
            RuntimeClass::ALL
                .iter()
                .map(|r| r.as_str().to_owned())
                .collect::<Vec<_>>(),
            "plugin.v1.json runtime enum drifted from RuntimeClass::ALL"
        );

        // provides item enum == CLUSTER_PROVIDES_ROLES.
        assert_eq!(
            str_list(&props["provides"]["items"]["enum"]),
            CLUSTER_PROVIDES_ROLES
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
            "plugin.v1.json provides enum drifted from CLUSTER_PROVIDES_ROLES"
        );
    }

    #[test]
    fn runtime_class_serde_matches_schema() {
        assert_eq!(
            serde_json::to_string(&RuntimeClass::StaticFirstparty).unwrap(),
            "\"static-firstparty-v1\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimeClass::NativeCdylib).unwrap(),
            "\"native-cdylib-v1\""
        );
        assert_eq!(
            serde_json::to_string(&RuntimeClass::Wasi).unwrap(),
            "\"wasi-v1\""
        );
    }

    #[test]
    fn runtime_class_display_matches_serde() {
        for rc in [
            RuntimeClass::StaticFirstparty,
            RuntimeClass::NativeCdylib,
            RuntimeClass::Wasi,
        ] {
            let via_json: String =
                serde_json::from_value(serde_json::to_value(rc).unwrap()).unwrap();
            assert_eq!(rc.to_string(), via_json);
        }
    }

    #[test]
    fn descriptor_roundtrip_json() {
        let d = PluginDescriptor {
            schema: DESCRIPTOR_SCHEMA_V1.into(),
            id: "dev.mcpg.example".into(),
            name: "Example".into(),
            description: "A plugin for demonstration.".into(),
            class: PluginClass::ToolGate,
            runtime: RuntimeClass::StaticFirstparty,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: vec![crate::capability::Capability::NetworkOutbound],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: PluginDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(back.is_current_schema());
    }

    #[test]
    fn descriptor_missing_description_and_caps_defaults() {
        // Minimum-viable descriptor: schema, id, name, class,
        // runtime, protocol_version.
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "dev.mcpg.min",
            "name": "Minimal",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
        });
        let d: PluginDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(d.description, "");
        assert!(d.required_capabilities.is_empty());
    }

    #[test]
    fn descriptor_accepts_license() {
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "dev.mcpg.licensed",
            "name": "Licensed",
            "license": "Apache-2.0",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
        });
        let d: PluginDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(d.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn descriptor_without_license_defaults_to_none() {
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "dev.mcpg.unlicensed",
            "name": "Unlicensed",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
        });
        let d: PluginDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(d.license, None);
    }

    #[test]
    fn descriptor_rejects_unknown_runtime() {
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "x",
            "name": "X",
            "class": "tool_gate",
            "runtime": "martian-v3",
            "protocol_version": "1.0",
        });
        assert!(serde_json::from_value::<PluginDescriptor>(json).is_err());
    }

    #[test]
    fn is_current_schema_rejects_future_values() {
        let mut d = PluginDescriptor {
            schema: "mcpg.dev/plugin/v9".into(),
            id: "x".into(),
            name: "x".into(),
            description: String::new(),
            class: PluginClass::ToolGate,
            runtime: RuntimeClass::Wasi,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
        };
        assert!(!d.is_current_schema());
        d.schema = DESCRIPTOR_SCHEMA_V1.into();
        assert!(d.is_current_schema());
    }

    #[test]
    fn descriptor_accepts_bare_string_required_capabilities() {
        // Operator-/plugin-author convenience: a no-args required
        // capability may be written as a bare string.
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "x",
            "name": "X",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
            "required_capabilities": ["network_outbound"],
        });
        let d: PluginDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(
            d.required_capabilities,
            vec![crate::capability::Capability::NetworkOutbound]
        );
    }

    #[test]
    fn descriptor_accepts_object_form_required_capabilities() {
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "x",
            "name": "X",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
            "required_capabilities": [
                { "type": "filesystem_read", "paths": ["/etc/myapp"] },
            ],
        });
        let d: PluginDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(
            d.required_capabilities,
            vec![crate::capability::Capability::FilesystemRead {
                paths: vec!["/etc/myapp".into()]
            }]
        );
    }

    #[test]
    fn descriptor_rejects_legacy_cap_host_string() {
        // Legacy descriptors used bare strings like
        // "cap.host.outbound_http". The typed capability
        // surface breaks that form intentionally — plugin authors
        // get a parse error pointing at the unknown kind.
        let json = serde_json::json!({
            "schema": DESCRIPTOR_SCHEMA_V1,
            "id": "x",
            "name": "X",
            "class": "tool_gate",
            "runtime": "static-firstparty-v1",
            "protocol_version": "1.0",
            "required_capabilities": ["cap.host.outbound_http"],
        });
        assert!(serde_json::from_value::<PluginDescriptor>(json).is_err());
    }

    #[test]
    fn embedded_schema_is_valid_json() {
        let parsed: serde_json::Value = serde_json::from_str(DESCRIPTOR_SCHEMA_V1_JSON)
            .expect("DESCRIPTOR_SCHEMA_V1_JSON must parse as JSON");
        // `$id` pins the schema URL; `$schema` pins the draft.
        assert_eq!(
            parsed.get("$id").and_then(|v| v.as_str()),
            Some("https://mcpg.dev/schema/plugin/v1"),
            "schema $id drifted from docs"
        );
        assert!(
            parsed
                .get("$schema")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("json-schema.org")),
            "schema $schema missing or malformed"
        );
    }
}
