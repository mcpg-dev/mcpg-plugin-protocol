//! Declarative macros that reduce first-party plugin boilerplate.
//!
//! Every first-party MCPG plugin constructs a [`PluginManifest`]
//! that differs by three fields only: `id`, `name`, and
//! `plugin_class`. The remaining fields (`version`,
//! `protocol_version`, `required_capabilities`) are
//! always filled the same way — `version` from
//! `CARGO_PKG_VERSION`, the version constants from this crate, and
//! capabilities default to empty.
//!
//! Before this macro, that produced 7–9 lines of near-identical
//! code per plugin (20+ sites). When the protocol grew a new field
//! (e.g. `protocol_version` in v1.0), every call-site had to be
//! updated individually. The [`firstparty_manifest!`] macro
//! centralises that construction so future field additions require
//! one change in one place.
//!
//! # Scope — when (not) to use this macro
//!
//! Use it inside **first-party** plugins in the MCPG workspace.
//! Third-party plugins and host-internal adapters (gateway runtime
//! wrappers, tests, benchmarks) should keep constructing manifests
//! explicitly — the macro hard-codes
//! `version = env!("CARGO_PKG_VERSION")` and an empty
//! `required_capabilities`, which is intentionally restrictive for
//! first-party callers but inappropriate for anyone else.
//!
//! # Examples
//!
//! ```
//! use mcpg_plugin_protocol::{firstparty_manifest, PluginManifest, PluginClass};
//!
//! let m: PluginManifest = firstparty_manifest! {
//!     id: "dev.mcpg.example",
//!     name: "Example Plugin",
//!     class: ToolGate,
//! };
//! assert_eq!(m.id, "dev.mcpg.example");
//! assert_eq!(m.plugin_class, PluginClass::ToolGate);
//! ```
//!
//! Plugins that declare required capabilities pass them as a list of
//! typed [`Capability`](crate::capability::Capability) values:
//!
//! ```
//! use mcpg_plugin_protocol::{firstparty_manifest, PluginClass};
//! use mcpg_plugin_protocol::capability::Capability;
//!
//! let m = firstparty_manifest! {
//!     id: "dev.mcpg.audit",
//!     name: "Audit Logger",
//!     class: ToolGate,
//!     capabilities: [Capability::AuditWrite, Capability::MetricEmit],
//! };
//! assert_eq!(m.required_capabilities, vec![Capability::AuditWrite, Capability::MetricEmit]);
//! ```

/// Construct a [`PluginManifest`](crate::PluginManifest) for a
/// first-party MCPG plugin. See the [module docs](self) for
/// scoping and usage guidance.
///
/// The macro expands to a struct literal, so it can be used
/// anywhere a `PluginManifest` value is expected (including in
/// `const` contexts — though `version` uses `env!` which is a
/// compile-time string, not a `const fn`, so the literal is still
/// built at runtime).
#[macro_export]
macro_rules! firstparty_manifest {
    (
        id: $id:expr,
        name: $name:expr,
        class: $class:ident $(,)?
    ) => {
        $crate::firstparty_manifest! {
            id: $id,
            name: $name,
            class: $class,
            capabilities: [],
        }
    };
    (
        id: $id:expr,
        name: $name:expr,
        class: $class:ident,
        capabilities: [$($cap:expr),* $(,)?] $(,)?
    ) => {
        $crate::PluginManifest {
            id: ::std::string::String::from($id),
            version: ::std::string::String::from(env!("CARGO_PKG_VERSION")),
            name: ::std::string::String::from($name),
            plugin_class: $crate::PluginClass::$class,
            // The runtime manifest reports the protocol version the plugin
            // was COMPILED against (this SDK's `PROTOCOL_VERSION`) — the
            // authoritative value, intentionally not a free-form per-plugin
            // field. The descriptor (`plugin.yaml`) carries the author-
            // declared version the loader cross-checks (same major) against
            // this. Under the frozen-version discipline both are "1.0", so
            // the host's stale-version WARN is dormant by construction.
            protocol_version: ::std::string::String::from($crate::PROTOCOL_VERSION),
            // License is descriptor-declared metadata; first-party
            // manifests built by this macro leave it unset.
            license: ::std::option::Option::None,
            // Typed `Capability` values (the unified representation). The
            // manifest's caps are host-derived from the authoritative
            // declaration in practice; this arm exists for first-party
            // manifests that inline them.
            required_capabilities: ::std::vec![$($cap),*],
            tags: ::std::vec::Vec::new(),
            provides: ::std::vec::Vec::new(),
            provides_schemes: ::std::vec::Vec::new(),
            // Capture the caller's `module_path!()` and
            // keep just the crate-root segment. The bridge maps
            // `target_prefix → plugin_id` from this value.
            module_path_prefix: ::std::string::String::from(
                ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
            ),
            // Host-derived on the FFI path from
            // `PluginRegistration.backend_profile`; first-party manifests
            // built by this macro default to `None` (today's behaviour).
            backend_profile: ::std::option::Option::None,
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{PluginClass, PluginManifest};

    #[test]
    fn minimal_form_fills_defaults() {
        let m: PluginManifest = firstparty_manifest! {
            id: "dev.mcpg.min",
            name: "Minimal",
            class: ToolGate,
        };
        assert_eq!(m.id, "dev.mcpg.min");
        assert_eq!(m.name, "Minimal");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
        assert_eq!(m.protocol_version, crate::PROTOCOL_VERSION);
        // The crate version is resolved at the caller's compile
        // time, so here (inside mcpg-plugin-protocol itself) we just
        // assert it parses as non-empty semver-ish.
        assert!(!m.version.is_empty());
        assert!(m.required_capabilities.is_empty());
    }

    #[test]
    fn capabilities_form_accepts_list() {
        use crate::capability::Capability;
        let m = firstparty_manifest! {
            id: "dev.mcpg.caps",
            name: "With Caps",
            class: Transform,
            capabilities: [Capability::AuditWrite, Capability::MetricEmit],
        };
        assert_eq!(m.plugin_class, PluginClass::Transform);
        assert_eq!(
            m.required_capabilities,
            vec![Capability::AuditWrite, Capability::MetricEmit]
        );
    }

    #[test]
    fn backend_and_watch_classes_work() {
        let b = firstparty_manifest! {
            id: "dev.mcpg.bind",
            name: "Backend",
            class: Backend,
        };
        assert_eq!(b.plugin_class, PluginClass::Backend);
        let w = firstparty_manifest! {
            id: "dev.mcpg.watch",
            name: "Watch",
            class: WatchStrategy,
        };
        assert_eq!(w.plugin_class, PluginClass::WatchStrategy);
    }

    #[test]
    fn identity_provider_class_works() {
        let m = firstparty_manifest! {
            id: "dev.mcpg.idp",
            name: "IdP",
            class: IdentityProvider,
        };
        assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    }

    #[test]
    fn trailing_comma_is_tolerated() {
        // Both forms must accept optional trailing comma — catches
        // a rustfmt / author inconsistency.
        let _ = firstparty_manifest! {
            id: "a",
            name: "A",
            class: ToolGate
        };
        let _ = firstparty_manifest! {
            id: "b",
            name: "B",
            class: ToolGate,
            capabilities: [crate::capability::Capability::AuditWrite]
        };
    }
}
