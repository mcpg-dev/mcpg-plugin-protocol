//! `transport` entity kind — a listener that brings HTTP requests to
//! the gateway (spec §9.6).
//!
//! A transport owns the connections (a tunnel such as ngrok, a relay, a
//! tailnet socket the gateway does not bind) and hands each whole HTTP
//! request to the gateway's [`HttpIngressServer`]. The gateway runs it
//! through its own HTTP router, so the identity chain, OAuth discovery,
//! rate limits, SSE and MCP 2026-07-28 behave as on the gateway's own
//! listener.
//!
//! # Composition
//!
//! Keyed by transport name. A transport self-declares its name
//! (`"ngrok-v1"`, `"tailscale-v1"`, ...); one name is served by
//! exactly one active plugin. Operators enable transports via
//! `server.transports[]` (each `{ kind: <plugin_id> }`); the
//! plugin's own `config:` carries any listener settings.
//!
//! # Not Wasm-reachable
//!
//! Transports live at the process boundary and need host-level
//! network access. The Wasm tier's capability surface doesn't
//! expose raw sockets, so this entity kind is native-only. Wasm
//! plugins that need a custom transport bridge delegate to a
//! native transport plugin.

use std::pin::Pin;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;

/// The head of one request a transport received.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpIngressRequestHead {
    /// Request method, e.g. `POST`.
    pub method: String,
    /// Origin-form target: path and query, e.g. `/mcp?x=1`.
    pub uri: String,
    /// Header pairs in arrival order. A name can repeat.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// The client's address as `ip:port`, as the transport saw it (for a
    /// tunnel: the address the tunnel's edge reports). Per-IP rate limits
    /// key on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    /// The client's TLS session, when the transport terminated TLS itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::types::TlsInfo>,
    /// The caller, as the transport itself established it (for a tailnet:
    /// the owner of the peer node, as the tailnet's control server says).
    /// The gateway uses it when the request carries no credential of its
    /// own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<TransportPeer>,
}

/// A caller identity a transport attests. The gateway records the
/// transport's plugin id as the identity's source, so a transport speaks
/// only for itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportPeer {
    /// Who vouches for the caller, e.g. `tailscale`.
    pub provider: String,
    /// `verified` (the transport authenticated the caller
    /// cryptographically) or `header_asserted` (it only names them).
    pub trust_level: String,
    /// The caller's stable name, e.g. a login `alice@example.com`.
    pub subject_id: String,
    /// The authority that issued the name, e.g. `tailscale:example.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Further facts about the caller, e.g. the node name.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
}

/// Head of the response to an [`HttpIngressRequestHead`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpIngressResponseHead {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// Response body: data frames in order. An `Err` ends the body early; the
/// transport aborts the response instead of completing it.
pub type BoxBodyStream =
    Pin<Box<dyn futures_core::Stream<Item = Result<Bytes, String>> + Send + 'static>>;

/// The gateway's answer to one request.
pub struct HttpIngressResponse {
    pub head: HttpIngressResponseHead,
    pub body: BoxBodyStream,
}

impl std::fmt::Debug for HttpIngressResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpIngressResponse")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// The gateway-provided HTTP server a transport calls once per received
/// request. The response body can stay open (SSE); dropping it stops the
/// gateway's side of that response.
#[crate::async_trait]
pub trait HttpIngressServer: Send + Sync {
    async fn serve(&self, head: HttpIngressRequestHead, body: Bytes) -> HttpIngressResponse;
}

/// Failure modes for transport lifecycle operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportError {
    /// Binding the listener failed (port in use, permission
    /// denied, invalid address, ...).
    BindFailed { reason: String },
    /// `start_http` called twice without an intervening `close` on the
    /// previous handle. Most transport implementations are
    /// single-instance per process.
    AlreadyListening,
    /// `listener_config` shape is wrong for this transport.
    /// Usually a config-authoring bug.
    InvalidConfig { message: String },
    /// No plugin registered for the named transport.
    UnknownTransport { name: String },
    /// Generic I/O failure after the listener came up (accept
    /// loop error, socket read failure on a long-lived stream,
    /// ...).
    Io { reason: String },
    /// The transport was asked to start while the gateway was
    /// already in shutdown. Not a plugin bug; the startup-vs-
    /// shutdown race is the operator's concern.
    Shutdown,
}

impl TransportError {
    /// Bounded metrics label.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::BindFailed { .. } => "bind_failed",
            Self::AlreadyListening => "already_listening",
            Self::InvalidConfig { .. } => "invalid_config",
            Self::UnknownTransport { .. } => "unknown_transport",
            Self::Io { .. } => "io",
            Self::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed { reason } => {
                write!(f, "transport bind failed: {reason}")
            }
            Self::AlreadyListening => write!(f, "transport already listening"),
            Self::InvalidConfig { message } => {
                write!(f, "invalid transport config: {message}")
            }
            Self::UnknownTransport { name } => {
                write!(f, "no transport registered with name '{name}'")
            }
            Self::Io { reason } => write!(f, "transport I/O: {reason}"),
            Self::Shutdown => write!(f, "gateway shutting down"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Handle returned from `Transport::start_http`. Dropping the handle
/// or calling `close` stops accepting new connections; requests
/// already in flight complete at the transport's own cadence.
#[crate::async_trait]
pub trait TransportHandle: Send + Sync {
    /// Operator-visible listen address (for a tunnel: its public
    /// URL). `None` for transports without a meaningful address.
    async fn listen_address(&self) -> Option<String>;

    /// Stop accepting new connections. Idempotent — multiple calls
    /// are safe. Returns when the listener is closed; requests in
    /// flight may still complete after this returns.
    async fn close(&self);
}

/// The `transport` entity trait. Dispatched per-name by the
/// gateway's registry.
#[crate::async_trait]
pub trait Transport: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Self-declared transport name (e.g. `"ngrok-v1"`). Registry
    /// refuses a duplicate plugin for the same name.
    fn name(&self) -> &str;

    /// Start accepting connections. `listener_config` is the
    /// operator-supplied opaque config for this transport; the
    /// transport parses it per its own contract. Every request it
    /// receives goes to `server`.
    ///
    /// Returns a `TransportHandle` whose drop (or explicit `close`)
    /// stops the listener.
    async fn start_http(
        &self,
        listener_config: &Value,
        server: std::sync::Arc<dyn HttpIngressServer>,
    ) -> Result<Box<dyn TransportHandle>, TransportError>;

    /// Called on gateway shutdown. Default is a no-op — the
    /// transport is expected to clean up when the handle returned
    /// from `start_http` is dropped.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_kind_label_bounded() {
        assert_eq!(
            TransportError::BindFailed {
                reason: "EADDRINUSE".into()
            }
            .kind_label(),
            "bind_failed"
        );
        assert_eq!(
            TransportError::AlreadyListening.kind_label(),
            "already_listening"
        );
        assert_eq!(
            TransportError::InvalidConfig {
                message: "no bind addr".into()
            }
            .kind_label(),
            "invalid_config"
        );
        assert_eq!(
            TransportError::UnknownTransport { name: "h3".into() }.kind_label(),
            "unknown_transport"
        );
        assert_eq!(
            TransportError::Io {
                reason: "EIO".into()
            }
            .kind_label(),
            "io"
        );
        assert_eq!(TransportError::Shutdown.kind_label(), "shutdown");
    }

    #[test]
    fn transport_error_display_includes_detail() {
        let e = TransportError::BindFailed {
            reason: "address already in use".into(),
        };
        assert!(e.to_string().contains("address already in use"));

        let e = TransportError::UnknownTransport {
            name: "h3-v1".into(),
        };
        assert!(e.to_string().contains("h3-v1"));
    }

    #[test]
    fn transport_error_json_roundtrip() {
        let e = TransportError::InvalidConfig {
            message: "listener_config has no bind".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: TransportError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
