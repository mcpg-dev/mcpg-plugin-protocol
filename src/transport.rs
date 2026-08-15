//! `transport` entity kind — the MCP wire transport itself
//! (spec §9.6).
//!
//! A transport accepts incoming connections, parses MCP messages,
//! identifies sessions, and hands every received message to the
//! gateway's `MessageDispatcher`. Canonical built-ins: HTTP, stdio.
//! Extension path: WebSocket, gRPC, custom protocol bridges.
//!
//! # Composition
//!
//! Keyed by transport name. A transport self-declares its name
//! (`"http-v1"`, `"stdio-v1"`, `"websocket-v1"`, ...); one name is
//! served by exactly one active plugin. Operators enable transports
//! via `server.transports[]` (each `{ kind: <plugin_id> }`); the
//! plugin's own `config:` carries any listener settings.
//!
//! # Not Wasm-reachable
//!
//! Transports live at the process boundary and need host-level
//! network access. The Wasm tier's capability surface doesn't
//! expose raw sockets, so this entity kind is native-only. Wasm
//! plugins that need a custom transport bridge delegate to a
//! native transport plugin.
//!
//! # Session identification
//!
//! Each transport is responsible for assigning the `session_id`
//! it passes to `MessageDispatcher::dispatch`. HTTP uses a cookie
//! or header; stdio uses a single synthetic id (there is one
//! session); WebSocket uses the connection id. The gateway treats
//! `session_id` as opaque — transports define their own mapping.

use std::pin::Pin;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;

/// Stream of outbound frames for a streaming reply (SSE, WebSocket
/// text frames, chunked HTTP). Kept as a separate alias — several
/// entity kinds return `Bytes` streams and they all share this
/// type name pattern.
pub type BoxBytesStream = Pin<Box<dyn futures_core::Stream<Item = Bytes> + Send + 'static>>;

/// Response returned by `MessageDispatcher::dispatch`.
///
/// Exactly one of `reply` / `stream` is populated:
///   - `reply: Some(bytes)` — the message has a single reply the
///     transport should send back (HTTP POST /messages, stdio
///     request).
///   - `stream: Some(stream)` — the message opens a streaming
///     channel the transport should forward frame-by-frame (SSE
///     subscription, long-lived WebSocket read).
///
/// A dispatcher returning both populated is a bug; consumers MUST
/// treat `reply` as precedence and ignore `stream` if both are
/// set. (The protocol defines precedence rather than panicking so
/// that a buggy dispatcher doesn't wedge the transport.)
pub struct DispatchResponse {
    pub reply: Option<Bytes>,
    pub stream: Option<BoxBytesStream>,
}

impl std::fmt::Debug for DispatchResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchResponse")
            .field("reply_len", &self.reply.as_ref().map(|b| b.len()))
            .field("has_stream", &self.stream.is_some())
            .finish()
    }
}

impl DispatchResponse {
    /// Shorthand for a unary reply with no streaming channel.
    pub fn unary(reply: impl Into<Bytes>) -> Self {
        Self {
            reply: Some(reply.into()),
            stream: None,
        }
    }

    /// Shorthand for a streaming response with no single reply.
    pub fn streaming(stream: BoxBytesStream) -> Self {
        Self {
            reply: None,
            stream: Some(stream),
        }
    }

    /// Shorthand for an ack with no reply (fire-and-forget
    /// notification). Transports MUST accept this — some MCP
    /// messages are notifications.
    pub fn ack() -> Self {
        Self {
            reply: None,
            stream: None,
        }
    }
}

/// Errors the gateway's dispatcher returns to the transport.
/// Kept small — the transport doesn't route on most of these; it
/// logs + closes or re-tries per its own policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DispatcherError {
    /// No session matches `session_id` — either never existed or
    /// expired. Transport MAY close the connection.
    SessionNotFound,
    /// The message bytes did not parse as MCP. Transport typically
    /// responds to the peer with a JSON-RPC parse-error reply and
    /// keeps the session open.
    InvalidMessage { reason: String },
    /// Gateway-internal failure (plugin chain panic, backend
    /// unavailable, ...). Transport logs + keeps serving other
    /// sessions.
    Internal { reason: String },
    /// Gateway is draining — don't accept new messages on this
    /// session. Transport SHOULD close the connection gracefully.
    Shutdown,
}

impl DispatcherError {
    /// Bounded metrics label.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::SessionNotFound => "session_not_found",
            Self::InvalidMessage { .. } => "invalid_message",
            Self::Internal { .. } => "internal",
            Self::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for DispatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "session not found"),
            Self::InvalidMessage { reason } => {
                write!(f, "invalid message: {reason}")
            }
            Self::Internal { reason } => write!(f, "internal: {reason}"),
            Self::Shutdown => write!(f, "gateway shutting down"),
        }
    }
}

impl std::error::Error for DispatcherError {}

/// The gateway-provided interface the transport calls on every
/// received message. The gateway implements this; the transport
/// receives it as `Arc<dyn MessageDispatcher>` in `start`.
#[crate::async_trait]
pub trait MessageDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        session_id: &str,
        message: Bytes,
    ) -> Result<DispatchResponse, DispatcherError>;
}

/// Failure modes for transport lifecycle operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportError {
    /// Binding the listener failed (port in use, permission
    /// denied, invalid address, ...).
    BindFailed { reason: String },
    /// `start` called twice without an intervening `close` on the
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

/// Handle returned from `Transport::start`. Dropping the handle
/// or calling `close` stops accepting new sessions; already-
/// in-flight sessions complete at the transport's own cadence.
#[crate::async_trait]
pub trait TransportHandle: Send + Sync {
    /// Operator-visible listen address (e.g. `"0.0.0.0:8080"` for
    /// HTTP, `"stdio"` for stdio). `None` for transports without
    /// a meaningful address.
    async fn listen_address(&self) -> Option<String>;

    /// Stop accepting new sessions. Idempotent — multiple calls
    /// are safe. Returns when the listener is closed; in-flight
    /// sessions may still complete after this returns.
    async fn close(&self);
}

/// The `transport` entity trait. Dispatched per-name by the
/// gateway's registry.
#[crate::async_trait]
pub trait Transport: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Self-declared transport name (e.g. `"http-v1"`,
    /// `"stdio-v1"`, `"websocket-v1"`). Registry refuses a
    /// duplicate plugin for the same name.
    fn name(&self) -> &str;

    /// Start accepting sessions. `listener_config` is the operator-
    /// supplied opaque config for this transport (HTTP bind
    /// address + TLS certs, stdio line delimiter, ...); the
    /// transport parses it per its own contract. `dispatcher` is
    /// the gateway-supplied callback the transport invokes on
    /// every received message.
    ///
    /// Returns a `TransportHandle` whose drop (or explicit
    /// `close`) stops the listener.
    async fn start(
        &self,
        listener_config: &Value,
        dispatcher: std::sync::Arc<dyn MessageDispatcher>,
    ) -> Result<Box<dyn TransportHandle>, TransportError>;

    /// Called on gateway shutdown. Default is a no-op — the
    /// transport is expected to clean up when the handle returned
    /// from `start` is dropped.
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
    fn dispatcher_error_kind_label_bounded() {
        assert_eq!(
            DispatcherError::SessionNotFound.kind_label(),
            "session_not_found"
        );
        assert_eq!(
            DispatcherError::InvalidMessage {
                reason: "not JSON".into()
            }
            .kind_label(),
            "invalid_message"
        );
        assert_eq!(
            DispatcherError::Internal {
                reason: "panic".into()
            }
            .kind_label(),
            "internal"
        );
        assert_eq!(DispatcherError::Shutdown.kind_label(), "shutdown");
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
    fn dispatcher_error_display_includes_detail() {
        let e = DispatcherError::InvalidMessage {
            reason: "unterminated string".into(),
        };
        assert!(e.to_string().contains("unterminated string"));
    }

    #[test]
    fn dispatch_response_unary_ok() {
        let r = DispatchResponse::unary(b"pong".to_vec());
        assert_eq!(r.reply.as_deref(), Some(b"pong".as_slice()));
        assert!(r.stream.is_none());
    }

    #[test]
    fn dispatch_response_ack_has_neither() {
        let r = DispatchResponse::ack();
        assert!(r.reply.is_none());
        assert!(r.stream.is_none());
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

    #[test]
    fn dispatcher_error_json_roundtrip() {
        let e = DispatcherError::Internal {
            reason: "plugin panicked".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: DispatcherError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
