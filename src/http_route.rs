//! `http_route` entity kind — custom HTTP handlers mounted on the
//! gateway's HTTP listener.
//!
//! Per spec §9.7, canonical use cases:
//!
//! - Health / readiness probes beyond the gateway's built-in
//!   `/healthz` / `/readyz`.
//! - Prometheus exposition format variants.
//! - Webhook receivers (inbound HTTP into the gateway).
//! - OAuth callback landing URLs.
//! - Elicitation URL callbacks (UCP / ACP).
//! - Operator admin UI extensions mounted under `/plugins/{id}/*`.
//!
//! # Mount policy
//!
//! - **Namespaced** (default, always allowed): the plugin's routes
//!   mount under `/plugins/{plugin_id}/{entity_name}/*`. No
//!   collisions possible; no operator action needed beyond enabling
//!   the plugin.
//! - **Override** (opt-in, not yet wired): the plugin
//!   declares a top-level path AND the operator sets
//!   `plugins[…].http_route.allow_path_override: true`. The
//!   gateway refuses override if two plugins claim the same path.
//! - **Reserved paths** — never overridable: `/`, `/mcp`,
//!   `/.well-known/*`.
//!
//! # Streaming
//!
//! The response body is an [`HttpBody`] enum: either bytes (most
//! handlers) or a stream of [`HttpChunk`]s (SSE, long-running
//! responses). Streaming support is optional; a handler that sets
//! `RouteSpec.streaming = false` MUST return `HttpBody::Bytes` and
//! the host rejects `HttpBody::Stream` with a 500.

use std::collections::BTreeMap;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

/// One HTTP route the plugin exposes. Multiple routes per plugin are
/// allowed; the host builds a dispatch table from all declared
/// `RouteSpec`s across every registered `http_route` entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSpec {
    /// HTTP method — `"GET"`, `"POST"`, etc., case-insensitive. `"*"`
    /// matches any method (use sparingly; method-aware routes are
    /// easier to reason about).
    ///
    /// Intentionally an OPEN string (the gateway matches it
    /// case-insensitively against the incoming request method), NOT a
    /// closed enum: `http_route` plugins serve arbitrary verbs (webhooks,
    /// health checks, callbacks) so the method vocabulary can't be
    /// closed here. This is a different layer from the *backend* binding
    /// `method:` field (`HttpBackendMethod`, a closed GET/POST enum) —
    /// that one drives request shaping for a single upstream call, so a
    /// closed set is correct there. The two are deliberately distinct.
    pub method: String,

    /// Path pattern, relative to the plugin's mount point in
    /// namespaced mode (i.e., relative to
    /// `/plugins/{plugin_id}/{entity_name}/`). Supports `:name`
    /// placeholders that surface in
    /// [`HttpRouteRequest::path_params`].
    ///
    /// Examples:
    /// - `"/health"` → mounted at `/plugins/{id}/{entity}/health`
    /// - `"/webhooks/:name"` → captures `name` as a path param.
    pub path: String,

    /// If `true`, the host rejects unauthenticated requests with a
    /// 401 before dispatching to `handle`. If `false`, the handler
    /// receives `HttpRouteRequest.identity = None` for unauthenticated
    /// callers and decides how to respond. Default: `false` (handler
    /// decides; health endpoints typically want this).
    #[serde(default)]
    pub requires_identity: bool,

    /// If `true`, the handler MAY return `HttpBody::Stream`. If
    /// `false`, the host rejects a streaming response with a 500.
    /// Default: `false`.
    #[serde(default)]
    pub streaming: bool,

    /// Maximum request body size in bytes. `None` uses the host's
    /// transport-level default (today 1 MiB). The host enforces by
    /// truncating + returning 413 Payload Too Large.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
}

/// Request payload passed to [`HttpRoute::handle`].
///
/// Every field is populated by the host before dispatch. Identity is
/// resolved via the identity chain (§9.3) and reflects whatever the
/// caller's credentials produced — `Some(anonymous)` for anonymous
/// traffic, `None` only if no identity resolver ran (stdio transport
/// wouldn't be routed here).
#[derive(Debug, Clone)]
pub struct HttpRouteRequest {
    pub method: String,
    /// Full path as received, including the plugin's mount prefix.
    /// Handlers typically ignore this and use `path_params` for
    /// parameterised routes.
    pub full_path: String,
    pub path_params: BTreeMap<String, String>,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
    pub identity: Option<PluginIdentity>,
    pub request_id: String,
    pub remote_addr: Option<String>,
}

/// Response from [`HttpRoute::handle`].
#[derive(Debug)]
pub struct HttpRouteResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: HttpBody,
}

impl HttpRouteResponse {
    /// Plain `200 OK` with an opaque byte payload + caller-supplied
    /// content-type.
    pub fn ok_bytes<B: Into<bytes::Bytes>>(content_type: &str, body: B) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), content_type.to_owned())],
            body: HttpBody::Bytes(body.into()),
        }
    }

    /// `200 OK` with a JSON-encoded body.
    pub fn ok_json<T: Serialize>(value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self::ok_bytes("application/json", body)
    }

    /// Simple status-only response (empty body, no custom headers).
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: vec![],
            body: HttpBody::Bytes(bytes::Bytes::new()),
        }
    }

    /// `4xx` / `5xx` with a JSON `{"error": "..."}` body.
    pub fn error_json(status: u16, message: impl Into<String>) -> Self {
        let msg = message.into();
        let body = serde_json::to_vec(&serde_json::json!({ "error": msg }))
            .unwrap_or_else(|_| b"{}".to_vec());
        Self::error_bytes(status, "application/json", body)
    }

    /// Custom-status body with caller-supplied content-type.
    pub fn error_bytes<B: Into<bytes::Bytes>>(status: u16, content_type: &str, body: B) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), content_type.to_owned())],
            body: HttpBody::Bytes(body.into()),
        }
    }
}

/// Response body. `Bytes` is the common path; `Stream` is for SSE /
/// chunked responses on routes that declared `streaming: true`.
pub enum HttpBody {
    Bytes(bytes::Bytes),
    /// Async stream of chunks. Keyed off `HttpChunk::End` or stream
    /// exhaustion. The host closes the TCP connection once the stream
    /// terminates.
    Stream(Pin<Box<dyn futures_core::Stream<Item = HttpChunk> + Send + 'static>>),
}

impl std::fmt::Debug for HttpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpBody::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            HttpBody::Stream(_) => f.debug_tuple("Stream").field(&"..").finish(),
        }
    }
}

/// One element of a streaming body.
#[derive(Debug)]
pub enum HttpChunk {
    /// Raw bytes (chunked Transfer-Encoding).
    Data(bytes::Bytes),
    /// SSE-named event (`event:` / `data:` framing on the wire).
    Event { name: String, data: bytes::Bytes },
    /// End-of-stream marker. The host MUST close the connection after
    /// emitting any preceding chunks; any subsequent chunk from the
    /// stream is dropped with a warning.
    End,
}

// ---------------------------------------------------------------------------
// FFI wire types
// ---------------------------------------------------------------------------
//
// The native-plugin FFI boundary is synchronous and JSON-marshalled
// (matching the `BackendRequest` / `BackendResponse` pattern). The
// in-tree async trait types (`HttpRouteRequest`, `HttpRouteResponse`)
// carry `bytes::Bytes` and a boxed `Stream` trait object for streaming
// bodies — neither is serde-friendly, so we mirror them with wire-safe
// companions here.
//
// **Constraint on the non-streaming `handle` slot.** A plugin that
// returns `HttpBody::Stream` through the bytes-only FFI adapter will be
// rejected by the host with a 500. Streaming response bodies instead go
// through the dedicated `handle_streaming` slot, which uses a
// callback-based chunk channel (`EventSinkRef` / `BytesSinkRef`).

/// Wire-format mirror of [`HttpRouteRequest`] for FFI transport.
/// Identical field surface; `body` is a plain `Vec<u8>` so the
/// struct is `serde`-derivable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteRequestWire {
    pub method: String,
    pub full_path: String,
    pub path_params: BTreeMap<String, String>,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub identity: Option<PluginIdentity>,
    pub request_id: String,
    pub remote_addr: Option<String>,
}

/// Wire-format mirror of [`HttpRouteResponse`] for FFI transport.
/// Bytes-only — `HttpBody::Stream` is refused when converting from
/// the native response (see [`HttpRouteFfiError::Streaming`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteResponseWire {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Reasons an FFI adapter may refuse to marshal an HTTP route
/// response across the ABI boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum HttpRouteFfiError {
    /// The plugin returned a streaming response body through the
    /// bytes-only `handle` adapter, which only supports bytes bodies.
    Streaming,
}

impl std::fmt::Display for HttpRouteFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Streaming => {
                f.write_str("streaming response bodies are not supported across the FFI boundary")
            }
        }
    }
}

impl std::error::Error for HttpRouteFfiError {}

impl From<HttpRouteRequest> for HttpRouteRequestWire {
    fn from(src: HttpRouteRequest) -> Self {
        Self {
            method: src.method,
            full_path: src.full_path,
            path_params: src.path_params,
            query: src.query,
            headers: src.headers,
            body: src.body.to_vec(),
            identity: src.identity,
            request_id: src.request_id,
            remote_addr: src.remote_addr,
        }
    }
}

impl From<HttpRouteRequestWire> for HttpRouteRequest {
    fn from(src: HttpRouteRequestWire) -> Self {
        Self {
            method: src.method,
            full_path: src.full_path,
            path_params: src.path_params,
            query: src.query,
            headers: src.headers,
            body: bytes::Bytes::from(src.body),
            identity: src.identity,
            request_id: src.request_id,
            remote_addr: src.remote_addr,
        }
    }
}

impl TryFrom<HttpRouteResponse> for HttpRouteResponseWire {
    type Error = HttpRouteFfiError;

    fn try_from(src: HttpRouteResponse) -> Result<Self, Self::Error> {
        let body = match src.body {
            HttpBody::Bytes(b) => b.to_vec(),
            HttpBody::Stream(_) => return Err(HttpRouteFfiError::Streaming),
        };
        Ok(Self {
            status: src.status,
            headers: src.headers,
            body,
        })
    }
}

impl From<HttpRouteResponseWire> for HttpRouteResponse {
    fn from(src: HttpRouteResponseWire) -> Self {
        Self {
            status: src.status,
            headers: src.headers,
            body: HttpBody::Bytes(bytes::Bytes::from(src.body)),
        }
    }
}

/// Serde-derivable mirror of [`HttpChunk`] for FFI streaming.
/// Plugins emit `HttpChunkWire::End` when their source stream
/// exhausts; host's Stream adapter terminates on `End`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpChunkWire {
    Data { data: Vec<u8> },
    Event { name: String, data: Vec<u8> },
    End,
}

impl From<HttpChunk> for HttpChunkWire {
    fn from(c: HttpChunk) -> Self {
        match c {
            HttpChunk::Data(b) => Self::Data { data: b.to_vec() },
            HttpChunk::Event { name, data } => Self::Event {
                name,
                data: data.to_vec(),
            },
            HttpChunk::End => Self::End,
        }
    }
}

impl From<HttpChunkWire> for HttpChunk {
    fn from(w: HttpChunkWire) -> Self {
        match w {
            HttpChunkWire::Data { data } => Self::Data(bytes::Bytes::from(data)),
            HttpChunkWire::Event { name, data } => Self::Event {
                name,
                data: bytes::Bytes::from(data),
            },
            HttpChunkWire::End => Self::End,
        }
    }
}

/// Head portion of a streaming HTTP response. The plugin returns
/// this up-front (status + headers); chunks arrive on the sink.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpStreamHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// The `http_route` entity trait. A plugin providing HTTP extensions
/// implements this and declares its routes in `routes()`.
#[crate::async_trait]
pub trait HttpRoute: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Per-plugin route declarations. Invoked once at registration
    /// time by the host to build its dispatch table.
    fn routes(&self) -> Vec<RouteSpec>;

    /// Handle a request that matched one of this plugin's declared
    /// routes. Implementations SHOULD be short — long operations
    /// should spawn a background task and return an accepted/pending
    /// response.
    async fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse;

    /// Called on gateway shutdown. Default is a no-op; plugins with
    /// buffered state (webhook reply queues, in-flight uploads) MAY
    /// override to flush before the host drops the handle.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_spec_serializes_with_defaults_hidden() {
        let spec = RouteSpec {
            method: "GET".into(),
            path: "/health".into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: None,
        };
        let json = serde_json::to_value(&spec).unwrap();
        // `max_body_bytes: None` is skipped; the booleans serialize
        // as false explicitly (they aren't `skip_serializing_if`).
        assert_eq!(json["method"], "GET");
        assert_eq!(json["path"], "/health");
        assert!(json.get("max_body_bytes").is_none());
    }

    #[test]
    fn ok_json_builds_content_type_and_body() {
        #[derive(serde::Serialize)]
        struct Payload {
            status: &'static str,
        }
        let resp = HttpRouteResponse::ok_json(&Payload { status: "ok" });
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.iter().find(|(k, _)| k == "Content-Type"),
            Some(&("Content-Type".to_owned(), "application/json".to_owned()))
        );
        match &resp.body {
            HttpBody::Bytes(b) => {
                let parsed: serde_json::Value = serde_json::from_slice(b).unwrap();
                assert_eq!(parsed["status"], "ok");
            }
            _ => panic!("expected bytes body"),
        }
    }

    #[test]
    fn error_json_formats_payload() {
        let resp = HttpRouteResponse::error_json(404, "not found");
        assert_eq!(resp.status, 404);
        match &resp.body {
            HttpBody::Bytes(b) => {
                let parsed: serde_json::Value = serde_json::from_slice(b).unwrap();
                assert_eq!(parsed["error"], "not found");
            }
            _ => panic!("expected bytes body"),
        }
    }

    #[test]
    fn status_builds_empty_body() {
        let resp = HttpRouteResponse::status(204);
        assert_eq!(resp.status, 204);
        match &resp.body {
            HttpBody::Bytes(b) => assert_eq!(b.len(), 0),
            _ => panic!("expected bytes body"),
        }
    }

    fn sample_request() -> HttpRouteRequest {
        let mut path_params = BTreeMap::new();
        path_params.insert("id".into(), "42".into());
        HttpRouteRequest {
            method: "POST".into(),
            full_path: "/plugins/foo/webhook/42".into(),
            path_params,
            query: vec![("q".into(), "1".into())],
            headers: vec![("content-type".into(), "application/json".into())],
            body: bytes::Bytes::from_static(b"{\"hello\":\"world\"}"),
            identity: None,
            request_id: "req-1".into(),
            remote_addr: Some("10.0.0.1:4242".into()),
        }
    }

    #[test]
    fn wire_request_roundtrip_preserves_all_fields() {
        let req = sample_request();
        let wire: HttpRouteRequestWire = req.clone().into();
        let encoded = serde_json::to_string(&wire).unwrap();
        let decoded: HttpRouteRequestWire = serde_json::from_str(&encoded).unwrap();
        let back: HttpRouteRequest = decoded.into();
        assert_eq!(back.method, req.method);
        assert_eq!(back.full_path, req.full_path);
        assert_eq!(back.path_params, req.path_params);
        assert_eq!(back.query, req.query);
        assert_eq!(back.headers, req.headers);
        assert_eq!(back.body.as_ref(), req.body.as_ref());
        assert_eq!(back.request_id, req.request_id);
        assert_eq!(back.remote_addr, req.remote_addr);
    }

    #[test]
    fn wire_response_roundtrip_preserves_bytes_body() {
        let resp = HttpRouteResponse::ok_bytes("text/plain", "hello");
        let wire: HttpRouteResponseWire = resp.try_into().unwrap();
        let encoded = serde_json::to_string(&wire).unwrap();
        let decoded: HttpRouteResponseWire = serde_json::from_str(&encoded).unwrap();
        let back: HttpRouteResponse = decoded.into();
        assert_eq!(back.status, 200);
        match &back.body {
            HttpBody::Bytes(b) => assert_eq!(b.as_ref(), b"hello"),
            _ => panic!("expected bytes body"),
        }
    }

    #[test]
    fn wire_response_conversion_refuses_streaming() {
        use futures_core::Stream;
        use std::pin::Pin;
        let empty: Pin<Box<dyn Stream<Item = HttpChunk> + Send + 'static>> =
            Box::pin(futures_util_stub::empty());
        let resp = HttpRouteResponse {
            status: 200,
            headers: vec![],
            body: HttpBody::Stream(empty),
        };
        let err = HttpRouteResponseWire::try_from(resp).unwrap_err();
        assert_eq!(err, HttpRouteFfiError::Streaming);
    }

    /// Zero-dep tiny stand-in for `futures_util::stream::empty` so the
    /// test can construct an `HttpBody::Stream` without pulling in
    /// futures-util as a dev-dep (the crate already has futures-core).
    mod futures_util_stub {
        use super::HttpChunk;
        use futures_core::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        pub fn empty() -> Empty {
            Empty
        }

        pub struct Empty;

        impl Stream for Empty {
            type Item = HttpChunk;
            fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Ready(None)
            }
        }
    }
}
