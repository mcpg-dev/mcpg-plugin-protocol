//! Shared types that cross the plugin boundary.
//!
//! These types are serialization-friendly and do not carry any runtime state.
//! Both host and plugin agree on their shape.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Plugin Context — input to every plugin invocation
// ---------------------------------------------------------------------------

/// Context provided by the host for each plugin invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    /// Gateway-assigned request identifier.
    pub request_id: String,
    /// MCP session identifier (if established).
    pub session_id: Option<String>,
    /// The tool, prompt, resource, resource-template, or completion
    /// binding being invoked. Historically this was always a tool name;
    /// with whole-gateway mediation it carries the name of any
    /// surface the gateway is currently dispatching.
    pub tool_name: String,
    /// MCP surface this invocation is serving. `"tool"` is the legacy
    /// default; other values include `"prompt"`, `"resource"`,
    /// `"resource_template"`, `"completion"`, and `"control_plane"`.
    /// Plugins that only care about tool traffic can filter on this.
    #[serde(default = "default_surface_tool")]
    pub surface: String,
    /// Resolved caller identity.
    pub identity: PluginIdentity,
    /// Transport type (`"http"` or `"stdio"`).
    pub transport: String,
}

fn default_surface_tool() -> String {
    "tool".to_owned()
}

/// Identity of the caller as resolved by the gateway before plugins run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginIdentity {
    /// `"anonymous"`, `"header_asserted"`, or `"verified"`.
    pub kind: String,
    /// Trust level string: `"unauthenticated"`, `"header_asserted"`, `"verified"`.
    pub trust_level: String,
    /// Subject identifier (if authenticated).
    pub subject_id: Option<String>,
    /// Authentication provider name (if present).
    pub auth_provider: Option<String>,
    /// Token issuer (if present).
    pub issuer: Option<String>,
    /// Roles extracted from token claims (OIDC `role_claim_paths`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Groups extracted from token claims (OIDC `group_claim_paths`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Scopes extracted from token claims (OIDC `scope_claim_paths`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Arbitrary attributes from token claim mappings.
    ///
    /// The host also uses one reserved key here — `__mcpg_id_sig` — as the
    /// integrity tag it stamps when handing an identity to a cdylib over the
    /// FFI and verifies when a plugin relays it back (see
    /// `mcpg-plugin-host::identity_sig`). The tag is scoped to the dispatch it
    /// was issued for: relay the identity within the call that carried it, as
    /// every in-tree backend does. An identity kept past the end of its
    /// dispatch no longer verifies. The host strips that key before the
    /// identity is used downstream, so it never reaches the credential-cache
    /// key, an issuer, policy, or audit. Operator claim mappings must not emit
    /// a `__mcpg_*` attribute.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Request Metadata — protocol 1.1
// ---------------------------------------------------------------------------

/// Per-request metadata threaded through identity resolution
/// (and any future plugin kind that needs non-header request
/// context). Introduced in protocol 1.1 alongside native mTLS.
///
/// All fields are optional or have safe defaults — older plugins
/// compiled against protocol 1.0 receive a default-constructed
/// `RequestMetadata` and behave identically to their 1.0
/// behavior (header-only consumers ignore everything except
/// `headers` which they already have).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Remote peer address (post-trusted-proxy hop chain, if the
    /// transport layer applies one). For HTTP, this is the
    /// connection's accept-time peer address. `None` on stdio
    /// or when the transport layer cannot determine it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,

    /// TLS metadata. `None` on plain HTTP, on stdio, or when TLS
    /// terminates upstream and the gateway sees no client cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,

    /// Transport identifier — `"http"`, `"stdio"`, future
    /// `"grpc"` / `"ws"`. Lets identity plugins skip transports
    /// where their assumptions don't hold.
    #[serde(default = "default_transport_http")]
    pub transport: String,

    /// Request path the gateway received (HTTP only). Lets
    /// vhost-style identity plugins discriminate without
    /// re-extracting from headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// HTTP request method the gateway received (HTTP only), e.g.
    /// `"POST"` / `"GET"` / `"DELETE"`. `None` on stdio or when the
    /// transport cannot determine it. Signature-based identity plugins
    /// (e.g. RFC 9421 / AAuth) need it as a covered `@method` component;
    /// additive and serde-defaulted, so it crosses the JSON metadata FFI
    /// without an ABI change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Raw query string the gateway received (HTTP only), WITHOUT the
    /// leading `?` (e.g. `"scope=read&x=1"`). `None` when the request had
    /// no query. Signature-based identity plugins need it to reconstruct
    /// the RFC 9421 `@query` covered component; `path` stays query-free.
    /// Additive + serde-defaulted (no ABI change).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

fn default_transport_http() -> String {
    "http".to_owned()
}

/// TLS handshake metadata. Populated by the gateway when an
/// mTLS connection terminates at the gateway itself; absent when
/// TLS terminates upstream (use header-injection sources via
/// `dev.mcpg.identity.mtls`).
///
/// All cert-chain fields are pre-parsed by the gateway once at
/// handshake time — plugins read directly without reparsing
/// DER.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    /// SNI server-name the client presented in the handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Whether the gateway negotiated client-cert authentication.
    /// `false` when no client cert was presented or required.
    #[serde(default)]
    pub client_cert_present: bool,

    /// Full client cert chain in DER form, leaf first. Empty
    /// when `client_cert_present == false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_cert_chain_der: Vec<Vec<u8>>,

    /// Pre-parsed leaf-cert subject DN (RFC 4514 form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_subject_dn: Option<String>,

    /// Pre-parsed leaf-cert issuer DN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_issuer_dn: Option<String>,

    /// SubjectAltName URI entries from the leaf cert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_cert_san_uris: Vec<String>,

    /// SubjectAltName DNS entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_cert_san_dns: Vec<String>,

    /// SubjectAltName email entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_cert_san_emails: Vec<String>,

    /// SHA-256 of each cert in the chain, leaf first, hex
    /// lowercase.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_cert_chain_sha256: Vec<String>,

    /// Cert validity bounds (RFC3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_not_after: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool Gate Types
// ---------------------------------------------------------------------------

/// Decision returned by a tool-gate plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GateDecision {
    /// Allow the request to proceed.
    Allow {
        /// If set, replace the tool arguments with these.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        modified_arguments: Option<serde_json::Value>,
        /// If set, replace the tool result with this (post-dispatch only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        modified_result: Option<serde_json::Value>,
        /// Plugin-supplied metadata attached to `_meta` on the response.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
    },
    /// Deny the request with a structured error.
    Deny {
        /// HTTP status code to return (e.g. 403).
        http_status: u16,
        /// JSON-RPC error code.
        code: i32,
        /// Human-readable error message.
        message: String,
        /// Optional structured error data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_data: Option<serde_json::Value>,
    },
    /// Return a challenge to the client (e.g. payment challenge).
    Challenge {
        /// HTTP status code (e.g. 402).
        http_status: u16,
        /// JSON-RPC error code.
        code: i32,
        /// Human-readable message.
        message: String,
        /// Challenge payload for the client.
        challenge_data: serde_json::Value,
    },
    /// Pause the tool call pending human approval (protocol
    /// 1.2). The gateway intercepts: stores the in-
    /// flight request indexed by `approval_id`, dispatches the
    /// `ApprovalRequest` to bound `approval_notifier` plugins,
    /// then awaits resolution via the dispatched notifier's
    /// callback OR a direct HMAC-signed POST to
    /// `/webhooks/approvals/<approval_id>`. The tool call
    /// resumes on Approve, returns 403 on Deny, and 503 on
    /// dispatch failure / timeout.
    PendingApproval {
        /// Unique id for this in-flight approval. The plugin
        /// generates it (typically a UUID); the gateway uses it
        /// as the lookup key in the in-flight state map +
        /// embeds it in callback URLs + passes it to notifier
        /// plugins.
        approval_id: String,
        /// Approval deadline (RFC3339). After this the gateway
        /// times out + denies the request even if the notifier
        /// hasn't responded.
        deadline_at: String,
        /// Operator-supplied summary of WHAT requires approval.
        /// Surfaces in approval messages (Slack message body,
        /// email subject, etc.).
        summary: String,
        /// Optional list of `approval_notifier` plugin ids to
        /// dispatch to. Empty (default) = use every bound
        /// notifier in registration order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        target_notifiers: Vec<String>,
        /// Free-form metadata the notifier reads (channel name,
        /// mention list, severity, etc.). Plugin-specific
        /// shape; documented per-notifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
    },
}

impl GateDecision {
    /// Convenience: create an Allow with no modifications.
    pub fn allow() -> Self {
        Self::Allow {
            modified_arguments: None,
            modified_result: None,
            metadata: None,
        }
    }

    /// Convenience: create an Allow that attaches metadata.
    pub fn allow_with_metadata(metadata: serde_json::Value) -> Self {
        Self::Allow {
            modified_arguments: None,
            modified_result: None,
            metadata: Some(metadata),
        }
    }

    /// Returns true if this decision allows the request to proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

// ---------------------------------------------------------------------------
// Transform Types
// ---------------------------------------------------------------------------

/// Result of a transform plugin invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TransformResult {
    /// No changes — pass through the original value.
    Unchanged,
    /// The plugin produced a modified value.
    Modified { value: serde_json::Value },
    /// The plugin encountered an error.
    Error { message: String },
}

// ---------------------------------------------------------------------------
// Identity Types
// ---------------------------------------------------------------------------

/// Result of an identity plugin resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum IdentityResolution {
    /// Identity resolved successfully.
    Resolved { identity: PluginIdentity },
    /// No token/credential found — fall through to next resolver.
    None,
    /// Token found but invalid.
    Invalid {
        reason: String,
        /// Response headers the transport should attach to the resulting
        /// authentication-failure response — e.g. AAuth's `Signature-Error`
        /// and `Accept-Signature-*` diagnostics. `(name, value)` pairs,
        /// lowercase names. Additive field: absent means none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        response_headers: Vec<(String, String)>,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_decision_allow_roundtrip() {
        let decision = GateDecision::allow();
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_allow());
    }

    #[test]
    fn gate_decision_deny_roundtrip() {
        let decision = GateDecision::Deny {
            http_status: 403,
            code: -32044,
            message: "access denied".into(),
            error_data: None,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_allow());
    }

    #[test]
    fn gate_decision_challenge_roundtrip() {
        let decision = GateDecision::Challenge {
            http_status: 402,
            code: -32099,
            message: "payment required".into(),
            challenge_data: serde_json::json!({"challenge_id": "abc123"}),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("challenge"));
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_allow());
    }

    #[test]
    fn gate_decision_pending_approval_roundtrip() {
        let decision = GateDecision::PendingApproval {
            approval_id: "appr_01HFXYZ".into(),
            deadline_at: "2026-04-26T10:00:00Z".into(),
            summary: "rm /etc/passwd requires approval".into(),
            target_notifiers: vec!["security.tool-gate-slack-approval".into()],
            metadata: Some(serde_json::json!({"risk": "high"})),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("pending_approval"));
        assert!(json.contains("appr_01HFXYZ"));
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_allow());
        match parsed {
            GateDecision::PendingApproval {
                approval_id,
                target_notifiers,
                ..
            } => {
                assert_eq!(approval_id, "appr_01HFXYZ");
                assert_eq!(target_notifiers.len(), 1);
            }
            _ => panic!("expected PendingApproval"),
        }
    }

    #[test]
    fn gate_decision_pending_approval_minimal_omits_optional_fields() {
        let decision = GateDecision::PendingApproval {
            approval_id: "appr_minimal".into(),
            deadline_at: "2026-04-26T10:00:00Z".into(),
            summary: "summary".into(),
            target_notifiers: Vec::new(),
            metadata: None,
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(!json.contains("target_notifiers"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn transform_result_roundtrip() {
        let result = TransformResult::Modified {
            value: serde_json::json!({"redacted": true}),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: TransformResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, TransformResult::Modified { .. }));
    }

    #[test]
    fn identity_resolution_roundtrip() {
        let res = IdentityResolution::Resolved {
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("user-123".into()),
                auth_provider: Some("okta".into()),
                issuer: Some("https://okta.example.com".into()),
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        };
        let json = serde_json::to_string(&res).unwrap();
        let parsed: IdentityResolution = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IdentityResolution::Resolved { .. }));
    }

    #[test]
    fn plugin_context_serialization() {
        let ctx = PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-001".into(),
            session_id: Some("sess-001".into()),
            tool_name: "orders.list".into(),
            identity: PluginIdentity {
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
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("orders.list"));
        assert!(json.contains("req-001"));
    }
}
