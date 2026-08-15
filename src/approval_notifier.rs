//! `approval_notifier` entity kind — human-approval workflow
//! notification delivery (protocol 1.2).
//!
//! When a `tool_gate` plugin returns `GateDecision::PendingApproval`
//! the gateway:
//!
//! 1. Stores the in-flight request indexed by `approval_id`.
//! 2. Builds a `NotificationRequest` describing what's awaiting
//!    approval (caller, tool, summary, deadline, callback URL).
//! 3. Dispatches the request to one or more bound
//!    `approval_notifier` plugins (Slack, email, PagerDuty,
//!    Microsoft Teams, etc.).
//! 4. Awaits resolution via either the notifier-handled callback
//!    (e.g. the Slack interactive button POST) or a direct
//!    HMAC-signed POST to the gateway's
//!    `/webhooks/approvals/<approval_id>` endpoint.
//!
//! Notifier plugins are the shipping mechanism — they're
//! responsible for posting the approval request to the right
//! channel + extracting the human's response. They MUST NOT make
//! the approval decision themselves; that's always the human's
//! call (or, in v0.2, a programmatic policy).
//!
//! # Composition
//!
//! Operators bind one or more notifiers in `plugins[]`.
//! When the tool_gate's `PendingApproval` carries
//! `target_notifiers: []`, every bound notifier receives the
//! request (fan-out). When it lists specific plugin ids, only
//! those are dispatched to.
//!
//! # Side-effect contract
//!
//! Notifiers MAY (and typically DO) make outbound network
//! requests — to Slack, email servers, PagerDuty, etc. The
//! `notify()` call returns once the message is posted; the
//! gateway then awaits a separate resolution callback. Notifier
//! plugins SHOULD validate their channel config at registration
//! time (`from_config_json`) and panic on invalid config.
//!
//! # `cap.host.outbound_http`
//!
//! Most notifiers (Slack, email-via-API, PagerDuty) require this
//! capability. Operators authorise it explicitly. The plugin
//! manifest declares `required_capabilities: [cap.host.outbound_http]`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

// ---------------------------------------------------------------------------
// Request + Result types
// ---------------------------------------------------------------------------

/// What the gateway hands a notifier when an approval is in
/// flight. Carries everything the notifier needs to post a
/// message and let the human resolve it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Unique id for this approval — same value the
    /// `GateDecision::PendingApproval` variant carried. Notifiers
    /// embed it in their interactive UI so the resolution
    /// callback knows which approval the human responded to.
    pub approval_id: String,

    /// Operator-supplied summary of what needs approval.
    pub summary: String,

    /// Approval deadline (RFC3339). The gateway times out + denies
    /// the request after this; notifiers SHOULD honour the
    /// deadline by ignoring late button presses (the gateway
    /// rejects late resolutions anyway via the in-flight state
    /// map's expiry check).
    pub deadline_at: String,

    /// HMAC-signed callback URL the notifier embeds in its
    /// interactive UI. POSTing to this URL with body
    /// `{"outcome": "approve" | "deny", "reason": "..."}` resolves
    /// the approval. Used as a fallback / alternative path when
    /// the notifier doesn't have its own callback handler.
    /// The HMAC stops anyone-with-the-link from forging
    /// resolutions.
    pub direct_callback_url: String,

    /// Caller identity — who's asking for approval.
    pub identity: PluginIdentity,

    /// MCP tool / surface being invoked.
    pub tool_name: String,

    /// Tool-call arguments (redacted by upstream policy if
    /// applicable). Notifiers SHOULD render this in the approval
    /// message so the human can decide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,

    /// Free-form metadata from the
    /// `GateDecision::PendingApproval` variant. Notifier-specific
    /// shape (channel name, mention list, severity, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// What the notifier returns from a successful `notify()` call.
/// Surfaced via audit + observability.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationResult {
    /// Operator-readable identifier for the dispatched message.
    /// Conventional shapes:
    ///
    /// - `"slack:#approvals:<thread-ts>"`
    /// - `"email:<recipient>:<message-id>"`
    /// - `"pagerduty:<incident-id>"`
    ///
    /// Used in audit + admin endpoints to surface "where did this
    /// approval go?" and to support per-channel rate-limit /
    /// throttle observability.
    pub channel: String,

    /// Plugin-specific metadata (e.g. Slack channel id, message
    /// timestamp). Useful for downstream reconciliation or for the
    /// notifier's own resolution-callback path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Notifier failure surface. Returned errors are typed so the
/// gateway can map to the right outcome (try the next notifier
/// in the chain, fail-closed deny, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationError {
    /// Backend (Slack, email server, PagerDuty) unreachable.
    /// Gateway tries the next bound notifier.
    Backend { reason: String },
    /// Operator config error (channel doesn't exist, token
    /// invalid, etc.). Should have been caught at boot but may
    /// surface at runtime if the backend's state changed.
    Misconfigured { reason: String },
    /// Backend rate-limited the notifier. Gateway tries the next
    /// notifier; v0.2 may add per-notifier backoff.
    Throttled { reason: String },
    /// Notifier-internal error not covered by the others.
    Internal { reason: String },
}

impl NotificationError {
    /// Bounded metrics label.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::Misconfigured { .. } => "misconfigured",
            Self::Throttled { .. } => "throttled",
            Self::Internal { .. } => "internal",
        }
    }
}

impl std::fmt::Display for NotificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "backend: {reason}"),
            Self::Misconfigured { reason } => write!(f, "misconfigured: {reason}"),
            Self::Throttled { reason } => write!(f, "throttled: {reason}"),
            Self::Internal { reason } => write!(f, "internal: {reason}"),
        }
    }
}

impl std::error::Error for NotificationError {}

// ---------------------------------------------------------------------------
// Resolution outcome
// ---------------------------------------------------------------------------

/// What the human decided. Notifiers + the direct-callback
/// webhook both pass this to
/// `PluginRegistry::resolve_pending_approval`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Human approved. Optional reason text surfaces in audit.
    Approved {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approver_subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Human denied. Reason flows to the caller as the deny
    /// message.
    Denied {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approver_subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Async trait
// ---------------------------------------------------------------------------

/// Notifier — posts approval requests to a human-facing channel
/// (Slack, email, PagerDuty, Teams, etc.). Plugin authors
/// implement this against their channel's API.
#[async_trait::async_trait]
pub trait ApprovalNotifier: Send + Sync {
    /// Plugin manifest. The gateway uses this for capability
    /// checks + observability.
    fn manifest(&self) -> &PluginManifest;

    /// Deliver the approval request. Returns once the message is
    /// posted (or the notifier fails). The gateway then awaits a
    /// separate resolution callback — either the notifier's own
    /// http_route (Slack interactive callback) or the
    /// HMAC-signed direct URL embedded in `request.direct_callback_url`.
    async fn notify(
        &self,
        request: &NotificationRequest,
    ) -> Result<NotificationResult, NotificationError>;

    /// Optional graceful-shutdown hook. Notifiers with in-flight
    /// background tasks (Slack rate-limit retry queues, PagerDuty
    /// debounce timers) drain here.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn approval_outcome_serializes_with_outcome_tag() {
        let approved = ApprovalOutcome::Approved {
            approver_subject: Some("alice".into()),
            reason: None,
        };
        let s = serde_json::to_string(&approved).unwrap();
        assert!(s.contains("\"outcome\":\"approved\""));
        assert!(s.contains("alice"));

        let denied = ApprovalOutcome::Denied {
            approver_subject: None,
            reason: Some("not authorized".into()),
        };
        let s = serde_json::to_string(&denied).unwrap();
        assert!(s.contains("\"outcome\":\"denied\""));
    }

    #[test]
    fn notification_request_roundtrip() {
        let identity = PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("alice".into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: Default::default(),
        };
        let req = NotificationRequest {
            approval_id: "appr-123".into(),
            summary: "delete order #42".into(),
            deadline_at: "2026-04-26T00:30:00Z".into(),
            direct_callback_url:
                "https://gw.example.com/webhooks/approvals/appr-123?expires=...&sig=...".into(),
            identity,
            tool_name: "orders.delete".into(),
            arguments: Some(json!({"order_id": 42})),
            metadata: Some(json!({"channel": "#approvals"})),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: NotificationRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.approval_id, "appr-123");
        assert_eq!(back.tool_name, "orders.delete");
    }

    #[test]
    fn notification_error_kind_labels_are_bounded() {
        assert_eq!(
            NotificationError::Backend { reason: "x".into() }.kind_label(),
            "backend"
        );
        assert_eq!(
            NotificationError::Misconfigured { reason: "x".into() }.kind_label(),
            "misconfigured"
        );
        assert_eq!(
            NotificationError::Throttled { reason: "x".into() }.kind_label(),
            "throttled"
        );
        assert_eq!(
            NotificationError::Internal { reason: "x".into() }.kind_label(),
            "internal"
        );
    }
}
